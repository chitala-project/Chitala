//! In-memory backend: deterministic and free of OS calls. For tests and the
//! simulator — **never for production**: entropy is seeded, keys live in RAM and
//! components are threads (no isolation).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::{
    AppendLog, ComponentHandle, ComponentSpec, DeviceAddress, DeviceChannel, DeviceInfo, DeviceIo, Endpoint, Entropy,
    ExecutionHost, HttpRequest, HttpResponse, IpcListener, IpcStream, IpcTransport, KeyRef, KeyStoreInfo,
    NetworkTransport, Platform, PlatformError, Result, SecureKeyStore, SeedSigner, Signer, Spawned, Storage,
    StoragePath, TimeSource, Visibility,
};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ───────────────────────────── time ─────────────────────────────

/// A clock driven by the test: wall and monotonic time move only when told to.
pub struct MemoryTime {
    wall: AtomicU64,
    mono: AtomicU64,
}

impl MemoryTime {
    pub fn new(wall_ms: u64) -> Self {
        Self { wall: AtomicU64::new(wall_ms), mono: AtomicU64::new(0) }
    }
    /// Set the wall clock (forward or backward); the monotonic clock is untouched.
    pub fn set_wall(&self, ms: u64) {
        self.wall.store(ms, Ordering::SeqCst);
    }
    /// Let real time pass: both clocks advance.
    pub fn advance(&self, ms: u64) {
        self.wall.fetch_add(ms, Ordering::SeqCst);
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }
    pub fn advance_monotonic(&self, ms: u64) {
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }
}

impl TimeSource for MemoryTime {
    fn wall_ms(&self) -> u64 {
        self.wall.load(Ordering::SeqCst)
    }
    fn monotonic_ms(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }
}

// ───────────────────────────── entropy ─────────────────────────────

/// Deterministic byte stream: SHA-256(seed ‖ counter). Reproducible test runs,
/// **not** secure randomness.
pub struct SeededEntropy {
    seed: [u8; 32],
    counter: AtomicU64,
}

impl SeededEntropy {
    pub fn new(seed: &str) -> Self {
        Self { seed: Sha256::digest(seed.as_bytes()).into(), counter: AtomicU64::new(0) }
    }
}

/// One deterministic source shared by a whole test process: every draw
/// differs, nothing touches the OS. **Tests only.**
pub fn test_entropy() -> &'static SeededEntropy {
    static E: std::sync::OnceLock<SeededEntropy> = std::sync::OnceLock::new();
    E.get_or_init(|| SeededEntropy::new("chitala-test-entropy"))
}

impl Entropy for SeededEntropy {
    fn fill(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(32) {
            let n = self.counter.fetch_add(1, Ordering::SeqCst);
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(n.to_le_bytes());
            let block = h.finalize();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

// ───────────────────────────── keys ─────────────────────────────

pub struct MemoryKeyStore {
    keys: Mutex<BTreeMap<KeyRef, [u8; 32]>>,
    entropy: Arc<dyn Entropy>,
    info: KeyStoreInfo,
}

impl MemoryKeyStore {
    /// A software store whose keys can be exported.
    pub fn new(entropy: Arc<dyn Entropy>) -> Self {
        Self {
            keys: Mutex::new(BTreeMap::new()),
            entropy,
            info: KeyStoreInfo { hardware_backed: false, exportable: true },
        }
    }

    /// Behaves like hardware: keys can sign but never leave the store.
    pub fn non_exportable(entropy: Arc<dyn Entropy>) -> Self {
        Self { info: KeyStoreInfo { hardware_backed: true, exportable: false }, ..Self::new(entropy) }
    }

    /// Put a known key in the store (test vectors).
    pub fn import(&self, key: &KeyRef, seed: &[u8; 32]) -> Result<[u8; 32]> {
        let mut keys = lock(&self.keys);
        if keys.contains_key(key) {
            return Err(PlatformError::AlreadyExists(key.to_string()));
        }
        keys.insert(key.clone(), *seed);
        Ok(SeedSigner::from_seed(seed).public_key())
    }
}

impl SecureKeyStore for MemoryKeyStore {
    fn info(&self) -> KeyStoreInfo {
        self.info
    }
    fn contains(&self, key: &KeyRef) -> Result<bool> {
        Ok(lock(&self.keys).contains_key(key))
    }
    fn generate(&self, key: &KeyRef) -> Result<[u8; 32]> {
        let seed = crate::random_array(&*self.entropy);
        self.import(key, &seed)
    }
    fn signer(&self, key: &KeyRef) -> Result<Arc<dyn Signer>> {
        let keys = lock(&self.keys);
        let seed = keys.get(key).ok_or_else(|| PlatformError::NotFound(key.to_string()))?;
        Ok(Arc::new(SeedSigner::from_seed(seed)))
    }
    fn export_seed(&self, key: &KeyRef) -> Result<[u8; 32]> {
        if !self.info.exportable {
            return Err(PlatformError::Unsupported(format!("{key} is not exportable")));
        }
        lock(&self.keys).get(key).copied().ok_or_else(|| PlatformError::NotFound(key.to_string()))
    }
}

// ───────────────────────────── storage ─────────────────────────────

struct Object {
    data: Vec<u8>,
    visibility: Visibility,
    /// Simulates a protection downgrade outside Chitala (a `chmod` on a host).
    weakened: bool,
}

type Objects = Arc<Mutex<BTreeMap<String, Object>>>;

#[derive(Default)]
pub struct MemoryStorage {
    objects: Objects,
    /// Paths whose replacements fail after this many more succeed (a disk
    /// that fills up, a device that fails).
    failing: Mutex<BTreeMap<String, usize>>,
    /// Paths claimed now ([`Storage::claim`]).
    claims: Arc<Mutex<std::collections::BTreeSet<String>>>,
}

/// A claim on a [`MemoryStorage`] path; dropping it ends the claim.
struct MemoryClaim {
    claims: Arc<Mutex<std::collections::BTreeSet<String>>>,
    path: String,
}

impl crate::storage::Claim for MemoryClaim {}

impl Drop for MemoryClaim {
    fn drop(&mut self) {
        lock(&self.claims).remove(&self.path);
    }
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make an object readable/writable by others (contract tests).
    pub fn weaken(&self, path: &StoragePath) {
        if let Some(o) = lock(&self.objects).get_mut(path.as_str()) {
            o.weakened = true;
        }
    }

    /// Make every `write_atomic` of `path` fail, or succeed again (fault tests).
    pub fn fail_writes(&self, path: &StoragePath, fail: bool) {
        let mut f = lock(&self.failing);
        if fail {
            f.insert(path.as_str().to_string(), 0);
        } else {
            f.remove(path.as_str());
        }
    }

    /// Let `ok` more replacements of `path` succeed, then fail every one.
    pub fn fail_writes_after(&self, path: &StoragePath, ok: usize) {
        lock(&self.failing).insert(path.as_str().to_string(), ok);
    }

    /// Overwrite raw bytes behind the platform's back (tampering tests).
    pub fn tamper(&self, path: &StoragePath, data: Vec<u8>) {
        if let Some(o) = lock(&self.objects).get_mut(path.as_str()) {
            o.data = data;
        }
    }

    fn check(o: &Object, wanted: Visibility, path: &StoragePath) -> Result<()> {
        if wanted == Visibility::Private && (o.visibility != Visibility::Private || o.weakened) {
            return Err(PlatformError::Insecure(format!("{path} is accessible by others")));
        }
        Ok(())
    }
}

struct MemoryLog {
    objects: Objects,
    path: String,
}

impl AppendLog for MemoryLog {
    fn append(&mut self, record: &[u8]) -> Result<()> {
        let mut objects = lock(&self.objects);
        let o = objects.get_mut(&self.path).ok_or_else(|| PlatformError::NotFound(self.path.clone()))?;
        o.data.extend_from_slice(record);
        Ok(())
    }
}

impl Storage for MemoryStorage {
    fn read(&self, path: &StoragePath, visibility: Visibility) -> Result<Option<Vec<u8>>> {
        let objects = lock(&self.objects);
        match objects.get(path.as_str()) {
            None => Ok(None),
            Some(o) => {
                Self::check(o, visibility, path)?;
                Ok(Some(o.data.clone()))
            }
        }
    }
    fn write_atomic(&self, path: &StoragePath, data: &[u8], visibility: Visibility) -> Result<()> {
        if let Some(left) = lock(&self.failing).get_mut(path.as_str()) {
            if *left == 0 {
                return Err(PlatformError::Io(format!("{path}: injected write failure")));
            }
            *left -= 1;
        }
        lock(&self.objects)
            .insert(path.as_str().to_string(), Object { data: data.to_vec(), visibility, weakened: false });
        Ok(())
    }
    fn create_new(&self, path: &StoragePath, data: &[u8], visibility: Visibility) -> Result<()> {
        let mut objects = lock(&self.objects);
        if objects.contains_key(path.as_str()) {
            return Err(PlatformError::AlreadyExists(path.to_string()));
        }
        objects.insert(path.as_str().to_string(), Object { data: data.to_vec(), visibility, weakened: false });
        Ok(())
    }
    fn open_append(&self, path: &StoragePath, visibility: Visibility) -> Result<Box<dyn AppendLog>> {
        let mut objects = lock(&self.objects);
        match objects.get(path.as_str()) {
            Some(o) => Self::check(o, visibility, path)?,
            None => {
                objects.insert(path.as_str().to_string(), Object { data: Vec::new(), visibility, weakened: false });
            }
        }
        Ok(Box::new(MemoryLog { objects: Arc::clone(&self.objects), path: path.as_str().to_string() }))
    }
    fn exists(&self, path: &StoragePath) -> Result<bool> {
        Ok(lock(&self.objects).contains_key(path.as_str()))
    }
    fn remove(&self, path: &StoragePath) -> Result<()> {
        lock(&self.objects).remove(path.as_str()).map(|_| ()).ok_or_else(|| PlatformError::NotFound(path.to_string()))
    }
    fn ensure_dir(&self, _path: &StoragePath, _visibility: Visibility) -> Result<()> {
        Ok(())
    }
    fn claim(&self, path: &StoragePath) -> Result<Box<dyn crate::storage::Claim>> {
        if !lock(&self.claims).insert(path.as_str().to_string()) {
            return Err(PlatformError::AlreadyExists(format!("{path} is claimed")));
        }
        Ok(Box::new(MemoryClaim { claims: Arc::clone(&self.claims), path: path.as_str().to_string() }))
    }
}

// ───────────────────────────── pipes ─────────────────────────────

#[derive(Default)]
struct PipeState {
    buf: VecDeque<u8>,
    writers: usize,
    readers: usize,
    closed: bool,
}

#[derive(Default)]
struct PipeShared {
    state: Mutex<PipeState>,
    ready: Condvar,
}

impl PipeShared {
    fn close(&self) {
        lock(&self.state).closed = true;
        self.ready.notify_all();
    }
}

/// An in-memory byte pipe; `(writer, reader)`.
fn pipe() -> (PipeWriter, PipeReader) {
    let shared = Arc::new(PipeShared::default());
    (PipeWriter::new(Arc::clone(&shared)), PipeReader::new(shared, Arc::new(Mutex::new(None))))
}

struct PipeWriter {
    shared: Arc<PipeShared>,
}

impl PipeWriter {
    fn new(shared: Arc<PipeShared>) -> Self {
        lock(&shared.state).writers += 1;
        Self { shared }
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        lock(&self.shared.state).writers -= 1;
        self.shared.ready.notify_all();
    }
}

impl Write for PipeWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut st = lock(&self.shared.state);
        if st.closed || st.readers == 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"));
        }
        st.buf.extend(data);
        self.shared.ready.notify_all();
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PipeReader {
    shared: Arc<PipeShared>,
    timeout: Arc<Mutex<Option<Duration>>>,
}

impl PipeReader {
    fn new(shared: Arc<PipeShared>, timeout: Arc<Mutex<Option<Duration>>>) -> Self {
        lock(&shared.state).readers += 1;
        Self { shared, timeout }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        lock(&self.shared.state).readers -= 1;
    }
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let timeout = *lock(&self.timeout);
        let mut st = lock(&self.shared.state);
        loop {
            if !st.buf.is_empty() {
                let n = out.len().min(st.buf.len());
                for (i, b) in st.buf.drain(..n).enumerate() {
                    out[i] = b;
                }
                return Ok(n);
            }
            if st.closed || st.writers == 0 {
                return Ok(0);
            }
            st = match timeout {
                None => self.shared.ready.wait(st).unwrap_or_else(|p| p.into_inner()),
                Some(t) => {
                    let (g, res) = self.shared.ready.wait_timeout(st, t).unwrap_or_else(|p| p.into_inner());
                    if res.timed_out() && g.buf.is_empty() && !g.closed && g.writers > 0 {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "read timed out"));
                    }
                    g
                }
            };
        }
    }
}

// ───────────────────────────── IPC ─────────────────────────────

struct Duplex {
    reader: PipeReader,
    writer: PipeWriter,
}

impl Read for Duplex {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.reader.read(out)
    }
}

impl Write for Duplex {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.writer.write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl IpcStream for Duplex {
    fn try_clone(&self) -> Result<Box<dyn IpcStream>> {
        Ok(Box::new(Duplex {
            reader: PipeReader::new(Arc::clone(&self.reader.shared), Arc::clone(&self.reader.timeout)),
            writer: PipeWriter::new(Arc::clone(&self.writer.shared)),
        }))
    }
    fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.reader.timeout) = timeout;
        Ok(())
    }
}

fn duplex_pair() -> (Duplex, Duplex) {
    let (w1, r1) = pipe();
    let (w2, r2) = pipe();
    (Duplex { reader: r1, writer: w2 }, Duplex { reader: r2, writer: w1 })
}

struct Registration {
    queue: Sender<Duplex>,
    alive: Arc<AtomicBool>,
}

#[derive(Default)]
pub struct MemoryIpc {
    endpoints: Mutex<HashMap<String, Registration>>,
}

impl MemoryIpc {
    pub fn new() -> Self {
        Self::default()
    }
}

struct MemoryListener {
    incoming: Mutex<Receiver<Duplex>>,
    alive: Arc<AtomicBool>,
}

impl Drop for MemoryListener {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
    }
}

impl IpcListener for MemoryListener {
    fn accept(&self) -> Result<Box<dyn IpcStream>> {
        let rx = lock(&self.incoming);
        rx.recv().map(|d| Box::new(d) as Box<dyn IpcStream>).map_err(|_| PlatformError::Io("endpoint closed".into()))
    }
}

impl IpcTransport for MemoryIpc {
    fn listen(&self, endpoint: &Endpoint) -> Result<Box<dyn IpcListener>> {
        let mut eps = lock(&self.endpoints);
        if eps.get(endpoint.as_str()).is_some_and(|r| r.alive.load(Ordering::SeqCst)) {
            return Err(PlatformError::AlreadyExists(format!("{endpoint} is in use")));
        }
        let (tx, rx) = mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));
        eps.insert(endpoint.as_str().to_string(), Registration { queue: tx, alive: Arc::clone(&alive) });
        Ok(Box::new(MemoryListener { incoming: Mutex::new(rx), alive }))
    }
    fn connect(&self, endpoint: &Endpoint) -> Result<Box<dyn IpcStream>> {
        let eps = lock(&self.endpoints);
        let reg = eps
            .get(endpoint.as_str())
            .filter(|r| r.alive.load(Ordering::SeqCst))
            .ok_or_else(|| PlatformError::NotFound(format!("no listener on {endpoint}")))?;
        let (client, server) = duplex_pair();
        reg.queue.send(server).map_err(|_| PlatformError::NotFound(format!("no listener on {endpoint}")))?;
        Ok(Box::new(client))
    }
    fn describe(&self, endpoint: &Endpoint) -> String {
        format!("memory://{endpoint}")
    }
}

// ───────────────────────────── execution ─────────────────────────────

/// An in-process "program": reads its input, writes its output, gets its env.
pub type Program = Arc<dyn Fn(Box<dyn Read + Send>, Box<dyn Write + Send>, Vec<(String, String)>) + Send + Sync>;

#[derive(Default)]
pub struct MemoryExec {
    programs: Mutex<HashMap<String, Program>>,
}

impl MemoryExec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, name: &str, program: Program) {
        lock(&self.programs).insert(name.to_string(), program);
    }
}

struct ThreadHandle {
    input: Arc<PipeShared>,
    output: Arc<PipeShared>,
}

impl ComponentHandle for ThreadHandle {
    fn kill(&mut self) {
        // a thread cannot be killed; closing its channels makes it observe EOF
        // and makes every further exchange fail, which is what callers rely on
        self.input.close();
        self.output.close();
    }
    fn id(&self) -> Option<u32> {
        None
    }
}

impl ExecutionHost for MemoryExec {
    fn spawn(&self, spec: &ComponentSpec) -> Result<Spawned> {
        let program = lock(&self.programs)
            .get(&spec.program)
            .cloned()
            .ok_or_else(|| PlatformError::NotFound(format!("no program {:?}", spec.program)))?;
        let (in_w, in_r) = pipe();
        let (out_w, out_r) = pipe();
        let handle = ThreadHandle { input: Arc::clone(&in_w.shared), output: Arc::clone(&out_w.shared) };
        let env = spec.env.clone();
        std::thread::spawn(move || program(Box::new(in_r), Box::new(out_w), env));
        Ok(Spawned { input: Box::new(in_w), output: Box::new(out_r), handle: Box::new(handle) })
    }
    fn isolated(&self) -> bool {
        false
    }
}

// ───────────────────────────── network ─────────────────────────────

/// No network at all.
pub struct NoNetwork;

impl NetworkTransport for NoNetwork {
    fn http(&self, request: &HttpRequest) -> Result<HttpResponse> {
        Err(PlatformError::Unsupported(format!("no network in this platform ({})", request.url)))
    }
}

// ───────────────────────────── devices ─────────────────────────────

/// What a simulated device answers to the bytes written to it.
pub type Responder = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// Simulated hardware: each registered device answers writes through its responder.
#[derive(Default)]
pub struct MemoryDevices {
    devices: Mutex<BTreeMap<DeviceAddress, (String, Responder)>>,
    open: Arc<Mutex<BTreeSet<DeviceAddress>>>,
}

impl MemoryDevices {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, address: DeviceAddress, description: &str, responder: Responder) {
        self.devices.lock().unwrap_or_else(|p| p.into_inner()).insert(address, (description.into(), responder));
    }
}

struct MemoryChannel {
    address: DeviceAddress,
    responder: Responder,
    pending: VecDeque<u8>,
    open: Arc<Mutex<BTreeSet<DeviceAddress>>>,
}

impl Drop for MemoryChannel {
    fn drop(&mut self) {
        self.open.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.address);
    }
}

impl DeviceChannel for MemoryChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = buf.len().min(self.pending.len());
        for (i, b) in self.pending.drain(..n).enumerate() {
            buf[i] = b;
        }
        Ok(n)
    }
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.pending.extend((self.responder)(data));
        Ok(())
    }
    fn set_timeout(&mut self, _timeout: Duration) -> Result<()> {
        Ok(())
    }
}

impl DeviceIo for MemoryDevices {
    fn devices(&self) -> Vec<DeviceInfo> {
        let d = self.devices.lock().unwrap_or_else(|p| p.into_inner());
        d.iter().map(|(a, (desc, _))| DeviceInfo { address: a.clone(), description: desc.clone() }).collect()
    }

    fn open(&self, address: &DeviceAddress) -> Result<Box<dyn DeviceChannel>> {
        let responder = {
            let d = self.devices.lock().unwrap_or_else(|p| p.into_inner());
            let (_, r) = d.get(address).ok_or_else(|| PlatformError::NotFound(address.to_string()))?;
            Arc::clone(r)
        };
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        if !open.insert(address.clone()) {
            return Err(PlatformError::AlreadyExists(format!("{address} is already open")));
        }
        Ok(Box::new(MemoryChannel {
            address: address.clone(),
            responder,
            pending: VecDeque::new(),
            open: Arc::clone(&self.open),
        }))
    }
}

// ───────────────────────────── assembly ─────────────────────────────

/// Handles to the concrete memory backends, for tests that steer them.
pub struct MemoryControls {
    pub time: Arc<MemoryTime>,
    pub keys: Arc<MemoryKeyStore>,
    pub storage: Arc<MemoryStorage>,
    pub exec: Arc<MemoryExec>,
    pub devices: Arc<MemoryDevices>,
}

/// A complete in-memory platform; `seed` makes entropy (and thus keys) reproducible.
pub fn platform(seed: &str, wall_ms: u64) -> (Platform, MemoryControls) {
    let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(seed));
    let time = Arc::new(MemoryTime::new(wall_ms));
    let keys = Arc::new(MemoryKeyStore::new(Arc::clone(&entropy)));
    let storage = Arc::new(MemoryStorage::new());
    let exec = Arc::new(MemoryExec::new());
    let devices = Arc::new(MemoryDevices::new());
    let p = Platform {
        name: "memory",
        time: time.clone(),
        entropy,
        keys: keys.clone(),
        storage: storage.clone(),
        ipc: Arc::new(MemoryIpc::new()),
        exec: exec.clone(),
        network: Arc::new(NoNetwork),
        devices: devices.clone(),
    };
    (p, MemoryControls { time, keys, storage, exec, devices })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract;

    #[test]
    fn memory_backend_passes_the_contract() {
        let (p, c) = platform("contract", 1_790_000_000_000);
        contract::time(&*p.time);
        contract::entropy(&*p.entropy);
        contract::key_store(&*p.keys);
        contract::key_store(&MemoryKeyStore::non_exportable(p.entropy.clone()));
        contract::storage(&*p.storage, &|path| c.storage.weaken(path));
        contract::ipc(&*p.ipc);
        c.exec.register("echo", contract::echo_program());
        contract::exec(&*p.exec, &ComponentSpec { program: "echo".into(), env: vec![] });
        let echo = DeviceAddress::new("serial:echo").unwrap();
        c.devices.add(echo.clone(), "loopback", Arc::new(|b: &[u8]| b.to_vec()));
        contract::devices(&*p.devices, &echo, true);
    }

    #[test]
    fn seeded_entropy_is_reproducible() {
        let a = crate::random_array::<48>(&SeededEntropy::new("x"));
        let b = crate::random_array::<48>(&SeededEntropy::new("x"));
        let c = crate::random_array::<48>(&SeededEntropy::new("y"));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
