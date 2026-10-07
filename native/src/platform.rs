//! The Native platform (spec 20): the PAL of spec 18 on a unikernel.
//!
//! What comes from the machine, with no host operating system, is time (the
//! board's real-time clock and timer, through the Hermit kernel) and entropy
//! (the CPU's random number generator, read directly: see [`NativeEntropy`]).
//! Everything else lives in RAM for this spike: keys, storage, IPC and
//! components. The adapter host runs as an in-process component, or, when the
//! guest has a channel to another guest (N1.4, [`crate::channel`]), in that
//! other guest: the node does not know which. Persistent storage and a
//! hardware key store are later steps (spec 20, *Not yet*).

use std::fs::File;
use std::io::BufReader;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chitala_platform::memory::{MemoryExec, MemoryIpc, MemoryKeyStore, MemoryStorage, NoNetwork, Program};
use chitala_platform::{
    contract, ComponentHandle, ComponentSpec, Entropy, ExecutionHost, NoDevices, Platform, PlatformError, Spawned,
    TimeSource, TrustedClock,
};

use crate::channel;

/// The component name of the adapter host.
pub const ADAPTER_HOST: &str = "adapter-host";

/// The board's clocks, as the kernel reports them.
pub struct NativeTime {
    origin: Instant,
}

impl NativeTime {
    pub fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

impl TimeSource for NativeTime {
    fn wall_ms(&self) -> u64 {
        // a clock before 1970 reads as 0: the trusted clock's floor takes over
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }

    fn monotonic_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
}

/// Where the platform's randomness comes from. A platform without a secure
/// source does not start: the PAL's rule is to fail closed, never to hand out
/// weak bytes.
pub struct NativeEntropy {
    #[cfg_attr(not(all(target_os = "hermit", target_arch = "aarch64")), allow(dead_code))]
    source: Source,
}

#[cfg(all(target_os = "hermit", target_arch = "aarch64"))]
type Source = aarch64_cpu::asm::random::ArmRng;
#[cfg(not(all(target_os = "hermit", target_arch = "aarch64")))]
type Source = ();

/// A transient `RNDR` failure is retried; this many in a row is a broken RNG.
#[cfg(all(target_os = "hermit", target_arch = "aarch64"))]
const RNDR_RETRIES: u32 = 1_000;

impl NativeEntropy {
    /// The CPU's random number generator (Armv8.5 FEAT_RNG). The Hermit
    /// kernel's own source is not used: on aarch64 it has none and falls back
    /// to a predictable generator without failing.
    #[cfg(all(target_os = "hermit", target_arch = "aarch64"))]
    pub fn new() -> Result<Self, String> {
        let source = aarch64_cpu::asm::random::ArmRng::new()
            .ok_or("the CPU has no random number generator (Armv8.5 FEAT_RNG, RNDR)")?;
        Ok(Self { source })
    }

    #[cfg(all(target_os = "hermit", not(target_arch = "aarch64")))]
    pub fn new() -> Result<Self, String> {
        Err(format!("no admitted entropy source on {} yet", std::env::consts::ARCH))
    }

    /// The development host's operating system.
    #[cfg(not(target_os = "hermit"))]
    pub fn new() -> Result<Self, String> {
        let mut probe = [0u8; 32];
        getrandom::getrandom(&mut probe).map_err(|e| format!("the host has no random source: {e}"))?;
        Ok(Self { source: () })
    }

    pub fn describe(&self) -> &'static str {
        if cfg!(target_os = "hermit") {
            "CPU RNDR (FEAT_RNG)"
        } else {
            "host OS"
        }
    }
}

impl Entropy for NativeEntropy {
    #[cfg(all(target_os = "hermit", target_arch = "aarch64"))]
    fn fill(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = (0..RNDR_RETRIES)
                .find_map(|_| self.source.rndr())
                .unwrap_or_else(|| panic!("the CPU's random number generator keeps failing; refusing to continue"));
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
    }

    #[cfg(not(target_os = "hermit"))]
    fn fill(&self, buf: &mut [u8]) {
        if let Err(e) = getrandom::getrandom(buf) {
            panic!("the host's random source failed ({e}); refusing to continue");
        }
    }

    #[cfg(all(target_os = "hermit", not(target_arch = "aarch64")))]
    fn fill(&self, _buf: &mut [u8]) {
        unreachable!("NativeEntropy::new refuses this architecture")
    }
}

/// N1.4: the adapter host in the guest at the other end of the channel.
/// The handshake runs on its own thread from this guest's start, the only
/// reader of the channel until the other side is READY. Starting the adapter
/// host takes the channel once the handshake is done; the adapter host's
/// protocol then runs on it, unchanged.
///
/// N1.6: the core never waits on the other guest without end. The first
/// start waits for the handshake until [`HANDSHAKE_GRACE`] after this
/// guest's start; past it, starting fails at once, the node treats the
/// adapter host as unavailable (its orders are not sent) and carries on. A
/// handshake that completes later is still taken by the next start. The other
/// guest cannot be restarted from this one: once the channel has been taken,
/// starting it again fails.
struct ChannelExec {
    handshake: Arc<(Mutex<Handshake>, Condvar)>,
    deadline: Instant,
    told: AtomicBool,
}

/// How long the other guest has, from this guest's start, to answer the
/// handshake. It boots alongside this one, in seconds.
const HANDSHAKE_GRACE: Duration = Duration::from_secs(20);

enum Handshake {
    Waiting,
    /// the node writes to the first handle and reads from the second
    Up(File, File),
    Failed(String),
    Taken,
}

impl ChannelExec {
    fn new() -> Self {
        let handshake = Arc::new((Mutex::new(Handshake::Waiting), Condvar::new()));
        let shared = Arc::clone(&handshake);
        std::thread::spawn(move || {
            let up = channel::open().and_then(|mut input| {
                let mut output = channel::open()?;
                channel::connect(&mut output, &mut input)?;
                Ok((input, output))
            });
            let (state, done) = &*shared;
            *state.lock().unwrap_or_else(|p| p.into_inner()) = match up {
                Ok((input, output)) => Handshake::Up(input, output),
                Err(e) => Handshake::Failed(format!("{}: {e}", channel::PATH)),
            };
            done.notify_all();
        });
        Self { handshake, deadline: Instant::now() + HANDSHAKE_GRACE, told: AtomicBool::new(false) }
    }
}

struct ChannelHandle;

impl ComponentHandle for ChannelHandle {
    /// The adapter host's guest runs on; only this side lets go.
    fn kill(&mut self) {}
    fn id(&self) -> Option<u32> {
        None
    }
}

impl ExecutionHost for ChannelExec {
    fn spawn(&self, spec: &ComponentSpec) -> chitala_platform::Result<Spawned> {
        if spec.program != ADAPTER_HOST {
            return Err(PlatformError::NotFound(format!("no program {:?} in the other guest", spec.program)));
        }
        let (state, done) = &*self.handshake;
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            match std::mem::replace(&mut *st, Handshake::Taken) {
                Handshake::Up(input, output) => {
                    return Ok(Spawned {
                        input: Box::new(input),
                        output: Box::new(output),
                        handle: Box::new(ChannelHandle),
                    })
                }
                Handshake::Taken => {
                    return Err(PlatformError::Unsupported(
                        "the adapter host's guest cannot be restarted from this guest".into(),
                    ))
                }
                Handshake::Failed(e) => {
                    *st = Handshake::Failed(e.clone());
                    return Err(PlatformError::Io(e));
                }
                Handshake::Waiting => {
                    *st = Handshake::Waiting;
                    let now = Instant::now();
                    if now >= self.deadline {
                        let why = format!(
                            "the adapter host's guest did not answer the handshake within {} s",
                            HANDSHAKE_GRACE.as_secs()
                        );
                        if !self.told.swap(true, Ordering::SeqCst) {
                            println!("[node]      adapter host unavailable: {why}; carrying on without it");
                        }
                        return Err(PlatformError::Unsupported(why));
                    }
                    st = done.wait_timeout(st, self.deadline - now).unwrap_or_else(|p| p.into_inner()).0;
                }
            }
        }
    }

    /// The other guest has its own memory, under seL4. This is the spike's
    /// claim, from the topology: N1.5 tests it, and the built system's
    /// PlatformIsolationEvidence checks it (native/spike/scripts/
    /// isolation-evidence.py). After N1, isolation
    /// must come from the platform's validated configuration or from
    /// attestation, never from a constant (docs/architecture/direction.md).
    fn isolated(&self) -> bool {
        true
    }
}

/// Where the adapter host runs, as the boot line says it.
pub fn adapter_host_place() -> &'static str {
    if channel::present() {
        "in another guest, over the channel"
    } else {
        "in this image (an in-process component)"
    }
}

/// The real adapter host protocol loop, as a component of the execution host.
fn adapter_host(time: Arc<dyn TimeSource>) -> Program {
    Arc::new(move |input, mut output, _env| {
        let clock = Arc::new(TrustedClock::new(Arc::clone(&time), 0)).as_clock();
        chitala_adapters::host::run(&mut BufReader::new(input), &mut output, clock);
    })
}

pub fn platform(entropy: Arc<NativeEntropy>) -> Platform {
    let entropy: Arc<dyn Entropy> = entropy;
    let time: Arc<dyn TimeSource> = Arc::new(NativeTime::new());
    let exec: Arc<dyn ExecutionHost> = if channel::present() {
        Arc::new(ChannelExec::new())
    } else {
        let exec = MemoryExec::new();
        exec.register(ADAPTER_HOST, adapter_host(Arc::clone(&time)));
        Arc::new(exec)
    };
    Platform {
        name: "native-hermit",
        time,
        keys: Arc::new(MemoryKeyStore::new(Arc::clone(&entropy))),
        entropy,
        storage: Arc::new(MemoryStorage::new()),
        ipc: Arc::new(MemoryIpc::new()),
        exec,
        network: Arc::new(NoNetwork),
        devices: Arc::new(NoDevices),
    }
}

/// Run the PAL contract (spec 18) against fresh instances of every backend
/// this platform uses. Panics on the first violation.
pub fn check_contract(entropy: &Arc<NativeEntropy>) -> Vec<&'static str> {
    let p = platform(Arc::clone(entropy));
    contract::time(p.time.as_ref());
    contract::entropy(p.entropy.as_ref());
    contract::key_store(p.keys.as_ref());
    let storage = MemoryStorage::new();
    contract::storage(&storage, &|path| storage.weaken(path));
    contract::ipc(p.ipc.as_ref());
    let exec = MemoryExec::new();
    exec.register("echo", contract::echo_program());
    contract::exec(&exec, &ComponentSpec { program: "echo".into(), env: vec![] });
    vec!["time", "entropy", "key store", "storage", "ipc", "exec"]
}
