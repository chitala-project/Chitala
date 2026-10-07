//! Hosted backend of the Chitala PAL (spec `specs/18-platform.md`, Blueprint v20 §3.1).
//!
//! The only crate allowed to call host-OS APIs on behalf of the Trusted Core:
//! files and permission bits, Unix sockets, processes, the system clock, the OS
//! RNG, HTTP and configured character devices. Everything here implements a `chitala-platform` trait and
//! passes `chitala_platform::contract`.
//!
//! Supported hosts: Unix (Linux, macOS). Private storage, IPC and process
//! isolation rely on Unix semantics; other hosts need their own backend
//! (named pipes, ACLs) rather than a weaker fallback.

#![forbid(unsafe_code)]

mod device;
mod exec;
mod fs;
mod ipc;
mod net;

use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use chitala_platform::{Entropy, Platform, Result, SoftwareKeyStore, StoragePath, TimeSource};

pub use device::HostDevices;
pub use exec::ProcessHost;
pub use fs::FsStorage;
pub use ipc::{UnixIpc, MAX_SOCKET_PATH};
pub use net::UreqNetwork;

/// System clock: wall time from the OS, monotonic time from `Instant`.
pub struct SystemTimeSource {
    origin: Instant,
}

impl SystemTimeSource {
    pub fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

impl Default for SystemTimeSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for SystemTimeSource {
    fn wall_ms(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
    fn monotonic_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
}

/// The operating system's CSPRNG. Panics if it fails (fail closed).
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&self, buf: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(buf);
    }
}

/// Storage directory of the key store inside the platform root.
pub const KEYS_DIR: &str = "keys";

/// A hosted platform rooted at `root` (the domain directory): storage and keys
/// under `root`, IPC endpoints next to it (or in a private per-user directory
/// when the path is too long for a Unix socket).
pub fn platform(root: &Path) -> Result<Platform> {
    let entropy: Arc<dyn Entropy> = Arc::new(OsEntropy);
    let storage = Arc::new(FsStorage::new(root)?);
    let keys = SoftwareKeyStore::new(storage.clone(), Arc::clone(&entropy), StoragePath::new(KEYS_DIR)?)?;
    Ok(Platform {
        name: "hosted-unix",
        time: Arc::new(SystemTimeSource::new()),
        entropy,
        keys: Arc::new(keys),
        storage,
        ipc: Arc::new(UnixIpc::new(root)?),
        exec: Arc::new(ProcessHost),
        network: Arc::new(UreqNetwork),
        devices: Arc::new(chitala_platform::NoDevices),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_platform::{contract, ComponentSpec, ExecutionHost};
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn temp_root(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "chitala-pal-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn hosted_backend_passes_the_contract() {
        let root = temp_root("contract");
        let p = platform(&root).unwrap();
        contract::time(&*p.time);
        contract::entropy(&*p.entropy);
        contract::key_store(&*p.keys);
        let weaken_root = root.clone();
        contract::storage(&*p.storage, &move |path| {
            let f = weaken_root.join(path.as_str());
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644)).unwrap();
        });
        contract::ipc(&*p.ipc);
        let echo = root.join("echo.sh");
        std::fs::write(&echo, "#!/bin/sh\nwhile read l; do echo \"$l\"; done\n").unwrap();
        std::fs::set_permissions(&echo, std::fs::Permissions::from_mode(0o700)).unwrap();
        contract::exec(&*p.exec, &ComponentSpec { program: echo.display().to_string(), env: vec![] });
        // a plain file stands in for a character device
        let dev = chitala_platform::DeviceAddress::new("serial:test").unwrap();
        std::fs::write(root.join("tty"), b"").unwrap();
        let devices = HostDevices::new([(dev.clone(), root.join("tty"), "test line".to_string())]);
        contract::devices(&devices, &dev, false);
        assert_eq!(std::fs::read(root.join("tty")).unwrap(), b"ping\n");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// R2: a claim is an advisory lock (`flock`) that other processes see,
    /// and that a process's death releases: a crashed node leaves no claim.
    #[test]
    fn a_claim_is_seen_across_processes_and_ends_with_its_holder() {
        use chitala_platform::{PlatformError, Storage, StoragePath};
        let root = temp_root("claim");
        let storage = FsStorage::new(&root).unwrap();
        let lock = StoragePath::new("state.json.lock").unwrap();
        drop(storage.claim(&lock).unwrap()); // the lock file exists, private
                                             // another process holds it
        let mut holder = std::process::Command::new("perl")
            .args([
                "-e",
                r#"use Fcntl ":flock"; open(my $f, ">>", $ARGV[0]) or die; flock($f, LOCK_EX) or die; $| = 1; print "held\n"; sleep 30"#,
                &root.join("state.json.lock").display().to_string(),
            ])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("perl is available");
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(holder.stdout.take().unwrap()), &mut line).unwrap();
        assert_eq!(line.trim(), "held");
        assert!(matches!(storage.claim(&lock), Err(PlatformError::AlreadyExists(_))), "held by another process");
        // the holder dies without letting go: the kernel ends its claim
        holder.kill().unwrap();
        holder.wait().unwrap();
        let claim = storage.claim(&lock).expect("a dead holder leaves no claim behind");
        let mode = std::fs::metadata(root.join("state.json.lock")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the lock file is private");
        drop(claim);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The lock belongs to the open file. A child process forked while it is
    /// held keeps a copy until it executes its program: a claim released
    /// meanwhile still looks held (a CI-only failure, 2026-10-06). Here the
    /// child keeps its copy as its standard input, for a moment: the claim
    /// waits for it, and is taken.
    #[test]
    fn a_lock_a_child_still_holds_a_copy_of_is_waited_for() {
        use chitala_platform::{Storage, StoragePath};
        let root = temp_root("claim-copy");
        let storage = FsStorage::new(&root).unwrap();
        let lock = StoragePath::new("state.json.lock").unwrap();
        let held = child_holding(&root.join("state.json.lock"), "0.4");
        let started = std::time::Instant::now();
        let claim = storage.claim(&lock).expect("taken once the child's copy is gone");
        assert!(started.elapsed() >= std::time::Duration::from_millis(250), "it did wait");
        drop(claim);
        let mut held = held;
        held.wait().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The wait does not weaken the claim: a holder that keeps the lock, as
    /// another node does, is still refused, after the wait.
    #[test]
    fn a_lock_held_all_along_is_still_refused() {
        use chitala_platform::{PlatformError, Storage, StoragePath};
        let root = temp_root("claim-kept");
        let storage = FsStorage::new(&root).unwrap();
        let lock = StoragePath::new("state.json.lock").unwrap();
        let mut held = child_holding(&root.join("state.json.lock"), "30");
        let started = std::time::Instant::now();
        assert!(matches!(storage.claim(&lock), Err(PlatformError::AlreadyExists(_))));
        assert!(started.elapsed() >= crate::fs::CLAIM_WAIT);
        held.kill().unwrap();
        held.wait().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Lock `path` and hand a copy of the open file to a child (`sleep
    /// seconds`), as its standard input; this side's copy is closed. The
    /// lock is waited for a moment: a child another test forks may hold a
    /// copy of it until it executes (the very case under test).
    fn child_holding(path: &std::path::Path, seconds: &str) -> std::process::Child {
        use std::os::unix::fs::OpenOptionsExt;
        let mut open = std::fs::OpenOptions::new();
        open.read(true).write(true).create(true).truncate(false).mode(0o600);
        let file = open.open(path).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while file.try_lock().is_err() {
            assert!(std::time::Instant::now() < deadline, "the lock was free");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        std::process::Command::new("sleep").arg(seconds).stdin(std::process::Stdio::from(file)).spawn().unwrap()
    }

    /// A program is busy while any process has it open for writing, and a
    /// child forked by another thread keeps such a copy until it executes.
    /// Here a child keeps it, as its standard output, for a moment: the start
    /// waits for it, and runs the program.
    #[test]
    fn a_program_a_child_still_writes_is_waited_for() {
        let root = temp_root("busy-program");
        let (program, writer) = busy_program(&root, "0.4");
        let refused = kernel_refuses(&program);
        let started = std::time::Instant::now();
        let spawned = ProcessHost.spawn(&program).expect("started once the child's copy is gone");
        if refused {
            assert!(started.elapsed() >= std::time::Duration::from_millis(250), "it did wait");
        }
        drop(spawned);
        let mut writer = writer;
        writer.wait().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The wait does not hide a program that stays busy: it is still refused.
    #[test]
    fn a_program_kept_open_for_writing_is_still_refused() {
        let root = temp_root("busy-kept");
        let (program, mut writer) = busy_program(&root, "30");
        if kernel_refuses(&program) {
            let started = std::time::Instant::now();
            let err = ProcessHost.spawn(&program).err().expect("refused");
            assert!(err.to_string().contains("busy"), "{err}");
            assert!(started.elapsed() >= crate::exec::SPAWN_WAIT);
        }
        writer.kill().unwrap();
        writer.wait().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Write a program, and hand a copy of it, open for writing, to a child
    /// (`sleep seconds`) as its standard output; this side's copy is closed.
    fn busy_program(root: &std::path::Path, seconds: &str) -> (ComponentSpec, std::process::Child) {
        let path = root.join("prog.sh");
        std::fs::write(&path, "#!/bin/sh\nwhile read l; do echo \"$l\"; done\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        let child =
            std::process::Command::new("sleep").arg(seconds).stdout(std::process::Stdio::from(file)).spawn().unwrap();
        (ComponentSpec { program: path.display().to_string(), env: vec![] }, child)
    }

    /// Whether this kernel refuses to run a program open for writing (Linux
    /// does; macOS runs it), asked once, directly.
    fn kernel_refuses(program: &ComponentSpec) -> bool {
        match std::process::Command::new(&program.program).stdin(std::process::Stdio::null()).spawn() {
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                false
            }
            Err(e) => e.kind() == std::io::ErrorKind::ExecutableFileBusy,
        }
    }

    #[test]
    fn existing_key_files_keep_working() {
        // domains created before the PAL: keys/<kind>-<local>.key, hex seed + newline
        let root = temp_root("compat");
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::set_permissions(root.join("keys"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let f = root.join("keys/person-alice.key");
        std::fs::write(&f, format!("{}\n", "11".repeat(32))).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let p = platform(&root).unwrap();
        let k = chitala_platform::KeyRef::new("person-alice").unwrap();
        let expected = chitala_platform::SeedSigner::from_seed(&[0x11; 32]);
        use chitala_platform::Signer;
        assert_eq!(p.keys.public_key(&k).unwrap(), expected.public_key());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
