//! PAL contract tests (spec 14 §"Contract"). Every backend runs these from its
//! own test suite; they panic on the first violation. A new backend — Windows,
//! a native substrate, a TPM key store — is admissible only if it passes them.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use crate::keys::verify;
use crate::{
    random_array, ComponentSpec, Endpoint, Entropy, ExecutionHost, IpcTransport, KeyRef, PlatformError, SecureKeyStore,
    Signer, Storage, StoragePath, TimeSource, Visibility,
};

fn unique(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    // backends run the contract in a fresh root, so a counter is unique enough
    format!("{prefix}-{}", N.fetch_add(1, Ordering::SeqCst))
}

/// Monotonic time never decreases.
pub fn time(t: &dyn TimeSource) {
    let mut last = t.monotonic_ms();
    for _ in 0..1_000 {
        let now = t.monotonic_ms();
        assert!(now >= last, "monotonic clock went backwards: {last} → {now}");
        last = now;
    }
    let _ = t.wall_ms();
}

/// Draws differ and are not trivially weak.
pub fn entropy(e: &dyn Entropy) {
    let a: [u8; 32] = random_array(e);
    let b: [u8; 32] = random_array(e);
    assert_ne!(a, b, "two draws were identical");
    assert_ne!(a, [0u8; 32], "all-zero draw");
    let mut big = vec![0u8; 4096];
    e.fill(&mut big);
    let zeros = big.iter().filter(|b| **b == 0).count();
    assert!(zeros < 64, "suspiciously many zero bytes: {zeros}");
}

/// Keys are created inside the store, never overwritten, sign verifiably, and
/// are exportable only if the store says so.
pub fn key_store(ks: &dyn SecureKeyStore) {
    let name = KeyRef::new(unique("contract-key")).expect("valid key name");
    assert!(!ks.contains(&name).unwrap());
    assert!(matches!(ks.signer(&name), Err(PlatformError::NotFound(_))));
    let pk = ks.generate(&name).expect("generate");
    assert!(ks.contains(&name).unwrap());
    assert!(matches!(ks.generate(&name), Err(PlatformError::AlreadyExists(_))), "a key was overwritten");
    let signer = ks.signer(&name).expect("signer");
    assert_eq!(signer.public_key(), pk);
    assert_eq!(ks.public_key(&name).unwrap(), pk);
    let sig = signer.sign(b"chitala contract");
    assert!(verify(&pk, b"chitala contract", &sig));
    assert!(!verify(&pk, b"chitala contracT", &sig));
    match ks.export_seed(&name) {
        Ok(seed) => {
            assert!(ks.info().exportable, "store claims non-exportable but exported a key");
            assert_eq!(crate::SeedSigner::from_seed(&seed).public_key(), pk);
        }
        Err(PlatformError::Unsupported(_)) => assert!(!ks.info().exportable),
        Err(e) => panic!("export_seed: {e}"),
    }
}

/// Atomic replace, no overwrite on create, append-only logs, and refusal to use
/// private data whose protection was weakened behind the platform's back.
pub fn storage(s: &dyn Storage, weaken: &dyn Fn(&StoragePath)) {
    let dir = StoragePath::new(unique("contract")).unwrap();
    s.ensure_dir(&dir, Visibility::Private).unwrap();
    let p = dir.join("object").unwrap();
    assert_eq!(s.read(&p, Visibility::Private).unwrap(), None);
    assert!(!s.exists(&p).unwrap());
    s.write_atomic(&p, b"one", Visibility::Private).unwrap();
    s.write_atomic(&p, b"two", Visibility::Private).unwrap();
    assert_eq!(s.read(&p, Visibility::Private).unwrap().as_deref(), Some(&b"two"[..]));
    assert!(s.exists(&p).unwrap());

    let k = dir.join("key").unwrap();
    s.create_new(&k, b"secret", Visibility::Private).unwrap();
    assert!(matches!(s.create_new(&k, b"other", Visibility::Private), Err(PlatformError::AlreadyExists(_))));
    assert_eq!(s.read(&k, Visibility::Private).unwrap().as_deref(), Some(&b"secret"[..]));

    let log = dir.join("log").unwrap();
    {
        let mut l = s.open_append(&log, Visibility::Private).unwrap();
        l.append(b"a\n").unwrap();
        l.append(b"b\n").unwrap();
    }
    s.open_append(&log, Visibility::Private).unwrap().append(b"c\n").unwrap();
    assert_eq!(s.read(&log, Visibility::Private).unwrap().as_deref(), Some(&b"a\nb\nc\n"[..]));

    // shared data may be read as shared, never as private
    let shared = dir.join("shared").unwrap();
    s.write_atomic(&shared, b"public", Visibility::Shared).unwrap();
    assert!(s.read(&shared, Visibility::Shared).unwrap().is_some());
    assert!(matches!(s.read(&shared, Visibility::Private), Err(PlatformError::Insecure(_))));

    // a private object that others can now read or write must not be used
    weaken(&k);
    assert!(matches!(s.read(&k, Visibility::Private), Err(PlatformError::Insecure(_))), "weakened key was used");
    weaken(&log);
    assert!(matches!(s.open_append(&log, Visibility::Private), Err(PlatformError::Insecure(_))));

    s.remove(&p).unwrap();
    assert!(!s.exists(&p).unwrap());
    assert!(StoragePath::new("../escape").is_err());
    assert!(StoragePath::new("/abs").is_err());
    assert!(StoragePath::new("a//b").is_err());
}

/// A listener answers a client; a second listener on a live endpoint is refused.
pub fn ipc(t: &dyn IpcTransport) {
    let ep = Endpoint::new(unique("ep")).unwrap();
    let listener = t.listen(&ep).expect("listen");
    assert!(t.listen(&ep).is_err(), "endpoint hijacked while its listener is alive");
    let server = std::thread::spawn(move || loop {
        // liveness probes (e.g. the refused second listen) may leave empty connections
        let mut conn = listener.accept().expect("accept");
        let mut line = String::new();
        if BufReader::new(conn.try_clone().unwrap()).read_line(&mut line).unwrap_or(0) == 0 {
            continue;
        }
        conn.write_all(format!("echo {line}").as_bytes()).unwrap();
        conn.flush().unwrap();
        return listener;
    });
    let mut client = t.connect(&ep).expect("connect");
    client.set_timeout(Some(Duration::from_secs(5))).unwrap();
    client.write_all(b"hello\n").unwrap();
    client.flush().unwrap();
    let mut reply = String::new();
    BufReader::new(client.try_clone().unwrap()).read_line(&mut reply).unwrap();
    assert_eq!(reply, "echo hello\n");
    drop(server.join().unwrap());
    assert!(t.connect(&Endpoint::new(unique("nobody")).unwrap()).is_err());
}

/// The program used by [`exec`]: echoes each input line, then exits on EOF.
pub fn echo_program() -> crate::memory::Program {
    Arc::new(|input, mut output, _env| {
        for line in BufReader::new(input).lines() {
            let Ok(line) = line else { return };
            if writeln!(output, "{line}").is_err() {
                return;
            }
        }
    })
}

/// A component talks over its private channel and can be killed.
pub fn exec(h: &dyn ExecutionHost, echo: &ComponentSpec) {
    let mut c = h.spawn(echo).expect("spawn");
    writeln!(c.input, "ping").unwrap();
    c.input.flush().unwrap();
    let mut reader = BufReader::new(c.output);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line, "ping\n");
    c.handle.kill();
    c.handle.kill(); // idempotent
                     // after kill the channel is gone: EOF (or an error), never more data
    let mut rest = Vec::new();
    let _ = reader.read_to_end(&mut rest);
    assert!(rest.is_empty());
    let missing = ComponentSpec { program: unique("no-such-program"), env: vec![] };
    assert!(h.spawn(&missing).is_err());
}
