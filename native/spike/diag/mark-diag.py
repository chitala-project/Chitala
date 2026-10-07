#!/usr/bin/env python3
"""N1.6 diagnosis: mark each latency sample through the node's IPC in the Hermit
kernel's event ring (diag/hermit-n16-trace.patch), and ask the kernel for the
events of a sample slower than 100 ms. In the working tree, for a diagnostic
build only; the marks go through sys_futex_wake with counts the patched kernel
reserves; the diagnostic build lowers the crate's forbid(unsafe_code) to deny,
and allows the one call. Undo with `git checkout -- native/src/main.rs`."""
p = "native/src/main.rs"
s = open(p).read()
pairs = [
    ("#![forbid(unsafe_code)]", "#![deny(unsafe_code)] // N1.6 diagnosis build"),
    ("""                let bytes = self.signed("person:bob", door, "lock.lock", Payload::new());
                let start = Instant::now();
                let r = self.client.submit(&bytes).unwrap_or_else(|e| panic!("the node did not answer: {e}"));
                let took = start.elapsed().as_micros() as u64;
                if took > 100_000 {
""",
     """                let bytes = self.signed("person:bob", door, "lock.lock", Payload::new());
                n16_mark(0x4E160);
                let start = Instant::now();
                let r = self.client.submit(&bytes).unwrap_or_else(|e| panic!("the node did not answer: {e}"));
                let took = start.elapsed().as_micros() as u64;
                if took > 100_000 {
                    n16_mark(0x4E162);
"""),
    ("""/// The CPU's virtual counter, on Native (N1.6 diagnosis); 0 elsewhere.
""",
     """/// N1.6 diagnosis: a mark in the patched Hermit kernel's event ring.
#[allow(unsafe_code)]
fn n16_mark(code: i32) {
    #[cfg(target_os = "hermit")]
    {
        extern "C" {
            fn sys_futex_wake(address: *mut u32, count: i32) -> i32;
        }
        let mut x = 0u32;
        unsafe { sys_futex_wake(&mut x, code) };
    }
    #[cfg(not(target_os = "hermit"))]
    let _ = code;
}

/// The CPU's virtual counter, on Native (N1.6 diagnosis); 0 elsewhere.
"""),
]
for old, new in pairs:
    assert s.count(old) == 1, old[:60]
    s = s.replace(old, new)
open(p, "w").write(s)
print("marks applied")
