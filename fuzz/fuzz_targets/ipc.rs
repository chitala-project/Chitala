#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| chitala_fuzz::ipc(data));
