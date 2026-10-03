#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| chitala_fuzz::audit_log(data));
