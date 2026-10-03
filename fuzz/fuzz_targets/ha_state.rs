#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| chitala_fuzz::ha_state(data));
