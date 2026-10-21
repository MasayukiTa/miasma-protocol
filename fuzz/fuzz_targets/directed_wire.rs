#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    miasma_fuzz_harness::directed_wire(data);
});
