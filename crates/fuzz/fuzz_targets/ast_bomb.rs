#![no_main]

use janitor_fuzz::assert_parse_budget;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    assert_parse_budget(data);
});

