// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    vulns_rust::parse_packet(data);   // the one entry point the developer harnessed
});
