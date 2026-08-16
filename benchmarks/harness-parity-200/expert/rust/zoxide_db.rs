// SPDX-License-Identifier: Apache-2.0

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::fs;

// This target is compiled in-tree so it can reach the binary crate's db module.
// The input is the database file; the temporary directory is call context.
fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().expect("temporary database directory");
    fs::write(dir.path().join("db.zo"), data).expect("write fuzz database");
    let _ = crate::db::Database::open_dir(dir.path());
});
