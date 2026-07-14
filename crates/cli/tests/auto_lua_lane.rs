// SPDX-License-Identifier: Apache-2.0
//
// M3.10 native Lua lane: the `lua_lane` fixture is discovered, built into a framed
// `lua` launcher (debug.sethook line coverage), fuzzed by the builtin engine, and the
// planted integer divide-by-zero surfaces as a CWE-369 finding. The end-to-end
// portion skips cleanly when no `lua` is installed (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/lua_lane")
        .canonicalize()
        .expect("canonicalize lua_lane fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn have_lua() -> bool {
    ["lua", "lua5.4", "lua5.3"].iter().any(|l| {
        Command::new(l)
            .arg("-e")
            .arg("return 1")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

#[test]
fn discovers_lua_functions() {
    let candidates = discover(&fixture()).expect("discover lua_lane fixture");
    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
    assert!(
        candidates.iter().all(|c| c.lang == Lang::Lua),
        "every candidate is Lang::Lua: {names:?}"
    );
    assert!(
        names.contains(&"M.parse_record"),
        "module field function discovered: {names:?}"
    );
    let p = candidates
        .iter()
        .find(|c| c.name == "M.parse_record")
        .expect("parse_record discovered");
    assert!(
        p.harness_id.starts_with("H-V"),
        "Lua id prefix H-V: {}",
        p.harness_id
    );
}

#[test]
fn auto_builds_fuzzes_and_finds_divide_by_zero_cwe369() {
    if !have_lua() {
        eprintln!("skipping: no lua on PATH (GNAT-less rule)");
        return;
    }
    let src = std::env::temp_dir().join(format!("gf_lualane_it_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(
        fixture().join("record_parser.lua"),
        src.join("record_parser.lua"),
    )
    .unwrap();
    let work = std::env::temp_dir().join(format!("gf_lualane_w_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);

    let out = Command::new(govfuzz_bin())
        .args([
            "auto",
            "--per-target-time",
            "20",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    assert!(
        out.status.success(),
        "govfuzz auto exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap_or_default();
    assert!(
        csv.contains(",369;") || csv.contains(",369,"),
        "expected a CWE-369 arithmetic finding in findings.csv:\n{csv}"
    );
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
}
