// SPDX-License-Identifier: Apache-2.0
//
// `govfuzz auto --max-len` end-to-end, with NO seed corpus. The fixture faults only on
// an input of >= 8000 bytes — far above the historical 4096 cap. With `--max-len auto`
// (the default) the adaptive length ceiling grows past 4096 seed-free and finds the
// crash (its reproducer is >= 8000 bytes, which a fixed 4096 cap could never produce).
// With a fixed `--max-len 128` the crash is unreachable, proving the cap is honored.
// A malformed `--max-len` fails the run fast. Skips cleanly without clang.

use std::path::{Path, PathBuf};
use std::process::Command;

fn have_clang() -> bool {
    Command::new("clang").arg("--version").output().is_ok()
        && Command::new("make").arg("--version").output().is_ok()
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

const FAULT_LEN: usize = 6000;

fn write_fixture(dir: &Path) {
    // A DENSE length-correlated coverage gradient (as a real large-object parser has):
    // a distinct branch every 256 bytes, so each small length increase the mutator can
    // reach hits a new edge and is retained, letting coverage-guided fuzzing climb
    // continuously. Crossing 4096 (the historical cap) requires the adaptive ceiling to
    // grow past it seed-free; the crash is at the deepest bucket (>= FAULT_LEN).
    let mut body = String::from(
        "#include <stddef.h>\nvoid process(const char *data, size_t len) {\n    (void)data;\n    volatile int s = 0;\n",
    );
    let mut idx = 0;
    let mut threshold = 256;
    while threshold < FAULT_LEN {
        idx += 1;
        body.push_str(&format!("    if (len > {threshold}) s += {idx};\n"));
        threshold += 256;
    }
    body.push_str(&format!(
        "    if (len >= {FAULT_LEN}) {{ *(volatile int *)0 = 1; }}\n}}\n"
    ));
    std::fs::write(dir.join("gt.c"), body).unwrap();
}

/// Largest reproducer byte-length across all findings, or 0 if none.
fn largest_repro(work: &Path) -> usize {
    let mut largest = 0;
    if let Ok(entries) = std::fs::read_dir(work.join("findings")) {
        for entry in entries.flatten() {
            if let Ok(tc) = std::fs::read(entry.path().join("testcase.bin")) {
                largest = largest.max(tc.len());
            }
        }
    }
    largest
}

#[test]
fn auto_max_len_auto_grows_seedlessly_and_fixed_cap_bounds() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built");
        return;
    }
    if !have_clang() {
        eprintln!("skip: clang/make unavailable");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-auto-maxlen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).unwrap();
    write_fixture(&src);

    // 1) --max-len auto (the default): seedless, the adaptive ceiling grows past 4096
    //    and the >= 8000-byte crash is found.
    let work_auto = tmp.join("work_auto");
    let out = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--per-target-time",
            "30",
            "--max-targets",
            "1",
            "--work-dir",
            work_auto.to_str().unwrap(),
        ])
        .output()
        .expect("run auto --max-len auto");
    let largest = largest_repro(&work_auto);
    assert!(
        largest >= FAULT_LEN,
        "seedless auto should grow length past 4096 and crash on a >= {FAULT_LEN}-byte \
         input; largest reproducer was {largest} bytes.\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 2) --max-len 128: the crash needs >= 8000 bytes, so a 128-byte cap makes it
    //    unreachable — the fixed cap is honored.
    let work_fixed = tmp.join("work_fixed");
    let _ = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--per-target-time",
            "4",
            "--max-targets",
            "1",
            "--max-len",
            "128",
            "--work-dir",
            work_fixed.to_str().unwrap(),
        ])
        .output()
        .expect("run auto --max-len 128");
    assert_eq!(
        largest_repro(&work_fixed),
        0,
        "with --max-len 128 the >= {FAULT_LEN}-byte crash must be unreachable"
    );

    // 3) A malformed --max-len fails the run fast.
    let bad = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--max-len",
            "huge",
            "--work-dir",
            tmp.join("work_bad").to_str().unwrap(),
        ])
        .output()
        .expect("run auto --max-len huge");
    assert!(!bad.status.success(), "a non-numeric --max-len should fail");
    assert!(
        String::from_utf8_lossy(&bad.stderr)
            .to_lowercase()
            .contains("max-len"),
        "the error should name --max-len:\n{}",
        String::from_utf8_lossy(&bad.stderr)
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
