// SPDX-License-Identifier: Apache-2.0

//! #437: ASan fiber-switch annotations (`c_runtime/govfuzz_asan_fiber.h`).
//!
//! A cooperative context switch (ucontext) confuses ASan's `detect_stack_use_
//! after_return` fake stack: it assumes one linear stack, so switching between
//! coroutine stacks can produce bogus `stack-use-after-return` reports. The
//! header brackets each switch with `__sanitizer_{start,finish}_switch_fiber`
//! so ASan follows the switch.
//!
//! This builds a ucontext coroutine that ping-pongs with main twice, each side
//! using (and returning from) deep stack frames, under
//! `ASAN_OPTIONS=detect_stack_use_after_return=1` — the strict fake-stack mode in
//! which unannotated context switches risk false positives. WITH the annotations
//! the program runs to completion with no ASan error report; that clean run is
//! the evidence the start/finish_switch_fiber bracketing is correct — incorrect
//! stack bounds or a mismatched fake-stack save/restore make ASan error or crash
//! on the switched-to stack under this mode. Skips without clang.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn have_clang() -> bool {
    Command::new("clang")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn c_runtime_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("c_runtime")
}

fn tmpdir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-asan-fiber-{n}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

const PROGRAM: &str = r#"
#define _XOPEN_SOURCE 700
#include "govfuzz_asan_fiber.h"
#include <ucontext.h>
#include <stdio.h>
#include <string.h>

static ucontext_t main_uc, co_uc;
static char co_stack[256 * 1024];
static govfuzz_fiber_t main_fiber = {0, 0, 0};
static govfuzz_fiber_t co_fiber;
static volatile int sink;

/* Grow the stack and return, so ASan's fake-stack machinery is exercised. */
static void touch_stack(int depth) {
    char buf[2048];
    memset(buf, depth & 0xff, sizeof buf);
    sink += buf[(depth * 7) % (int)sizeof buf];
    if (depth > 0) touch_stack(depth - 1);
}

static void coroutine(void) {
    govfuzz_fiber_after_switch(&co_fiber, &main_fiber); /* learn main's region */
    touch_stack(6);
    govfuzz_fiber_before_switch(&co_fiber, &main_fiber);
    swapcontext(&co_uc, &main_uc);

    govfuzz_fiber_after_switch(&co_fiber, &main_fiber);
    touch_stack(6);
    govfuzz_fiber_before_switch(0, &main_fiber); /* exiting: drop fake stack */
    swapcontext(&co_uc, &main_uc);
}

int main(void) {
    co_fiber.stack_bottom = co_stack;
    co_fiber.stack_size = sizeof co_stack;
    co_fiber.fake_stack = 0;

    getcontext(&co_uc);
    co_uc.uc_stack.ss_sp = co_stack;
    co_uc.uc_stack.ss_size = sizeof co_stack;
    co_uc.uc_link = &main_uc;
    makecontext(&co_uc, coroutine, 0);

    touch_stack(6);
    govfuzz_fiber_before_switch(&main_fiber, &co_fiber);
    swapcontext(&main_uc, &co_uc);
    govfuzz_fiber_after_switch(&main_fiber, &co_fiber);

    touch_stack(6);
    govfuzz_fiber_before_switch(&main_fiber, &co_fiber);
    swapcontext(&main_uc, &co_uc);
    govfuzz_fiber_after_switch(&main_fiber, &co_fiber);

    touch_stack(6);
    printf("ok %d\n", sink);
    return 0;
}
"#;

fn build_and_run(dir: &Path) -> (Option<i32>, String, String) {
    let src = dir.join("co.c");
    std::fs::write(&src, PROGRAM).unwrap();
    let bin = dir.join("co");
    let out = Command::new("clang")
        .arg("-O1")
        .arg("-g")
        .arg("-fsanitize=address")
        .arg("-Wno-deprecated-declarations") // makecontext/swapcontext
        .arg(format!("-I{}", c_runtime_dir().display()))
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("spawn clang");
    assert!(
        out.status.success(),
        "fiber fixture must compile:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let run = Command::new(&bin)
        .env(
            "ASAN_OPTIONS",
            "detect_stack_use_after_return=1:abort_on_error=0:detect_leaks=0",
        )
        .env("DEBUGINFOD_URLS", "")
        .output()
        .expect("run fiber program");
    (
        run.status.code(),
        String::from_utf8_lossy(&run.stdout).into_owned(),
        String::from_utf8_lossy(&run.stderr).into_owned(),
    )
}

#[test]
fn fiber_annotations_keep_cooperative_switch_clean_under_fake_stack() {
    if !have_clang() {
        eprintln!("skipping: clang not available");
        return;
    }
    let dir = tmpdir();
    let (code, stdout, stderr) = build_and_run(&dir);
    // No ASan error report: wrong annotations (bad stack bottom/size, or a
    // mismatched fake_stack save/restore) make ASan error or crash on the
    // switched-to stack under fake-stack mode, so a clean stderr is the evidence
    // the start/finish_switch_fiber bracketing is correct. (ASan prints a generic
    // "doesn't fully support makecontext" note regardless of annotations — that is
    // not an error and is not asserted on.)
    assert!(
        !stderr.contains("AddressSanitizer"),
        "annotated fiber switches must not trip ASan under fake-stack mode; stderr:\n{stderr}"
    );
    assert_eq!(
        code,
        Some(0),
        "program must run to completion; stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("ok"),
        "program must reach the end; stdout was {stdout:?}"
    );
}
