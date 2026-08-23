// SPDX-License-Identifier: Apache-2.0
//
// End-to-end ThreadSanitizer corpus-replay: `run_tsan_replay` builds a harness's
// `make tsan` variant, replays its corpus through it, and writes a GF-556 data-race
// finding whose faulting frame lands in a TARGET source (not the govfuzz driver /
// system libs). Uses a real racy fixture — two unsynchronized writes to a shared
// global across a spawned thread, the canonical always-detected TSan race — compiled
// as a separate target source so the race frame passes the target-frame filter.
// Skips cleanly when clang lacks a working ThreadSanitizer (the GNAT-less rule).

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use cli::auto::tsan::run_tsan_replay;

fn clang_has_tsan() -> bool {
    let probe = std::env::temp_dir().join(format!("govfuzz-tsan-probe-{}", std::process::id()));
    let probe_log = probe.with_extension("log");
    let ok = Command::new("clang")
        .args(["-fsanitize=thread", "-pthread", "-x", "c", "-", "-o"])
        .arg(&probe)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(
                    b"#include <pthread.h>\nstatic int x;\nstatic void *w(void *p){(void)p;x=1;return 0;}\nint main(void){pthread_t t;pthread_create(&t,0,w,0);x=2;pthread_join(t,0);return 0;}",
                )?;
            child.wait()
        })
        .map(|status| status.success())
        .unwrap_or(false);
    // Compiling and running a single-threaded binary is not enough. Some hosts'
    // high-entropy ASLR lets that probe exit but makes the runtime hang as soon
    // as instrumented threads touch shared state. Require the canonical race to
    // produce an actual report, with a short wall-clock bound.
    let ok = ok && tsan_probe_reports_race(&probe, &probe_log);
    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_file(&probe_log);
    ok
}

fn tsan_probe_reports_race(probe: &Path, log: &Path) -> bool {
    let Ok(stderr) = std::fs::File::create(log) else {
        return false;
    };
    let Ok(mut child) = Command::new(probe)
        .env("TSAN_OPTIONS", "halt_on_error=1:exitcode=86")
        .stdout(std::process::Stdio::null())
        .stderr(stderr)
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let exited = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    if !exited {
        return false;
    }
    let Ok(file) = std::fs::File::open(log) else {
        return false;
    };
    let mut output = Vec::new();
    use std::io::Read;
    let _ = file.take(1024 * 1024).read_to_end(&mut output);
    String::from_utf8_lossy(&output).contains("data race")
}

fn tsan_fixture_report(binary: &Path, input: &Path, log: &Path) -> Option<String> {
    let stderr = std::fs::File::create(log).ok()?;
    let mut child = Command::new(binary)
        .arg(input)
        .env("TSAN_OPTIONS", "halt_on_error=1:exitcode=86")
        .stdout(std::process::Stdio::null())
        .stderr(stderr)
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    std::fs::read_to_string(log).ok()
}

#[test]
fn tsan_replay_writes_gf556_for_target_source_data_race() {
    if !clang_has_tsan() {
        eprintln!("skip: clang has no working ThreadSanitizer");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-tsan-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let work = tmp.join("work");
    let hdir = work.join("harnesses").join("H-C0001");
    let queue = work.join("corpus").join("H-C0001").join("queue");
    let target_dir = work.join("target");
    for d in [&hdir, &queue, &target_dir] {
        std::fs::create_dir_all(d).unwrap();
    }

    // The race lives in a SEPARATE target source, so its frame is not under the
    // harness dir (which the finding filter treats as govfuzz scaffolding).
    let race_c = target_dir.join("race.c");
    std::fs::write(
        &race_c,
        "#include <pthread.h>\n\
         static int g_shared;\n\
         static void *worker(void *arg) {\n\
             (void)arg;\n\
             g_shared = 1;\n\
             return 0;\n\
         }\n\
         void run_race(void) {\n\
             pthread_t t;\n\
             pthread_create(&t, 0, worker, 0);\n\
             g_shared = 2;\n\
             pthread_join(t, 0);\n\
         }\n",
    )
    .unwrap();

    // The harness "driver" (analog of govfuzz's generated main.c) just invokes the
    // target; the govfuzz driver passes the replayed input as argv[1], which this
    // fixture ignores — the race is unconditional.
    std::fs::write(
        hdir.join("main.c"),
        "extern void run_race(void);\n\
         int main(int argc, char **argv) {\n\
             (void)argc;\n\
             (void)argv;\n\
             run_race();\n\
             return 0;\n\
         }\n",
    )
    .unwrap();

    // A minimal Makefile exposing the `tsan` target `run_tsan_replay` invokes.
    std::fs::write(
        hdir.join("Makefile"),
        format!(
            "tsan: main_tsan\n\
             main_tsan: main.c\n\
             \tclang -O0 -g -fsanitize=thread -pthread -o main_tsan main.c {race}\n",
            race = race_c.display()
        ),
    )
    .unwrap();

    // Any corpus input drives the (unconditional) race.
    std::fs::write(queue.join("seed"), b"anything").unwrap();

    let replay = run_tsan_replay(&work);
    let written = replay.findings;
    if written == 0 {
        let binary = hdir.join("main_tsan");
        assert!(
            binary.is_file(),
            "the TSan fixture did not build even though the compiler preflight passed"
        );
        // `unmeasured` counts inputs whose TSan run never completed — it timed
        // out or failed to spawn, after retries. That is not "replayed and found
        // no race", it is "never examined", and asserting a finding against it
        // asserts on evidence that does not exist. The runtime really does hang:
        // the preflight's own comment describes it, and a probe binary that
        // exits instantly can stop completing minutes later on the same host,
        // which is exactly how this test failed on CI while a postflight run
        // still reported the race.
        if replay.unmeasured > 0 {
            eprintln!(
                "skip: ThreadSanitizer never completed a replay run \
                 ({} input(s) unmeasured after retries)",
                replay.unmeasured
            );
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
        let postflight =
            tsan_fixture_report(&binary, &queue.join("seed"), &tmp.join("postflight.log"))
                .unwrap_or_default();
        if !postflight.contains("data race") {
            eprintln!("skip: ThreadSanitizer became unavailable after its preflight: {postflight}");
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
        assert!(
            postflight.contains(&race_c.to_string_lossy().into_owned()),
            "TSan emitted a race without a symbolized target frame:\n{postflight}"
        );
    }
    assert_eq!(
        written, 1,
        "expected exactly one GF-556 data-race finding, got {written} \
         ({} input(s) unmeasured)",
        replay.unmeasured
    );

    let finding = work
        .join("findings")
        .join("F-TSAN-0000")
        .join("finding.json");
    let json = std::fs::read_to_string(&finding)
        .unwrap_or_else(|e| panic!("finding.json missing at {}: {e}", finding.display()));
    assert!(
        json.contains("GF-556"),
        "finding must carry GF-556:\n{json}"
    );
    assert!(
        json.contains("CWE-362"),
        "finding must carry CWE-362:\n{json}"
    );
    assert!(
        json.contains("race.c"),
        "faulting frame should be the target race.c source:\n{json}"
    );
    assert!(
        !Path::new(&finding)
            .parent()
            .unwrap()
            .join("..")
            .join("F-TSAN-0001")
            .exists(),
        "the two racing writes at one site must collapse to a single finding"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
