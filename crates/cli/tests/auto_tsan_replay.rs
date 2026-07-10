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

use cli::auto::tsan::run_tsan_replay;

fn clang_has_tsan() -> bool {
    let probe = std::env::temp_dir().join(format!("govfuzz-tsan-probe-{}", std::process::id()));
    let ok = Command::new("clang")
        .args(["-fsanitize=thread", "-x", "c", "-", "-o"])
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
                .write_all(b"int main(void){return 0;}")?;
            child.wait()
        })
        .map(|status| status.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&probe);
    ok
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

    let written = run_tsan_replay(&work);
    assert_eq!(
        written, 1,
        "expected exactly one GF-556 data-race finding, got {written}"
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
