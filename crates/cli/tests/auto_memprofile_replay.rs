// SPDX-License-Identifier: Apache-2.0
//
// End-to-end memory-consumption replay: `run_mem_profile` replays a harness's corpus
// in fresh processes, measures each input's peak resident set (wait4 ru_maxrss), and
// writes a GF-558 finding for an input whose memory is far above baseline AND
// amplified vs its size. The fixture allocates+touches N MB where N is the first
// input byte, so a 4-byte "large" input balloons memory while a "small" one does not.
// Skips cleanly without clang.

use std::path::Path;
use std::process::Command;

use cli::auto::memprofile::run_mem_profile;

fn have_clang() -> bool {
    Command::new("clang").arg("--version").output().is_ok()
}

#[test]
fn mem_profile_flags_amplified_allocation_input() {
    if !have_clang() {
        eprintln!("skip: clang unavailable");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-mem-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let work = tmp.join("work");
    let hdir = work.join("harnesses").join("H-C0001");
    let queue = work.join("corpus").join("H-C0001").join("queue");
    for d in [&hdir, &queue] {
        std::fs::create_dir_all(d).unwrap();
    }

    // The replay binary: reads argv[1] (the input file, as the govfuzz driver passes
    // it), takes the first byte as a megabyte count, and allocates+touches that many
    // MB so it shows up in the resident set. Capped so the test can't OOM the host.
    let src = hdir.join("alloc.c");
    std::fs::write(
        &src,
        "#include <stdlib.h>\n\
         #include <string.h>\n\
         #include <stdio.h>\n\
         int main(int argc, char **argv) {\n\
             if (argc < 2) return 0;\n\
             FILE *f = fopen(argv[1], \"rb\");\n\
             if (!f) return 0;\n\
             int c = fgetc(f);\n\
             fclose(f);\n\
             unsigned long mb = c > 0 ? (unsigned long)c : 1UL;\n\
             if (mb > 300) mb = 300;\n\
             size_t n = mb * 1024UL * 1024UL;\n\
             char *p = (char *)malloc(n);\n\
             if (p) { memset(p, 1, n); }\n\
             return p ? (int)p[0] : 0;\n\
         }\n",
    )
    .unwrap();
    let build = Command::new("clang")
        .args(["-O1", "-o"])
        .arg(hdir.join("main"))
        .arg(&src)
        .output()
        .expect("clang");
    assert!(
        build.status.success(),
        "fixture build failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );

    // Corpus: a small input (1 MB) and a large one (200 MB) — the large is a 4-byte
    // input driving ~200 MB, hugely amplified.
    std::fs::write(queue.join("small"), [1u8, 0, 0, 0]).unwrap();
    std::fs::write(queue.join("large"), [200u8, 0, 0, 0]).unwrap();

    let written = run_mem_profile(&work);
    assert_eq!(
        written, 1,
        "expected exactly one GF-558 uncontrolled-consumption finding, got {written}"
    );

    let finding = work
        .join("findings")
        .join("F-MEM-0000")
        .join("finding.json");
    let json = std::fs::read_to_string(&finding)
        .unwrap_or_else(|e| panic!("finding.json missing at {}: {e}", finding.display()));
    assert!(
        json.contains("GF-558"),
        "finding must carry GF-558:\n{json}"
    );
    assert!(
        json.contains("CWE-400"),
        "finding must carry CWE-400:\n{json}"
    );
    // The reproducer is the large input (first byte 200).
    let repro = work
        .join("findings")
        .join("F-MEM-0000")
        .join("testcase.bin");
    assert_eq!(
        std::fs::read(&repro).ok().and_then(|b| b.first().copied()),
        Some(200u8),
        "reproducer should be the amplifying (large) input"
    );

    let _ = std::fs::remove_dir_all(Path::new(&tmp));
}
