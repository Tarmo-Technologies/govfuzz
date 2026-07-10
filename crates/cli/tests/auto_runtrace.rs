// SPDX-License-Identifier: Apache-2.0

//! End-to-end test for Slice B: target's getenv + open hits get
//! audited and injected.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-auto-rt-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn auto_sweep_captures_runtime_resources() {
    if !support::libfuzzer_toolchain_available("runtrace") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }

    let root = tmpdir("root");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("probe.c"),
        "#include <stdlib.h>\n\
         #include <fcntl.h>\n\
         int parse_input(const unsigned char *d, unsigned long n) {\n\
             const char *cfg = getenv(\"ACME_RT_CONFIG\");\n\
             (void)cfg;\n\
             int fd = open(\"/etc/acme_rt_missing.conf\", 0);\n\
             (void)fd;\n\
             return (int)n;\n\
         }\n",
    )
    .unwrap();

    let status = support::govfuzz_cargo_command()
        .current_dir(&root)
        .args(["auto", root.to_str().unwrap(), "--per-target-time", "3"])
        .status()
        .expect("run govfuzz auto");
    assert!(status.success() || status.code() == Some(1));

    let run_json: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("govfuzz_work/auto/run.json")).unwrap())
            .unwrap();

    let env_faked = &run_json["needed_for_build"]["environment_variables_faked"];
    let files = &run_json["needed_for_build"]["missing_files"];

    let env_names: Vec<&str> = env_faked
        .as_array()
        .map(|a| a.iter().filter_map(|e| e["name"].as_str()).collect())
        .unwrap_or_default();
    let file_names: Vec<&str> = files
        .as_array()
        .map(|a| a.iter().filter_map(|e| e["name"].as_str()).collect())
        .unwrap_or_default();

    assert!(
        env_names.contains(&"ACME_RT_CONFIG"),
        "expected ACME_RT_CONFIG in env_faked, got {env_names:?}"
    );
    assert!(
        file_names.contains(&"/etc/acme_rt_missing.conf"),
        "expected /etc/acme_rt_missing.conf in missing_files, got {file_names:?}"
    );
}
