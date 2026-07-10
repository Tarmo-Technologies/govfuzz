// SPDX-License-Identifier: Apache-2.0

//! End-to-end (#422): dynamic byte-origin taint confirms fuzz-controlled values
//! reaching the network-egress (GF-433), dynamic-library-load (GF-435), and
//! destructive-filesystem (GF-440) sinks, and reports nothing for the hardcoded
//! counterparts. Each fixture is inert by construction (a non-existent unix
//! socket / library / temp path), so nothing dangerous runs while the audited
//! subject stays fuzz-controlled.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-auto-sink-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn finding_jsons(root: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "finding.json") {
                if let Ok(bytes) = fs::read(&path) {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        out.push(value);
                    }
                }
            }
        }
    }
    out
}

fn run_auto(root: &Path) {
    let status = support::govfuzz_cargo_command()
        .current_dir(root)
        .args(["auto", root.to_str().unwrap(), "--per-target-time", "3"])
        .status()
        .expect("run govfuzz auto");
    assert!(status.success() || status.code() == Some(1));
}

fn taint_path_of(finding: &serde_json::Value) -> &str {
    finding["oracle"]["evidence"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|e| e["key"] == "taint_path")
                .and_then(|e| e["value"].as_str())
        })
        .unwrap_or_default()
}

/// Write a single-file C project and fuzz it, returning all findings.
fn build_and_fuzz(prefix: &str, source: &str) -> Vec<serde_json::Value> {
    let root = tmpdir(prefix);
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("runner.c"), source).unwrap();
    run_auto(&root);
    finding_jsons(&root.join("govfuzz_work"))
}

// ---- SSRF (GF-433) — a fuzz-controlled unix-socket destination via connect ----

const SSRF_CONTROLLED: &str = "#include <sys/socket.h>\n\
     #include <sys/un.h>\n\
     #include <string.h>\n\
     #include <stdio.h>\n\
     #include <unistd.h>\n\
     int run_connect(const unsigned char *d, unsigned long n) {\n\
         unsigned long i;\n\
         if (n < 4 || n > 80) return 0;\n\
         for (i = 0; i < n; i++) {\n\
             if (d[i] < 0x20 || d[i] > 0x7e || d[i] == '/') return 0;\n\
         }\n\
         struct sockaddr_un sa;\n\
         memset(&sa, 0, sizeof(sa));\n\
         sa.sun_family = AF_UNIX;\n\
         snprintf(sa.sun_path, sizeof(sa.sun_path), \"/nonexistent/gf_%.*s\", (int)n, d);\n\
         int fd = socket(AF_UNIX, SOCK_STREAM, 0);\n\
         if (fd < 0) return 0;\n\
         connect(fd, (struct sockaddr *)&sa, sizeof(sa));\n\
         close(fd);\n\
         return (int)n;\n\
     }\n";

const SSRF_HARDCODED: &str = "#include <sys/socket.h>\n\
     #include <sys/un.h>\n\
     #include <string.h>\n\
     #include <unistd.h>\n\
     int run_connect(const unsigned char *d, unsigned long n) {\n\
         (void)d;\n\
         struct sockaddr_un sa;\n\
         memset(&sa, 0, sizeof(sa));\n\
         sa.sun_family = AF_UNIX;\n\
         strcpy(sa.sun_path, \"/nonexistent/gf_fixed_socket\");\n\
         int fd = socket(AF_UNIX, SOCK_STREAM, 0);\n\
         if (fd < 0) return 0;\n\
         connect(fd, (struct sockaddr *)&sa, sizeof(sa));\n\
         close(fd);\n\
         return (int)n;\n\
     }\n";

#[test]
fn auto_confirms_ssrf_controlled_gf433() {
    if !support::libfuzzer_toolchain_available("ssrf-controlled") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let findings = build_and_fuzz("ssrf-controlled", SSRF_CONTROLLED);
    let gf433: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "GF-433")
        .collect();
    assert!(
        !gf433.is_empty(),
        "expected a runtime-confirmed GF-433 SSRF finding; findings: {:#?}",
        findings
    );
    let confirmed = gf433
        .iter()
        .find(|f| f["confirmation"] == "runtime")
        .expect("GF-433 must be runtime-confirmed (#422)");
    assert!(
        taint_path_of(confirmed).contains("connect(address)"),
        "GF-433 must carry a connect source→sink taint path, got: {:?}",
        taint_path_of(confirmed)
    );
}

#[test]
fn auto_hardcoded_destination_reports_no_gf433() {
    if !support::libfuzzer_toolchain_available("ssrf-hardcoded") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let findings = build_and_fuzz("ssrf-hardcoded", SSRF_HARDCODED);
    assert!(
        !findings.iter().any(|f| f["rule_id"] == "GF-433"),
        "hardcoded destination must not produce a GF-433 finding; findings: {:#?}",
        findings
    );
}

// ---- Controlled library load (GF-435) — a fuzz-controlled dlopen path ----

const DLOPEN_CONTROLLED: &str = "#include <dlfcn.h>\n\
     #include <stdio.h>\n\
     #include <string.h>\n\
     int run_load(const unsigned char *d, unsigned long n) {\n\
         char lib[200];\n\
         char full[256];\n\
         unsigned long i;\n\
         if (n < 4 || n >= sizeof(lib)) return 0;\n\
         for (i = 0; i < n; i++) {\n\
             if (d[i] < 0x20 || d[i] > 0x7e || d[i] == '/') return 0;\n\
         }\n\
         memcpy(lib, d, n);\n\
         lib[n] = 0;\n\
         snprintf(full, sizeof(full), \"/nonexistent/gf_%s.so\", lib);\n\
         void *h = dlopen(full, RTLD_NOW);\n\
         if (h) dlclose(h);\n\
         return (int)n;\n\
     }\n";

const DLOPEN_HARDCODED: &str = "#include <dlfcn.h>\n\
     int run_load(const unsigned char *d, unsigned long n) {\n\
         (void)d;\n\
         void *h = dlopen(\"/nonexistent/gf_fixed_plugin.so\", RTLD_NOW);\n\
         if (h) dlclose(h);\n\
         return (int)n;\n\
     }\n";

#[test]
fn auto_confirms_library_load_controlled_gf435() {
    if !support::libfuzzer_toolchain_available("dlopen-controlled") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let findings = build_and_fuzz("dlopen-controlled", DLOPEN_CONTROLLED);
    let gf435: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "GF-435")
        .collect();
    assert!(
        !gf435.is_empty(),
        "expected a runtime-confirmed GF-435 library-load finding; findings: {:#?}",
        findings
    );
    let confirmed = gf435
        .iter()
        .find(|f| f["confirmation"] == "runtime")
        .expect("GF-435 must be runtime-confirmed (#422)");
    assert!(
        taint_path_of(confirmed).contains("dlopen(path)"),
        "GF-435 must carry a dlopen source→sink taint path, got: {:?}",
        taint_path_of(confirmed)
    );
}

#[test]
fn auto_hardcoded_library_reports_no_gf435() {
    if !support::libfuzzer_toolchain_available("dlopen-hardcoded") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let findings = build_and_fuzz("dlopen-hardcoded", DLOPEN_HARDCODED);
    assert!(
        !findings.iter().any(|f| f["rule_id"] == "GF-435"),
        "hardcoded library path must not produce a GF-435 finding; findings: {:#?}",
        findings
    );
}

// ---- Destructive filesystem op (GF-440) — a fuzz-controlled unlink path ----

const UNLINK_CONTROLLED: &str = "#include <unistd.h>\n\
     #include <stdio.h>\n\
     #include <string.h>\n\
     int run_delete(const unsigned char *d, unsigned long n) {\n\
         char name[200];\n\
         char full[256];\n\
         unsigned long i;\n\
         if (n < 4 || n >= sizeof(name)) return 0;\n\
         for (i = 0; i < n; i++) {\n\
             if (d[i] < 0x20 || d[i] > 0x7e || d[i] == '/') return 0;\n\
         }\n\
         memcpy(name, d, n);\n\
         name[n] = 0;\n\
         snprintf(full, sizeof(full), \"/nonexistent/gf_%s\", name);\n\
         unlink(full);\n\
         return (int)n;\n\
     }\n";

const UNLINK_HARDCODED: &str = "#include <unistd.h>\n\
     int run_delete(const unsigned char *d, unsigned long n) {\n\
         (void)d;\n\
         unlink(\"/nonexistent/gf_fixed_victim\");\n\
         return (int)n;\n\
     }\n";

#[test]
fn auto_confirms_destructive_path_controlled_gf440() {
    if !support::libfuzzer_toolchain_available("unlink-controlled") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let findings = build_and_fuzz("unlink-controlled", UNLINK_CONTROLLED);
    let gf440: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "GF-440")
        .collect();
    assert!(
        !gf440.is_empty(),
        "expected a runtime-confirmed GF-440 destructive-path finding; findings: {:#?}",
        findings
    );
    let confirmed = gf440
        .iter()
        .find(|f| f["confirmation"] == "runtime")
        .expect("GF-440 must be runtime-confirmed (#422)");
    assert!(
        taint_path_of(confirmed).contains("unlink(path)"),
        "GF-440 must carry an unlink source→sink taint path, got: {:?}",
        taint_path_of(confirmed)
    );
}

#[test]
fn auto_hardcoded_destructive_path_reports_no_gf440() {
    if !support::libfuzzer_toolchain_available("unlink-hardcoded") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let findings = build_and_fuzz("unlink-hardcoded", UNLINK_HARDCODED);
    assert!(
        !findings.iter().any(|f| f["rule_id"] == "GF-440"),
        "hardcoded destructive path must not produce a GF-440 finding; findings: {:#?}",
        findings
    );
}

// ---- SQL injection (GF-441) — a fuzz-controlled query reaching sqlite3_exec ----
//
// The fixture declares sqlite3_exec `weak` so it links without libsqlite3; at
// runtime the LD_PRELOAD shim provides the symbol and audits the query. No real
// database is contacted (the shim forwards to RTLD_NEXT, which finds no client
// library, and returns an error).

const SQL_CONTROLLED: &str = "#include <stdio.h>\n\
     #include <string.h>\n\
     extern int sqlite3_exec(void *, const char *, void *, void *, char **)\n\
         __attribute__((weak));\n\
     int run_query(const unsigned char *d, unsigned long n) {\n\
         char val[128];\n\
         char q[256];\n\
         unsigned long i;\n\
         if (n < 4 || n >= sizeof(val)) return 0;\n\
         for (i = 0; i < n; i++) {\n\
             if (d[i] < 0x20 || d[i] > 0x7e || d[i] == 0x27 || d[i] == 0x22) return 0;\n\
         }\n\
         memcpy(val, d, n);\n\
         val[n] = 0;\n\
         snprintf(q, sizeof(q), \"SELECT * FROM users WHERE name='%s'\", val);\n\
         if (sqlite3_exec) sqlite3_exec(0, q, 0, 0, 0);\n\
         return (int)n;\n\
     }\n";

const SQL_HARDCODED: &str =
    "extern int sqlite3_exec(void *, const char *, void *, void *, char **)\n\
         __attribute__((weak));\n\
     int run_query(const unsigned char *d, unsigned long n) {\n\
         (void)d;\n\
         if (sqlite3_exec) sqlite3_exec(0, \"SELECT COUNT(*) FROM users\", 0, 0, 0);\n\
         return (int)n;\n\
     }\n";

#[test]
fn auto_confirms_sql_injection_controlled_gf441() {
    if !support::libfuzzer_toolchain_available("sql-controlled") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let findings = build_and_fuzz("sql-controlled", SQL_CONTROLLED);
    let gf441: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "GF-441")
        .collect();
    assert!(
        !gf441.is_empty(),
        "expected a runtime-confirmed GF-441 SQL-injection finding; findings: {:#?}",
        findings
    );
    let confirmed = gf441
        .iter()
        .find(|f| f["confirmation"] == "runtime")
        .expect("GF-441 must be runtime-confirmed (#422)");
    assert!(
        taint_path_of(confirmed).contains("sqlite3_exec(sql)"),
        "GF-441 must carry a sqlite3_exec source→sink taint path, got: {:?}",
        taint_path_of(confirmed)
    );
}

#[test]
fn auto_parameterized_query_reports_no_gf441() {
    if !support::libfuzzer_toolchain_available("sql-hardcoded") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let findings = build_and_fuzz("sql-hardcoded", SQL_HARDCODED);
    assert!(
        !findings.iter().any(|f| f["rule_id"] == "GF-441"),
        "a constant query must not produce a GF-441 finding; findings: {:#?}",
        findings
    );
}
