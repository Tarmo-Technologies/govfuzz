// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn binary_scan_inventories_elf_pe_macho_and_firmware_blobs() {
    let root = temp_dir("inventory");
    write_elf64_x86_64(&root.join("sample.elf"));
    write_pe_x86_64(&root.join("sample.exe"));
    write_macho64_x86_64(&root.join("sample.macho"));
    fs::write(root.join("firmware.bin"), b"raw firmware bytes").unwrap();

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    assert_eq!(report["schema_version"], "govfuzz.binary.v1");
    assert_eq!(report["counts"]["files"], 4);
    assert_eq!(report["counts"]["by_format"]["elf"], 1);
    assert_eq!(report["counts"]["by_format"]["pe"], 1);
    assert_eq!(report["counts"]["by_format"]["mach_o"], 1);
    assert_eq!(report["counts"]["by_format"]["firmware_blob"], 1);

    assert_eq!(binary(&report, "sample.elf")["architecture"], "x86_64");
    assert_eq!(binary(&report, "sample.elf")["bits"], 64);
    assert_eq!(binary(&report, "sample.exe")["format"], "pe");
    assert_eq!(binary(&report, "sample.macho")["endian"], "little");
    assert!(
        binary(&report, "firmware.bin")["sha256"]
            .as_str()
            .unwrap()
            .len()
            == 64
    );
}

#[test]
fn binary_scan_records_symbol_debug_states_and_malformed_inputs() {
    let root = temp_dir("symbol-debug");
    write_elf64_x86_64(&root.join("stripped.elf"));
    write_elf64_x86_64_with_markers(&root.join("partial.elf"), &[b".dynsym"]);
    write_elf64_x86_64_with_markers(&root.join("debug.elf"), &[b".symtab", b".debug_info"]);
    fs::write(root.join("malformed.elf"), b"\x7fELF\x02\x01").unwrap();

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    assert_eq!(report["counts"]["files"], 3);
    assert_eq!(report["counts"]["skipped"], 1);
    assert_eq!(binary(&report, "stripped.elf")["symbol_status"], "stripped");
    assert_eq!(
        binary(&report, "partial.elf")["symbol_status"],
        "partially_symbolized"
    );
    assert_eq!(
        binary(&report, "debug.elf")["symbol_status"],
        "debug_info_rich"
    );
    assert_eq!(binary(&report, "debug.elf")["debug_info_status"], "present");
    assert_eq!(skipped(&report, "malformed.elf")["reason"], "malformed_elf");
}

#[test]
fn binary_scan_traverses_archives_and_respects_size_limits() {
    let root = temp_dir("archives-limits");
    let member = elf64_x86_64_with_markers(&[b".symtab", b".debug_info"]);
    write_ar_archive(
        &root.join("liblegacy.a"),
        &[("legacy.o", member.as_slice())],
    );
    fs::write(root.join("oversize.bin"), vec![0x41; 600]).unwrap();

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--max-bytes",
            "512",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    assert_eq!(report["counts"]["containers"], 1);
    assert_eq!(report["counts"]["skipped"], 1);
    let member = binary(&report, "liblegacy.a!legacy.o");
    assert_eq!(member["format"], "elf");
    assert_eq!(member["container_path"], "liblegacy.a");
    assert_eq!(member["member_name"], "legacy.o");
    assert_eq!(member["debug_info_status"], "present");
    assert_eq!(skipped(&report, "oversize.bin")["reason"], "size_limit");
}

#[test]
fn binary_scan_reports_import_export_hardening_and_firmware_strings() {
    let root = temp_dir("depth");
    write_elf64_x86_64_with_markers(
        &root.join("service.elf"),
        &[
            b".dynsym",
            b".rela.plt",
            b"GNU_RELRO",
            b"__stack_chk_fail",
            b"/etc/legacy.conf",
        ],
    );
    write_pe_x86_64_with_markers(
        &root.join("service.exe"),
        &[b".idata", b".edata", b"RSDS", b"CreateFileA"],
    );
    fs::write(
        root.join("firmware.img"),
        b"BOOT\x00/etc/passwd\x00http://192.0.2.1/update\x00",
    )
    .unwrap();

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let elf = binary(&report, "service.elf");
    assert_eq!(elf["imports"]["status"], "dynamic_imports_present");
    // This fixture carries a RELRO marker but no BIND_NOW dynamic entry → Partial RELRO.
    assert_eq!(elf["hardening"]["relro"], "partial");
    assert_eq!(elf["hardening"]["stack_canary"], "present");
    // No PT_GNU_STACK program header and no fortified `*_chk` wrappers in this fixture:
    // NX is undeterminable and FORTIFY is absent (the canary is not FORTIFY).
    assert_eq!(elf["hardening"]["nx"], "not_detected");
    assert_eq!(elf["hardening"]["fortify_source"], "not_detected");
    assert!(elf["strings"]["interesting"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "/etc/legacy.conf"));

    let pe = binary(&report, "service.exe");
    assert_eq!(pe["imports"]["status"], "import_table_present");
    assert_eq!(pe["exports"]["status"], "export_table_present");
    assert_eq!(pe["debug_info_status"], "present");

    let firmware = binary(&report, "firmware.img");
    assert_eq!(firmware["format"], "firmware_blob");
    assert!(firmware["strings"]["interesting"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "http://192.0.2.1/update"));
    assert_eq!(
        report["counts"]["binaries_with_interesting_strings"]
            .as_u64()
            .unwrap(),
        3
    );
}

#[test]
fn binary_scan_reports_nx_and_fortify_source() {
    let root = temp_dir("nx-fortify");
    // A: PT_GNU_STACK read-write (no exec bit) → NX enabled.
    write_elf64_x86_64_with_gnu_stack(&root.join("nx-on.elf"), 0x6);
    // B: PT_GNU_STACK read-write-EXECUTE → executable stack (NX disabled), a real gap.
    write_elf64_x86_64_with_gnu_stack(&root.join("nx-off.elf"), 0x7);
    // C: fortified `*_chk` wrapper linked in → FORTIFY_SOURCE present.
    write_elf64_x86_64_with_markers(&root.join("fortified.elf"), &[b".dynsym", b"__memcpy_chk"]);

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();

    let nx_on = binary(&report, "nx-on.elf");
    assert_eq!(nx_on["hardening"]["nx"], "present");

    let nx_off = binary(&report, "nx-off.elf");
    assert_eq!(nx_off["hardening"]["nx"], "disabled");
    assert!(nx_off["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "hardening:nx_disabled"));

    let fortified = binary(&report, "fortified.elf");
    assert_eq!(fortified["hardening"]["fortify_source"], "present");
    assert!(!fortified["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "hardening:fortify_source_missing"));
}

#[test]
fn binary_scan_reports_relro_full_partial_and_none() {
    let root = temp_dir("relro");
    // Full: PT_GNU_RELRO segment + a DT_BIND_NOW dynamic entry → GOT read-only.
    write_elf64_x86_64_with_relro(&root.join("full.elf"), true);
    // Partial: PT_GNU_RELRO segment but no BIND_NOW → GOT stays writable.
    write_elf64_x86_64_with_relro(&root.join("partial.elf"), false);
    // None: no RELRO at all.
    write_elf64_x86_64(&root.join("none.elf"));

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();

    let full = binary(&report, "full.elf");
    assert_eq!(full["hardening"]["relro"], "full");
    assert!(!full["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "hardening:relro_missing" || factor == "hardening:relro_partial"));

    let partial = binary(&report, "partial.elf");
    assert_eq!(partial["hardening"]["relro"], "partial");
    assert!(partial["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "hardening:relro_partial"));

    let none = binary(&report, "none.elf");
    assert_eq!(none["hardening"]["relro"], "none");
    assert!(none["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "hardening:relro_missing"));
}

#[test]
fn binary_scan_reports_pe_aslr_dep_and_cfg() {
    let root = temp_dir("pe-hardening");
    // DYNAMIC_BASE (0x40) | NX_COMPAT (0x100) | GUARD_CF (0x4000): every mitigation on.
    write_pe_x86_64_with_dll_characteristics(&root.join("hardened.exe"), 0x0040 | 0x0100 | 0x4000);
    // No DllCharacteristics bits: ASLR / DEP / CFG all missing.
    write_pe_x86_64_with_dll_characteristics(&root.join("legacy.exe"), 0x0000);

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();

    let hardened = binary(&report, "hardened.exe");
    assert_eq!(hardened["hardening"]["aslr"], "present");
    assert_eq!(hardened["hardening"]["nx"], "present");
    assert_eq!(hardened["hardening"]["control_flow_guard"], "present");
    // ELF-only mitigations are not applicable to a PE.
    assert_eq!(hardened["hardening"]["relro"], "not_applicable");
    assert_eq!(hardened["hardening"]["pie"], "not_applicable");
    assert_eq!(hardened["hardening"]["fortify_source"], "not_applicable");

    let legacy = binary(&report, "legacy.exe");
    assert_eq!(legacy["hardening"]["aslr"], "not_detected");
    assert_eq!(legacy["hardening"]["nx"], "disabled");
    assert_eq!(legacy["hardening"]["control_flow_guard"], "not_detected");
    let factors = legacy["triage"]["risk_factors"].as_array().unwrap();
    for expected in [
        "hardening:aslr_missing",
        "hardening:nx_disabled",
        "hardening:control_flow_guard_missing",
    ] {
        assert!(
            factors.iter().any(|factor| factor == expected),
            "missing {expected} in {factors:?}"
        );
    }
}

#[test]
fn binary_scan_detects_and_redacts_embedded_secrets() {
    let root = temp_dir("secrets");
    write_elf64_x86_64_with_markers(
        &root.join("creds.elf"),
        &[
            b"AKIAIOSFODNN7EXAMPLE",
            b"ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            b"npm_0123456789abcdefghijklmnopqrstuvwxyz",
            b"-----BEGIN RSA PRIVATE KEY-----",
        ],
    );
    // A benign binary must not trip the detectors.
    write_elf64_x86_64_with_markers(
        &root.join("benign.elf"),
        &[b"/usr/lib/libc.so.6", b"normal_config_value"],
    );

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();

    let creds = binary(&report, "creds.elf");
    let secrets = creds["secrets"].as_array().unwrap();
    let kinds: Vec<&str> = secrets
        .iter()
        .map(|s| s["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"aws_access_key_id"), "kinds={kinds:?}");
    assert!(kinds.contains(&"github_token"), "kinds={kinds:?}");
    assert!(kinds.contains(&"npm_token"), "kinds={kinds:?}");
    assert!(kinds.contains(&"private_key_pem"), "kinds={kinds:?}");

    // Every secret finding carries a CWE (321 for keys, 798 for credentials).
    let aws = secrets
        .iter()
        .find(|s| s["kind"] == "aws_access_key_id")
        .unwrap();
    assert_eq!(aws["cwe"], "CWE-798");
    let pem = secrets
        .iter()
        .find(|s| s["kind"] == "private_key_pem")
        .unwrap();
    assert_eq!(pem["cwe"], "CWE-321");

    // The full secret is never emitted — only a redacted preview.
    assert_eq!(aws["preview"], "AKIA***[20 chars]");
    assert!(
        !secrets
            .iter()
            .any(|s| s["preview"].as_str().unwrap().contains("IOSFODNN7EXAMPLE")),
        "raw secret leaked into preview"
    );

    // Embedded credentials promote the binary to high triage priority.
    assert_eq!(creds["triage"]["priority"], "high");
    assert!(creds["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "embedded_secret:aws_access_key_id"));

    let benign = binary(&report, "benign.elf");
    assert!(
        benign["secrets"].as_array().unwrap().is_empty(),
        "benign binary tripped a secret detector: {:?}",
        benign["secrets"]
    );
    assert_eq!(report["counts"]["binaries_with_secrets"], 1);
}

#[test]
fn binary_scan_reports_macho_pie_nx_and_code_signature() {
    let root = temp_dir("macho-hardening");
    // MH_PIE (0x200000), non-exec stack, and a LC_CODE_SIGNATURE load command.
    write_macho64_x86_64_with_hardening(&root.join("signed.macho"), 0x0020_0000, true);
    // No MH_PIE, MH_ALLOW_STACK_EXECUTION (0x20000) set, unsigned.
    write_macho64_x86_64_with_hardening(&root.join("legacy.macho"), 0x0002_0000, false);

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();

    let signed = binary(&report, "signed.macho");
    assert_eq!(signed["hardening"]["pie"], "present");
    assert_eq!(signed["hardening"]["nx"], "present");
    assert_eq!(signed["hardening"]["code_signature"], "present");
    // ELF/PE-only mitigations are not applicable to a Mach-O.
    assert_eq!(signed["hardening"]["relro"], "not_applicable");
    assert_eq!(signed["hardening"]["aslr"], "not_applicable");

    let legacy = binary(&report, "legacy.macho");
    assert_eq!(legacy["hardening"]["pie"], "not_detected");
    assert_eq!(legacy["hardening"]["nx"], "disabled");
    assert_eq!(legacy["hardening"]["code_signature"], "not_detected");
    let factors = legacy["triage"]["risk_factors"].as_array().unwrap();
    for expected in [
        "hardening:pie_missing",
        "hardening:nx_disabled",
        "hardening:code_signature_missing",
    ] {
        assert!(
            factors.iter().any(|factor| factor == expected),
            "missing {expected} in {factors:?}"
        );
    }
}

#[test]
fn binary_scan_classifies_risky_imports_and_triage_factors() {
    let root = temp_dir("risky-imports");
    write_elf64_x86_64_with_markers(
        &root.join("legacy-daemon.elf"),
        &[b".dynsym", b"system", b"strcpy", b"connect"],
    );

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let binary = binary(&report, "legacy-daemon.elf");
    assert!(binary["imports"]["risky_apis"]
        .as_array()
        .unwrap()
        .iter()
        .any(|api| api["name"] == "system"
            && api["category"] == "command_execution"
            && api["severity"] == "high"));
    assert!(binary["imports"]["risky_apis"]
        .as_array()
        .unwrap()
        .iter()
        .any(|api| api["name"] == "strcpy"
            && api["category"] == "memory_unsafe"
            && api["severity"] == "high"));
    assert_eq!(binary["triage"]["priority"], "high");
    assert!(binary["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "risky_import:system"));
    assert!(binary["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "hardening:relro_missing"));
    assert!(binary["triage"]["recommended_campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|campaign| campaign == "command-injection-review"));
    assert!(binary["triage"]["recommended_campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|campaign| campaign == "network-model-review"));
}

#[test]
fn binary_scan_extracts_elf_dynsym_import_export_symbols() {
    let root = temp_dir("elf-dynsym-symbols");
    write_elf64_x86_64_with_dynsym_symbols(
        &root.join("service.elf"),
        "LegacyServiceEntry",
        "LegacyExportedRoutine",
    );

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let elf = binary(&report, "service.elf");
    assert_eq!(elf["imports"]["status"], "dynamic_imports_present");
    assert!(elf["imports"]["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .any(|symbol| symbol == "LegacyServiceEntry"));
    assert_eq!(elf["exports"]["status"], "symbol_table_present");
    assert!(elf["exports"]["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .any(|symbol| symbol == "LegacyExportedRoutine"));
}

#[test]
fn binary_scan_extracts_dynamic_dependency_evidence() {
    let root = temp_dir("dependencies");
    write_elf64_x86_64_with_markers(
        &root.join("legacy.elf"),
        &[
            b".dynsym",
            b"libcrypto.so.1.0.1",
            b"/lib64/ld-linux-x86-64.so.2",
            b"RUNPATH=/opt/legacy/lib:/tmp/vendor",
        ],
    );
    write_pe_x86_64_with_markers(&root.join("legacy.exe"), &[b"KERNEL32.dll"]);
    write_macho64_x86_64_with_markers(&root.join("legacy.macho"), &[b"/usr/lib/libSystem.B.dylib"]);

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let elf = binary(&report, "legacy.elf");
    assert!(elf["dependencies"]["libraries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|library| library == "libcrypto.so.1.0.1"));
    assert!(elf["dependencies"]["interpreters"]
        .as_array()
        .unwrap()
        .iter()
        .any(|interpreter| interpreter == "/lib64/ld-linux-x86-64.so.2"));
    assert!(elf["dependencies"]["rpaths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rpath| rpath == "/opt/legacy/lib"));
    assert!(elf["dependencies"]["rpaths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rpath| rpath == "/tmp/vendor"));
    let pe = binary(&report, "legacy.exe");
    assert!(pe["dependencies"]["libraries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|library| library == "KERNEL32.dll"));
    let macho = binary(&report, "legacy.macho");
    assert!(macho["dependencies"]["libraries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|library| library == "/usr/lib/libSystem.B.dylib"));
}

#[test]
fn binary_scan_extracts_elf_interp_from_program_header() {
    let root = temp_dir("elf-interp");
    write_elf64_x86_64_with_interp_segment(&root.join("loader.elf"), "/opt/legacy/custom-loader");

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let elf = binary(&report, "loader.elf");
    assert!(elf["dependencies"]["interpreters"]
        .as_array()
        .unwrap()
        .iter()
        .any(|interpreter| interpreter == "/opt/legacy/custom-loader"));
    assert!(elf["layout"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == "PT_INTERP[0]" && section["kind"] == "segment"));
}

#[test]
fn binary_scan_extracts_elf_note_build_id() {
    let root = temp_dir("elf-build-id");
    write_elf64_x86_64_with_build_id_note(
        &root.join("segment-note.elf"),
        &[
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32,
            0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        ],
    );
    write_elf64_x86_64_with_build_id_section(
        &root.join("section-note.elf"),
        &[
            0xca, 0xfe, 0xba, 0xbe, 0x55, 0xaa, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ],
    );

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let elf = binary(&report, "segment-note.elf");
    assert_eq!(elf["build_id"], "deadbeef0123456789abcdef1032547698badcfe");
    assert!(elf["evidence"]["markers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|marker| marker == "elf:build_id"));
    assert!(elf["layout"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == "PT_NOTE[0]" && section["kind"] == "segment"));
    let section_note = binary(&report, "section-note.elf");
    assert_eq!(section_note["build_id"], "cafebabe55aa00112233445566778899");
    assert!(section_note["evidence"]["markers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|marker| marker == "elf:build_id"));
}

#[test]
fn binary_scan_extracts_elf_dynamic_table_dependencies() {
    let root = temp_dir("elf-dynamic");
    write_elf64_x86_64_with_dynamic_dependencies(
        &root.join("service.elf"),
        "libgovlegacy",
        "/srv/legacy/lib",
        "$ORIGIN/plugins:/tmp/vendor",
    );

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let elf = binary(&report, "service.elf");
    assert!(elf["dependencies"]["libraries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|library| library == "libgovlegacy"));
    assert!(elf["dependencies"]["rpaths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rpath| rpath == "/srv/legacy/lib"));
    assert!(elf["dependencies"]["rpaths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rpath| rpath == "$ORIGIN/plugins"));
    assert!(elf["dependencies"]["rpaths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rpath| rpath == "/tmp/vendor"));
    assert!(elf["layout"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == "PT_DYNAMIC[1]" && section["kind"] == "segment"));
}

#[test]
fn binary_scan_extracts_pe_import_directory_dependencies() {
    let root = temp_dir("pe-imports");
    write_pe_x86_64_with_import_directory(
        &root.join("service.exe"),
        "LEGACYDRIVER",
        "LegacyOpenChannel",
    );

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let pe = binary(&report, "service.exe");
    assert!(pe["dependencies"]["libraries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|library| library == "LEGACYDRIVER"));
    assert!(pe["layout"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == ".idata" && section["kind"] == "section"));
    assert!(pe["imports"]["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .any(|symbol| symbol == "LEGACYDRIVER!LegacyOpenChannel"));
}

#[test]
fn binary_scan_extracts_pe_export_directory_symbols() {
    let root = temp_dir("pe-exports");
    write_pe_x86_64_with_export_directory(&root.join("service.exe"), "LegacyDispatch");

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let pe = binary(&report, "service.exe");
    assert_eq!(pe["exports"]["status"], "export_table_present");
    assert!(pe["layout"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == ".edata" && section["kind"] == "section"));
    assert!(pe["exports"]["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .any(|symbol| symbol == "LegacyDispatch"));
}

#[test]
fn binary_scan_extracts_macho_dylib_load_command_dependencies() {
    let root = temp_dir("macho-dylib");
    write_macho64_x86_64_with_dylib_command(&root.join("service.macho"), "LegacyFramework");

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let macho = binary(&report, "service.macho");
    assert!(macho["dependencies"]["libraries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|library| library == "LegacyFramework"));
}

#[test]
fn binary_scan_extracts_macho_symtab_import_export_symbols() {
    let root = temp_dir("macho-symtab");
    write_macho64_x86_64_with_symtab_symbols(
        &root.join("service.macho"),
        "_LegacyImportedRoutine",
        "_LegacyExportedRoutine",
    );

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let macho = binary(&report, "service.macho");
    assert_eq!(macho["imports"]["status"], "dynamic_imports_present");
    assert!(macho["imports"]["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .any(|symbol| symbol == "_LegacyImportedRoutine"));
    assert_eq!(macho["exports"]["status"], "symbol_table_present");
    assert!(macho["exports"]["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .any(|symbol| symbol == "_LegacyExportedRoutine"));
}

#[test]
fn binary_scan_extracts_header_layout_metadata() {
    let root = temp_dir("layout");
    write_elf64_x86_64_with_layout(&root.join("layout.elf"), 0x401000, 3, 9);
    write_pe_x86_64_with_layout(&root.join("layout.exe"), 5, 0x1234, 0x140000000);
    write_macho64_x86_64_with_layout(&root.join("layout.macho"), 2, 128);

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let elf = binary(&report, "layout.elf");
    assert_eq!(elf["layout"]["entrypoint"], 0x401000);
    assert_eq!(elf["layout"]["program_header_count"], 3);
    assert_eq!(elf["layout"]["section_count"], 9);
    let pe = binary(&report, "layout.exe");
    assert_eq!(pe["layout"]["entrypoint"], 0x1234);
    assert_eq!(pe["layout"]["image_base"], 0x140000000u64);
    assert_eq!(pe["layout"]["section_count"], 5);
    let macho = binary(&report, "layout.macho");
    assert_eq!(macho["layout"]["load_command_count"], 2);
    assert_eq!(macho["layout"]["load_command_bytes"], 128);
}

#[test]
fn binary_scan_reports_entropy_and_packed_firmware_risk() {
    let root = temp_dir("entropy");
    let mut high_entropy = Vec::new();
    for _ in 0..4 {
        high_entropy.extend(0u8..=255);
    }
    fs::write(root.join("packed.bin"), high_entropy).unwrap();
    fs::write(root.join("plain.bin"), vec![0u8; 512]).unwrap();

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let packed = binary(&report, "packed.bin");
    assert_eq!(packed["entropy"]["classification"], "high");
    assert!(packed["entropy"]["shannon"].as_f64().unwrap() >= 7.9);
    assert_eq!(packed["triage"]["priority"], "medium");
    assert!(packed["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "binary_entropy:high"));
    assert!(packed["triage"]["recommended_campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|campaign| campaign == "packed-binary-review"));

    let plain = binary(&report, "plain.bin");
    assert_eq!(plain["entropy"]["classification"], "low");
    assert!(plain["entropy"]["shannon"].as_f64().unwrap() < 1.0);
    assert!(!plain["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "binary_entropy:high"));
}

#[test]
fn binary_scan_extracts_section_layout_and_triages_packed_names() {
    let root = temp_dir("sections");
    write_elf64_x86_64_with_sections(&root.join("packed.elf"), &[(".text", 0x6), ("UPX0", 0x7)]);
    write_pe_x86_64_with_sections(&root.join("service.exe"), &[".text", ".rdata"]);
    write_macho64_x86_64_with_segment(&root.join("service.macho"), "__TEXT");

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let elf = binary(&report, "packed.elf");
    assert!(elf["layout"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == "UPX0"
            && section["kind"] == "section"
            && section["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flag| flag == "executable")
            && section["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flag| flag == "writable")));
    assert_eq!(elf["triage"]["priority"], "medium");
    assert!(elf["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "section:upx"));
    assert!(elf["triage"]["recommended_campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|campaign| campaign == "packed-binary-review"));

    let pe = binary(&report, "service.exe");
    assert!(pe["layout"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == ".rdata" && section["kind"] == "section"));

    let macho = binary(&report, "service.macho");
    assert!(macho["layout"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == "__TEXT" && section["kind"] == "segment"));
}

#[test]
fn binary_scan_extracts_elf_program_segment_permissions() {
    let root = temp_dir("segments");
    write_elf64_x86_64_with_rwx_load_segment(&root.join("rwx.elf"));

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let elf = binary(&report, "rwx.elf");
    assert!(elf["layout"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["name"] == "PT_LOAD[0]"
            && section["kind"] == "segment"
            && section["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flag| flag == "executable")
            && section["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flag| flag == "writable")));
    assert_eq!(elf["triage"]["priority"], "medium");
    assert!(elf["triage"]["risk_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor == "segment:executable_writable"));
    assert!(elf["triage"]["recommended_campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|campaign| campaign == "binary-layout-review"));
}

#[test]
fn binary_scan_triages_suspicious_loader_paths() {
    let root = temp_dir("loader-paths");
    write_elf64_x86_64_with_markers(
        &root.join("legacy-loader.elf"),
        &[b"RUNPATH=/tmp/vendor:./plugins:/opt/legacy/lib"],
    );

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    let binary = binary(&report, "legacy-loader.elf");
    assert_eq!(binary["triage"]["priority"], "medium");
    let risk_factors = binary["triage"]["risk_factors"].as_array().unwrap();
    assert!(risk_factors
        .iter()
        .any(|factor| factor == "loader_path:writable_rpath:/tmp/vendor"));
    assert!(risk_factors
        .iter()
        .any(|factor| factor == "loader_path:relative_rpath:./plugins"));
    assert!(binary["triage"]["recommended_campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|campaign| campaign == "loader-path-review"));
}

#[test]
fn binary_scan_matches_offline_cves_and_emits_triage_depth_metadata() {
    let root = temp_dir("cve-depth");
    write_elf64_x86_64_with_markers(
        &root.join("legacy-openssl.elf"),
        &[
            b".dynsym",
            b".debug_info",
            b"OpenSSL 1.0.1",
            b"/etc/passwd",
            b"socket",
        ],
    );
    let cve_db = root.join("cves.json");
    fs::write(
        &cve_db,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "govfuzz.binary.cves.v1",
            "components": [{
                "name": "openssl",
                "version": "1.0.1",
                "purl": "pkg:generic/openssl@1.0.1",
                "match_strings": ["OpenSSL 1.0.1"],
                "cves": [{
                    "id": "CVE-2014-0160",
                    "severity": "critical",
                    "summary": "OpenSSL Heartbeat information disclosure"
                }]
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("binary");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--cve-db",
            cve_db.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("binary-inventory.json")).unwrap()).unwrap();
    assert_eq!(report["counts"]["cve_matches"], 1);
    assert_eq!(report["counts"]["binaries_with_cve_matches"], 1);
    let binary = binary(&report, "legacy-openssl.elf");
    assert_eq!(binary["sbom"]["components"][0]["name"], "openssl");
    assert_eq!(
        binary["sbom"]["components"][0]["purl"],
        "pkg:generic/openssl@1.0.1"
    );
    assert_eq!(binary["cve_matches"][0]["id"], "CVE-2014-0160");
    assert_eq!(binary["cve_matches"][0]["severity"], "critical");
    assert_eq!(binary["triage"]["dedup_key"].as_str().unwrap().len(), 48);
    assert_eq!(binary["triage"]["crash_replay"]["stdin"], true);
    assert_eq!(binary["triage"]["crash_replay"]["file"], true);
    assert!(binary["analysis_plan"]["reverse_engineering_tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["tool"] == "ghidra" && tool["status"] == "offline_export_supported"));
    assert_eq!(
        binary["analysis_plan"]["symbolization"],
        "debug_info_present"
    );
}

fn binary<'a>(report: &'a serde_json::Value, suffix: &str) -> &'a serde_json::Value {
    report["binaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|binary| {
            binary["path"]
                .as_str()
                .is_some_and(|path| path.ends_with(suffix))
        })
        .unwrap()
}

fn skipped<'a>(report: &'a serde_json::Value, suffix: &str) -> &'a serde_json::Value {
    report["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .find(|skipped| {
            skipped["path"]
                .as_str()
                .is_some_and(|path| path.ends_with(suffix))
        })
        .unwrap()
}

fn write_elf64_x86_64(path: &std::path::Path) {
    fs::write(path, elf64_x86_64_with_markers(&[])).unwrap();
}

fn write_elf64_x86_64_with_markers(path: &std::path::Path, markers: &[&[u8]]) {
    fs::write(path, elf64_x86_64_with_markers(markers)).unwrap();
}

fn write_elf64_x86_64_with_layout(
    path: &std::path::Path,
    entrypoint: u64,
    program_header_count: u16,
    section_count: u16,
) {
    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes[24..32].copy_from_slice(&entrypoint.to_le_bytes());
    bytes[56..58].copy_from_slice(&program_header_count.to_le_bytes());
    bytes[60..62].copy_from_slice(&section_count.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_elf64_x86_64_with_sections(path: &std::path::Path, sections: &[(&str, u64)]) {
    let mut names = vec![0u8];
    let mut name_offsets = Vec::new();
    for (name, _) in sections {
        name_offsets.push(names.len() as u32);
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    let shstrtab_name = names.len() as u32;
    names.extend_from_slice(b".shstrtab\0");

    let section_header_offset = 0x100usize;
    let string_table_offset = section_header_offset + ((sections.len() + 2) * 64);
    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes.resize(section_header_offset, 0);
    bytes[40..48].copy_from_slice(&(section_header_offset as u64).to_le_bytes());
    bytes[58..60].copy_from_slice(&(64u16).to_le_bytes());
    bytes[60..62].copy_from_slice(&((sections.len() + 2) as u16).to_le_bytes());
    bytes[62..64].copy_from_slice(&((sections.len() + 1) as u16).to_le_bytes());

    bytes.resize(string_table_offset + names.len(), 0);
    for (index, ((_, flags), name_offset)) in sections.iter().zip(name_offsets).enumerate() {
        let offset = section_header_offset + ((index + 1) * 64);
        bytes[offset..offset + 4].copy_from_slice(&name_offset.to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&(1u32).to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&flags.to_le_bytes());
        bytes[offset + 24..offset + 32]
            .copy_from_slice(&((0x200 + (index * 0x20)) as u64).to_le_bytes());
        bytes[offset + 32..offset + 40].copy_from_slice(&(0x20u64).to_le_bytes());
    }
    let shstrtab_offset = section_header_offset + ((sections.len() + 1) * 64);
    bytes[shstrtab_offset..shstrtab_offset + 4].copy_from_slice(&shstrtab_name.to_le_bytes());
    bytes[shstrtab_offset + 4..shstrtab_offset + 8].copy_from_slice(&(3u32).to_le_bytes());
    bytes[shstrtab_offset + 24..shstrtab_offset + 32]
        .copy_from_slice(&(string_table_offset as u64).to_le_bytes());
    bytes[shstrtab_offset + 32..shstrtab_offset + 40]
        .copy_from_slice(&(names.len() as u64).to_le_bytes());
    bytes[string_table_offset..string_table_offset + names.len()].copy_from_slice(&names);
    fs::write(path, bytes).unwrap();
}

fn write_elf64_x86_64_with_gnu_stack(path: &std::path::Path, flags: u32) {
    let program_header_offset = 0x40usize;
    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes.resize(program_header_offset + 56, 0);
    bytes[32..40].copy_from_slice(&(program_header_offset as u64).to_le_bytes());
    bytes[54..56].copy_from_slice(&(56u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&(1u16).to_le_bytes());

    // PT_GNU_STACK (0x6474e551); the segment flags carry the stack's permissions.
    bytes[program_header_offset..program_header_offset + 4]
        .copy_from_slice(&0x6474_e551u32.to_le_bytes());
    bytes[program_header_offset + 4..program_header_offset + 8]
        .copy_from_slice(&flags.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_elf64_x86_64_with_relro(path: &std::path::Path, bind_now: bool) {
    let program_header_offset = 0x40usize;
    let entry_size = 56usize;
    let dynamic_offset = 0x100usize;
    let count: u16 = if bind_now { 2 } else { 1 };
    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes.resize(dynamic_offset + 32, 0);
    bytes[32..40].copy_from_slice(&(program_header_offset as u64).to_le_bytes());
    bytes[54..56].copy_from_slice(&(entry_size as u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&count.to_le_bytes());

    // PH0: PT_GNU_RELRO (0x6474e552), read-only.
    bytes[program_header_offset..program_header_offset + 4]
        .copy_from_slice(&0x6474_e552u32.to_le_bytes());
    bytes[program_header_offset + 4..program_header_offset + 8]
        .copy_from_slice(&4u32.to_le_bytes());

    if bind_now {
        // PH1: PT_DYNAMIC pointing at a table holding a DT_BIND_NOW (24) entry + DT_NULL.
        let dyn_ph = program_header_offset + entry_size;
        bytes[dyn_ph..dyn_ph + 4].copy_from_slice(&2u32.to_le_bytes());
        bytes[dyn_ph + 4..dyn_ph + 8].copy_from_slice(&6u32.to_le_bytes());
        bytes[dyn_ph + 8..dyn_ph + 16].copy_from_slice(&(dynamic_offset as u64).to_le_bytes());
        bytes[dyn_ph + 32..dyn_ph + 40].copy_from_slice(&32u64.to_le_bytes());
        bytes[dynamic_offset..dynamic_offset + 8].copy_from_slice(&24u64.to_le_bytes());
    }
    fs::write(path, bytes).unwrap();
}

fn write_elf64_x86_64_with_rwx_load_segment(path: &std::path::Path) {
    let program_header_offset = 0x40usize;
    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes.resize(program_header_offset + 56, 0);
    bytes[32..40].copy_from_slice(&(program_header_offset as u64).to_le_bytes());
    bytes[54..56].copy_from_slice(&(56u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&(1u16).to_le_bytes());

    bytes[program_header_offset..program_header_offset + 4].copy_from_slice(&(1u32).to_le_bytes());
    bytes[program_header_offset + 4..program_header_offset + 8]
        .copy_from_slice(&(7u32).to_le_bytes());
    bytes[program_header_offset + 8..program_header_offset + 16]
        .copy_from_slice(&(0x1000u64).to_le_bytes());
    bytes[program_header_offset + 16..program_header_offset + 24]
        .copy_from_slice(&(0x401000u64).to_le_bytes());
    bytes[program_header_offset + 32..program_header_offset + 40]
        .copy_from_slice(&(0x200u64).to_le_bytes());
    bytes[program_header_offset + 40..program_header_offset + 48]
        .copy_from_slice(&(0x200u64).to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_elf64_x86_64_with_interp_segment(path: &std::path::Path, interpreter: &str) {
    let program_header_offset = 0x40usize;
    let interpreter_offset = 0x100usize;
    let interpreter_bytes = interpreter.as_bytes();
    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes.resize(interpreter_offset + interpreter_bytes.len() + 1, 0);
    bytes[32..40].copy_from_slice(&(program_header_offset as u64).to_le_bytes());
    bytes[54..56].copy_from_slice(&(56u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&(1u16).to_le_bytes());

    bytes[program_header_offset..program_header_offset + 4].copy_from_slice(&(3u32).to_le_bytes());
    bytes[program_header_offset + 4..program_header_offset + 8]
        .copy_from_slice(&(4u32).to_le_bytes());
    bytes[program_header_offset + 8..program_header_offset + 16]
        .copy_from_slice(&(interpreter_offset as u64).to_le_bytes());
    bytes[program_header_offset + 32..program_header_offset + 40]
        .copy_from_slice(&((interpreter_bytes.len() + 1) as u64).to_le_bytes());
    bytes[program_header_offset + 40..program_header_offset + 48]
        .copy_from_slice(&((interpreter_bytes.len() + 1) as u64).to_le_bytes());
    bytes[interpreter_offset..interpreter_offset + interpreter_bytes.len()]
        .copy_from_slice(interpreter_bytes);
    fs::write(path, bytes).unwrap();
}

fn write_elf64_x86_64_with_build_id_note(path: &std::path::Path, build_id: &[u8]) {
    let program_header_offset = 0x40usize;
    let note_offset = 0x100usize;
    let note = elf_build_id_note_bytes(build_id);

    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes.resize(note_offset + note.len(), 0);
    bytes[32..40].copy_from_slice(&(program_header_offset as u64).to_le_bytes());
    bytes[54..56].copy_from_slice(&(56u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&(1u16).to_le_bytes());

    bytes[program_header_offset..program_header_offset + 4].copy_from_slice(&(4u32).to_le_bytes());
    bytes[program_header_offset + 4..program_header_offset + 8]
        .copy_from_slice(&(4u32).to_le_bytes());
    bytes[program_header_offset + 8..program_header_offset + 16]
        .copy_from_slice(&(note_offset as u64).to_le_bytes());
    bytes[program_header_offset + 16..program_header_offset + 24]
        .copy_from_slice(&(0x400100u64).to_le_bytes());
    bytes[program_header_offset + 32..program_header_offset + 40]
        .copy_from_slice(&(note.len() as u64).to_le_bytes());
    bytes[program_header_offset + 40..program_header_offset + 48]
        .copy_from_slice(&(note.len() as u64).to_le_bytes());
    bytes[note_offset..note_offset + note.len()].copy_from_slice(&note);
    fs::write(path, bytes).unwrap();
}

fn write_elf64_x86_64_with_build_id_section(path: &std::path::Path, build_id: &[u8]) {
    let note_offset = 0x100usize;
    let section_header_offset = 0x180usize;
    let shstrtab_offset = section_header_offset + (3 * 64);
    let note = elf_build_id_note_bytes(build_id);
    let mut section_names = vec![0u8];
    let note_name = push_elf_string(&mut section_names, ".note.gnu.build-id") as u32;
    let shstrtab_name = push_elf_string(&mut section_names, ".shstrtab") as u32;

    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes.resize(shstrtab_offset + section_names.len(), 0);
    bytes[40..48].copy_from_slice(&(section_header_offset as u64).to_le_bytes());
    bytes[58..60].copy_from_slice(&(64u16).to_le_bytes());
    bytes[60..62].copy_from_slice(&(3u16).to_le_bytes());
    bytes[62..64].copy_from_slice(&(2u16).to_le_bytes());

    bytes[note_offset..note_offset + note.len()].copy_from_slice(&note);
    write_elf64_section_header(
        &mut bytes,
        section_header_offset + 64,
        note_name,
        7,
        0x2,
        0x400100,
        note_offset as u64,
        note.len() as u64,
        0,
        0,
        4,
        0,
    );
    write_elf64_section_header(
        &mut bytes,
        section_header_offset + (2 * 64),
        shstrtab_name,
        3,
        0,
        0,
        shstrtab_offset as u64,
        section_names.len() as u64,
        0,
        0,
        1,
        0,
    );
    bytes[shstrtab_offset..shstrtab_offset + section_names.len()].copy_from_slice(&section_names);
    fs::write(path, bytes).unwrap();
}

fn elf_build_id_note_bytes(build_id: &[u8]) -> Vec<u8> {
    let mut note = Vec::new();
    note.extend_from_slice(&(4u32).to_le_bytes());
    note.extend_from_slice(&(build_id.len() as u32).to_le_bytes());
    note.extend_from_slice(&(3u32).to_le_bytes());
    note.extend_from_slice(b"GNU\0");
    note.extend_from_slice(build_id);
    while note.len() % 4 != 0 {
        note.push(0);
    }
    note
}

fn write_elf64_x86_64_with_dynamic_dependencies(
    path: &std::path::Path,
    needed: &str,
    rpath: &str,
    runpath: &str,
) {
    let program_header_offset = 0x40usize;
    let dynamic_offset = 0x200usize;
    let strtab_offset = 0x300usize;
    let load_virtual_address = 0x400000u64;
    let strtab_virtual_address = load_virtual_address + ((strtab_offset - dynamic_offset) as u64);
    let mut strings = vec![0u8];
    let needed_offset = push_elf_string(&mut strings, needed);
    let rpath_offset = push_elf_string(&mut strings, rpath);
    let runpath_offset = push_elf_string(&mut strings, runpath);
    let dynamic_entries = [
        (5u64, strtab_virtual_address),
        (10u64, strings.len() as u64),
        (1u64, needed_offset as u64),
        (15u64, rpath_offset as u64),
        (29u64, runpath_offset as u64),
        (0u64, 0u64),
    ];
    let dynamic_size = dynamic_entries.len() * 16;

    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes.resize(strtab_offset + strings.len(), 0);
    bytes[32..40].copy_from_slice(&(program_header_offset as u64).to_le_bytes());
    bytes[54..56].copy_from_slice(&(56u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&(2u16).to_le_bytes());

    bytes[program_header_offset..program_header_offset + 4].copy_from_slice(&(1u32).to_le_bytes());
    bytes[program_header_offset + 4..program_header_offset + 8]
        .copy_from_slice(&(4u32).to_le_bytes());
    bytes[program_header_offset + 8..program_header_offset + 16]
        .copy_from_slice(&(dynamic_offset as u64).to_le_bytes());
    bytes[program_header_offset + 16..program_header_offset + 24]
        .copy_from_slice(&load_virtual_address.to_le_bytes());
    bytes[program_header_offset + 32..program_header_offset + 40]
        .copy_from_slice(&((strtab_offset + strings.len() - dynamic_offset) as u64).to_le_bytes());
    bytes[program_header_offset + 40..program_header_offset + 48]
        .copy_from_slice(&((strtab_offset + strings.len() - dynamic_offset) as u64).to_le_bytes());

    let dynamic_header = program_header_offset + 56;
    bytes[dynamic_header..dynamic_header + 4].copy_from_slice(&(2u32).to_le_bytes());
    bytes[dynamic_header + 4..dynamic_header + 8].copy_from_slice(&(4u32).to_le_bytes());
    bytes[dynamic_header + 8..dynamic_header + 16]
        .copy_from_slice(&(dynamic_offset as u64).to_le_bytes());
    bytes[dynamic_header + 16..dynamic_header + 24]
        .copy_from_slice(&load_virtual_address.to_le_bytes());
    bytes[dynamic_header + 32..dynamic_header + 40]
        .copy_from_slice(&(dynamic_size as u64).to_le_bytes());
    bytes[dynamic_header + 40..dynamic_header + 48]
        .copy_from_slice(&(dynamic_size as u64).to_le_bytes());

    for (index, (tag, value)) in dynamic_entries.iter().enumerate() {
        let offset = dynamic_offset + (index * 16);
        bytes[offset..offset + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
    }
    bytes[strtab_offset..strtab_offset + strings.len()].copy_from_slice(&strings);
    fs::write(path, bytes).unwrap();
}

fn push_elf_string(strings: &mut Vec<u8>, value: &str) -> usize {
    let offset = strings.len();
    strings.extend_from_slice(value.as_bytes());
    strings.push(0);
    offset
}

fn write_elf64_x86_64_with_dynsym_symbols(path: &std::path::Path, imported: &str, exported: &str) {
    let section_header_offset = 0x100usize;
    let dynstr_offset = 0x300usize;
    let dynsym_offset = 0x340usize;
    let shstrtab_offset = 0x3c0usize;
    let text_offset = 0x400usize;
    let mut section_names = vec![0u8];
    let text_name = push_elf_string(&mut section_names, ".text") as u32;
    let dynstr_name = push_elf_string(&mut section_names, ".dynstr") as u32;
    let dynsym_name = push_elf_string(&mut section_names, ".dynsym") as u32;
    let shstrtab_name = push_elf_string(&mut section_names, ".shstrtab") as u32;

    let mut dynstr = vec![0u8];
    let imported_name = push_elf_string(&mut dynstr, imported) as u32;
    let exported_name = push_elf_string(&mut dynstr, exported) as u32;
    let dynsym_size = 3usize * 24;

    let mut bytes = elf64_x86_64_with_markers(&[]);
    bytes.resize(text_offset + 0x20, 0);
    bytes[40..48].copy_from_slice(&(section_header_offset as u64).to_le_bytes());
    bytes[58..60].copy_from_slice(&(64u16).to_le_bytes());
    bytes[60..62].copy_from_slice(&(5u16).to_le_bytes());
    bytes[62..64].copy_from_slice(&(4u16).to_le_bytes());

    write_elf64_section_header(
        &mut bytes,
        section_header_offset + 64,
        text_name,
        1,
        0x6,
        0x401000,
        text_offset as u64,
        0x20,
        0,
        0,
        16,
        0,
    );
    write_elf64_section_header(
        &mut bytes,
        section_header_offset + (2 * 64),
        dynstr_name,
        3,
        0x2,
        0,
        dynstr_offset as u64,
        dynstr.len() as u64,
        0,
        0,
        1,
        0,
    );
    write_elf64_section_header(
        &mut bytes,
        section_header_offset + (3 * 64),
        dynsym_name,
        11,
        0x2,
        0,
        dynsym_offset as u64,
        dynsym_size as u64,
        2,
        1,
        8,
        24,
    );
    write_elf64_section_header(
        &mut bytes,
        section_header_offset + (4 * 64),
        shstrtab_name,
        3,
        0,
        0,
        shstrtab_offset as u64,
        section_names.len() as u64,
        0,
        0,
        1,
        0,
    );

    bytes[dynstr_offset..dynstr_offset + dynstr.len()].copy_from_slice(&dynstr);
    bytes[shstrtab_offset..shstrtab_offset + section_names.len()].copy_from_slice(&section_names);
    let import_entry = dynsym_offset + 24;
    bytes[import_entry..import_entry + 4].copy_from_slice(&imported_name.to_le_bytes());
    bytes[import_entry + 4] = 0x12;
    bytes[import_entry + 6..import_entry + 8].copy_from_slice(&(0u16).to_le_bytes());
    let export_entry = dynsym_offset + 48;
    bytes[export_entry..export_entry + 4].copy_from_slice(&exported_name.to_le_bytes());
    bytes[export_entry + 4] = 0x12;
    bytes[export_entry + 6..export_entry + 8].copy_from_slice(&(1u16).to_le_bytes());
    bytes[export_entry + 8..export_entry + 16].copy_from_slice(&(0x401000u64).to_le_bytes());
    bytes[export_entry + 16..export_entry + 24].copy_from_slice(&(16u64).to_le_bytes());
    fs::write(path, bytes).unwrap();
}

#[allow(clippy::too_many_arguments)]
fn write_elf64_section_header(
    bytes: &mut [u8],
    offset: usize,
    name: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    file_offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
) {
    bytes[offset..offset + 4].copy_from_slice(&name.to_le_bytes());
    bytes[offset + 4..offset + 8].copy_from_slice(&section_type.to_le_bytes());
    bytes[offset + 8..offset + 16].copy_from_slice(&flags.to_le_bytes());
    bytes[offset + 16..offset + 24].copy_from_slice(&address.to_le_bytes());
    bytes[offset + 24..offset + 32].copy_from_slice(&file_offset.to_le_bytes());
    bytes[offset + 32..offset + 40].copy_from_slice(&size.to_le_bytes());
    bytes[offset + 40..offset + 44].copy_from_slice(&link.to_le_bytes());
    bytes[offset + 44..offset + 48].copy_from_slice(&info.to_le_bytes());
    bytes[offset + 48..offset + 56].copy_from_slice(&addralign.to_le_bytes());
    bytes[offset + 56..offset + 64].copy_from_slice(&entsize.to_le_bytes());
}

fn elf64_x86_64_with_markers(markers: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // 64-bit
    bytes[5] = 1; // little endian
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    for marker in markers {
        bytes.extend_from_slice(marker);
        bytes.push(0);
    }
    bytes
}

fn write_pe_x86_64(path: &std::path::Path) {
    write_pe_x86_64_with_markers(path, &[]);
}

fn write_pe_x86_64_with_markers(path: &std::path::Path, markers: &[&[u8]]) {
    let mut bytes = vec![0u8; 0x100];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes());
    for marker in markers {
        bytes.extend_from_slice(marker);
        bytes.push(0);
    }
    fs::write(path, bytes).unwrap();
}

fn write_pe_x86_64_with_dll_characteristics(path: &std::path::Path, dll_characteristics: u16) {
    // e_lfanew = 0x80; PE signature + COFF header + optional header follow.
    let mut bytes = vec![0u8; 0x100];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes());
    // COFF SizeOfOptionalHeader (pe_offset + 20) — must span DllCharacteristics.
    bytes[0x94..0x96].copy_from_slice(&(0xF0u16).to_le_bytes());
    // Optional header magic PE32+ at pe_offset + 24.
    bytes[0x98..0x9a].copy_from_slice(&(0x20bu16).to_le_bytes());
    // DllCharacteristics at pe_offset + 24 + 0x46.
    bytes[0xDE..0xE0].copy_from_slice(&dll_characteristics.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_pe_x86_64_with_layout(
    path: &std::path::Path,
    section_count: u16,
    entrypoint_rva: u32,
    image_base: u64,
) {
    let mut bytes = vec![0u8; 0x100];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&section_count.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&(0x20bu16).to_le_bytes());
    bytes[0xa8..0xac].copy_from_slice(&entrypoint_rva.to_le_bytes());
    bytes[0xb0..0xb8].copy_from_slice(&image_base.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_pe_x86_64_with_sections(path: &std::path::Path, section_names: &[&str]) {
    let optional_header_size = 0xf0u16;
    let pe_offset = 0x80usize;
    let section_table_offset = pe_offset + 24 + optional_header_size as usize;
    let mut bytes = vec![0u8; section_table_offset + (section_names.len() * 40)];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    bytes[pe_offset + 4..pe_offset + 6].copy_from_slice(&(0x8664u16).to_le_bytes());
    bytes[pe_offset + 6..pe_offset + 8]
        .copy_from_slice(&(section_names.len() as u16).to_le_bytes());
    bytes[pe_offset + 20..pe_offset + 22].copy_from_slice(&optional_header_size.to_le_bytes());
    bytes[pe_offset + 24..pe_offset + 26].copy_from_slice(&(0x20bu16).to_le_bytes());
    for (index, name) in section_names.iter().enumerate() {
        let offset = section_table_offset + (index * 40);
        let raw_name = name.as_bytes();
        let copy_len = raw_name.len().min(8);
        bytes[offset..offset + copy_len].copy_from_slice(&raw_name[..copy_len]);
        bytes[offset + 8..offset + 12].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[offset + 12..offset + 16]
            .copy_from_slice(&(0x1000 + (index as u32 * 0x1000)).to_le_bytes());
        bytes[offset + 16..offset + 20].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[offset + 20..offset + 24]
            .copy_from_slice(&(0x400 + (index as u32 * 0x200)).to_le_bytes());
        bytes[offset + 36..offset + 40].copy_from_slice(&(0x40000040u32).to_le_bytes());
    }
    fs::write(path, bytes).unwrap();
}

fn write_pe_x86_64_with_import_directory(
    path: &std::path::Path,
    library: &str,
    imported_symbol: &str,
) {
    let pe_offset = 0x80usize;
    let optional_header_size = 0xf0u16;
    let section_table_offset = pe_offset + 24 + optional_header_size as usize;
    let section_raw_offset = 0x200usize;
    let section_rva = 0x1000u32;
    let import_descriptor_rva = section_rva;
    let library_name_rva = section_rva + 0x40;
    let import_lookup_rva = section_rva + 0x80;
    let import_address_rva = section_rva + 0x90;
    let hint_name_rva = section_rva + 0xa0;
    let mut bytes = vec![0u8; section_raw_offset + 0x200];

    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    bytes[pe_offset + 4..pe_offset + 6].copy_from_slice(&(0x8664u16).to_le_bytes());
    bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&(1u16).to_le_bytes());
    bytes[pe_offset + 20..pe_offset + 22].copy_from_slice(&optional_header_size.to_le_bytes());

    let optional_header = pe_offset + 24;
    bytes[optional_header..optional_header + 2].copy_from_slice(&(0x20bu16).to_le_bytes());
    bytes[optional_header + 0x78..optional_header + 0x7c]
        .copy_from_slice(&import_descriptor_rva.to_le_bytes());
    bytes[optional_header + 0x7c..optional_header + 0x80].copy_from_slice(&(0x28u32).to_le_bytes());

    bytes[section_table_offset..section_table_offset + 6].copy_from_slice(b".idata");
    bytes[section_table_offset + 8..section_table_offset + 12]
        .copy_from_slice(&(0x200u32).to_le_bytes());
    bytes[section_table_offset + 12..section_table_offset + 16]
        .copy_from_slice(&section_rva.to_le_bytes());
    bytes[section_table_offset + 16..section_table_offset + 20]
        .copy_from_slice(&(0x200u32).to_le_bytes());
    bytes[section_table_offset + 20..section_table_offset + 24]
        .copy_from_slice(&(section_raw_offset as u32).to_le_bytes());
    bytes[section_table_offset + 36..section_table_offset + 40]
        .copy_from_slice(&(0x40000040u32).to_le_bytes());

    bytes[section_raw_offset + 12..section_raw_offset + 16]
        .copy_from_slice(&library_name_rva.to_le_bytes());
    bytes[section_raw_offset..section_raw_offset + 4]
        .copy_from_slice(&import_lookup_rva.to_le_bytes());
    bytes[section_raw_offset + 16..section_raw_offset + 20]
        .copy_from_slice(&import_address_rva.to_le_bytes());
    let name_offset = section_raw_offset + 0x40;
    bytes[name_offset..name_offset + library.len()].copy_from_slice(library.as_bytes());
    let lookup_offset = section_raw_offset + 0x80;
    bytes[lookup_offset..lookup_offset + 8].copy_from_slice(&(hint_name_rva as u64).to_le_bytes());
    let address_offset = section_raw_offset + 0x90;
    bytes[address_offset..address_offset + 8]
        .copy_from_slice(&(hint_name_rva as u64).to_le_bytes());
    let hint_name_offset = section_raw_offset + 0xa0;
    bytes[hint_name_offset..hint_name_offset + 2].copy_from_slice(&(0u16).to_le_bytes());
    bytes[hint_name_offset + 2..hint_name_offset + 2 + imported_symbol.len()]
        .copy_from_slice(imported_symbol.as_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_pe_x86_64_with_export_directory(path: &std::path::Path, exported_symbol: &str) {
    let pe_offset = 0x80usize;
    let optional_header_size = 0xf0u16;
    let section_table_offset = pe_offset + 24 + optional_header_size as usize;
    let section_raw_offset = 0x200usize;
    let section_rva = 0x1000u32;
    let export_directory_rva = section_rva;
    let dll_name_rva = section_rva + 0x40;
    let function_table_rva = section_rva + 0x60;
    let name_table_rva = section_rva + 0x70;
    let ordinal_table_rva = section_rva + 0x80;
    let symbol_name_rva = section_rva + 0x90;
    let mut bytes = vec![0u8; section_raw_offset + 0x200];

    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    bytes[pe_offset + 4..pe_offset + 6].copy_from_slice(&(0x8664u16).to_le_bytes());
    bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&(1u16).to_le_bytes());
    bytes[pe_offset + 20..pe_offset + 22].copy_from_slice(&optional_header_size.to_le_bytes());

    let optional_header = pe_offset + 24;
    bytes[optional_header..optional_header + 2].copy_from_slice(&(0x20bu16).to_le_bytes());
    bytes[optional_header + 0x70..optional_header + 0x74]
        .copy_from_slice(&export_directory_rva.to_le_bytes());
    bytes[optional_header + 0x74..optional_header + 0x78].copy_from_slice(&(0x40u32).to_le_bytes());

    bytes[section_table_offset..section_table_offset + 6].copy_from_slice(b".edata");
    bytes[section_table_offset + 8..section_table_offset + 12]
        .copy_from_slice(&(0x200u32).to_le_bytes());
    bytes[section_table_offset + 12..section_table_offset + 16]
        .copy_from_slice(&section_rva.to_le_bytes());
    bytes[section_table_offset + 16..section_table_offset + 20]
        .copy_from_slice(&(0x200u32).to_le_bytes());
    bytes[section_table_offset + 20..section_table_offset + 24]
        .copy_from_slice(&(section_raw_offset as u32).to_le_bytes());
    bytes[section_table_offset + 36..section_table_offset + 40]
        .copy_from_slice(&(0x40000040u32).to_le_bytes());

    bytes[section_raw_offset + 12..section_raw_offset + 16]
        .copy_from_slice(&dll_name_rva.to_le_bytes());
    bytes[section_raw_offset + 16..section_raw_offset + 20].copy_from_slice(&(1u32).to_le_bytes());
    bytes[section_raw_offset + 20..section_raw_offset + 24].copy_from_slice(&(1u32).to_le_bytes());
    bytes[section_raw_offset + 24..section_raw_offset + 28].copy_from_slice(&(1u32).to_le_bytes());
    bytes[section_raw_offset + 28..section_raw_offset + 32]
        .copy_from_slice(&function_table_rva.to_le_bytes());
    bytes[section_raw_offset + 32..section_raw_offset + 36]
        .copy_from_slice(&name_table_rva.to_le_bytes());
    bytes[section_raw_offset + 36..section_raw_offset + 40]
        .copy_from_slice(&ordinal_table_rva.to_le_bytes());
    bytes[section_raw_offset + 0x40..section_raw_offset + 0x4b].copy_from_slice(b"service.dll");
    bytes[section_raw_offset + 0x60..section_raw_offset + 0x64]
        .copy_from_slice(&(section_rva + 0x120).to_le_bytes());
    bytes[section_raw_offset + 0x70..section_raw_offset + 0x74]
        .copy_from_slice(&symbol_name_rva.to_le_bytes());
    bytes[section_raw_offset + 0x80..section_raw_offset + 0x82]
        .copy_from_slice(&(0u16).to_le_bytes());
    bytes[section_raw_offset + 0x90..section_raw_offset + 0x90 + exported_symbol.len()]
        .copy_from_slice(exported_symbol.as_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_macho64_x86_64(path: &std::path::Path) {
    write_macho64_x86_64_with_markers(path, &[]);
}

fn write_macho64_x86_64_with_markers(path: &std::path::Path, markers: &[&[u8]]) {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
    for marker in markers {
        bytes.extend_from_slice(marker);
        bytes.push(0);
    }
    fs::write(path, bytes).unwrap();
}

fn write_macho64_x86_64_with_hardening(path: &std::path::Path, flags: u32, code_signature: bool) {
    let command_offset = 32usize;
    let command_size = 16usize; // LC_CODE_SIGNATURE: cmd, cmdsize, dataoff, datasize.
    let total = if code_signature {
        command_offset + command_size
    } else {
        command_offset
    };
    let mut bytes = vec![0u8; total];
    bytes[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&flags.to_le_bytes());
    if code_signature {
        bytes[16..20].copy_from_slice(&(1u32).to_le_bytes());
        bytes[20..24].copy_from_slice(&(command_size as u32).to_le_bytes());
        bytes[command_offset..command_offset + 4].copy_from_slice(&(0x1du32).to_le_bytes());
        bytes[command_offset + 4..command_offset + 8]
            .copy_from_slice(&(command_size as u32).to_le_bytes());
    }
    fs::write(path, bytes).unwrap();
}

fn write_macho64_x86_64_with_layout(
    path: &std::path::Path,
    load_command_count: u32,
    load_command_bytes: u32,
) {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&load_command_count.to_le_bytes());
    bytes[20..24].copy_from_slice(&load_command_bytes.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_macho64_x86_64_with_segment(path: &std::path::Path, segment_name: &str) {
    let mut bytes = vec![0u8; 32 + 72];
    bytes[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&(1u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&(72u32).to_le_bytes());
    bytes[32..36].copy_from_slice(&(0x19u32).to_le_bytes());
    bytes[36..40].copy_from_slice(&(72u32).to_le_bytes());
    let raw_name = segment_name.as_bytes();
    let copy_len = raw_name.len().min(16);
    bytes[40..40 + copy_len].copy_from_slice(&raw_name[..copy_len]);
    bytes[56..64].copy_from_slice(&(0x100000000u64).to_le_bytes());
    bytes[64..72].copy_from_slice(&(0x1000u64).to_le_bytes());
    bytes[72..80].copy_from_slice(&(0u64).to_le_bytes());
    bytes[80..88].copy_from_slice(&(0x1000u64).to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_macho64_x86_64_with_dylib_command(path: &std::path::Path, library: &str) {
    let command_offset = 32usize;
    let name_offset = 24u32;
    let command_size = (name_offset as usize + library.len() + 1 + 7) & !7;
    let mut bytes = vec![0u8; command_offset + command_size];
    bytes[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&(1u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&(command_size as u32).to_le_bytes());
    bytes[command_offset..command_offset + 4].copy_from_slice(&(0xcu32).to_le_bytes());
    bytes[command_offset + 4..command_offset + 8]
        .copy_from_slice(&(command_size as u32).to_le_bytes());
    bytes[command_offset + 8..command_offset + 12].copy_from_slice(&name_offset.to_le_bytes());
    let raw_name_offset = command_offset + name_offset as usize;
    bytes[raw_name_offset..raw_name_offset + library.len()].copy_from_slice(library.as_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_macho64_x86_64_with_symtab_symbols(
    path: &std::path::Path,
    imported: &str,
    exported: &str,
) {
    let command_offset = 32usize;
    let command_size = 24usize;
    let symbol_offset = 0x100usize;
    let string_offset = 0x160usize;
    let mut strings = vec![0u8];
    let imported_offset = push_elf_string(&mut strings, imported) as u32;
    let exported_offset = push_elf_string(&mut strings, exported) as u32;
    let mut bytes = vec![0u8; string_offset + strings.len()];
    bytes[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&(1u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&(command_size as u32).to_le_bytes());
    bytes[command_offset..command_offset + 4].copy_from_slice(&(0x2u32).to_le_bytes());
    bytes[command_offset + 4..command_offset + 8]
        .copy_from_slice(&(command_size as u32).to_le_bytes());
    bytes[command_offset + 8..command_offset + 12]
        .copy_from_slice(&(symbol_offset as u32).to_le_bytes());
    bytes[command_offset + 12..command_offset + 16].copy_from_slice(&(2u32).to_le_bytes());
    bytes[command_offset + 16..command_offset + 20]
        .copy_from_slice(&(string_offset as u32).to_le_bytes());
    bytes[command_offset + 20..command_offset + 24]
        .copy_from_slice(&(strings.len() as u32).to_le_bytes());

    bytes[symbol_offset..symbol_offset + 4].copy_from_slice(&imported_offset.to_le_bytes());
    bytes[symbol_offset + 4] = 0x01;
    let export_entry = symbol_offset + 16;
    bytes[export_entry..export_entry + 4].copy_from_slice(&exported_offset.to_le_bytes());
    bytes[export_entry + 4] = 0x0f;
    bytes[export_entry + 5] = 1;
    bytes[export_entry + 8..export_entry + 16].copy_from_slice(&(0x1000u64).to_le_bytes());
    bytes[string_offset..string_offset + strings.len()].copy_from_slice(&strings);
    fs::write(path, bytes).unwrap();
}

fn write_ar_archive(path: &std::path::Path, members: &[(&str, &[u8])]) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"!<arch>\n");
    for (name, data) in members {
        let identifier = format!("{:<16}", format!("{name}/"));
        let header = format!(
            "{}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            identifier,
            0,
            0,
            0,
            0o100644,
            data.len()
        );
        assert_eq!(header.len(), 60);
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(data);
        if data.len() % 2 != 0 {
            bytes.push(b'\n');
        }
    }
    fs::write(path, bytes).unwrap();
}

fn govfuzz_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_govfuzz"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-binary-scan-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
