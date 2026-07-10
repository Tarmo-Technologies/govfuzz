// SPDX-License-Identifier: Apache-2.0

//! Compile-time registry of bug-oracle plugins. Pairs with
//! `oracle_manifest::ORACLE_MANIFEST` (cli-safe POD). The unit test
//! `registry_and_manifest_match` keeps the two in sync.

use crate::oracle_sdk::{BugOracle, OracleCategory, OracleEvidence, OracleHit, OracleRuntimeEvent};

pub struct PathTraversalAda;

impl BugOracle for PathTraversalAda {
    fn name(&self) -> &'static str {
        "path-traversal-ada"
    }
    fn rule_id(&self) -> &'static str {
        "GF-101"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "Ada.Directories.Open",
            "Ada.Text_IO.Open",
            "Ada.Streams.Stream_IO.Open",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect caller-controlled paths containing '..' reaching Ada filesystem APIs"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::FilePath { api, path } = event else {
            return None;
        };
        if !contains_parent_directory_component(path) {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "filesystem path contains a parent-directory component",
            vec![OracleEvidence::new("path", path)],
        ))
    }
}

pub struct SqlInjectionAda;

impl BugOracle for SqlInjectionAda {
    fn name(&self) -> &'static str {
        "sql-injection-ada"
    }
    fn rule_id(&self) -> &'static str {
        "GF-302"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "GNATColl.SQL.Execute",
            "GNATColl.SQL.Exec.Prepare",
            "Interfaces.C.Strings.New_String",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect test-case-controlled bytes reaching Ada SQL execution APIs without parameter binding"
    }
}

pub struct SsrfAda;

impl BugOracle for SsrfAda {
    fn name(&self) -> &'static str {
        "ssrf-ada"
    }
    fn rule_id(&self) -> &'static str {
        "GF-303"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "GNAT.Sockets.Connect_Socket",
            "AWS.Client.Get",
            "AWS.Client.Post",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect controlled URL/hostname reaching Ada network-egress APIs"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::NetworkAddress { api, address } = event else {
            return None;
        };
        if !looks_like_network_destination(address) {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "network egress destination observed during fuzz execution",
            vec![OracleEvidence::new("address", address)],
        ))
    }
}

pub struct CommandInjectionAda;

impl BugOracle for CommandInjectionAda {
    fn name(&self) -> &'static str {
        "command-injection-ada"
    }
    fn rule_id(&self) -> &'static str {
        "GF-304"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "GNAT.OS_Lib.Spawn",
            "GNAT.OS_Lib.Non_Blocking_Spawn",
            "Ada.Command_Line.Argument",
            "system",
            "popen",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect controlled argv/cmdline reaching Ada process-spawn APIs without quoting"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::Command { api, command } = event else {
            return None;
        };
        if !looks_like_shell_injection(command) {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "shell metacharacters observed in a runtime command string",
            vec![OracleEvidence::new("command", command)],
        ))
    }
}

pub struct SensitiveEnvAda;

impl BugOracle for SensitiveEnvAda {
    fn name(&self) -> &'static str {
        "sensitive-env-ada"
    }
    fn rule_id(&self) -> &'static str {
        "GF-305"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "Ada.Environment_Variables.Value",
            "GNAT.OS_Lib.Getenv",
            "Interfaces.C.getenv",
            "secure_getenv",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect runtime reads of secret-like environment variable names"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::EnvVar { api, name } = event else {
            return None;
        };
        if !is_sensitive_env_name(name) {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "secret-like environment variable read observed during fuzz execution",
            vec![OracleEvidence::new("env_var", name)],
        ))
    }
}

pub struct ResourceLeakAda;

impl BugOracle for ResourceLeakAda {
    fn name(&self) -> &'static str {
        "resource-leak-ada"
    }
    fn rule_id(&self) -> &'static str {
        "GF-306"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "Ada.Text_IO.Open",
            "Ada.Streams.Stream_IO.Open",
            "open",
            "openat",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect resources opened during fuzz execution and not released before testcase exit"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::ResourceLeak {
            api,
            resource,
            evidence,
        } = event
        else {
            return None;
        };
        if resource.trim().is_empty() {
            return None;
        }
        let mut hit_evidence = vec![OracleEvidence::new("resource", resource)];
        hit_evidence.extend(
            evidence
                .iter()
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .map(|(key, value)| OracleEvidence::new(key.as_str(), value.as_str())),
        );
        Some(OracleHit::from_oracle(
            self,
            api,
            "resource opened during fuzz execution was not released",
            hit_evidence,
        ))
    }
}

/// Human-readable list of the dangerous permission bits set in `mode`.
fn insecure_permission_bits(mode: i64) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if mode & 0o4000 != 0 {
        parts.push("setuid");
    }
    if mode & 0o2000 != 0 {
        parts.push("setgid");
    }
    if mode & 0o0002 != 0 {
        parts.push("world-writable");
    }
    parts.join(", ")
}

pub struct InsecurePermissionsRuntime;

impl BugOracle for InsecurePermissionsRuntime {
    fn name(&self) -> &'static str {
        "insecure-permissions-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-416"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "chmod",
            "fchmod",
            "fchmodat",
            "mkdir",
            "mkdirat",
            "GNAT.OS_Lib.Set_File_Permissions",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect setuid/setgid/world-writable file or directory permissions assigned during fuzz execution"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::InsecurePermissions { api, path, mode } = event else {
            return None;
        };
        let bits = insecure_permission_bits(*mode);
        if bits.is_empty() {
            return None;
        }
        let subject = if path.is_empty() {
            "<file descriptor>"
        } else {
            path.as_str()
        };
        Some(OracleHit::from_oracle(
            self,
            api,
            "dangerous file permissions (setuid/setgid/world-writable) assigned at runtime",
            vec![
                OracleEvidence::new("path", subject),
                OracleEvidence::new("mode", format!("0o{mode:o}")),
                OracleEvidence::new("bits", bits),
            ],
        ))
    }
}

pub struct InsecureTempFileRuntime;

impl BugOracle for InsecureTempFileRuntime {
    fn name(&self) -> &'static str {
        "insecure-temp-file-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-417"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["open", "openat", "fopen", "mktemp", "tmpnam", "tempnam"]
    }
    fn describe(&self) -> &'static str {
        "Detect temporary files created in world-writable directories without O_EXCL during fuzz execution"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::InsecureTempFile { api, path } = event else {
            return None;
        };
        let dir = world_writable_tmp_dir(path)?;
        Some(OracleHit::from_oracle(
            self,
            api,
            "temporary file created in a world-writable directory without O_EXCL (symlink/temp-file race)",
            vec![
                OracleEvidence::new("path", path),
                OracleEvidence::new("directory", dir),
            ],
        ))
    }
}

pub struct ToctouRuntime;

impl BugOracle for ToctouRuntime {
    fn name(&self) -> &'static str {
        "toctou-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-418"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["access", "faccessat", "stat", "open", "openat"]
    }
    fn describe(&self) -> &'static str {
        "Detect a path checked (access/stat) then opened during fuzz execution — a time-of-check/time-of-use race"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::Toctou { api, path } = event else {
            return None;
        };
        Some(OracleHit::from_oracle(
            self,
            api,
            "path checked then opened (time-of-check/time-of-use race on the same path)",
            vec![
                OracleEvidence::new("path", path),
                OracleEvidence::new("sequence", api),
            ],
        ))
    }
}

pub struct DynamicLibraryLoadRuntime;

impl BugOracle for DynamicLibraryLoadRuntime {
    fn name(&self) -> &'static str {
        "dynamic-library-load-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-413"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["dlopen", "dlmopen", "LoadLibraryA", "LoadLibraryW"]
    }
    fn describe(&self) -> &'static str {
        "Detect runtime dynamic-library loads through relative or attacker-writable search paths"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::Library { api, library } = event else {
            return None;
        };
        let reason = dynamic_library_load_reason(library)?;
        Some(OracleHit::from_oracle(
            self,
            api,
            "runtime dynamic-library load used an unsafe search path",
            vec![
                OracleEvidence::new("library", library),
                OracleEvidence::new("reason", reason),
            ],
        ))
    }
}

pub struct FileDeletionRuntime;

impl BugOracle for FileDeletionRuntime {
    fn name(&self) -> &'static str {
        "file-deletion-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-414"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["unlink", "unlinkat", "remove"]
    }
    fn describe(&self) -> &'static str {
        "Detect runtime file deletion APIs receiving parent-directory paths"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::FileDeletion { api, path } = event else {
            return None;
        };
        if !contains_parent_directory_component(path) {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "runtime file deletion used a parent-directory path",
            vec![OracleEvidence::new("path", path)],
        ))
    }
}

pub struct NativeAssertionContract;

impl BugOracle for NativeAssertionContract {
    fn name(&self) -> &'static str {
        "native-assertion-contract"
    }
    fn rule_id(&self) -> &'static str {
        "GF-415"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["__assert_fail", "__assert_perror_fail", "assert"]
    }
    fn describe(&self) -> &'static str {
        "Detect C/C++ assertion failures promoted from runtime evidence"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::RuntimeCheck {
            api,
            language,
            exception,
            check,
            handled,
            evidence,
        } = event
        else {
            return None;
        };
        if !is_native_assertion_runtime_check(language, exception, check) {
            return None;
        }
        let mut hit_evidence = vec![
            OracleEvidence::new("exception", exception),
            OracleEvidence::new("check", check),
            OracleEvidence::new("handled", handled.to_string()),
        ];
        hit_evidence.extend(
            evidence
                .iter()
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .map(|(key, value)| OracleEvidence::new(key.as_str(), value.as_str())),
        );
        Some(OracleHit::from_oracle(
            self,
            api,
            "native assertion contract failed during fuzz execution",
            hit_evidence,
        ))
    }
}

pub struct DifferentialOutputRuntime;

impl BugOracle for DifferentialOutputRuntime {
    fn name(&self) -> &'static str {
        "differential-output-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-301"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["govfuzz differential"]
    }
    fn describe(&self) -> &'static str {
        "Detect output or exit-status divergence between two implementations on the same input"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::Differential {
            api,
            stdout_equal,
            exit_equal,
            timed_out_a,
            timed_out_b,
            evidence,
        } = event
        else {
            return None;
        };
        if *stdout_equal && *exit_equal {
            return None;
        }

        let mut hit_evidence = vec![
            OracleEvidence::new("stdout_equal", stdout_equal.to_string()),
            OracleEvidence::new("exit_equal", exit_equal.to_string()),
            OracleEvidence::new("timed_out_a", timed_out_a.to_string()),
            OracleEvidence::new("timed_out_b", timed_out_b.to_string()),
        ];
        hit_evidence.extend(
            evidence
                .iter()
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .map(|(key, value)| OracleEvidence::new(key.as_str(), value.as_str())),
        );

        Some(OracleHit::from_oracle(
            self,
            api,
            "two implementations diverged on the same input",
            hit_evidence,
        ))
    }
}

pub struct MetamorphicRelationRuntime;

impl BugOracle for MetamorphicRelationRuntime {
    fn name(&self) -> &'static str {
        "metamorphic-relation-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-307"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["govfuzz differential --metamorphic-transform"]
    }
    fn describe(&self) -> &'static str {
        "Detect violated metamorphic relations between an input and its transformed variant"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::Metamorphic {
            api,
            relation,
            stdout_equal,
            exit_equal,
            timed_out_original,
            timed_out_transformed,
            evidence,
        } = event
        else {
            return None;
        };
        if *stdout_equal && *exit_equal {
            return None;
        }

        let mut hit_evidence = vec![
            OracleEvidence::new("relation", relation),
            OracleEvidence::new("stdout_equal", stdout_equal.to_string()),
            OracleEvidence::new("exit_equal", exit_equal.to_string()),
            OracleEvidence::new("timed_out_original", timed_out_original.to_string()),
            OracleEvidence::new("timed_out_transformed", timed_out_transformed.to_string()),
        ];
        hit_evidence.extend(
            evidence
                .iter()
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .map(|(key, value)| OracleEvidence::new(key.as_str(), value.as_str())),
        );

        Some(OracleHit::from_oracle(
            self,
            api,
            "metamorphic relation was violated by a transformed input",
            hit_evidence,
        ))
    }
}

pub struct FormatStringRuntime;

impl BugOracle for FormatStringRuntime {
    fn name(&self) -> &'static str {
        "format-string-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-408"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["printf", "fprintf", "sprintf", "snprintf", "dprintf"]
    }
    fn describe(&self) -> &'static str {
        "Detect fuzz-controlled printf-style format strings reaching runtime formatting APIs"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::FormatString {
            api,
            format,
            controlled,
        } = event
        else {
            return None;
        };
        if !controlled || !contains_printf_conversion(format) {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "fuzz-controlled printf-style format string reached a formatting API",
            vec![
                OracleEvidence::new("format", format),
                OracleEvidence::new("controlled", "true"),
                // Source→sink taint path (#422): the format argument is the
                // fuzz input itself, reaching the printf-family sink unsanitized.
                OracleEvidence::new("taint_path", format!("fuzz_input → {api}(format)")),
            ],
        ))
    }
}

/// Runtime confirmation of the static `path-controlled-file-open`
/// candidate (GF-405, #422). Fires when an `open`/`openat` path argument
/// was derived from the current fuzz input (byte-origin taint recorded by
/// the runtrace shim) and reaches the sink unsanitized. Distinct from the
/// `..`-pattern path-traversal heuristic (GF-101, `PathTraversalAda`):
/// this one is gated on dynamic taint, so a sanitized variant (basename,
/// canonicalization, allow-list) severs the byte-origin match and reports
/// nothing.
pub struct PathControlledOpenRuntime;

impl BugOracle for PathControlledOpenRuntime {
    fn name(&self) -> &'static str {
        "path-controlled-open-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-405"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["open", "openat", "fopen"]
    }
    fn describe(&self) -> &'static str {
        "Detect fuzz-controlled paths reaching file-open APIs unsanitized during fuzz execution"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::TaintedFilePath {
            api,
            path,
            taint_offset,
        } = event
        else {
            return None;
        };
        if path.is_empty() {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "fuzz-controlled path reached a file-open API during fuzz execution",
            vec![
                OracleEvidence::new("path", path),
                OracleEvidence::new("controlled", "true"),
                // Source→sink taint path (#422): bytes at this input offset
                // flowed into the open() path argument unsanitized.
                OracleEvidence::new(
                    "taint_path",
                    format!("fuzz_input[{taint_offset}..] → {api}(path)"),
                ),
            ],
        ))
    }
}

/// Runtime confirmation that a fuzz-controlled command string reached a
/// shell-execution API (GF-431, #422). Fires when a contiguous run of the
/// argument passed to `system`/`popen` was derived from the current fuzz
/// input (byte-origin taint recorded by the runtrace shim) and the exact
/// command was never executed without that taint. `system`/`popen` pass
/// their whole argument to `/bin/sh -c`, so any attacker-controlled span is
/// shell-interpreted — this is OS command injection by construction.
/// Distinct from the shell-metacharacter heuristic (GF-304,
/// `CommandInjectionAda`): this one is gated on dynamic taint, so a
/// hardcoded command with metacharacters (or a sanitized/allow-listed
/// argument that severs the byte-origin match) reports nothing.
pub struct CommandInjectionRuntime;

impl BugOracle for CommandInjectionRuntime {
    fn name(&self) -> &'static str {
        "command-controlled-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-431"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["system", "popen"]
    }
    fn describe(&self) -> &'static str {
        "Detect fuzz-controlled command strings reaching shell-execution APIs during fuzz execution"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::TaintedCommand {
            api,
            command,
            taint_offset,
        } = event
        else {
            return None;
        };
        if command.is_empty() {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "fuzz-controlled command reached a shell-execution API during fuzz execution",
            vec![
                OracleEvidence::new("command", command),
                OracleEvidence::new("controlled", "true"),
                // Source→sink taint path (#422): bytes at this input offset
                // flowed into the command string passed to /bin/sh -c.
                OracleEvidence::new(
                    "taint_path",
                    format!("fuzz_input[{taint_offset}..] → {api}(command)"),
                ),
            ],
        ))
    }
}

/// Runtime confirmation that a fuzz-controlled network destination reached an
/// egress API (GF-433, #422, CWE-918 SSRF). Fires when a `getaddrinfo`
/// hostname or `connect` address was derived from the current fuzz input
/// (byte-origin taint) and the exact destination was never reached without
/// that taint. Distinct from the presence heuristic (GF-303, `SsrfAda`): a
/// fixed destination the target always contacts accumulates an untainted
/// sighting and is suppressed, so only an input-chosen destination confirms.
pub struct SsrfControlledRuntime;

impl BugOracle for SsrfControlledRuntime {
    fn name(&self) -> &'static str {
        "ssrf-controlled-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-433"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["getaddrinfo", "connect", "gethostbyname"]
    }
    fn describe(&self) -> &'static str {
        "Detect fuzz-controlled network destinations reaching egress APIs during fuzz execution"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::TaintedNetworkAddress {
            api,
            address,
            taint_offset,
        } = event
        else {
            return None;
        };
        if address.is_empty() {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "fuzz-controlled network destination reached an egress API during fuzz execution",
            vec![
                OracleEvidence::new("address", address),
                OracleEvidence::new("controlled", "true"),
                OracleEvidence::new(
                    "taint_path",
                    format!("fuzz_input[{taint_offset}..] → {api}(address)"),
                ),
            ],
        ))
    }
}

/// Runtime confirmation that a fuzz-controlled library path reached a dynamic
/// loader (GF-435, #422, CWE-427). Fires when the `dlopen`/`dlmopen` filename
/// was derived from the current fuzz input (byte-origin taint) and the exact
/// library was never loaded without that taint. Loading an attacker-chosen
/// shared object is arbitrary code execution; the taint gate rules out a fixed
/// plugin path the target always loads.
pub struct LibraryLoadControlledRuntime;

impl BugOracle for LibraryLoadControlledRuntime {
    fn name(&self) -> &'static str {
        "library-load-controlled-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-435"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["dlopen", "dlmopen"]
    }
    fn describe(&self) -> &'static str {
        "Detect fuzz-controlled library paths reaching dynamic loaders during fuzz execution"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::TaintedLibrary {
            api,
            library,
            taint_offset,
        } = event
        else {
            return None;
        };
        if library.is_empty() {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "fuzz-controlled library path reached a dynamic loader during fuzz execution",
            vec![
                OracleEvidence::new("library", library),
                OracleEvidence::new("controlled", "true"),
                OracleEvidence::new(
                    "taint_path",
                    format!("fuzz_input[{taint_offset}..] → {api}(path)"),
                ),
            ],
        ))
    }
}

/// Runtime confirmation that a fuzz-controlled SQL text reached a
/// database-execution API (GF-441, #422, CWE-89). Fires when the query string
/// passed to `sqlite3_exec`/`PQexec`/`mysql_query`/... was derived from the
/// current fuzz input (byte-origin taint) and the exact query was never
/// executed without that taint. A parameterized query keeps its untrusted
/// values out of the SQL text, so the byte-origin match is severed and nothing
/// is reported — this confirms string-built (concatenated) queries only.
pub struct SqlInjectionRuntime;

impl BugOracle for SqlInjectionRuntime {
    fn name(&self) -> &'static str {
        "sql-injection-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-441"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "sqlite3_exec",
            "sqlite3_prepare_v2",
            "PQexec",
            "mysql_query",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect fuzz-controlled SQL text reaching database-execution APIs during fuzz execution"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::TaintedSqlQuery {
            api,
            query,
            taint_offset,
        } = event
        else {
            return None;
        };
        if query.is_empty() {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "fuzz-controlled SQL text reached a database-execution API during fuzz execution",
            vec![
                OracleEvidence::new("query", query),
                OracleEvidence::new("controlled", "true"),
                OracleEvidence::new(
                    "taint_path",
                    format!("fuzz_input[{taint_offset}..] → {api}(sql)"),
                ),
            ],
        ))
    }
}

/// Runtime confirmation that a fuzz-controlled path reached a destructive
/// filesystem API (GF-440, #422, CWE-73). Fires when the path passed to
/// `unlink`/`rename`/`mkdir`/`symlink`/`truncate`/... was derived from the
/// current fuzz input (byte-origin taint) and the exact path was never
/// operated on without that taint. Distinct from the file-open traversal
/// oracle (GF-405, read/open sink): this covers *mutating* operations where a
/// controlled name lets an attacker delete, move, or clobber arbitrary files.
pub struct DestructivePathControlledRuntime;

impl BugOracle for DestructivePathControlledRuntime {
    fn name(&self) -> &'static str {
        "destructive-path-controlled-runtime"
    }
    fn rule_id(&self) -> &'static str {
        "GF-440"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "unlink", "unlinkat", "remove", "rename", "renameat", "mkdir", "rmdir", "symlink",
            "link", "truncate",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect fuzz-controlled paths reaching destructive filesystem APIs during fuzz execution"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::TaintedDestructivePath {
            api,
            path,
            taint_offset,
        } = event
        else {
            return None;
        };
        if path.is_empty() {
            return None;
        }
        Some(OracleHit::from_oracle(
            self,
            api,
            "fuzz-controlled path reached a destructive filesystem API during fuzz execution",
            vec![
                OracleEvidence::new("path", path),
                OracleEvidence::new("controlled", "true"),
                OracleEvidence::new(
                    "taint_path",
                    format!("fuzz_input[{taint_offset}..] → {api}(path)"),
                ),
            ],
        ))
    }
}

pub struct AdaRuntimeConstraintCheck;

impl BugOracle for AdaRuntimeConstraintCheck {
    fn name(&self) -> &'static str {
        "ada-runtime-constraint-check"
    }
    fn rule_id(&self) -> &'static str {
        "GF-102"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "Ada runtime checks",
            "Constraint_Error",
            "range_check",
            "index_check",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect handled Ada Constraint_Error range/index checks promoted from runtime evidence"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::RuntimeCheck {
            api,
            language,
            exception,
            check,
            handled,
            evidence,
        } = event
        else {
            return None;
        };
        if !language.eq_ignore_ascii_case("ada")
            || exception != "Constraint_Error"
            || !*handled
            || !is_range_or_index_check(check)
        {
            return None;
        }
        let mut hit_evidence = vec![
            OracleEvidence::new("exception", exception),
            OracleEvidence::new("check", check),
            OracleEvidence::new("handled", handled.to_string()),
        ];
        hit_evidence.extend(
            evidence
                .iter()
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .map(|(key, value)| OracleEvidence::new(key.as_str(), value.as_str())),
        );
        Some(OracleHit::from_oracle(
            self,
            api,
            "handled Ada Constraint_Error range/index check observed during fuzz execution",
            hit_evidence,
        ))
    }
}

pub struct AdaRuntimeStorageError;

impl BugOracle for AdaRuntimeStorageError {
    fn name(&self) -> &'static str {
        "ada-runtime-storage-error"
    }
    fn rule_id(&self) -> &'static str {
        "GF-103"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["Ada runtime checks", "Storage_Error", "allocation_check"]
    }
    fn describe(&self) -> &'static str {
        "Detect handled Ada Storage_Error events promoted from runtime evidence"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::RuntimeCheck {
            api,
            language,
            exception,
            check,
            handled,
            evidence,
        } = event
        else {
            return None;
        };
        if !language.eq_ignore_ascii_case("ada") || exception != "Storage_Error" || !*handled {
            return None;
        }
        let mut hit_evidence = vec![
            OracleEvidence::new("exception", exception),
            OracleEvidence::new("check", check),
            OracleEvidence::new("handled", handled.to_string()),
        ];
        hit_evidence.extend(
            evidence
                .iter()
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .map(|(key, value)| OracleEvidence::new(key.as_str(), value.as_str())),
        );
        Some(OracleHit::from_oracle(
            self,
            api,
            "handled Ada Storage_Error observed during fuzz execution",
            hit_evidence,
        ))
    }
}

pub struct AdaRuntimeTaskingError;

impl BugOracle for AdaRuntimeTaskingError {
    fn name(&self) -> &'static str {
        "ada-runtime-tasking-error"
    }
    fn rule_id(&self) -> &'static str {
        "GF-104"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::Concurrency
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &["Ada runtime checks", "Tasking_Error", "task_activation"]
    }
    fn describe(&self) -> &'static str {
        "Detect handled Ada Tasking_Error events promoted from runtime evidence"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::RuntimeCheck {
            api,
            language,
            exception,
            check,
            handled,
            evidence,
        } = event
        else {
            return None;
        };
        if !language.eq_ignore_ascii_case("ada") || exception != "Tasking_Error" || !*handled {
            return None;
        }
        let mut hit_evidence = vec![
            OracleEvidence::new("exception", exception),
            OracleEvidence::new("check", check),
            OracleEvidence::new("handled", handled.to_string()),
        ];
        hit_evidence.extend(
            evidence
                .iter()
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .map(|(key, value)| OracleEvidence::new(key.as_str(), value.as_str())),
        );
        Some(OracleHit::from_oracle(
            self,
            api,
            "handled Ada Tasking_Error observed during fuzz execution",
            hit_evidence,
        ))
    }
}

pub struct AdaRuntimeUserException;

impl BugOracle for AdaRuntimeUserException {
    fn name(&self) -> &'static str {
        "ada-runtime-user-exception"
    }
    fn rule_id(&self) -> &'static str {
        "GF-105"
    }
    fn category(&self) -> OracleCategory {
        OracleCategory::LogicBug
    }
    fn dangerous_apis(&self) -> &'static [&'static str] {
        &[
            "Ada runtime checks",
            "user-defined exception",
            "when others",
        ]
    }
    fn describe(&self) -> &'static str {
        "Detect handled Ada user-defined exceptions promoted from runtime evidence"
    }

    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let OracleRuntimeEvent::RuntimeCheck {
            api,
            language,
            exception,
            check,
            handled,
            evidence,
        } = event
        else {
            return None;
        };
        if !language.eq_ignore_ascii_case("ada")
            || !*handled
            || exception.trim().is_empty()
            || is_known_ada_runtime_exception(exception)
        {
            return None;
        }
        let mut hit_evidence = vec![
            OracleEvidence::new("exception", exception),
            OracleEvidence::new("check", check),
            OracleEvidence::new("handled", handled.to_string()),
        ];
        hit_evidence.extend(
            evidence
                .iter()
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .map(|(key, value)| OracleEvidence::new(key.as_str(), value.as_str())),
        );
        Some(OracleHit::from_oracle(
            self,
            api,
            "handled Ada user-defined exception observed during fuzz execution",
            hit_evidence,
        ))
    }
}

pub static ORACLE_REGISTRY: &[&'static dyn BugOracle] = &[
    &PathTraversalAda,
    &SqlInjectionAda,
    &SsrfAda,
    &CommandInjectionAda,
    &SensitiveEnvAda,
    &ResourceLeakAda,
    &DynamicLibraryLoadRuntime,
    &FileDeletionRuntime,
    &NativeAssertionContract,
    &DifferentialOutputRuntime,
    &MetamorphicRelationRuntime,
    &FormatStringRuntime,
    &AdaRuntimeConstraintCheck,
    &AdaRuntimeStorageError,
    &AdaRuntimeTaskingError,
    &AdaRuntimeUserException,
    &InsecurePermissionsRuntime,
    &InsecureTempFileRuntime,
    &ToctouRuntime,
    &PathControlledOpenRuntime,
    &CommandInjectionRuntime,
    &SsrfControlledRuntime,
    &LibraryLoadControlledRuntime,
    &SqlInjectionRuntime,
    &DestructivePathControlledRuntime,
];

fn contains_parent_directory_component(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| segment == "..")
}

/// Return the world-writable temp directory prefix a path lives under, if any.
/// Used to confirm an insecure-temp-file event independently of the frontend
/// that produced it.
fn world_writable_tmp_dir(path: &str) -> Option<&'static str> {
    const DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];
    DIRS.iter()
        .find(|dir| path.starts_with(*dir))
        .map(|dir| dir.trim_end_matches('/'))
}

fn looks_like_network_destination(address: &str) -> bool {
    let address = address.trim();
    !address.is_empty() && !address.starts_with('/')
}

fn looks_like_shell_injection(command: &str) -> bool {
    let command = command.trim();
    if command.is_empty() {
        return false;
    }
    command.contains(';')
        || command.contains("&&")
        || command.contains("||")
        || command.contains("`")
        || command.contains("$(")
        || command.contains('\n')
        || command.contains('|')
        || command.contains('>')
        || command.contains('<')
}

fn is_sensitive_env_name(name: &str) -> bool {
    let upper = name.trim().to_ascii_uppercase();
    if upper.is_empty() {
        return false;
    }
    let compact: String = upper
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    [
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "TOKEN",
        "CREDENTIAL",
        "APIKEY",
        "ACCESSKEY",
        "PRIVATEKEY",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
}

fn dynamic_library_load_reason(library: &str) -> Option<&'static str> {
    let library = library.trim();
    if library.is_empty() {
        return None;
    }
    if contains_parent_directory_component(library) {
        return Some("parent-directory");
    }
    if !library.starts_with('/') && !looks_like_windows_absolute_path(library) {
        return Some("relative-or-search-path");
    }
    if starts_with_any(library, &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"]) {
        return Some("temporary-writable-directory");
    }
    if starts_with_any(
        library,
        &[
            "/lib/",
            "/lib64/",
            "/usr/lib/",
            "/usr/lib64/",
            "/usr/local/lib/",
        ],
    ) {
        return None;
    }
    Some("non-system-absolute-path")
}

fn starts_with_any(value: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| value.starts_with(prefix))
}

fn looks_like_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/')
}

fn contains_printf_conversion(format: &str) -> bool {
    let bytes = format.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        index += 1;
        if index < bytes.len() && bytes[index] == b'%' {
            index += 1;
            continue;
        }
        return true;
    }
    false
}

fn is_native_assertion_runtime_check(language: &str, exception: &str, check: &str) -> bool {
    matches!(
        language.trim().to_ascii_lowercase().as_str(),
        "c" | "cpp" | "c++"
    ) && exception.eq_ignore_ascii_case("AssertionFailure")
        && check.trim().eq_ignore_ascii_case("assertion")
}

fn is_range_or_index_check(check: &str) -> bool {
    let normalized = check
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    normalized.contains("range") || normalized.contains("index")
}

fn is_known_ada_runtime_exception(exception: &str) -> bool {
    let folded = exception.trim().to_ascii_lowercase();
    let short = folded
        .rsplit(['.', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(&folded);
    matches!(
        short,
        "constraint_error"
            | "program_error"
            | "storage_error"
            | "tasking_error"
            | "numeric_error"
            | "assertion_error"
            | "abort_signal"
            | "communication_error"
            | "data_error"
            | "device_error"
            | "end_error"
            | "layout_error"
            | "mode_error"
            | "name_error"
            | "status_error"
            | "use_error"
    )
}

#[cfg(test)]
mod tests {
    use super::ORACLE_REGISTRY;
    use crate::oracle_manifest::ORACLE_MANIFEST;

    #[test]
    fn registry_and_manifest_match() {
        assert_eq!(
            ORACLE_REGISTRY.len(),
            ORACLE_MANIFEST.len(),
            "registry and manifest length differ"
        );
        for (oracle, entry) in ORACLE_REGISTRY.iter().zip(ORACLE_MANIFEST.iter()) {
            assert_eq!(oracle.name(), entry.name);
            assert_eq!(oracle.rule_id(), entry.rule_id);
            assert_eq!(oracle.category(), entry.category);
            assert_eq!(oracle.dangerous_apis(), entry.dangerous_apis);
            assert_eq!(oracle.describe(), entry.describe);
        }
    }

    #[test]
    fn oracle_rule_ids_resolve_in_finding_rules_catalog() {
        for entry in ORACLE_MANIFEST {
            assert!(
                crate::by_id(entry.rule_id).is_some(),
                "oracle {} references unknown rule {}",
                entry.name,
                entry.rule_id
            );
        }
    }

    #[test]
    fn path_traversal_oracle_matches_parent_directory_file_event() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::PathTraversalAda
            .evaluate(&OracleRuntimeEvent::FilePath {
                api: "open".to_owned(),
                path: "../../etc/passwd".to_owned(),
            })
            .expect("parent directory paths should trip the path traversal oracle");

        assert_eq!(hit.oracle_name, "path-traversal-ada");
        assert_eq!(hit.rule_id, "GF-101");
        assert_eq!(hit.api, "open");
        assert_eq!(hit.evidence_value("path"), Some("../../etc/passwd"));
    }

    #[test]
    fn path_controlled_open_oracle_confirms_tainted_open() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::PathControlledOpenRuntime
            .evaluate(&OracleRuntimeEvent::TaintedFilePath {
                api: "open".to_owned(),
                path: "../../etc/passwd".to_owned(),
                taint_offset: 5,
            })
            .expect("a confirmed fuzz-controlled open path should confirm GF-405");

        assert_eq!(hit.oracle_name, "path-controlled-open-runtime");
        assert_eq!(hit.rule_id, "GF-405");
        assert_eq!(hit.api, "open");
        assert_eq!(hit.evidence_value("path"), Some("../../etc/passwd"));
        assert_eq!(hit.evidence_value("controlled"), Some("true"));
        assert_eq!(
            hit.evidence_value("taint_path"),
            Some("fuzz_input[5..] → open(path)")
        );
    }

    #[test]
    fn path_controlled_open_oracle_ignores_plain_file_path() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        // A raw (uncorrelated) FilePath event never confirms GF-405 — only a
        // cross-execution-confirmed TaintedFilePath does. This keeps the
        // oracle off the per-input path (no flood) and off untainted/constant
        // opens (no FP).
        assert!(super::PathControlledOpenRuntime
            .evaluate(&OracleRuntimeEvent::FilePath {
                api: "open".to_owned(),
                path: "/etc/app.conf".to_owned(),
            })
            .is_none());
    }

    #[test]
    fn command_controlled_runtime_oracle_confirms_tainted_command() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::CommandInjectionRuntime
            .evaluate(&OracleRuntimeEvent::TaintedCommand {
                api: "system".to_owned(),
                command: "convert AAAA out.png".to_owned(),
                taint_offset: 8,
            })
            .expect("a confirmed fuzz-controlled command should confirm GF-431");

        assert_eq!(hit.oracle_name, "command-controlled-runtime");
        assert_eq!(hit.rule_id, "GF-431");
        assert_eq!(hit.api, "system");
        assert_eq!(hit.evidence_value("command"), Some("convert AAAA out.png"));
        assert_eq!(hit.evidence_value("controlled"), Some("true"));
        assert_eq!(
            hit.evidence_value("taint_path"),
            Some("fuzz_input[8..] → system(command)")
        );
    }

    #[test]
    fn command_controlled_runtime_oracle_ignores_plain_command() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        // A raw (uncorrelated) Command event never confirms GF-431 — only a
        // cross-execution-confirmed TaintedCommand does. The shell-metacharacter
        // heuristic (GF-304) still handles the untainted case; this taint-gated
        // oracle stays off constant commands (no FP) and off the per-input path.
        assert!(super::CommandInjectionRuntime
            .evaluate(&OracleRuntimeEvent::Command {
                api: "system".to_owned(),
                command: "ls -la | grep foo".to_owned(),
            })
            .is_none());
    }

    #[test]
    fn ssrf_oracle_matches_network_address_event() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::SsrfAda
            .evaluate(&OracleRuntimeEvent::NetworkAddress {
                api: "connect".to_owned(),
                address: "169.254.169.254:80".to_owned(),
            })
            .expect("network egress events should trip the SSRF oracle");

        assert_eq!(hit.oracle_name, "ssrf-ada");
        assert_eq!(hit.rule_id, "GF-303");
        assert_eq!(hit.api, "connect");
        assert_eq!(hit.evidence_value("address"), Some("169.254.169.254:80"));
    }

    #[test]
    fn ssrf_oracle_ignores_unix_socket_paths() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::SsrfAda.evaluate(&OracleRuntimeEvent::NetworkAddress {
            api: "connect".to_owned(),
            address: "/var/run/acme.sock".to_owned(),
        });

        assert_eq!(hit, None);
    }

    #[test]
    fn command_injection_oracle_matches_shell_metachar_command() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::CommandInjectionAda
            .evaluate(&OracleRuntimeEvent::Command {
                api: "system".to_owned(),
                command: "echo ok; id".to_owned(),
            })
            .expect("shell metacharacters should trip the command oracle");

        assert_eq!(hit.oracle_name, "command-injection-ada");
        assert_eq!(hit.rule_id, "GF-304");
        assert_eq!(hit.api, "system");
        assert_eq!(hit.evidence_value("command"), Some("echo ok; id"));
    }

    #[test]
    fn command_injection_oracle_ignores_plain_executable_name() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::CommandInjectionAda.evaluate(&OracleRuntimeEvent::Command {
            api: "system".to_owned(),
            command: "/usr/bin/true".to_owned(),
        });

        assert_eq!(hit, None);
    }

    #[test]
    fn sensitive_env_oracle_matches_secret_environment_name() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::SensitiveEnvAda
            .evaluate(&OracleRuntimeEvent::EnvVar {
                api: "getenv".to_owned(),
                name: "AWS_SECRET_ACCESS_KEY".to_owned(),
            })
            .expect("secret-like environment names should trip the env oracle");

        assert_eq!(hit.oracle_name, "sensitive-env-ada");
        assert_eq!(hit.rule_id, "GF-305");
        assert_eq!(hit.api, "getenv");
        assert_eq!(hit.evidence_value("env_var"), Some("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn sensitive_env_oracle_ignores_ordinary_configuration_names() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::SensitiveEnvAda.evaluate(&OracleRuntimeEvent::EnvVar {
            api: "getenv".to_owned(),
            name: "ACME_CONFIG_DIR".to_owned(),
        });

        assert_eq!(hit, None);
    }

    #[test]
    fn resource_leak_oracle_matches_runtime_resource_event() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::ResourceLeakAda
            .evaluate(&OracleRuntimeEvent::ResourceLeak {
                api: "open".to_owned(),
                resource: "fd:7 path:/tmp/acme.conf".to_owned(),
                evidence: vec![
                    ("fd".to_owned(), "7".to_owned()),
                    ("path".to_owned(), "/tmp/acme.conf".to_owned()),
                ],
            })
            .expect("unclosed runtime resources should trip the leak oracle");

        assert_eq!(hit.oracle_name, "resource-leak-ada");
        assert_eq!(hit.rule_id, "GF-306");
        assert_eq!(hit.api, "open");
        assert_eq!(hit.evidence_value("fd"), Some("7"));
        assert_eq!(hit.evidence_value("path"), Some("/tmp/acme.conf"));
    }

    #[test]
    fn file_deletion_oracle_matches_parent_directory_delete_event() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::FileDeletionRuntime
            .evaluate(&OracleRuntimeEvent::FileDeletion {
                api: "unlink".to_owned(),
                path: "../state/session.db".to_owned(),
            })
            .expect("parent-directory deletion paths should trip the deletion oracle");

        assert_eq!(hit.oracle_name, "file-deletion-runtime");
        assert_eq!(hit.rule_id, "GF-414");
        assert_eq!(hit.api, "unlink");
        assert_eq!(hit.evidence_value("path"), Some("../state/session.db"));
    }

    #[test]
    fn file_deletion_oracle_ignores_ordinary_relative_delete_event() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::FileDeletionRuntime.evaluate(&OracleRuntimeEvent::FileDeletion {
            api: "unlink".to_owned(),
            path: "cache/session.db".to_owned(),
        });

        assert_eq!(hit, None);
    }

    #[test]
    fn dynamic_library_oracle_matches_relative_dlopen_library() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::DynamicLibraryLoadRuntime
            .evaluate(&OracleRuntimeEvent::Library {
                api: "dlopen".to_owned(),
                library: "plugins/libcodec.so".to_owned(),
            })
            .expect("relative dynamic-library loads should trip the oracle");

        assert_eq!(hit.oracle_name, "dynamic-library-load-runtime");
        assert_eq!(hit.rule_id, "GF-413");
        assert_eq!(hit.api, "dlopen");
        assert_eq!(hit.evidence_value("library"), Some("plugins/libcodec.so"));
    }

    #[test]
    fn dynamic_library_oracle_ignores_absolute_system_library() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::DynamicLibraryLoadRuntime.evaluate(&OracleRuntimeEvent::Library {
            api: "dlopen".to_owned(),
            library: "/usr/lib/x86_64-linux-gnu/libm.so.6".to_owned(),
        });

        assert_eq!(hit, None);
    }

    #[test]
    fn format_string_oracle_matches_controlled_conversion_format() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::FormatStringRuntime
            .evaluate(&OracleRuntimeEvent::FormatString {
                api: "printf".to_owned(),
                format: "%x %x %n".to_owned(),
                controlled: true,
            })
            .expect("controlled printf conversion formats should trip the format oracle");

        assert_eq!(hit.oracle_name, "format-string-runtime");
        assert_eq!(hit.rule_id, "GF-408");
        assert_eq!(hit.api, "printf");
        assert_eq!(hit.evidence_value("format"), Some("%x %x %n"));
        assert_eq!(hit.evidence_value("controlled"), Some("true"));
    }

    #[test]
    fn format_string_oracle_ignores_uncontrolled_static_format() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::FormatStringRuntime.evaluate(&OracleRuntimeEvent::FormatString {
            api: "printf".to_owned(),
            format: "value=%d".to_owned(),
            controlled: false,
        });

        assert_eq!(hit, None);
    }

    #[test]
    fn runtime_constraint_check_oracle_matches_handled_index_check() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::AdaRuntimeConstraintCheck
            .evaluate(&OracleRuntimeEvent::RuntimeCheck {
                api: "ada-runtime".to_owned(),
                language: "ada".to_owned(),
                exception: "Constraint_Error".to_owned(),
                check: "index_check".to_owned(),
                handled: true,
                evidence: vec![
                    ("handler".to_owned(), "when others".to_owned()),
                    ("source".to_owned(), "parser.adb:42".to_owned()),
                ],
            })
            .expect("handled Ada Constraint_Error index checks should trip the runtime oracle");

        assert_eq!(hit.oracle_name, "ada-runtime-constraint-check");
        assert_eq!(hit.rule_id, "GF-102");
        assert_eq!(hit.api, "ada-runtime");
        assert_eq!(hit.evidence_value("exception"), Some("Constraint_Error"));
        assert_eq!(hit.evidence_value("check"), Some("index_check"));
        assert_eq!(hit.evidence_value("handled"), Some("true"));
        assert_eq!(hit.evidence_value("handler"), Some("when others"));
        assert_eq!(hit.evidence_value("source"), Some("parser.adb:42"));
    }

    #[test]
    fn runtime_constraint_check_oracle_ignores_unhandled_exception() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::AdaRuntimeConstraintCheck.evaluate(&OracleRuntimeEvent::RuntimeCheck {
            api: "ada-runtime".to_owned(),
            language: "ada".to_owned(),
            exception: "Constraint_Error".to_owned(),
            check: "index_check".to_owned(),
            handled: false,
            evidence: Vec::new(),
        });

        assert_eq!(hit, None);
    }

    #[test]
    fn runtime_storage_error_oracle_matches_handled_exception() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::AdaRuntimeStorageError
            .evaluate(&OracleRuntimeEvent::RuntimeCheck {
                api: "ada-runtime".to_owned(),
                language: "ada".to_owned(),
                exception: "Storage_Error".to_owned(),
                check: "allocation_check".to_owned(),
                handled: true,
                evidence: vec![
                    ("handler".to_owned(), "when others".to_owned()),
                    ("source".to_owned(), "allocator.adb:17".to_owned()),
                ],
            })
            .expect("handled Ada Storage_Error checks should trip the runtime oracle");

        assert_eq!(hit.oracle_name, "ada-runtime-storage-error");
        assert_eq!(hit.rule_id, "GF-103");
        assert_eq!(hit.api, "ada-runtime");
        assert_eq!(hit.evidence_value("exception"), Some("Storage_Error"));
        assert_eq!(hit.evidence_value("check"), Some("allocation_check"));
        assert_eq!(hit.evidence_value("handled"), Some("true"));
        assert_eq!(hit.evidence_value("handler"), Some("when others"));
        assert_eq!(hit.evidence_value("source"), Some("allocator.adb:17"));
    }

    #[test]
    fn runtime_tasking_error_oracle_matches_handled_exception() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::AdaRuntimeTaskingError
            .evaluate(&OracleRuntimeEvent::RuntimeCheck {
                api: "ada-runtime".to_owned(),
                language: "ada".to_owned(),
                exception: "Tasking_Error".to_owned(),
                check: "task_activation".to_owned(),
                handled: true,
                evidence: vec![
                    ("handler".to_owned(), "when others".to_owned()),
                    ("source".to_owned(), "workers.adb:88".to_owned()),
                ],
            })
            .expect("handled Ada Tasking_Error checks should trip the runtime oracle");

        assert_eq!(hit.oracle_name, "ada-runtime-tasking-error");
        assert_eq!(hit.rule_id, "GF-104");
        assert_eq!(hit.api, "ada-runtime");
        assert_eq!(hit.evidence_value("exception"), Some("Tasking_Error"));
        assert_eq!(hit.evidence_value("check"), Some("task_activation"));
        assert_eq!(hit.evidence_value("handled"), Some("true"));
        assert_eq!(hit.evidence_value("handler"), Some("when others"));
        assert_eq!(hit.evidence_value("source"), Some("workers.adb:88"));
    }

    #[test]
    fn runtime_user_exception_oracle_matches_handled_exception() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::AdaRuntimeUserException
            .evaluate(&OracleRuntimeEvent::RuntimeCheck {
                api: "ada-runtime".to_owned(),
                language: "ada".to_owned(),
                exception: "Protocol.Bad_Frame".to_owned(),
                check: "explicit_raise".to_owned(),
                handled: true,
                evidence: vec![
                    ("handler".to_owned(), "when others".to_owned()),
                    ("source".to_owned(), "protocol.adb:54".to_owned()),
                ],
            })
            .expect("handled Ada user-defined exceptions should trip the runtime oracle");

        assert_eq!(hit.oracle_name, "ada-runtime-user-exception");
        assert_eq!(hit.rule_id, "GF-105");
        assert_eq!(hit.api, "ada-runtime");
        assert_eq!(hit.evidence_value("exception"), Some("Protocol.Bad_Frame"));
        assert_eq!(hit.evidence_value("check"), Some("explicit_raise"));
        assert_eq!(hit.evidence_value("handled"), Some("true"));
        assert_eq!(hit.evidence_value("handler"), Some("when others"));
        assert_eq!(hit.evidence_value("source"), Some("protocol.adb:54"));
    }

    #[test]
    fn runtime_user_exception_oracle_ignores_predefined_exception() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::AdaRuntimeUserException.evaluate(&OracleRuntimeEvent::RuntimeCheck {
            api: "ada-runtime".to_owned(),
            language: "ada".to_owned(),
            exception: "Constraint_Error".to_owned(),
            check: "index_check".to_owned(),
            handled: true,
            evidence: Vec::new(),
        });

        assert_eq!(hit, None);
    }

    #[test]
    fn native_assertion_contract_oracle_matches_c_assertion_failure() {
        use crate::oracle_sdk::OracleRuntimeEvent;

        let oracle = ORACLE_REGISTRY
            .iter()
            .find(|oracle| oracle.name() == "native-assertion-contract")
            .expect("native assertion contract oracle registered");
        let hit = oracle
            .evaluate(&OracleRuntimeEvent::RuntimeCheck {
                api: "__assert_fail".to_owned(),
                language: "c".to_owned(),
                exception: "AssertionFailure".to_owned(),
                check: "assertion".to_owned(),
                handled: false,
                evidence: vec![
                    ("expression".to_owned(), "len < cap".to_owned()),
                    ("source".to_owned(), "parser.c:42:parse_frame".to_owned()),
                ],
            })
            .expect("native assertion failures should trip the contract oracle");

        assert_eq!(hit.oracle_name, "native-assertion-contract");
        assert_eq!(hit.rule_id, "GF-415");
        assert_eq!(hit.api, "__assert_fail");
        assert_eq!(hit.evidence_value("exception"), Some("AssertionFailure"));
        assert_eq!(hit.evidence_value("check"), Some("assertion"));
        assert_eq!(hit.evidence_value("expression"), Some("len < cap"));
        assert_eq!(
            hit.evidence_value("source"),
            Some("parser.c:42:parse_frame")
        );
    }

    #[test]
    fn differential_oracle_matches_output_divergence() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::DifferentialOutputRuntime
            .evaluate(&OracleRuntimeEvent::Differential {
                api: "govfuzz differential".to_owned(),
                stdout_equal: false,
                exit_equal: true,
                timed_out_a: false,
                timed_out_b: false,
                evidence: vec![("input_sha256".to_owned(), "abc123".to_owned())],
            })
            .expect("differential output divergence should trip the oracle");

        assert_eq!(hit.oracle_name, "differential-output-runtime");
        assert_eq!(hit.rule_id, "GF-301");
        assert_eq!(hit.api, "govfuzz differential");
        assert_eq!(hit.evidence_value("stdout_equal"), Some("false"));
        assert_eq!(hit.evidence_value("exit_equal"), Some("true"));
        assert_eq!(hit.evidence_value("input_sha256"), Some("abc123"));
    }

    #[test]
    fn insecure_permissions_oracle_flags_setuid_and_world_writable() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        // setuid (0o4755) is flagged.
        let hit =
            super::InsecurePermissionsRuntime.evaluate(&OracleRuntimeEvent::InsecurePermissions {
                api: "chmod".to_owned(),
                path: "/tmp/extracted".to_owned(),
                mode: 0o4755,
            });
        let hit = hit.expect("setuid mode must be flagged");
        assert_eq!(hit.rule_id, "GF-416");
        assert!(hit.evidence.iter().any(|e| e.value.contains("setuid")));

        // World-writable (0o0002) is flagged.
        assert!(super::InsecurePermissionsRuntime
            .evaluate(&OracleRuntimeEvent::InsecurePermissions {
                api: "chmod".to_owned(),
                path: "/tmp/x".to_owned(),
                mode: 0o0666,
            })
            .is_some());

        // A safe mode (0o0644, owner-write only) is NOT flagged.
        assert_eq!(
            super::InsecurePermissionsRuntime.evaluate(&OracleRuntimeEvent::InsecurePermissions {
                api: "chmod".to_owned(),
                path: "/tmp/x".to_owned(),
                mode: 0o0644,
            }),
            None
        );
    }

    #[test]
    fn insecure_temp_file_oracle_flags_world_writable_dirs_only() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        // A creation under /tmp is flagged with the directory as evidence.
        let hit = super::InsecureTempFileRuntime.evaluate(&OracleRuntimeEvent::InsecureTempFile {
            api: "open".to_owned(),
            path: "/tmp/govfuzz-pidXXXX.tmp".to_owned(),
        });
        let hit = hit.expect("/tmp creation must be flagged");
        assert_eq!(hit.rule_id, "GF-417");
        assert_eq!(hit.evidence_value("directory"), Some("/tmp"));

        // /var/tmp and /dev/shm are world-writable too.
        for path in ["/var/tmp/x", "/dev/shm/y"] {
            assert!(
                super::InsecureTempFileRuntime
                    .evaluate(&OracleRuntimeEvent::InsecureTempFile {
                        api: "openat".to_owned(),
                        path: path.to_owned(),
                    })
                    .is_some(),
                "{path} must be flagged"
            );
        }

        // A private path is NOT a CWE-377 temp race even if it reaches here.
        assert_eq!(
            super::InsecureTempFileRuntime.evaluate(&OracleRuntimeEvent::InsecureTempFile {
                api: "open".to_owned(),
                path: "/home/user/.cache/app/scratch".to_owned(),
            }),
            None
        );
    }

    #[test]
    fn toctou_oracle_flags_check_then_open() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::ToctouRuntime.evaluate(&OracleRuntimeEvent::Toctou {
            api: "access->open".to_owned(),
            path: "/var/run/app/state".to_owned(),
        });
        let hit = hit.expect("check-then-open must be flagged");
        assert_eq!(hit.rule_id, "GF-418");
        assert_eq!(hit.evidence_value("path"), Some("/var/run/app/state"));
        assert_eq!(hit.evidence_value("sequence"), Some("access->open"));

        // Unrelated event shapes are ignored.
        assert_eq!(
            super::ToctouRuntime.evaluate(&OracleRuntimeEvent::FilePath {
                api: "open".to_owned(),
                path: "/etc/passwd".to_owned(),
            }),
            None
        );
    }

    #[test]
    fn differential_oracle_ignores_matching_outputs() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::DifferentialOutputRuntime.evaluate(&OracleRuntimeEvent::Differential {
            api: "govfuzz differential".to_owned(),
            stdout_equal: true,
            exit_equal: true,
            timed_out_a: false,
            timed_out_b: false,
            evidence: Vec::new(),
        });

        assert_eq!(hit, None);
    }

    #[test]
    fn metamorphic_oracle_matches_relation_violation() {
        use crate::oracle_sdk::{BugOracle, OracleRuntimeEvent};

        let hit = super::MetamorphicRelationRuntime
            .evaluate(&OracleRuntimeEvent::Metamorphic {
                api: "govfuzz differential metamorphic".to_owned(),
                relation: "append-newline".to_owned(),
                stdout_equal: false,
                exit_equal: true,
                timed_out_original: false,
                timed_out_transformed: false,
                evidence: vec![("input_sha256".to_owned(), "abc123".to_owned())],
            })
            .expect("metamorphic relation violations should trip the oracle");

        assert_eq!(hit.oracle_name, "metamorphic-relation-runtime");
        assert_eq!(hit.rule_id, "GF-307");
        assert_eq!(hit.api, "govfuzz differential metamorphic");
        assert_eq!(hit.evidence_value("relation"), Some("append-newline"));
        assert_eq!(hit.evidence_value("stdout_equal"), Some("false"));
        assert_eq!(hit.evidence_value("exit_equal"), Some("true"));
        assert_eq!(hit.evidence_value("input_sha256"), Some("abc123"));
    }
}
