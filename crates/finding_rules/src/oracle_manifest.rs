// SPDX-License-Identifier: Apache-2.0

//! Compile-time inventory of bug-oracle plugins.

use crate::oracle_sdk::{OracleCategory, OracleManifestEntry};

pub const ORACLE_MANIFEST: &[OracleManifestEntry] = &[
    OracleManifestEntry {
        name: "path-traversal-ada",
        rule_id: "GF-101",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "Ada.Directories.Open",
            "Ada.Text_IO.Open",
            "Ada.Streams.Stream_IO.Open",
        ],
        describe: "Detect caller-controlled paths containing '..' reaching Ada filesystem APIs",
    },
    OracleManifestEntry {
        name: "sql-injection-ada",
        rule_id: "GF-302",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "GNATColl.SQL.Execute",
            "GNATColl.SQL.Exec.Prepare",
            "Interfaces.C.Strings.New_String",
        ],
        describe: "Detect test-case-controlled bytes reaching Ada SQL execution APIs without parameter binding",
    },
    OracleManifestEntry {
        name: "ssrf-ada",
        rule_id: "GF-303",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "GNAT.Sockets.Connect_Socket",
            "AWS.Client.Get",
            "AWS.Client.Post",
        ],
        describe: "Detect controlled URL/hostname reaching Ada network-egress APIs",
    },
    OracleManifestEntry {
        name: "command-injection-ada",
        rule_id: "GF-304",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "GNAT.OS_Lib.Spawn",
            "GNAT.OS_Lib.Non_Blocking_Spawn",
            "Ada.Command_Line.Argument",
            "system",
            "popen",
        ],
        describe: "Detect controlled argv/cmdline reaching Ada process-spawn APIs without quoting",
    },
    OracleManifestEntry {
        name: "sensitive-env-ada",
        rule_id: "GF-305",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "Ada.Environment_Variables.Value",
            "GNAT.OS_Lib.Getenv",
            "Interfaces.C.getenv",
            "secure_getenv",
        ],
        describe: "Detect runtime reads of secret-like environment variable names",
    },
    OracleManifestEntry {
        name: "resource-leak-ada",
        rule_id: "GF-306",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "Ada.Text_IO.Open",
            "Ada.Streams.Stream_IO.Open",
            "open",
            "openat",
        ],
        describe: "Detect resources opened during fuzz execution and not released before testcase exit",
    },
    OracleManifestEntry {
        name: "dynamic-library-load-runtime",
        rule_id: "GF-413",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["dlopen", "dlmopen", "LoadLibraryA", "LoadLibraryW"],
        describe: "Detect runtime dynamic-library loads through relative or attacker-writable search paths",
    },
    OracleManifestEntry {
        name: "file-deletion-runtime",
        rule_id: "GF-414",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["unlink", "unlinkat", "remove"],
        describe: "Detect runtime file deletion APIs receiving parent-directory paths",
    },
    OracleManifestEntry {
        name: "native-assertion-contract",
        rule_id: "GF-415",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["__assert_fail", "__assert_perror_fail", "assert"],
        describe: "Detect C/C++ assertion failures promoted from runtime evidence",
    },
    OracleManifestEntry {
        name: "differential-output-runtime",
        rule_id: "GF-301",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["govfuzz differential"],
        describe: "Detect output or exit-status divergence between two implementations on the same input",
    },
    OracleManifestEntry {
        name: "metamorphic-relation-runtime",
        rule_id: "GF-307",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["govfuzz differential --metamorphic-transform"],
        describe: "Detect violated metamorphic relations between an input and its transformed variant",
    },
    OracleManifestEntry {
        name: "format-string-runtime",
        rule_id: "GF-408",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["printf", "fprintf", "sprintf", "snprintf", "dprintf"],
        describe: "Detect fuzz-controlled printf-style format strings reaching runtime formatting APIs",
    },
    OracleManifestEntry {
        name: "ada-runtime-constraint-check",
        rule_id: "GF-102",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "Ada runtime checks",
            "Constraint_Error",
            "range_check",
            "index_check",
        ],
        describe: "Detect handled Ada Constraint_Error range/index checks promoted from runtime evidence",
    },
    OracleManifestEntry {
        name: "ada-runtime-storage-error",
        rule_id: "GF-103",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["Ada runtime checks", "Storage_Error", "allocation_check"],
        describe: "Detect handled Ada Storage_Error events promoted from runtime evidence",
    },
    OracleManifestEntry {
        name: "ada-runtime-tasking-error",
        rule_id: "GF-104",
        category: OracleCategory::Concurrency,
        dangerous_apis: &["Ada runtime checks", "Tasking_Error", "task_activation"],
        describe: "Detect handled Ada Tasking_Error events promoted from runtime evidence",
    },
    OracleManifestEntry {
        name: "ada-runtime-user-exception",
        rule_id: "GF-105",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "Ada runtime checks",
            "user-defined exception",
            "when others",
        ],
        describe: "Detect handled Ada user-defined exceptions promoted from runtime evidence",
    },
    OracleManifestEntry {
        name: "insecure-permissions-runtime",
        rule_id: "GF-416",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "chmod",
            "fchmod",
            "fchmodat",
            "mkdir",
            "mkdirat",
            "GNAT.OS_Lib.Set_File_Permissions",
        ],
        describe: "Detect setuid/setgid/world-writable file or directory permissions assigned during fuzz execution",
    },
    OracleManifestEntry {
        name: "insecure-temp-file-runtime",
        rule_id: "GF-417",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["open", "openat", "fopen", "mktemp", "tmpnam", "tempnam"],
        describe: "Detect temporary files created in world-writable directories without O_EXCL during fuzz execution",
    },
    OracleManifestEntry {
        name: "toctou-runtime",
        rule_id: "GF-418",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["access", "faccessat", "stat", "open", "openat"],
        describe: "Detect a path checked (access/stat) then opened during fuzz execution — a time-of-check/time-of-use race",
    },
    OracleManifestEntry {
        name: "path-controlled-open-runtime",
        rule_id: "GF-405",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["open", "openat", "fopen"],
        describe: "Detect fuzz-controlled paths reaching file-open APIs unsanitized during fuzz execution",
    },
    OracleManifestEntry {
        name: "command-controlled-runtime",
        rule_id: "GF-431",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["system", "popen"],
        describe: "Detect fuzz-controlled command strings reaching shell-execution APIs during fuzz execution",
    },
    OracleManifestEntry {
        name: "ssrf-controlled-runtime",
        rule_id: "GF-433",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["getaddrinfo", "connect", "gethostbyname"],
        describe: "Detect fuzz-controlled network destinations reaching egress APIs during fuzz execution",
    },
    OracleManifestEntry {
        name: "library-load-controlled-runtime",
        rule_id: "GF-435",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["dlopen", "dlmopen"],
        describe: "Detect fuzz-controlled library paths reaching dynamic loaders during fuzz execution",
    },
    OracleManifestEntry {
        name: "sql-injection-runtime",
        rule_id: "GF-441",
        category: OracleCategory::LogicBug,
        dangerous_apis: &["sqlite3_exec", "sqlite3_prepare_v2", "PQexec", "mysql_query"],
        describe: "Detect fuzz-controlled SQL text reaching database-execution APIs during fuzz execution",
    },
    OracleManifestEntry {
        name: "destructive-path-controlled-runtime",
        rule_id: "GF-440",
        category: OracleCategory::LogicBug,
        dangerous_apis: &[
            "unlink", "unlinkat", "remove", "rename", "renameat", "mkdir", "rmdir", "symlink",
            "link", "truncate",
        ],
        describe: "Detect fuzz-controlled paths reaching destructive filesystem APIs during fuzz execution",
    },
];

/// Evidence keys that are SITE-STABLE discriminators for an oracle's findings,
/// folded into the cluster key so two distinct sites of the same defect do not
/// over-merge into one row. Per-input evidence (the opened path/fd, the injected
/// command, the format string) is deliberately NOT listed — it varies per
/// testcase and must stay out of the cluster key. Empty for oracles whose
/// `(rule | oracle | api)` tuple already uniquely identifies the site.
pub fn site_keys_for(oracle_name: &str) -> &'static [&'static str] {
    match oracle_name {
        // Every native C/C++ assertion shares `__assert_fail` as its API, so the
        // (rule | oracle | api) tuple collapses distinct assert sites into one
        // cluster with an empty sink. The assertion's source location and
        // expression are fixed per site and are the right discriminators.
        "native-assertion-contract" => &["source", "expression"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::{site_keys_for, ORACLE_MANIFEST};

    #[test]
    fn native_assertion_site_keys_discriminate_by_source() {
        assert_eq!(
            site_keys_for("native-assertion-contract"),
            &["source", "expression"]
        );
        // Per-input oracles keep an empty allowlist (no over-discrimination).
        assert!(site_keys_for("path-traversal-ada").is_empty());
        assert!(site_keys_for("resource-leak-ada").is_empty());
    }

    #[test]
    fn path_traversal_ada_oracle_present() {
        let oracle = ORACLE_MANIFEST
            .iter()
            .find(|e| e.name == "path-traversal-ada")
            .expect("path-traversal-ada present");
        assert_eq!(oracle.rule_id, "GF-101");
        assert!(oracle.dangerous_apis.contains(&"Ada.Directories.Open"));
    }
}
