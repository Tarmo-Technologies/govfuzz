// SPDX-License-Identifier: Apache-2.0

//! Static SDK for bug-oracle plugins. Each oracle is a unit struct
//! implementing `BugOracle` plus a matching `OracleManifestEntry`.
//! The trait carries static metadata plus a narrow runtime event hook
//! for executable oracle hits produced by harness instrumentation.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleCategory {
    /// SPARK / Ravenscar / MISRA / CERT compliance.
    Compliance,
    /// Jazzer-style logic-bug detection (path traversal, SSRF, SQL
    /// injection, command injection, deserialization gadgets, etc.).
    LogicBug,
    /// Cryptographic misuse.
    Crypto,
    /// Concurrency hazards beyond simple race detection.
    Concurrency,
}

impl OracleCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            OracleCategory::Compliance => "compliance",
            OracleCategory::LogicBug => "logic-bug",
            OracleCategory::Crypto => "crypto",
            OracleCategory::Concurrency => "concurrency",
        }
    }
}

/// A bug oracle plugin. v0.1 implementations are unit structs that
/// supply only metadata; #307 will extend with runtime instrumentation
/// hooks (likely via the existing `instrumenter` crate).
pub trait BugOracle: Sync {
    /// Stable kebab-case identifier.
    fn name(&self) -> &'static str;

    /// Numeric rule id (`GF-NNNN`) the oracle's findings map to.
    /// Must match a `finding_rules::RULES` entry.
    fn rule_id(&self) -> &'static str;

    /// Category for filtering and reporting.
    fn category(&self) -> OracleCategory;

    /// Names of the dangerous APIs the oracle would instrument
    /// (e.g. `"Ada.Directories.Open"`). Used by diagnostics.
    fn dangerous_apis(&self) -> &'static [&'static str];

    /// One-line human description.
    fn describe(&self) -> &'static str;

    /// Evaluate one runtime event. Metadata-only oracles can keep the
    /// default no-op implementation; executable oracles override this
    /// to turn instrumentation evidence into findings.
    fn evaluate(&self, event: &OracleRuntimeEvent) -> Option<OracleHit> {
        let _ = event;
        None
    }
}

/// Runtime evidence shape understood by executable oracle plugins.
/// It intentionally uses generic event families so frontends can map
/// LD_PRELOAD hooks, compiler instrumentation, or language-specific
/// callbacks into the same SDK without linking frontend types here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleRuntimeEvent {
    FilePath {
        api: String,
        path: String,
    },
    /// A file-open path that the CLI's cross-execution correlation pass
    /// has confirmed is fuzz-controlled (#422): the path carried
    /// byte-origin taint on at least one execution and was never opened
    /// without that taint, ruling out a program constant that the
    /// auto-dictionary merely echoed into the input. `taint_offset` is
    /// the fuzz-input offset the path bytes came from. Drives the
    /// `path-controlled-open-runtime` oracle (GF-405); produced only by
    /// correlation, never by a single raw open event.
    TaintedFilePath {
        api: String,
        path: String,
        taint_offset: u32,
    },
    FileDeletion {
        api: String,
        path: String,
    },
    /// A dangerous file-permission assignment (setuid/setgid/world-writable).
    InsecurePermissions {
        api: String,
        path: String,
        mode: i64,
    },
    /// A temporary file created in a world-writable directory without O_EXCL
    /// (predictable name exposed to a symlink / temp-file race).
    InsecureTempFile {
        api: String,
        path: String,
    },
    /// A path checked (access/stat) then opened — a time-of-check/time-of-use
    /// race on the same path.
    Toctou {
        api: String,
        path: String,
    },
    NetworkAddress {
        api: String,
        address: String,
    },
    EnvVar {
        api: String,
        name: String,
    },
    Library {
        api: String,
        library: String,
    },
    Command {
        api: String,
        command: String,
    },
    /// A shell-execution command string that the CLI's cross-execution
    /// correlation pass has confirmed is fuzz-controlled (#422): a
    /// contiguous run of the command carried byte-origin taint on at least
    /// one execution and the exact command was never executed without that
    /// taint, ruling out a hardcoded command the auto-dictionary merely
    /// echoed into the input. `taint_offset` is the fuzz-input offset the
    /// controlled run came from. Drives the `command-controlled-runtime`
    /// oracle (GF-431); produced only by correlation, never by a single raw
    /// command event.
    TaintedCommand {
        api: String,
        command: String,
        taint_offset: u32,
    },
    /// A network destination (a `getaddrinfo` hostname or `connect` address)
    /// the CLI's cross-execution correlation has confirmed is fuzz-controlled
    /// (#422): tainted on >=1 execution and never reached untainted. Drives the
    /// `ssrf-controlled-runtime` oracle (GF-433, CWE-918). Produced only by
    /// correlation, never by a single raw egress event.
    TaintedNetworkAddress {
        api: String,
        address: String,
        taint_offset: u32,
    },
    /// A dynamic-library path passed to `dlopen`/`dlmopen` that the CLI's
    /// cross-execution correlation has confirmed is fuzz-controlled (#422).
    /// Drives the `library-load-controlled-runtime` oracle (GF-435, CWE-427).
    TaintedLibrary {
        api: String,
        library: String,
        taint_offset: u32,
    },
    /// A SQL text argument reaching a database-execution API
    /// (`sqlite3_exec`/`PQexec`/`mysql_query`/...) that the CLI's
    /// cross-execution correlation has confirmed is fuzz-controlled (#422).
    /// Drives the `sql-injection-runtime` oracle (GF-441, CWE-89).
    TaintedSqlQuery {
        api: String,
        query: String,
        taint_offset: u32,
    },
    /// A path reaching a destructive filesystem API (`unlink`/`rename`/`mkdir`/
    /// `symlink`/`truncate`/...) that the CLI's cross-execution correlation has
    /// confirmed is fuzz-controlled (#422). Drives the
    /// `destructive-path-controlled-runtime` oracle (GF-440, CWE-73).
    TaintedDestructivePath {
        api: String,
        path: String,
        taint_offset: u32,
    },
    FormatString {
        api: String,
        format: String,
        controlled: bool,
    },
    RuntimeCheck {
        api: String,
        language: String,
        exception: String,
        check: String,
        handled: bool,
        evidence: Vec<(String, String)>,
    },
    ResourceLeak {
        api: String,
        resource: String,
        evidence: Vec<(String, String)>,
    },
    Differential {
        api: String,
        stdout_equal: bool,
        exit_equal: bool,
        timed_out_a: bool,
        timed_out_b: bool,
        evidence: Vec<(String, String)>,
    },
    Metamorphic {
        api: String,
        relation: String,
        stdout_equal: bool,
        exit_equal: bool,
        timed_out_original: bool,
        timed_out_transformed: bool,
        evidence: Vec<(String, String)>,
    },
}

/// One key/value evidence item attached to an executable oracle hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OracleEvidence {
    pub key: String,
    pub value: String,
}

impl OracleEvidence {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// A runtime oracle match ready for finding emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OracleHit {
    pub oracle_name: String,
    pub rule_id: String,
    pub category: String,
    pub api: String,
    pub message: String,
    pub evidence: Vec<OracleEvidence>,
}

impl OracleHit {
    pub fn from_oracle(
        oracle: &dyn BugOracle,
        api: impl Into<String>,
        message: impl Into<String>,
        evidence: Vec<OracleEvidence>,
    ) -> Self {
        Self {
            oracle_name: oracle.name().to_owned(),
            rule_id: oracle.rule_id().to_owned(),
            category: oracle.category().as_str().to_owned(),
            api: api.into(),
            message: message.into(),
            evidence,
        }
    }

    pub fn evidence_value(&self, key: &str) -> Option<&str> {
        self.evidence
            .iter()
            .find(|item| item.key == key)
            .map(|item| item.value.as_str())
    }
}

/// Plain-data view of an oracle for callers that must not link
/// instrumentation (the cli's `list-oracles` command). One entry
/// per oracle; data must match the corresponding `BugOracle` impl,
/// cross-checked by the test in `oracle_registry.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleManifestEntry {
    pub name: &'static str,
    pub rule_id: &'static str,
    pub category: OracleCategory,
    pub dangerous_apis: &'static [&'static str],
    pub describe: &'static str,
}

#[cfg(test)]
mod tests {
    use super::{BugOracle, OracleCategory, OracleEvidence, OracleHit, OracleManifestEntry};

    struct Demo;
    impl BugOracle for Demo {
        fn name(&self) -> &'static str {
            "demo"
        }
        fn rule_id(&self) -> &'static str {
            "GF-101"
        }
        fn category(&self) -> OracleCategory {
            OracleCategory::LogicBug
        }
        fn dangerous_apis(&self) -> &'static [&'static str] {
            &["demo_api"]
        }
        fn describe(&self) -> &'static str {
            "demo oracle"
        }
    }

    #[test]
    fn bug_oracle_is_object_safe() {
        let plugin: &dyn BugOracle = &Demo;
        assert_eq!(plugin.name(), "demo");
        assert_eq!(plugin.rule_id(), "GF-101");
        assert_eq!(plugin.category(), OracleCategory::LogicBug);
        assert_eq!(plugin.dangerous_apis(), &["demo_api"]);
        assert_eq!(plugin.describe(), "demo oracle");
    }

    #[test]
    fn oracle_manifest_entry_is_pod_copy() {
        let entry = OracleManifestEntry {
            name: "demo",
            rule_id: "GF-101",
            category: OracleCategory::Compliance,
            dangerous_apis: &["a", "b"],
            describe: "demo",
        };
        let copy = entry;
        assert_eq!(copy.name, "demo");
        assert_eq!(copy.category.as_str(), "compliance");
    }

    #[test]
    fn oracle_category_as_str_covers_all_variants() {
        assert_eq!(OracleCategory::Compliance.as_str(), "compliance");
        assert_eq!(OracleCategory::LogicBug.as_str(), "logic-bug");
        assert_eq!(OracleCategory::Crypto.as_str(), "crypto");
        assert_eq!(OracleCategory::Concurrency.as_str(), "concurrency");
    }

    #[test]
    fn oracle_hit_from_oracle_carries_metadata_and_evidence() {
        let hit = OracleHit::from_oracle(
            &Demo,
            "open",
            "demo message",
            vec![OracleEvidence::new("path", "../x")],
        );

        assert_eq!(hit.oracle_name, "demo");
        assert_eq!(hit.rule_id, "GF-101");
        assert_eq!(hit.category, "logic-bug");
        assert_eq!(hit.api, "open");
        assert_eq!(hit.evidence_value("path"), Some("../x"));
    }
}
