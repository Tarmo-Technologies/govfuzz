// SPDX-License-Identifier: Apache-2.0

//! The evidence ladder: how we know a component is present and used.

/// Rungs ordered low → high. `derive(Ord)` makes "highest rung wins" a `max()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceKind {
    /// Named in a manifest (requirements.txt, pom.xml, package.json…).
    Declared,
    /// Pinned in a lockfile (+ integrity hash where available).
    Resolved,
    /// `#include` / `with` / `import` found in the parsed source.
    SourceObserved,
    /// Present in the built binary (DT_NEEDED / symbol / static archive).
    Linked,
    /// dlopen/exec observed at runtime by the runtrace shim.
    RuntimeLoaded,
    /// A fuzzed harness drove code inside the component.
    FuzzReached,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::Declared => "declared",
            EvidenceKind::Resolved => "resolved",
            EvidenceKind::SourceObserved => "source_observed",
            EvidenceKind::Linked => "linked",
            EvidenceKind::RuntimeLoaded => "runtime_loaded",
            EvidenceKind::FuzzReached => "fuzz_reached",
        }
    }
}

/// One observation supporting a component's presence/use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub kind: EvidenceKind,
    /// Human-auditable origin, e.g. `"src/zip.c:7 #include <zlib.h>"` or
    /// `"auto/run.json:dlopen:libz.so.1"`.
    pub source: String,
    /// Optional precise locator (file:line or symbol), when finer than `source`.
    pub locator: Option<String>,
}

impl Evidence {
    pub fn new(kind: EvidenceKind, source: impl Into<String>) -> Self {
        Evidence {
            kind,
            source: source.into(),
            locator: None,
        }
    }
}

/// The highest rung any evidence reaches (`None` if there is no evidence).
pub fn top_rung(evidence: &[Evidence]) -> Option<EvidenceKind> {
    evidence.iter().map(|item| item.kind).max()
}

/// A coarse usage label derived from the top rung — used by later phases for
/// output and VEX mapping. Not serialized in Phase 1.
pub fn usage_label(top: Option<EvidenceKind>) -> &'static str {
    match top {
        None => "unknown",
        Some(EvidenceKind::Declared) | Some(EvidenceKind::Resolved) => "present",
        Some(EvidenceKind::SourceObserved) => "imported",
        Some(EvidenceKind::Linked) => "linked",
        Some(EvidenceKind::RuntimeLoaded) => "loaded",
        Some(EvidenceKind::FuzzReached) => "exercised",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rungs_are_ordered_low_to_high() {
        assert!(EvidenceKind::Declared < EvidenceKind::Resolved);
        assert!(EvidenceKind::Resolved < EvidenceKind::SourceObserved);
        assert!(EvidenceKind::SourceObserved < EvidenceKind::Linked);
        assert!(EvidenceKind::Linked < EvidenceKind::RuntimeLoaded);
        assert!(EvidenceKind::RuntimeLoaded < EvidenceKind::FuzzReached);
    }

    #[test]
    fn top_rung_picks_highest() {
        let evidence = vec![
            Evidence::new(EvidenceKind::Declared, "requirements.txt:3"),
            Evidence::new(EvidenceKind::FuzzReached, "harness:zip_open"),
            Evidence::new(EvidenceKind::SourceObserved, "src/zip.c:7"),
        ];
        assert_eq!(top_rung(&evidence), Some(EvidenceKind::FuzzReached));
        assert_eq!(usage_label(top_rung(&evidence)), "exercised");
    }

    #[test]
    fn top_rung_of_empty_is_none() {
        assert_eq!(top_rung(&[]), None);
        assert_eq!(usage_label(None), "unknown");
    }

    #[test]
    fn as_str_is_stable_for_each_rung() {
        // Phase 2+ serializes these into evidence JSON — lock the contract now.
        assert_eq!(EvidenceKind::Declared.as_str(), "declared");
        assert_eq!(EvidenceKind::Resolved.as_str(), "resolved");
        assert_eq!(EvidenceKind::SourceObserved.as_str(), "source_observed");
        assert_eq!(EvidenceKind::Linked.as_str(), "linked");
        assert_eq!(EvidenceKind::RuntimeLoaded.as_str(), "runtime_loaded");
        assert_eq!(EvidenceKind::FuzzReached.as_str(), "fuzz_reached");
    }
}
