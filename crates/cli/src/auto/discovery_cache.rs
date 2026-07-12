// SPDX-License-Identifier: Apache-2.0

//! Persisted discovery cache for `govfuzz auto --reuse-discovery`.
//!
//! Discovery (the tree-sitter parse + entry-point ranking of the WHOLE source
//! tree) is the dominant cost of a re-run on a big tree — on the order of an
//! hour for ~5M LOC / ~140k candidates. When the tree is unchanged between runs
//! there is nothing to recompute: the ranked candidate list is a pure function
//! of the source bytes + the dir-filter config. This module persists that list
//! (under the work dir by default, or at an explicit `--discovery-cache <path>`)
//! and reloads it when a content fingerprint of the source matches.
//!
//! Correctness rule: a stale cache must NEVER be used silently. The fingerprint
//! (see [`crate::auto::discovery::source_fingerprint`]) guards every load — any
//! file added/removed/edited (by content, not mtime), or a changed
//! `--exclude-dir`/`--include-dir`, changes the fingerprint and forces a fresh
//! discovery + rewrite. The cache is a re-run optimization only; it can never
//! change WHAT is discovered.

use crate::auto::candidate::{Candidate, Lang};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use target_rank::InputReachability;

/// Cache format version. Bump when the on-disk shape OR the fingerprint algorithm
/// changes incompatibly, so a stale-format file is rejected (treated as a miss)
/// instead of mis-parsed. v2: the fingerprint hash moved from `DefaultHasher`
/// (toolchain-unstable) to a build-stable FNV-1a, so v1 fingerprints no longer
/// compare equal — a clean version-mismatch reject is clearer than a confusing
/// fingerprint mismatch.
const CACHE_VERSION: u32 = 2;

/// Filename written under the work dir.
pub const CACHE_FILENAME: &str = "discovery-cache.json";

/// The on-disk discovery cache: a header (version + fingerprint + the root it
/// was computed for) plus the ranked candidate list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryCache {
    pub version: u32,
    /// Source-tree fingerprint this candidate list was computed for. A load only
    /// succeeds when it equals a freshly computed fingerprint of the same root.
    pub fingerprint: String,
    /// The canonical sweep root, recorded for diagnostics / sanity (a cache from
    /// a different root is rejected).
    pub root: String,
    /// Ranked candidates, in the same score-descending order discovery emits.
    pub candidates: Vec<CandidateDto>,
}

/// Serializable mirror of [`Candidate`]. `lang` and `input_reachability` are
/// stored as stable lowercase strings rather than relying on serde derives on
/// the cross-crate enums, so the cache format is independent of those types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateDto {
    pub harness_id: String,
    pub lang: String,
    pub source_path: String,
    pub line: u32,
    pub name: String,
    pub score: i32,
    pub is_static: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_guard: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_reachability: Option<String>,
    /// M22: detected source dialect tag (`lang_profile::Dialect::as_str`).
    /// `None` for lanes where dialect detection is not yet wired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialect: Option<String>,
}

fn lang_to_str(lang: Lang) -> &'static str {
    match lang {
        Lang::Ada => "ada",
        Lang::C => "c",
        Lang::Cpp => "cpp",
        Lang::Rust => "rust",
        Lang::Java => "java",
        Lang::Python => "python",
        Lang::Perl => "perl",
        Lang::Go => "go",
        Lang::Cobol => "cobol",
        Lang::Fortran => "fortran",
        Lang::CSharp => "csharp",
    }
}

fn lang_from_str(s: &str) -> Option<Lang> {
    match s {
        "ada" => Some(Lang::Ada),
        "c" => Some(Lang::C),
        "cpp" => Some(Lang::Cpp),
        "rust" => Some(Lang::Rust),
        "java" => Some(Lang::Java),
        "python" => Some(Lang::Python),
        "perl" => Some(Lang::Perl),
        "go" => Some(Lang::Go),
        "cobol" => Some(Lang::Cobol),
        "fortran" => Some(Lang::Fortran),
        "csharp" => Some(Lang::CSharp),
        _ => None,
    }
}

fn reach_to_str(r: InputReachability) -> &'static str {
    match r {
        InputReachability::AttackerReachable => "attacker_reachable",
        InputReachability::OutputSerializer => "output_serializer",
        InputReachability::ReachabilityUnproven => "reachability_unproven",
        // Assigned dynamically post-run, not at discovery, so the discovery cache
        // never actually stores it; mapped here for an exhaustive round-trip.
        InputReachability::IpcChannelReachable => "ipc_channel_reachable",
    }
}

fn reach_from_str(s: &str) -> Option<InputReachability> {
    match s {
        "attacker_reachable" => Some(InputReachability::AttackerReachable),
        "output_serializer" => Some(InputReachability::OutputSerializer),
        "reachability_unproven" => Some(InputReachability::ReachabilityUnproven),
        "ipc_channel_reachable" => Some(InputReachability::IpcChannelReachable),
        _ => None,
    }
}

impl CandidateDto {
    fn from_candidate(c: &Candidate) -> Self {
        Self {
            harness_id: c.harness_id.clone(),
            lang: lang_to_str(c.lang).to_owned(),
            source_path: c.source_path.to_string_lossy().into_owned(),
            line: c.line,
            name: c.name.clone(),
            score: c.score,
            is_static: c.is_static,
            foreign_guard: c.foreign_guard.clone(),
            input_reachability: c.input_reachability.map(|r| reach_to_str(r).to_owned()),
            dialect: c.dialect.map(|d| d.as_str().to_owned()),
        }
    }

    /// Reconstruct a [`Candidate`]. Returns `None` for an unrecognized `lang`
    /// tag (a corrupt / future-format row), so a single bad row invalidates the
    /// whole cache load rather than silently dropping a target.
    fn to_candidate(&self) -> Option<Candidate> {
        Some(Candidate {
            harness_id: self.harness_id.clone(),
            lang: lang_from_str(&self.lang)?,
            source_path: PathBuf::from(&self.source_path),
            line: self.line,
            name: self.name.clone(),
            score: self.score,
            is_static: self.is_static,
            foreign_guard: self.foreign_guard.clone(),
            // An unknown reachability tag degrades to `None` (unproven-ish) rather
            // than failing the whole load — it only affects honesty labelling.
            input_reachability: self.input_reachability.as_deref().and_then(reach_from_str),
            // An unknown dialect tag degrades to `None` rather than failing the
            // whole load — it only affects profile selection / report labelling.
            dialect: self
                .dialect
                .as_deref()
                .and_then(lang_profile::Dialect::from_str),
        })
    }
}

impl DiscoveryCache {
    /// Build a cache from a freshly discovered candidate list + its fingerprint.
    pub fn build(root: &Path, fingerprint: String, candidates: &[Candidate]) -> Self {
        Self {
            version: CACHE_VERSION,
            fingerprint,
            root: root.to_string_lossy().into_owned(),
            candidates: candidates
                .iter()
                .map(CandidateDto::from_candidate)
                .collect(),
        }
    }

    /// Reconstruct the candidate list, or `None` if any row is unparseable.
    pub fn into_candidates(self) -> Option<Vec<Candidate>> {
        self.candidates
            .iter()
            .map(CandidateDto::to_candidate)
            .collect()
    }
}

/// Default path of the cache file under `work_dir`.
pub fn cache_path(work_dir: &Path) -> PathBuf {
    work_dir.join(CACHE_FILENAME)
}

/// Resolve the cache file: an explicit `--discovery-cache` override when given,
/// else the default `<work_dir>/discovery-cache.json`. The override decouples
/// the cache from the work dir / current directory, so a `--reuse-discovery`
/// re-run finds it regardless of where it is launched or what the work dir is.
pub fn resolve_cache_path(work_dir: &Path, override_path: Option<&Path>) -> PathBuf {
    match override_path {
        Some(path) => path.to_path_buf(),
        None => cache_path(work_dir),
    }
}

/// Write the cache to `cache_file` (best-effort: a failure is reported by the
/// caller but never aborts the run — the cache is an optimization, not a
/// correctness input). Parent directories are created so an explicit
/// `--discovery-cache` path under a not-yet-existing directory still works.
pub fn write(cache_file: &Path, cache: &DiscoveryCache) -> std::io::Result<()> {
    if let Some(parent) = cache_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(cache).map_err(std::io::Error::other)?;
    std::fs::write(cache_file, json)
}

/// Load a cache from disk and return its candidate list ONLY when the header is
/// current, the root matches, the fingerprint matches `expected_fingerprint`,
/// and every row parses. Any mismatch / parse failure returns `None` (a miss),
/// so a stale or corrupt cache transparently falls back to fresh discovery.
pub fn load_if_valid(
    cache_file: &Path,
    root: &Path,
    expected_fingerprint: &str,
) -> Option<Vec<Candidate>> {
    let text = std::fs::read_to_string(cache_file).ok()?;
    let cache: DiscoveryCache = serde_json::from_str(&text).ok()?;
    if cache.version != CACHE_VERSION {
        return None;
    }
    if cache.fingerprint != expected_fingerprint {
        return None;
    }
    if cache.root != root.to_string_lossy() {
        return None;
    }
    cache.into_candidates()
}

/// A human-readable explanation of why [`load_if_valid`] returned `None`, for
/// diagnostics when a re-run unexpectedly re-discovers. Distinguishes the cases a
/// bare "miss" conflates: no file, unreadable/corrupt JSON, format-version bump,
/// fingerprint change (the target source or dir-filter actually changed), or a
/// root-path mismatch (the cache was built for a different tree).
pub fn miss_reason(cache_file: &Path, root: &Path, expected_fingerprint: &str) -> String {
    let Ok(text) = std::fs::read_to_string(cache_file) else {
        return "no cache file yet".to_owned();
    };
    let Ok(cache) = serde_json::from_str::<DiscoveryCache>(&text) else {
        return "cache file unreadable/corrupt".to_owned();
    };
    if cache.version != CACHE_VERSION {
        return format!(
            "cache format v{} != current v{CACHE_VERSION} (govfuzz cache format changed)",
            cache.version
        );
    }
    if cache.root != root.to_string_lossy() {
        return format!("cached for a different root `{}`", cache.root);
    }
    if cache.fingerprint != expected_fingerprint {
        return format!(
            "source fingerprint changed (cached {}, now {expected_fingerprint}): the target source or dir-filter changed",
            cache.fingerprint
        );
    }
    "cache rows unparseable".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(name: &str, lang: Lang, reach: Option<InputReachability>) -> Candidate {
        Candidate {
            harness_id: format!("H-{name}"),
            lang,
            source_path: PathBuf::from(format!("/src/{name}.c")),
            line: 12,
            name: name.to_owned(),
            score: 42,
            is_static: false,
            foreign_guard: None,
            input_reachability: reach,
            dialect: None,
        }
    }

    #[test]
    fn round_trips_candidates_through_the_cache_dto() {
        let cands = vec![
            candidate("parse", Lang::C, Some(InputReachability::AttackerReachable)),
            candidate(
                "decode",
                Lang::Cpp,
                Some(InputReachability::OutputSerializer),
            ),
            candidate("run", Lang::Ada, None),
        ];
        let cache = DiscoveryCache::build(Path::new("/src"), "fp123".to_owned(), &cands);
        let back = cache.into_candidates().expect("all rows parse");
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].name, "parse");
        assert_eq!(back[0].lang, Lang::C);
        assert_eq!(
            back[0].input_reachability,
            Some(InputReachability::AttackerReachable)
        );
        assert_eq!(back[2].lang, Lang::Ada);
        assert_eq!(back[2].input_reachability, None);
    }

    #[test]
    fn write_then_load_with_matching_fingerprint_returns_candidates() {
        let dir = std::env::temp_dir().join(format!("govfuzz-disccache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cands = vec![candidate("parse", Lang::C, None)];
        let cache = DiscoveryCache::build(Path::new("/src"), "fp-match".to_owned(), &cands);
        let file = cache_path(&dir);
        write(&file, &cache).unwrap();

        // Matching fingerprint + root → hit.
        let hit = load_if_valid(&file, Path::new("/src"), "fp-match");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap()[0].name, "parse");

        // Fingerprint mismatch → miss (stale tree).
        assert!(load_if_valid(&file, Path::new("/src"), "fp-other").is_none());
        // Root mismatch → miss.
        assert!(load_if_valid(&file, Path::new("/other"), "fp-match").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_is_a_miss_when_no_cache_file_exists() {
        let dir =
            std::env::temp_dir().join(format!("govfuzz-disccache-none-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // No file written.
        assert!(load_if_valid(&cache_path(&dir), Path::new("/src"), "anything").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_cache_path_prefers_override_else_default() {
        let work = Path::new("/work");
        // No override → the default location under the work dir.
        assert_eq!(resolve_cache_path(work, None), work.join(CACHE_FILENAME));
        // Override → that exact file, independent of the work dir.
        let custom = Path::new("/elsewhere/my-cache.json");
        assert_eq!(resolve_cache_path(work, Some(custom)), custom.to_path_buf());
    }

    #[test]
    fn explicit_cache_file_is_written_and_loaded_independent_of_work_dir() {
        let base =
            std::env::temp_dir().join(format!("govfuzz-disccache-override-{}", std::process::id()));
        let work = base.join("work");
        let custom = base.join("nested/elsewhere/cache.json");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(custom.parent().unwrap()).unwrap();

        let cands = vec![candidate("parse", Lang::C, None)];
        let cache = DiscoveryCache::build(Path::new("/src"), "fp".to_owned(), &cands);
        write(&custom, &cache).unwrap();

        // The cache landed at the explicit file, NOT the work-dir default.
        assert!(custom.is_file());
        assert!(!cache_path(&work).exists());
        // And it loads back from the explicit file.
        let hit = load_if_valid(&custom, Path::new("/src"), "fp");
        assert_eq!(hit.expect("hit")[0].name, "parse");

        let _ = std::fs::remove_dir_all(&base);
    }
}
