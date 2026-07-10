// SPDX-License-Identifier: Apache-2.0

//! Project config file for `govfuzz auto` (`--config <PATH>`, or an auto-loaded
//! `.govfuzz.toml` in the scanned tree root): persist common flags so a project's runs
//! are reproducible without re-typing them.
//!
//! Merge rule: the CLI always overrides the config — the config only fills a field left
//! at its default/unset value. SECURITY: an AUTO-loaded `.govfuzz.toml` comes from the
//! scanned, possibly-untrusted tree, so it honors ONLY safe knobs; the fields that make
//! govfuzz EXECUTE the tree's own build (`build-command`, `unsafe-search-and-run…`,
//! `run-untrusted`) are ignored unless the config was passed EXPLICITLY with `--config`,
//! so a hostile tree can't auto-run code.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::cli::AutoArgs;

/// The default file name auto-loaded from the scanned tree root.
pub const CONFIG_FILE_NAME: &str = ".govfuzz.toml";

// Mirror the clap defaults so "still at default" can be detected for the merge.
const DEFAULT_PER_TARGET_TIME: u64 = 60;
const DEFAULT_JOBS: usize = 1;
const DEFAULT_RSS_LIMIT_MB: usize = 2048;
const DEFAULT_MAX_LEN: &str = "auto";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AutoConfig {
    // Safe knobs (honored from any config source).
    pub per_target_time: Option<u64>,
    pub max_targets: Option<usize>,
    pub jobs: Option<usize>,
    pub rss_limit_mb: Option<usize>,
    pub cxx_std: Option<String>,
    pub max_len: Option<String>,
    pub timeout: Option<String>,
    pub grammar: Option<PathBuf>,
    pub extra_include: Option<Vec<PathBuf>>,
    pub exclude_path: Option<Vec<String>>,
    pub force: Option<bool>,

    // Execute-y knobs: honored ONLY from an explicit --config (they run the tree's build).
    pub build_command: Option<String>,
    pub run_untrusted: Option<bool>,
    pub unsafe_search_and_run_build_commands: Option<bool>,
}

/// Where the effective config came from, which gates the execute-y knobs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Trust {
    /// Passed with `--config <PATH>` — the operator trusts it; honor everything.
    Explicit,
    /// Auto-loaded `.govfuzz.toml` from the scanned tree — honor only safe knobs.
    TreeAutoloaded,
}

/// Load the config for a run: `--config <PATH>` if given (explicit trust), else an
/// auto-loaded `.govfuzz.toml` from the tree root (safe knobs only). Returns the parsed
/// config + its trust level, or `Ok(None)` when there is no config. A malformed config
/// is a hard error.
fn load(
    config_flag: Option<&Path>,
    tree_root: &Path,
) -> Result<Option<(AutoConfig, Trust)>, String> {
    let (path, trust) = match config_flag {
        Some(p) => (p.to_path_buf(), Trust::Explicit),
        None => {
            let candidate = tree_root.join(CONFIG_FILE_NAME);
            if !candidate.is_file() {
                return Ok(None);
            }
            (candidate, Trust::TreeAutoloaded)
        }
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("read config {}: {e}", path.display()))?;
    let config: AutoConfig =
        toml::from_str(&text).map_err(|e| format!("parse config {}: {e}", path.display()))?;
    Ok(Some((config, trust)))
}

/// Load + apply the project config to `args` in place (CLI values already parsed win).
/// Returns human-readable notes to print (what was applied / ignored), or an error for
/// a malformed config / bad value.
pub fn apply(args: &mut AutoArgs, tree_root: &Path) -> Result<Vec<String>, String> {
    let Some((config, trust)) = load(args.config.as_deref(), tree_root)? else {
        return Ok(Vec::new());
    };
    let mut notes = Vec::new();

    // --- Safe knobs: apply only where the arg is still at its default/unset. ---
    if let Some(v) = config.per_target_time {
        if args.per_target_time == DEFAULT_PER_TARGET_TIME {
            args.per_target_time = v;
        }
    }
    if let Some(v) = config.max_targets {
        if args.max_targets.is_none() {
            args.max_targets = Some(v);
        }
    }
    if let Some(v) = config.jobs {
        if args.jobs == DEFAULT_JOBS {
            args.jobs = v;
        }
    }
    if let Some(v) = config.rss_limit_mb {
        if args.rss_limit_mb == DEFAULT_RSS_LIMIT_MB {
            args.rss_limit_mb = v;
        }
    }
    if let Some(v) = config.cxx_std {
        if args.cxx_std.is_none() {
            args.cxx_std = Some(v);
        }
    }
    if let Some(v) = config.max_len {
        if args.max_len == DEFAULT_MAX_LEN {
            args.max_len = v;
        }
    }
    if let Some(v) = &config.timeout {
        if args.timeout.is_none() {
            args.timeout = Some(crate::fuzz::parse_duration(v)?);
        }
    }
    if let Some(v) = config.grammar {
        if args.grammar_file.is_none() {
            args.grammar_file = Some(v);
        }
    }
    if let Some(v) = config.extra_include {
        if args.extra_includes.is_empty() {
            args.extra_includes = v;
        }
    }
    if let Some(v) = config.exclude_path {
        if args.exclude_paths.is_empty() {
            args.exclude_paths = v;
        }
    }
    if let Some(true) = config.force {
        args.force = true; // union: config or CLI enables it
    }

    // --- Execute-y knobs: only from an EXPLICIT --config. ---
    let execute_y_requested = config.build_command.is_some()
        || config.run_untrusted == Some(true)
        || config.unsafe_search_and_run_build_commands == Some(true);
    match trust {
        Trust::Explicit => {
            if let Some(v) = config.build_command {
                if args.build_command.is_none() {
                    args.build_command = Some(v);
                }
            }
            if config.run_untrusted == Some(true) {
                args.run_untrusted = true;
            }
            if config.unsafe_search_and_run_build_commands == Some(true) {
                args.unsafe_search_and_run_build_commands = true;
            }
        }
        Trust::TreeAutoloaded if execute_y_requested => {
            notes.push(format!(
                "ignoring build-executing keys in the auto-loaded {CONFIG_FILE_NAME} \
                 (build-command / run-untrusted / unsafe-search-and-run-build-commands) — \
                 pass it explicitly with --config to honor them, since it runs code from the scanned tree"
            ));
        }
        Trust::TreeAutoloaded => {}
    }

    let source = match trust {
        Trust::Explicit => args
            .config
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        Trust::TreeAutoloaded => tree_root.join(CONFIG_FILE_NAME).display().to_string(),
    };
    notes.insert(0, format!("loaded config from {source}"));
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_kebab_case_and_rejects_unknown_keys() {
        let cfg: AutoConfig = toml::from_str(
            "per-target-time = 30\ncxx-std = \"gnu++14\"\nextra-include = [\"deps/include\"]\n",
        )
        .unwrap();
        assert_eq!(cfg.per_target_time, Some(30));
        assert_eq!(cfg.cxx_std.as_deref(), Some("gnu++14"));
        assert_eq!(
            cfg.extra_include.unwrap(),
            vec![PathBuf::from("deps/include")]
        );
        assert!(toml::from_str::<AutoConfig>("bogus-key = 1\n").is_err());
    }
}
