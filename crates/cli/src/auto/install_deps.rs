// SPDX-License-Identifier: Apache-2.0

//! `--install-deps`: best-effort fetch of the dependencies the run recorded in
//! the missing-dependency manifest, using whatever package managers are present.
//!
//! Opt-in and online — the only part of `auto` that touches the network. From
//! the manifest, each dependency we can map to a concrete fetch (apt package for
//! a known header/lib, `alr get` for an Ada unit, ...) becomes an `InstallPlan`;
//! plans whose manager is on PATH are executed, the rest are reported with the
//! command to run by hand. Nothing is fatal: a manager that fails (no root for
//! apt, offline, unknown package) is recorded and the run continues. After
//! installing, re-run `govfuzz auto` to build against the real dependencies.

use crate::auto::dep_manifest::{DepEntry, DepKind, DependencyManifest};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Manager {
    Apt,
    Alr,
    Pip,
    Npm,
}

impl Manager {
    fn program(&self) -> &'static str {
        match self {
            Manager::Apt => "apt-get",
            Manager::Alr => "alr",
            Manager::Pip => "pip3",
            Manager::Npm => "npm",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallPlan {
    pub dep_name: String,
    pub manager: Manager,
    pub command: Vec<String>,
}

#[derive(Debug, Default)]
pub struct InstallReport {
    pub installed: Vec<String>,
    /// (dep, reason)
    pub failed: Vec<(String, String)>,
    /// deps with no auto-install mapping, with the manual hint to use.
    pub unmapped: Vec<(String, String)>,
}

impl InstallReport {
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "install-deps: {} installed, {} failed, {} need manual acquisition\n",
            self.installed.len(),
            self.failed.len(),
            self.unmapped.len(),
        ));
        for d in &self.installed {
            out.push_str(&format!("  installed: {d}\n"));
        }
        for (d, why) in &self.failed {
            out.push_str(&format!("  FAILED:    {d}  ({why})\n"));
        }
        for (d, hint) in &self.unmapped {
            out.push_str(&format!("  manual:    {d}  — {hint}\n"));
        }
        if !self.installed.is_empty() {
            out.push_str("re-run `govfuzz auto` to build against the installed dependencies.\n");
        }
        out
    }
}

/// Map the manifest's still-blocking dependencies to concrete fetch commands.
/// Only dependencies with a confident, executable mapping get a plan; the rest
/// are returned as `unmapped` (dep, manual-hint). Stubbed deps are skipped —
/// the build already continued past them; fetching the real one is optional.
pub fn plan_installs(manifest: &DependencyManifest) -> (Vec<InstallPlan>, Vec<(String, String)>) {
    let mut plans = Vec::new();
    let mut unmapped = Vec::new();
    for entry in manifest.entries.iter().filter(|e| !e.stubbed) {
        match install_command(entry) {
            Some((manager, command)) => plans.push(InstallPlan {
                dep_name: entry.name.clone(),
                manager,
                command,
            }),
            None => unmapped.push((
                entry.name.clone(),
                entry
                    .acquisition_hint
                    .clone()
                    .unwrap_or_else(|| "no known acquisition method".to_owned()),
            )),
        }
    }
    (plans, unmapped)
}

/// The concrete `(manager, argv)` to fetch `entry`, or None when there's no
/// confident automatic mapping (the caller falls back to the manual hint).
fn install_command(entry: &DepEntry) -> Option<(Manager, Vec<String>)> {
    let name = entry.name.as_str();
    match entry.kind {
        DepKind::SharedLibrary | DepKind::Header | DepKind::PkgConfig => {
            apt_package_for(entry.kind, name).map(|pkg| {
                (
                    Manager::Apt,
                    vec!["apt-get".into(), "install".into(), "-y".into(), pkg],
                )
            })
        }
        DepKind::AdaUnit => {
            // GNAT child units belong to the root unit's Alire crate.
            let root = name
                .to_ascii_lowercase()
                .split(['.', '-'])
                .next()
                .unwrap_or(name)
                .to_owned();
            Some((Manager::Alr, vec!["alr".into(), "get".into(), root]))
        }
        // Env vars, paths, symlinks, shares, endpoints, dlopen, codegen, types,
        // macros, symbols, generic gpr imports: no safe automatic fetch.
        _ => None,
    }
}

/// Debian/Ubuntu `-dev` package for a well-known header/library/pkg-config name.
/// Conservative: only names we're confident about, so we never `apt-get install`
/// a wrong/typo'd package.
fn apt_package_for(kind: DepKind, name: &str) -> Option<String> {
    let lname = name.to_ascii_lowercase();
    let leaf = lname.rsplit('/').next().unwrap_or(&lname);
    let top = lname.split('/').next().unwrap_or(&lname);
    let known = |n: &str| -> Option<&'static str> {
        match n {
            "z" | "libz" | "zlib" | "zlib.h" => Some("zlib1g-dev"),
            "ssl" | "crypto" | "libssl" | "libcrypto" | "openssl" => Some("libssl-dev"),
            "pcre2" | "libpcre2" => Some("libpcre2-dev"),
            "xml2" | "libxml2" => Some("libxml2-dev"),
            "curl" | "libcurl" => Some("libcurl4-openssl-dev"),
            "ace" => Some("libace-dev"),
            _ => None,
        }
    };
    let pkg = match kind {
        DepKind::SharedLibrary => known(&lname),
        DepKind::Header => known(leaf).or_else(|| known(top)),
        DepKind::PkgConfig => known(&lname),
        _ => None,
    };
    pkg.map(str::to_owned)
}

/// Whether `program` is an executable on `$PATH`.
pub fn on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate: PathBuf = dir.join(program);
        candidate.is_file()
    })
}

/// Execute every plan whose manager is available; record installed / failed /
/// unmapped. `run` indirection so tests can exercise planning without touching
/// the network.
pub fn run_installs(manifest: &DependencyManifest) -> InstallReport {
    let (plans, mut unmapped) = plan_installs(manifest);
    let mut report = InstallReport::default();
    for plan in plans {
        if !on_path(plan.manager.program()) {
            unmapped.push((
                plan.dep_name.clone(),
                format!(
                    "{} not on PATH; run: {}",
                    plan.manager.program(),
                    plan.command.join(" ")
                ),
            ));
            continue;
        }
        gfeprintln!(
            "govfuzz auto: installing '{}': {}",
            plan.dep_name,
            plan.command.join(" ")
        );
        match crate::command_output::output_with_timeout(
            Command::new(&plan.command[0]).args(&plan.command[1..]),
            std::time::Duration::from_secs(30 * 60),
        ) {
            Ok(out) if out.status.success() => report.installed.push(plan.dep_name),
            Ok(out) => {
                let tail = String::from_utf8_lossy(&out.stderr);
                let tail = tail
                    .trim()
                    .lines()
                    .last()
                    .unwrap_or("non-zero exit")
                    .to_owned();
                report.failed.push((plan.dep_name, tail));
            }
            Err(e) => report.failed.push((plan.dep_name, e.to_string())),
        }
    }
    report.unmapped = unmapped;
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::dep_manifest::DependencyManifest;

    #[test]
    fn plans_apt_for_known_lib_and_alr_for_ada_unit_skips_the_rest() {
        let mut m = DependencyManifest::new();
        m.push(DepKind::SharedLibrary, "z", vec!["H1".into()], false);
        m.push(DepKind::AdaUnit, "Util.Encoders", vec!["H2".into()], false);
        m.push(
            DepKind::SharedLibrary,
            "some_unknown_lib",
            vec!["H3".into()],
            false,
        );
        m.push(DepKind::EnvVar, "ACE_ROOT", vec!["build".into()], false);
        // A stubbed dep is not fetched (build already continued past it).
        m.push(DepKind::Header, "zlib.h", vec!["H4".into()], true);

        let (plans, unmapped) = plan_installs(&m);

        let apt = plans
            .iter()
            .find(|p| p.manager == Manager::Apt)
            .expect("apt plan");
        assert_eq!(apt.command, vec!["apt-get", "install", "-y", "zlib1g-dev"]);
        let alr = plans
            .iter()
            .find(|p| p.manager == Manager::Alr)
            .expect("alr plan");
        assert_eq!(alr.command, vec!["alr", "get", "util"]);
        // Unknown lib + env var fall to unmapped; the stubbed header is excluded.
        let unmapped_names: Vec<&str> = unmapped.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            unmapped_names.contains(&"some_unknown_lib"),
            "{unmapped_names:?}"
        );
        assert!(unmapped_names.contains(&"ACE_ROOT"), "{unmapped_names:?}");
        assert!(
            !plans.iter().any(|p| p.dep_name == "zlib.h"),
            "stubbed dep must not be planned"
        );
        assert_eq!(plans.len(), 2);
    }

    #[test]
    fn on_path_finds_a_real_program_and_misses_a_fake_one() {
        assert!(on_path("sh"), "sh should be on PATH");
        assert!(!on_path("definitely-not-a-real-program-xyzzy"));
    }
}
