// SPDX-License-Identifier: Apache-2.0

//! Toolchain preflight: which language lanes the discovered targets use, and whether
//! their required toolchains are installed — reported once at run start so a MISSING
//! toolchain is an explicit banner, not a silent per-target skip that reads like a
//! pass. Also feeds the end-of-run triage.

use crate::auto::candidate::{Candidate, Lang};

/// One language lane's toolchain status.
pub struct LaneStatus {
    pub lang: &'static str,
    pub targets: usize,
    /// Missing required tools (a group where NONE of the alternatives is installed).
    pub missing: Vec<&'static str>,
    pub install_hint: &'static str,
}

impl LaneStatus {
    pub fn ok(&self) -> bool {
        self.missing.is_empty()
    }
}

pub struct PreflightReport {
    pub lanes: Vec<LaneStatus>,
}

impl PreflightReport {
    /// Lanes with targets but a missing toolchain — those targets can't build/fuzz.
    pub fn missing_lanes(&self) -> impl Iterator<Item = &LaneStatus> {
        self.lanes.iter().filter(|l| !l.ok())
    }

    pub fn any_missing(&self) -> bool {
        self.lanes.iter().any(|l| !l.ok())
    }

    /// One informational line per present lane.
    pub fn render(&self) -> String {
        if self.lanes.is_empty() {
            return String::new();
        }
        let mut out = String::from("govfuzz auto: toolchain check\n");
        for lane in &self.lanes {
            if lane.ok() {
                out.push_str(&format!(
                    "  {:<6} ({} targets): ok\n",
                    lane.lang, lane.targets
                ));
            } else {
                out.push_str(&format!(
                    "  {:<6} ({} targets): MISSING {} — install: {}\n",
                    lane.lang,
                    lane.targets,
                    lane.missing.join(", "),
                    lane.install_hint,
                ));
            }
        }
        out
    }
}

fn have(tool: &str) -> bool {
    which::which(tool).is_ok()
}

/// `Some(display)` when a required tool group is satisfied by any alternative; `None`
/// (i.e. missing) reports the FIRST alternative as the canonical name to install.
fn missing_group<'a>(alternatives: &[&'a str]) -> Option<&'a str> {
    if alternatives.iter().any(|t| have(t)) {
        None
    } else {
        alternatives.first().copied()
    }
}

/// The required toolchain groups (each group = interchangeable alternatives) and the
/// install hint for a language lane.
fn requirements(
    lang: Lang,
) -> (
    &'static str,
    &'static [&'static [&'static str]],
    &'static str,
) {
    match lang {
        Lang::Ada => (
            "Ada",
            &[&["gnat", "gnatmake"], &["gprbuild"]],
            "apt-get install gnat gprbuild",
        ),
        Lang::C => (
            "C",
            &[&["clang", "cc", "gcc"], &["make"]],
            "apt-get install clang make",
        ),
        Lang::Cpp => (
            "C++",
            &[&["clang++", "c++", "g++"], &["make"]],
            "apt-get install clang make",
        ),
        Lang::Rust => (
            "Rust",
            &[&["cargo"]],
            "install rustup + a nightly toolchain (rustup toolchain install nightly)",
        ),
        Lang::Java => (
            "Java",
            &[&["javac"], &["java"]],
            "install a JDK (apt-get install default-jdk)",
        ),
        Lang::Python => (
            "Python",
            &[&["python3"]],
            "install python3 (3.12+ for sys.monitoring coverage)",
        ),
        Lang::Perl => ("Perl", &[&["perl"]], "install perl"),
        Lang::Go => ("Go", &[&["go"]], "install go"),
        Lang::Cobol => ("COBOL", &[&["cobc"]], "apt-get install gnucobol"),
    }
}

/// Fixed lane display order.
const LANES: [Lang; 9] = [
    Lang::Ada,
    Lang::C,
    Lang::Cpp,
    Lang::Rust,
    Lang::Java,
    Lang::Python,
    Lang::Perl,
    Lang::Go,
    Lang::Cobol,
];

/// Build the preflight report from the discovered candidates (one lane per language
/// that actually has targets).
pub fn run(candidates: &[Candidate]) -> PreflightReport {
    let mut lanes = Vec::new();
    for lang in LANES {
        let targets = candidates.iter().filter(|c| c.lang == lang).count();
        if targets == 0 {
            continue;
        }
        let (name, groups, hint) = requirements(lang);
        let missing: Vec<&'static str> = groups.iter().filter_map(|g| missing_group(g)).collect();
        lanes.push(LaneStatus {
            lang: name,
            targets,
            missing,
            install_hint: hint,
        });
    }
    PreflightReport { lanes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_group_reports_first_alternative_when_none_present() {
        assert_eq!(
            missing_group(&["definitely-not-a-real-tool-xyz"]),
            Some("definitely-not-a-real-tool-xyz")
        );
        // `sh` is on every unix host used here.
        assert_eq!(missing_group(&["sh"]), None);
        // Any alternative present satisfies the group.
        assert_eq!(missing_group(&["nope-xyz", "sh"]), None);
    }

    #[test]
    fn render_marks_ok_and_missing_lanes() {
        let report = PreflightReport {
            lanes: vec![
                LaneStatus {
                    lang: "C++",
                    targets: 12,
                    missing: vec!["clang++"],
                    install_hint: "apt-get install clang make",
                },
                LaneStatus {
                    lang: "Ada",
                    targets: 3,
                    missing: vec![],
                    install_hint: "",
                },
            ],
        };
        let text = report.render();
        assert!(text.contains("C++") && text.contains("MISSING clang++"));
        assert!(text.contains("Ada") && text.contains("(3 targets): ok"));
        assert!(report.any_missing());
        assert_eq!(report.missing_lanes().count(), 1);
    }
}
