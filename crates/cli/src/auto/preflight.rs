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
    // A few tools are installed somewhere the build step knows about but PATH
    // does not. Resolving them here with the SAME function the build uses is
    // what keeps the banner and the run from disagreeing — a lane reported
    // MISSING that then builds fine teaches operators to ignore the banner.
    match tool {
        "sharpfuzz" => crate::auto::csharp_build::locate_sharpfuzz().is_some(),
        _ => which::which(tool).is_ok(),
    }
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

/// The C# lane's install hint.
///
/// Named separately because it is the one hint that cannot be a single package
/// command. Two things the old hint got wrong on an offline host, which is where
/// this lane is most often set up:
///
///   * `dotnet tool install --global` needs the network, so the stated fix was
///     impossible on exactly the machines that see it most;
///   * it omitted NuGet entirely. The generated harness references
///     `SharpFuzz 2.3.0` plus every `<PackageReference>` copied from the target's
///     csproj, so `dotnet build` restores — and an offline host with both `dotnet`
///     and `sharpfuzz` present passes preflight and then fails EVERY target at
///     restore. Naming it here is the difference between one staging trip and
///     three.
const CSHARP_HINT: &str = concat!(
    "install the .NET SDK + `dotnet tool install --global SharpFuzz.CommandLine`; ",
    "offline: extract the SDK tarball and set DOTNET_ROOT, copy ~/.dotnet/tools (incl. .store) ",
    "from a staging host, and stage the NuGet packages the harness restores ",
    "(SharpFuzz 2.3.0 + the target's own PackageReferences) into NUGET_PACKAGES",
);

/// The required toolchain groups (each group = interchangeable alternatives) and the
/// install hint for a language lane.
fn requirements(
    lang: Lang,
) -> (
    &'static str,
    &'static [&'static [&'static str]],
    &'static str,
) {
    let (name, groups): (&'static str, &'static [&'static [&'static str]]) = match lang {
        Lang::Ada => ("Ada", &[&["gnat", "gnatmake"], &["gprbuild"]]),
        Lang::C => ("C", &[&["clang", "cc", "gcc"], &["make"]]),
        Lang::Cpp => ("C++", &[&["clang++", "c++", "g++"], &["make"]]),
        Lang::Rust => ("Rust", &[&["cargo"]]),
        Lang::Java => ("Java", &[&["javac"], &["java"]]),
        Lang::Python => ("Python", &[&["python3"]]),
        Lang::Perl => ("Perl", &[&["perl"]]),
        Lang::Go => ("Go", &[&["go"]]),
        Lang::Cobol => ("COBOL", &[&["cobc"]]),
        Lang::Fortran => ("Fortran", &[&["gfortran"]]),
        Lang::CSharp => ("C#", &[&["dotnet"], &["sharpfuzz"]]),
        Lang::Js => ("JavaScript", &[&["node"]]),
        Lang::Ts => ("TypeScript", &[&["node"], &["esbuild"]]),
        Lang::Ruby => ("Ruby", &[&["ruby"]]),
        Lang::Lua => ("Lua", &[&["lua", "lua5.4", "lua5.3"]]),
        Lang::Php => ("PHP", &[&["php"]]),
    };
    (name, groups, install_hint(lang, cfg!(windows)))
}

fn install_hint(lang: Lang, windows: bool) -> &'static str {
    if windows {
        return match lang {
            Lang::C | Lang::Cpp => {
                "install LLVM, VS 2022 Build Tools/Windows SDK, and GNU make (winget/Chocolatey + w64devkit)"
            }
            Lang::Ada => "install a Windows GNAT toolchain and GPRbuild",
            Lang::Rust => {
                "install rustup + a nightly toolchain (rustup toolchain install nightly)"
            }
            Lang::Java => "install a Windows JDK",
            Lang::Python => "install Python 3.12+ for sys.monitoring coverage",
            Lang::Perl => "install a Windows Perl distribution",
            Lang::Go => "install Go for Windows",
            Lang::Cobol => "install a Windows GnuCOBOL toolchain or use WSL/Linux",
            Lang::Fortran => "install a Windows gfortran toolchain or use WSL/Linux",
            Lang::CSharp => CSHARP_HINT,
            Lang::Js => "install Node.js for Windows",
            Lang::Ts => "install Node.js + esbuild (`npm i -g esbuild`)",
            Lang::Ruby => "install Ruby 2.0+ for Windows",
            Lang::Lua => "install Lua 5.3+ for Windows",
            Lang::Php => "install PHP 8.0+ and the pcov extension for Windows",
        };
    }
    match lang {
        Lang::Ada => "install GNAT and GPRbuild with your OS package manager",
        Lang::C | Lang::Cpp => {
            "install clang and make (RHEL 7: LLVM Toolset 7 clang + compiler-rt; RHEL 8+: `dnf install clang llvm make`; Ubuntu: `apt-get install clang make`)"
        }
        Lang::Rust => "install rustup + a nightly toolchain (rustup toolchain install nightly)",
        Lang::Java => {
            "install a JDK (RHEL: `dnf install java-17-openjdk-devel`; Ubuntu: `apt-get install default-jdk`)"
        }
        Lang::Python => "install python3 (3.12+ for sys.monitoring coverage)",
        Lang::Perl => "install perl",
        Lang::Go => "install go",
        Lang::Cobol => "install GnuCOBOL with your OS package manager",
        Lang::Fortran => "install gfortran with your OS package manager",
        Lang::CSharp => CSHARP_HINT,
        Lang::Js => "install Node.js",
        Lang::Ts => "install Node.js + esbuild (`npm i -g esbuild`)",
        Lang::Ruby => "install Ruby 2.0+ with your OS package manager",
        Lang::Lua => "install Lua 5.3+ with your OS package manager",
        Lang::Php => "install PHP 8.0+ and the pcov extension with your OS package manager",
    }
}

/// Fixed lane display order.
const LANES: [Lang; 16] = [
    Lang::Ada,
    Lang::C,
    Lang::Cpp,
    Lang::Rust,
    Lang::Java,
    Lang::Python,
    Lang::Perl,
    Lang::Go,
    Lang::Cobol,
    Lang::Fortran,
    Lang::CSharp,
    Lang::Js,
    Lang::Ts,
    Lang::Ruby,
    Lang::Lua,
    Lang::Php,
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

    /// `have` reads HOME/PATH, so the tests that rewrite them cannot overlap.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn missing_group_reports_first_alternative_when_none_present() {
        // Resolves `sh` on PATH, and a sibling test rewrites PATH: env is
        // process-global, so both must hold the same lock or they race.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    fn sharpfuzz_resolves_where_dotnet_installs_it_not_only_on_path() {
        // `dotnet tool install --global` writes to ~/.dotnet/tools, which is not
        // on PATH by default. Preflight used `which` alone and reported MISSING
        // for a host whose C# lane then built and fuzzed fine.
        let home = std::env::temp_dir().join(format!(
            "govfuzz-preflight-sharpfuzz-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let tools = home.join(".dotnet").join("tools");
        std::fs::create_dir_all(&tools).unwrap();

        // Isolate from the real environment: empty PATH, HOME pointed at the
        // fixture. Serialised against the other env-mutating test below.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let old_home = std::env::var_os("HOME");
        let old_path = std::env::var_os("PATH");
        std::env::set_var("HOME", &home);
        std::env::set_var("PATH", "");

        assert!(!have("sharpfuzz"), "no shim staged yet");
        std::fs::write(tools.join("sharpfuzz"), b"#!/bin/sh\n").unwrap();
        assert!(
            have("sharpfuzz"),
            "the shim dotnet actually installs must satisfy preflight"
        );
        // A tool with no special resolution is unaffected by the fallback.
        assert!(!have("definitely-not-a-real-tool-xyz"));

        match old_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match old_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn install_hints_carry_no_stray_whitespace() {
        // A `\`-continued literal keeps its source indentation INSIDE the string
        // if rustfmt joins the lines, and the hint is printed verbatim in the
        // banner. This caught exactly that on the C# hint.
        for lang in LANES {
            let (name, _, hint) = requirements(lang);
            assert!(
                !hint.contains("  "),
                "{name} hint has a double space: {hint}"
            );
        }
    }

    #[test]
    fn the_csharp_hint_covers_the_offline_path_and_the_nuget_requirement() {
        let (_, _, hint) = requirements(Lang::CSharp);
        // The online one-liner stays for the common case...
        assert!(hint.contains("dotnet tool install --global SharpFuzz.CommandLine"));
        // ...but an offline host cannot run it, and needs to be told so.
        assert!(hint.contains("offline"), "{hint}");
        assert!(hint.contains("DOTNET_ROOT"), "{hint}");
        // The requirement preflight does NOT probe, and that fails every target
        // at restore once dotnet and sharpfuzz are both present.
        assert!(hint.contains("NUGET_PACKAGES"), "{hint}");
        assert!(hint.contains("SharpFuzz 2.3.0"), "{hint}");
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

    #[test]
    fn windows_hints_never_recommend_apt_get() {
        for lang in LANES {
            let hint = install_hint(lang, true);
            assert!(!hint.contains("apt-get"), "{lang:?}: {hint}");
        }
        let c = install_hint(Lang::C, true);
        assert!(c.contains("LLVM"));
        assert!(c.contains("VS 2022 Build Tools"));
        assert!(c.contains("GNU make"));
    }

    #[test]
    fn linux_c_hint_covers_rhel_and_ubuntu() {
        let hint = install_hint(Lang::C, false);
        assert!(hint.contains("RHEL 7"));
        assert!(hint.contains("RHEL 8+"));
        assert!(hint.contains("Ubuntu"));
    }
}
