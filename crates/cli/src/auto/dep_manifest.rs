// SPDX-License-Identifier: Apache-2.0

//! The consolidated missing-dependency manifest for an offline fuzz lab.
//!
//! `govfuzz auto` builds as far as it can, stubbing whatever a target needs but
//! the tree doesn't provide, and records every such dependency here. The point
//! is the air-gapped workflow: instead of "build, hit a missing dep, copy it
//! over, build again, hit the next one", a single run surfaces *all* missing
//! dependencies at once — each marked whether govfuzz stubbed it (build
//! continued) or it is still blocking — with a best-effort hint for how to
//! acquire the real thing. The user brings them all over in one trip (or lets
//! `--install-deps` fetch them), then re-runs against the real deps.
//!
//! Written to `<work>/auto/missing-deps.txt` (human) and `missing-deps.json`
//! (machine / `--install-deps`).

use serde::{Deserialize, Serialize};

/// What kind of external dependency was needed. Extensible: new build-time
/// discoveries (env vars, symlinks, network shares, codegen tools) get a kind
/// here so they all funnel into the one manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepKind {
    /// A compiler, linker, build driver, or language runtime executable required
    /// to build the discovered language lane on this host.
    Toolchain,
    /// A target ABI/runtime (including an emulator) required to execute the real
    /// target behavior instead of a host-side replacement.
    Runtime,
    /// Source produced by configure, an IDL compiler, an autocoder, or another
    /// project generator. This is separate from an ordinary missing header so it
    /// is not incorrectly presented as an installable distro package.
    GeneratedSource,
    /// Semantically significant dependency source declared by the project but
    /// absent from the source drop (for example an unfetched Git submodule or
    /// Alire crate).
    VendorSource,
    Header,
    CType,
    Macro,
    Symbol,
    SharedLibrary,
    GprImport,
    AdaUnit,
    /// An environment variable the build (gpr `external`, makefile `$(VAR)`) or
    /// the runtime (`getenv` returning NULL) needed.
    EnvVar,
    /// A filesystem path (file or directory) the build/runtime needed.
    FilePath,
    /// A path that resolved to a dangling symlink.
    Symlink,
    /// A path on a network mount (NFS/SMB: `//host/share`, `/mnt`, `/net`, ...).
    NetworkShare,
    /// A network endpoint the runtime tried to reach (`connect`/`getaddrinfo`).
    NetworkEndpoint,
    /// A library a `dlopen` couldn't load.
    DlopenLibrary,
    /// A code-generation/build tool the project needs run (fpp-to-cpp, alr, ...).
    CodegenTool,
    /// A package from a language ecosystem the interpreted lanes load at runtime
    /// (a RubyGem, a PyPI distribution, an npm package, a CPAN module, a
    /// LuaRock, a Composer package). Distinct from a shared library: it is
    /// acquired with the language's own package manager, and its absence stops
    /// the target from loading at all.
    LanguagePackage,
    /// A `pkg-config` module the build queried.
    PkgConfig,
    /// A CORBA/IDL interface whose generated stub (`<base>C.h`/`<base>S.h` from
    /// `<base>.idl`) is absent — the `.idl` and its compiled output aren't in the
    /// tree, so the IDL-defined types can't be built or fuzzed without them.
    IdlInterface,
    Other,
}

impl DepKind {
    /// Short human label for the text manifest.
    pub fn label(self) -> &'static str {
        match self {
            DepKind::Toolchain => "toolchain",
            DepKind::Runtime => "runtime",
            DepKind::GeneratedSource => "generated source",
            DepKind::VendorSource => "vendor/project source",
            DepKind::Header => "header",
            DepKind::CType => "type",
            DepKind::Macro => "macro",
            DepKind::Symbol => "symbol",
            DepKind::SharedLibrary => "shared library",
            DepKind::GprImport => "gpr import",
            DepKind::AdaUnit => "ada unit",
            DepKind::EnvVar => "env var",
            DepKind::FilePath => "file/path",
            DepKind::Symlink => "symlink",
            DepKind::NetworkShare => "network share",
            DepKind::NetworkEndpoint => "network endpoint",
            DepKind::DlopenLibrary => "dlopen library",
            DepKind::CodegenTool => "codegen tool",
            DepKind::LanguagePackage => "language package",
            DepKind::PkgConfig => "pkg-config",
            DepKind::IdlInterface => "idl interface",
            DepKind::Other => "other",
        }
    }

    /// Requirements that must be supplied to exercise the project's real
    /// semantics on an offline host. These render before ordinary repair
    /// artifacts even when GovFuzz managed to substitute a reduced-fidelity
    /// implementation.
    pub fn is_critical_offline_requirement(self) -> bool {
        matches!(
            self,
            DepKind::Toolchain
                | DepKind::Runtime
                | DepKind::GeneratedSource
                | DepKind::VendorSource
                | DepKind::CodegenTool
                | DepKind::LanguagePackage
                | DepKind::IdlInterface
        )
    }
}

/// If `header` is a CORBA/IDL-generated stub header (`<base>C.h`/`<base>S.h` and
/// the `.hpp`/`.hxx`/`.cpp`/`.inl` variants the IDL compiler emits), return the
/// source `.idl` it was generated from (`bankC.h` -> `bank.idl`). The `C`/`S`
/// suffix (client stub / server skeleton) before the extension is TAO/tao_idl's
/// convention. `None` for ordinary headers.
pub fn corba_generated_idl(header: &str) -> Option<String> {
    let leaf = header.rsplit(['/', '\\']).next().unwrap_or(header);
    let (stem, ext) = leaf.rsplit_once('.')?;
    if !matches!(
        ext,
        "h" | "hpp" | "hxx" | "hh" | "cpp" | "cxx" | "inl" | "i"
    ) {
        return None;
    }
    // Stem must end in C or S, with a real base before it.
    let base = stem.strip_suffix('C').or_else(|| stem.strip_suffix('S'))?;
    if base.is_empty() {
        return None;
    }
    // Guard the obvious false positive: a single-letter `C.h`/`S.h` (no base) is
    // already excluded; require the base's last char to be alphanumeric/`_` so a
    // path-ish or punctuation tail doesn't match.
    if !base
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(format!("{base}.idl"))
}

/// Whether a missing-header spelling looks like a header produced by the
/// project's own configure/cmake step rather than something installable from a
/// distro package — autoconf's `config.h`, or the per-project `<name>_config.h`
/// / `<name>_build.h` family (c-ares' `ares_build.h` / `ares_config.h`, curl's
/// `curl_config.h`, ...). These have a `.in`/`.dist`/`.cmake` template in the
/// tree but no compiled output until `./configure` (or cmake) runs, so the only
/// real fix is to run that step (or supply the generated header) — never apt.
/// Conservative by design: matched on the basename so a path prefix can't fool
/// it, and on high-precision stems so an ordinary in-tree header isn't mislabeled.
pub fn is_configure_generated_header(header: &str) -> bool {
    let leaf = header.rsplit(['/', '\\']).next().unwrap_or(header);
    let lower = leaf.to_ascii_lowercase();
    // Strip a trailing template extension a caller may pass through verbatim.
    let stem = lower
        .strip_suffix(".in")
        .or_else(|| lower.strip_suffix(".dist"))
        .unwrap_or(&lower);
    let stem = stem.strip_suffix(".h").unwrap_or(stem);
    stem == "config"
        || stem == "autoconfig"
        || stem.ends_with("_config")
        || stem.ends_with("-config")
        || stem.ends_with("_build")
        || stem.ends_with("_features")
}

/// How GovFuzz knows a requirement exists. This prevents a best-effort inference
/// from being presented with the same certainty as a project declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementBasis {
    Declared,
    Observed,
    Inferred,
}

impl RequirementBasis {
    fn label(self) -> &'static str {
        match self {
            RequirementBasis::Declared => "declared",
            RequirementBasis::Observed => "observed",
            RequirementBasis::Inferred => "inferred",
        }
    }

    fn rank(self) -> u8 {
        match self {
            RequirementBasis::Declared => 0,
            RequirementBasis::Observed => 1,
            RequirementBasis::Inferred => 2,
        }
    }
}

fn default_requirement_basis() -> RequirementBasis {
    RequirementBasis::Observed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepEntry {
    pub kind: DepKind,
    pub name: String,
    /// Harness ids / build phases that needed it (deduped).
    pub referenced_by: Vec<String>,
    /// True when govfuzz faked it so the build continued; false when it is still
    /// blocking (the user must supply the real thing to make progress).
    pub stubbed: bool,
    /// Best-effort hint for obtaining the real dependency offline (an apt package,
    /// an `alr get`, a pkg-config name, a path to place a file). `None` when no
    /// confident hint is known.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub acquisition_hint: Option<String>,
    /// Whether this came from project metadata, an actual build/runtime
    /// diagnostic, or a conservative inference from naming/source context.
    #[serde(default = "default_requirement_basis")]
    pub basis: RequirementBasis,
    /// Concise source of truth: manifest path/line, diagnostic, guard, or
    /// preflight probe. Kept machine-readable and shown in the text report.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub evidence: Option<String>,
}

fn manifest_schema_version() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyManifest {
    #[serde(default = "manifest_schema_version")]
    pub schema_version: u32,
    /// False for an in-progress checkpoint. True only after final report
    /// generation completed for the recorded target set.
    #[serde(default)]
    pub complete: bool,
    /// Number of completed target attempts folded into this checkpoint.
    #[serde(default)]
    pub completed_targets: usize,
    pub entries: Vec<DepEntry>,
}

impl Default for DependencyManifest {
    fn default() -> Self {
        Self {
            schema_version: manifest_schema_version(),
            complete: false,
            completed_targets: 0,
            entries: Vec::new(),
        }
    }
}

impl DependencyManifest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry, filling its acquisition hint. Entries are kept in insertion
    /// order; callers dedupe upstream (one entry per name+kind).
    pub fn push(
        &mut self,
        kind: DepKind,
        name: impl Into<String>,
        referenced_by: Vec<String>,
        stubbed: bool,
    ) {
        let name = name.into();
        let acquisition_hint = acquisition_hint(kind, &name);
        self.entries.push(DepEntry {
            kind,
            name,
            referenced_by,
            stubbed,
            acquisition_hint,
            basis: RequirementBasis::Observed,
            evidence: None,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether an entry with this kind+name is already recorded (for dedup across
    /// the ledger fold and the source-scan passes).
    pub fn has(&self, kind: DepKind, name: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.kind == kind && e.name == name)
    }

    /// Add, or merge into an existing same-kind+name entry: union the
    /// `referenced_by` lists and let a still-blocking sighting win over a stubbed
    /// one (if any target genuinely needs the real dependency, flag it as needed).
    /// Used when the same dependency surfaces from multiple passes.
    pub fn push_merge(
        &mut self,
        kind: DepKind,
        name: impl Into<String>,
        referenced_by: Vec<String>,
        stubbed: bool,
    ) {
        self.push_merge_with_hint(kind, name, referenced_by, stubbed, None);
    }

    /// As [`push_merge`], but with an explicit acquisition hint overriding the
    /// per-kind default. Used when the caller has tree context the generic hinter
    /// lacks — e.g. a `./configure`/cmake template found beside a missing header,
    /// which turns a useless `apt-file search` hint into "run configure to
    /// generate it". `None` falls back to the computed default.
    pub fn push_merge_with_hint(
        &mut self,
        kind: DepKind,
        name: impl Into<String>,
        referenced_by: Vec<String>,
        stubbed: bool,
        hint: Option<String>,
    ) {
        self.push_merge_detailed(
            kind,
            name,
            referenced_by,
            stubbed,
            hint,
            RequirementBasis::Observed,
            None,
        );
    }

    /// Add or merge a requirement while retaining its provenance. A stronger
    /// basis (declared > observed > inferred) wins when multiple discovery paths
    /// identify the same requirement.
    #[allow(clippy::too_many_arguments)]
    pub fn push_merge_detailed(
        &mut self,
        kind: DepKind,
        name: impl Into<String>,
        referenced_by: Vec<String>,
        stubbed: bool,
        hint: Option<String>,
        basis: RequirementBasis,
        evidence: Option<String>,
    ) {
        let name = name.into();
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.kind == kind && e.name == name)
        {
            let previous_basis_rank = e.basis.rank();
            // An early declaration scan can only say an output is absent. Once
            // an actual target proves GovFuzz substituted that same critical
            // requirement, promote it from "blocking" to "substituted". Any
            // later real blocker still wins and moves it back to blocking.
            let declaration_only = e.kind.is_critical_offline_requirement()
                && !e.stubbed
                && !e.referenced_by.iter().any(|r| r.starts_with("H-"));
            for r in referenced_by {
                if !e.referenced_by.contains(&r) {
                    e.referenced_by.push(r);
                }
            }
            e.stubbed = if declaration_only && stubbed {
                true
            } else {
                e.stubbed && stubbed
            };
            if hint.is_some()
                && (e.acquisition_hint.is_none() || basis.rank() <= previous_basis_rank)
            {
                e.acquisition_hint = hint;
            }
            if basis.rank() < e.basis.rank() {
                e.basis = basis;
            }
            if evidence.is_some() && (e.evidence.is_none() || basis.rank() <= previous_basis_rank) {
                e.evidence = evidence;
            }
        } else {
            let acquisition_hint = hint.or_else(|| acquisition_hint(kind, &name));
            self.entries.push(DepEntry {
                kind,
                name,
                referenced_by,
                stubbed,
                acquisition_hint,
                basis,
                evidence,
            });
        }
    }

    /// Merge another checkpoint/seed into this manifest.
    pub fn merge_from(&mut self, other: &DependencyManifest) {
        for entry in &other.entries {
            self.push_merge_detailed(
                entry.kind,
                entry.name.clone(),
                entry.referenced_by.clone(),
                entry.stubbed,
                entry.acquisition_hint.clone(),
                entry.basis,
                entry.evidence.clone(),
            );
        }
        self.completed_targets = self.completed_targets.max(other.completed_targets);
        self.complete |= other.complete;
    }

    pub fn mark_checkpoint(&mut self, completed_targets: usize, complete: bool) {
        self.schema_version = manifest_schema_version();
        self.completed_targets = completed_targets;
        self.complete = complete;
    }

    pub fn stubbed_count(&self) -> usize {
        self.entries.iter().filter(|e| e.stubbed).count()
    }

    pub fn blocking_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.stubbed).count()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_owned())
    }

    /// Human-readable manifest. Toolchains/runtimes and semantic generated/vendor
    /// source are deliberately first, followed by ordinary blockers and then
    /// reduced-fidelity substitutions.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("GovFuzz missing-dependency manifest\n");
        out.push_str("===================================\n\n");
        out.push_str(&format!(
            "Checkpoint: {} target(s) completed; {}.\n\n",
            self.completed_targets,
            if self.complete {
                "final"
            } else {
                "run still in progress"
            }
        ));
        if self.entries.is_empty() {
            out.push_str(
                "No external dependencies were missing — the tree built against its own sources.\n",
            );
            return out;
        }
        out.push_str(&format!(
            "{} external dependenc{} needed: {} still blocking, {} stubbed (build continued).\n\n",
            self.entries.len(),
            if self.entries.len() == 1 { "y" } else { "ies" },
            self.blocking_count(),
            self.stubbed_count(),
        ));

        let mut critical: Vec<&DepEntry> = self
            .entries
            .iter()
            .filter(|e| e.kind.is_critical_offline_requirement())
            .collect();
        let mut blockers: Vec<&DepEntry> = self
            .entries
            .iter()
            .filter(|e| !e.kind.is_critical_offline_requirement() && !e.stubbed)
            .collect();
        let mut substitutions: Vec<&DepEntry> = self
            .entries
            .iter()
            .filter(|e| !e.kind.is_critical_offline_requirement() && e.stubbed)
            .collect();
        let stable_sort = |items: &mut Vec<&DepEntry>| {
            items.sort_by(|a, b| {
                a.stubbed
                    .cmp(&b.stubbed)
                    .then_with(|| a.kind.label().cmp(b.kind.label()))
                    .then_with(|| a.name.cmp(&b.name))
            });
        };
        stable_sort(&mut critical);
        stable_sort(&mut blockers);
        stable_sort(&mut substitutions);

        let render_group = |out: &mut String, title: &str, entries: &[&DepEntry]| {
            if entries.is_empty() {
                return;
            }
            out.push_str(title);
            out.push('\n');
            out.push_str(&"-".repeat(title.len()));
            out.push_str("\n\n");
            for e in entries {
                let status = if e.stubbed {
                    if e.kind.is_critical_offline_requirement() {
                        "SUBSTITUTED - real semantics not exercised"
                    } else {
                        "stubbed"
                    }
                } else {
                    "STILL BLOCKING"
                };
                out.push_str(&format!(
                    "[{}] {} - {} ({})\n",
                    e.kind.label(),
                    e.name,
                    status,
                    e.basis.label()
                ));
                if !e.referenced_by.is_empty() {
                    let shown: Vec<&str> =
                        e.referenced_by.iter().take(6).map(String::as_str).collect();
                    let more = e.referenced_by.len().saturating_sub(shown.len());
                    let suffix = if more > 0 {
                        format!(" (+{more} more)")
                    } else {
                        String::new()
                    };
                    out.push_str(&format!(
                        "    referenced by: {}{}\n",
                        shown.join(", "),
                        suffix
                    ));
                }
                if let Some(hint) = &e.acquisition_hint {
                    out.push_str(&format!("    acquire: {hint}\n"));
                }
                if let Some(evidence) = &e.evidence {
                    out.push_str(&format!("    evidence: {evidence}\n"));
                }
            }
            out.push('\n');
        };
        render_group(
            &mut out,
            "Required toolchains, runtimes, generated and vendor source",
            &critical,
        );
        render_group(
            &mut out,
            "Other blocking build/runtime artifacts",
            &blockers,
        );
        render_group(&mut out, "Substituted fidelity gaps", &substitutions);
        out
    }
}

/// Best-effort hint for obtaining a dependency offline. Conservative: a small map
/// of well-known names plus a per-kind generic suggestion. Never claims more than
/// it knows — an unknown name gets a generic `apt-file search` / `alr get` style
/// pointer, which is still more useful than nothing for the offline-transfer
/// workflow.
pub fn acquisition_hint(kind: DepKind, name: &str) -> Option<String> {
    let lname = name.to_ascii_lowercase();
    // Well-known shared libs / headers -> Debian/Ubuntu -dev packages.
    let known_pkg = |n: &str| -> Option<&'static str> {
        match n {
            "z" | "libz" | "zlib" | "zlib.h" => Some("zlib1g-dev"),
            "ssl" | "crypto" | "libssl" | "libcrypto" => Some("libssl-dev"),
            "pthread" | "m" | "dl" | "rt" => Some("(libc — already present; drop the -l)"),
            "pcre" | "pcre2" => Some("libpcre2-dev"),
            "xml2" | "libxml2" => Some("libxml2-dev"),
            "curl" | "libcurl" => Some("libcurl4-openssl-dev"),
            "ace" => Some("libace-dev"),
            "tao" => Some("libtao-dev (or build ACE+TAO from source)"),
            _ => None,
        }
    };
    match kind {
        DepKind::Toolchain => Some(format!(
            "install a compatible '{name}' toolchain on the offline host and put it on PATH"
        )),
        DepKind::Runtime => Some(format!(
            "stage the compatible '{name}' runtime/SDK and its execution environment on the offline host"
        )),
        DepKind::GeneratedSource => Some(format!(
            "run the project generator that produces '{name}' on a connected/trusted build host, then transfer the output and its generator inputs"
        )),
        DepKind::VendorSource => Some(format!(
            "transfer the project-declared source for '{name}' at the revision/version pinned by the project"
        )),
        DepKind::SharedLibrary => Some(match known_pkg(&lname) {
            Some(pkg) => format!("apt-get install {pkg}  (or place lib{name}.so on the linker path)"),
            None => format!("apt-file search 'lib{name}.so'  (find the package providing it)"),
        }),
        DepKind::Header => {
            let leaf = lname.rsplit('/').next().unwrap_or(&lname);
            let top = lname.split('/').next().unwrap_or(&lname);
            // A configure/cmake-generated header (`config.h`, `ares_build.h`,
            // `ares_config.h`, ...) has no apt package — it's produced by the
            // project's own build system. Point the user at the real fix instead
            // of a dead-end `apt-file search`.
            if is_configure_generated_header(leaf) {
                return Some(format!(
                    "run the project's configure step (`./configure`, `cmake`, or `autoreconf -i \
                     && ./configure`) to generate '{name}', then re-run govfuzz with --probe-build \
                     / --consent-build; or copy the generated '{name}' into the tree"
                ));
            }
            Some(match known_pkg(leaf).or_else(|| known_pkg(top)) {
                Some(pkg) => format!("apt-get install {pkg}"),
                None => format!("apt-file search '{name}'  (find the package providing this header)"),
            })
        }
        DepKind::AdaUnit => {
            // GNAT child units use the root unit's crate (`util.encoders` ->
            // `util` / Alire crate `ada-util`); suggest the Alire fetch.
            let root = lname.split(['.', '-']).next().unwrap_or(&lname);
            Some(format!("alr get {root}  (or vendor the crate and pass --ada-deps <dir>)"))
        }
        DepKind::GprImport => Some(format!(
            "provide '{name}' (the dependency's project file) on GPR_PROJECT_PATH, or `alr get` the crate"
        )),
        DepKind::PkgConfig => Some(format!(
            "apt-file search '{name}.pc'  (install the -dev package providing the pkg-config module)"
        )),
        DepKind::EnvVar => Some(format!(
            "set {name} before the build/run (govfuzz used an empty/fake value)"
        )),
        DepKind::NetworkShare => Some(format!(
            "mount the share providing '{name}', or copy its contents locally"
        )),
        DepKind::Symlink => Some(format!(
            "recreate the symlink '{name}' (or copy its real target into place)"
        )),
        DepKind::IdlInterface => Some(format!(
            "bring '{name}' (and its IDL #includes), then re-run with --run-untrusted to compile it \
             (tao_idl / `govfuzz fake-corba --idl {name}`), or copy the generated C/S stub headers"
        )),
        DepKind::CodegenTool => Some(format!(
            "install '{name}' and re-run with --run-untrusted to generate its outputs"
        )),
        DepKind::LanguagePackage => Some(format!(
            "install the package providing '{name}' with the project's package manager \
             (bundle install / pip install / npm install / cpanm / luarocks / composer), \
             or run `govfuzz auto --install-deps`"
        )),
        DepKind::FilePath
        | DepKind::CType
        | DepKind::Macro
        | DepKind::Symbol
        | DepKind::NetworkEndpoint
        | DepKind::DlopenLibrary
        | DepKind::Other => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_blocking_before_stubbed_with_hints() {
        let mut m = DependencyManifest::new();
        m.push(
            DepKind::SharedLibrary,
            "ace",
            vec!["H-C001".into(), "H-C002".into()],
            true,
        );
        m.push(DepKind::Header, "tao/corba.h", vec!["H-C001".into()], false);
        m.push(
            DepKind::AdaUnit,
            "Util.Encoders",
            vec!["H-A003".into()],
            false,
        );

        let text = m.render_text();
        assert!(
            text.contains("3 external dependencies needed: 2 still blocking, 1 stubbed"),
            "{text}"
        );
        // Blocking entries come before stubbed.
        let tao = text.find("tao/corba.h").unwrap();
        let ace = text.find("[shared library] ace").unwrap();
        assert!(
            tao < ace,
            "blocking deps must list before stubbed ones:\n{text}"
        );
        // Hints are present and sensible.
        assert!(text.contains("apt-get install libtao-dev"), "{text}");
        assert!(text.contains("alr get util"), "{text}");
        assert_eq!(m.blocking_count(), 2);
        assert_eq!(m.stubbed_count(), 1);
    }

    #[test]
    fn corba_generated_idl_maps_stub_headers_to_their_idl() {
        assert_eq!(corba_generated_idl("bankC.h").as_deref(), Some("bank.idl"));
        assert_eq!(corba_generated_idl("bankS.h").as_deref(), Some("bank.idl"));
        assert_eq!(
            corba_generated_idl("dir/MessageC.hpp").as_deref(),
            Some("Message.idl")
        );
        assert_eq!(corba_generated_idl("FooS.cpp").as_deref(), Some("Foo.idl"));
        // Ordinary headers are not IDL stubs.
        assert_eq!(corba_generated_idl("stdio.h"), None);
        assert_eq!(corba_generated_idl("widget.h"), None);
        assert_eq!(corba_generated_idl("C.h"), None); // no base
        assert_eq!(corba_generated_idl("config"), None); // no extension
    }

    #[test]
    fn idl_interface_hint_points_at_the_idl_not_apt() {
        let mut m = DependencyManifest::new();
        m.push(DepKind::IdlInterface, "bank.idl", vec!["H1".into()], false);
        let hint = m.entries[0].acquisition_hint.as_deref().unwrap();
        assert!(
            hint.contains("bank.idl") && hint.contains("--run-untrusted"),
            "{hint}"
        );
        assert!(!hint.contains("apt-file"), "{hint}");
        assert!(m.has(DepKind::IdlInterface, "bank.idl"));
    }

    #[test]
    fn configure_generated_headers_are_recognised() {
        // c-ares / curl / autoconf generated headers.
        for h in [
            "ares_build.h",
            "ares_config.h",
            "src/lib/ares_build.h",
            "config.h",
            "curl_config.h",
            "lib/curl_config.h.in",
            "foo_features.h",
            "my-config.h",
        ] {
            assert!(is_configure_generated_header(h), "should match: {h}");
        }
        // Ordinary in-tree headers must NOT be mislabeled.
        for h in ["ares.h", "ares_dns.h", "stdio.h", "widget.h", "buildit.h"] {
            assert!(!is_configure_generated_header(h), "should not match: {h}");
        }
    }

    #[test]
    fn generated_header_hint_points_at_configure_not_apt() {
        let mut m = DependencyManifest::new();
        m.push(DepKind::Header, "ares_build.h", vec!["H1".into()], false);
        let hint = m.entries[0].acquisition_hint.as_deref().unwrap();
        assert!(hint.contains("configure"), "{hint}");
        assert!(hint.contains("--probe-build"), "{hint}");
        assert!(!hint.contains("apt-file"), "{hint}");
        // An ordinary missing header still gets the apt-file pointer.
        let mut m = DependencyManifest::new();
        m.push(
            DepKind::Header,
            "hiredis/hiredis.h",
            vec!["H1".into()],
            false,
        );
        assert!(m.entries[0]
            .acquisition_hint
            .as_deref()
            .unwrap()
            .contains("apt-file"));
    }

    #[test]
    fn push_merge_with_hint_overrides_default_and_merges_refs() {
        let mut m = DependencyManifest::new();
        m.push_merge_with_hint(
            DepKind::Header,
            "ares_build.h",
            vec!["H1".into()],
            false,
            Some("run ./configure to generate it".to_owned()),
        );
        // Merging a second sighting unions refs and keeps a still-blocking flag,
        // and an explicit hint overrides the prior one.
        m.push_merge_with_hint(
            DepKind::Header,
            "ares_build.h",
            vec!["H2".into()],
            true,
            Some("supply the generated ares_build.h".to_owned()),
        );
        assert_eq!(m.entries.len(), 1);
        let e = &m.entries[0];
        assert_eq!(e.referenced_by, vec!["H1".to_owned(), "H2".to_owned()]);
        assert!(!e.stubbed, "a still-blocking sighting wins");
        assert_eq!(
            e.acquisition_hint.as_deref(),
            Some("supply the generated ares_build.h")
        );
    }

    #[test]
    fn observed_substitution_updates_early_declaration_but_real_blocker_wins() {
        let mut m = DependencyManifest::new();
        m.push_merge_detailed(
            DepKind::GeneratedSource,
            "config.h",
            vec!["CMakeLists.txt".to_owned()],
            false,
            Some("run cmake".to_owned()),
            RequirementBasis::Declared,
            Some("configure_file declaration".to_owned()),
        );
        m.push_merge_detailed(
            DepKind::GeneratedSource,
            "config.h",
            vec!["H-C0001".to_owned()],
            true,
            Some("synthesized".to_owned()),
            RequirementBasis::Observed,
            Some("placeholder repair".to_owned()),
        );
        let entry = &m.entries[0];
        assert!(entry.stubbed, "the target proved a substitution was used");
        assert_eq!(entry.basis, RequirementBasis::Declared);
        assert_eq!(
            entry.evidence.as_deref(),
            Some("configure_file declaration")
        );
        assert_eq!(entry.acquisition_hint.as_deref(), Some("run cmake"));

        m.push_merge_detailed(
            DepKind::GeneratedSource,
            "config.h",
            vec!["H-C0002".to_owned()],
            false,
            None,
            RequirementBasis::Observed,
            Some("compiler still failed".to_owned()),
        );
        assert!(!m.entries[0].stubbed, "a later blocker must win");
    }

    #[test]
    fn empty_manifest_is_clearly_empty() {
        let m = DependencyManifest::new();
        assert!(m.is_empty());
        assert!(m
            .render_text()
            .contains("No external dependencies were missing"));
    }

    #[test]
    fn json_round_trips_kinds() {
        let mut m = DependencyManifest::new();
        m.push(DepKind::EnvVar, "ACE_ROOT", vec!["build".into()], true);
        let json = m.to_json();
        assert!(json.contains("\"kind\": \"env_var\""), "{json}");
        assert!(json.contains("\"ACE_ROOT\""), "{json}");
        assert!(json.contains("\"stubbed\": true"), "{json}");
    }
}
