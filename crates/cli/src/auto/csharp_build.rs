// SPDX-License-Identifier: Apache-2.0

//! C# / .NET harness build (M3.6) — see [`crate::auto::csharp`] for the strategy.
//!
//! Step 0 of the attempt loop for a `Lang::CSharp` candidate:
//!   1. Resolve the target method (by qualified name + line) and find the owning
//!      `.csproj`.
//!   2. Generate a `GovfuzzEntry.Run(byte[])` shim that statically calls the
//!      target with the fuzz bytes decoded to the parameter's type, plus a harness
//!      `.csproj` that references the target project + SharpFuzz + the fixed
//!      `csharp_runtime/Driver.cs`.
//!   3. `dotnet build -c Release` into `harnesses/<id>/out` (drops the target dll,
//!      its deps, SharpFuzz.Common.dll, and `govfuzz_harness.dll`).
//!   4. Instrument the target dll's IL with `sharpfuzz` (edge coverage into the
//!      shared map).
//!   5. Emit the `harnesses/<id>/main` launcher: `exec dotnet .../govfuzz_harness.dll`
//!      with `GOVFUZZ_CS_NAMESPACE` + `GOVFUZZ_EXPECTED_EXCEPTIONS`. The engine
//!      sets `GOVFUZZ_FRAMED` + `GOVFUZZ_COV_SHM` across the exec and drives the
//!      warm CLR over the framed fork-server protocol — same path as Java/Python.

use crate::auto::candidate::Candidate;
use crate::auto::csharp::{parse_csharp, CSharpMethod, CSharpParamKind};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A `--version`-style toolchain probe should answer instantly; this only exists
/// so a wedged or half-installed toolchain cannot hang the whole run.
const TOOL_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub enum CSharpBuildResult {
    Built {
        /// Under `--force`: what the entry shim had to synthesize to call the
        /// target — an uninitialized receiver for a type with no accessible
        /// parameterless constructor. `None` for every normal build. Recorded as
        /// [`crate::auto::repair::Repair::ForcedSyntheticParams`] so the report
        /// floors the target's findings: an object whose constructor never ran can
        /// throw on its own account.
        forced: Option<String>,
    },
    /// Not fuzzable here (no `dotnet`/`sharpfuzz`, no owning project, an instance
    /// method whose type needs constructor arguments) — skip cleanly.
    Skip(String),
    /// A genuine build/instrument failure.
    Failed(String),
}

fn have(bin: &str, arg: &str) -> bool {
    // Bounded like every other spawn: a wedged toolchain must not hang the run.
    let mut command = Command::new(bin);
    command.arg(arg);
    crate::command_output::output_with_timeout(&mut command, TOOL_PROBE_TIMEOUT)
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Resolve the `sharpfuzz` instrumentation tool: on PATH, or the default dotnet
/// global-tools location (`~/.dotnet/tools`), which `dotnet tool install
/// --global` writes to and which is NOT on PATH unless the user added it.
///
/// This is also what the preflight banner reports on, so the two agree. They did
/// not: preflight resolved on PATH only, so a host with the tool installed
/// exactly where dotnet puts it was told the C# lane was MISSING while the lane
/// went on to build and fuzz. On an offline host — where the reported fix is
/// `dotnet tool install`, a command that cannot run — a false MISSING is worse
/// than useless.
pub(crate) fn locate_sharpfuzz() -> Option<PathBuf> {
    // `.exe` on Windows, where `dotnet tool` also installs a shim of that name.
    const NAMES: [&str; 2] = ["sharpfuzz", "sharpfuzz.exe"];
    if let Ok(paths) = std::env::var("PATH") {
        for dir in std::env::split_paths(&paths) {
            for name in NAMES {
                let c = dir.join(name);
                if c.is_file() {
                    return Some(c);
                }
            }
        }
    }
    // HOME on unix, USERPROFILE on Windows — the previous HOME-only lookup never
    // fired on Windows, where a plain `dotnet tool install --global` leaves the
    // shim in %USERPROFILE%\.dotnet\tools.
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    if let Some(home) = home {
        for name in NAMES {
            let c = PathBuf::from(&home)
                .join(".dotnet")
                .join("tools")
                .join(name);
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

/// Locate the bundled `csharp_runtime/Driver.cs`, relative to the source tree
/// (dev) or the installed binary (release) — mirrors `locate_python_runtime`.
fn locate_csharp_runtime() -> Option<PathBuf> {
    crate::runtime_assets::locate("csharp_runtime", "Driver.cs")
}

/// Walk up from the source file to the nearest directory holding a `*.csproj`.
fn find_target_csproj(source: &Path) -> Option<PathBuf> {
    let mut dir = source.parent().map(Path::to_path_buf);
    for _ in 0..8 {
        let d = dir?;
        if let Ok(entries) = std::fs::read_dir(&d) {
            let mut projs: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "csproj").unwrap_or(false))
                .collect();
            projs.sort();
            if let Some(p) = projs.into_iter().next() {
                return Some(p);
            }
        }
        dir = d.parent().map(Path::to_path_buf);
    }
    None
}

/// The value of a `<Tag>...</Tag>` element in a csproj (first occurrence), trimmed.
fn xml_element<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(text[start..end].trim())
}

/// Rank a target framework moniker by preference for a net8.0 harness host: the
/// highest framework the host can reference wins. Returns `None` for a TFM the
/// net8.0 SDK/host cannot build or load (a newer preview like `net10.0`, or a
/// .NET Framework TFM like `net48` on a non-Windows host).
/// The highest .NET major version the installed SDK can target.
///
/// Hardcoding net8.0 as the ceiling both under-uses a newer SDK and mis-reports
/// what a host can do. `dotnet --list-sdks` prints one `8.0.129 [path]` line per
/// installed SDK; the highest major wins.
fn host_max_net_major() -> u32 {
    use std::sync::OnceLock;
    static MAX: OnceLock<u32> = OnceLock::new();
    *MAX.get_or_init(|| {
        let mut sdk_probe = Command::new("dotnet");
        sdk_probe.arg("--list-sdks");
        let Ok(out) =
            crate::command_output::output_with_timeout(&mut sdk_probe, TOOL_PROBE_TIMEOUT)
        else {
            return 8;
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| line.split('.').next()?.trim().parse::<u32>().ok())
            .max()
            .unwrap_or(8)
    })
}

/// Split `net8.0-windows10.0.19041.0` into its framework and platform parts.
fn split_tfm(tfm: &str) -> (String, Option<String>) {
    let t = tfm.trim().to_ascii_lowercase();
    match t.split_once('-') {
        Some((base, platform)) => (base.to_owned(), Some(platform.to_owned())),
        None => (t, None),
    }
}

/// Rank a target framework by how well this host can build it; `None` means it
/// cannot. Platform-specific TFMs (`-windows`, `-android`, `-ios`) need either
/// that OS or an installed workload, so on Linux they are unbuildable however
/// new the SDK is — the harness must not reference a project pinned to one.
fn tfm_rank(tfm: &str) -> Option<u32> {
    let (base, platform) = split_tfm(tfm);
    if let Some(platform) = platform {
        let usable = cfg!(target_os = "windows") && platform.starts_with("windows");
        if !usable {
            return None;
        }
    }
    if let Some(version) = base.strip_prefix("net") {
        if let Some((major, minor)) = version.split_once('.') {
            if let (Ok(major), Ok(minor)) = (major.parse::<u32>(), minor.parse::<u32>()) {
                // `net5.0`+ are the modern line; a version past the installed
                // SDK cannot be built at all.
                if major >= 5 {
                    if major > host_max_net_major() {
                        return None;
                    }
                    return Some(1000 + major * 10 + minor);
                }
            }
        }
    }
    match base.as_str() {
        "netcoreapp3.1" => Some(60),
        "netcoreapp3.0" => Some(55),
        "netstandard2.1" => Some(50),
        "netstandard2.0" => Some(40),
        "netstandard1.6" => Some(30),
        // .NET Framework (`net48`) needs Mono/Windows; not buildable here.
        _ => None,
    }
}

/// Choose the best framework to pin the target `ProjectReference` to. A .NET
/// library often multi-targets (`netstandard2.0;net8.0;net10.0`); without pinning,
/// the reference builds *every* framework — including any the installed SDK can't
/// build (a preview `net10.0`), failing the whole harness. Parse the declared
/// `<TargetFramework(s)>` and return the highest one the net8.0 host supports.
fn choose_target_framework(csproj: &Path) -> Option<String> {
    declared_target_frameworks(csproj)
        .into_iter()
        .filter_map(|tfm| tfm_rank(&tfm).map(|r| (r, tfm)))
        .max_by_key(|(r, _)| *r)
        .map(|(_, tfm)| tfm)
}

/// Every framework the project says it targets, buildable here or not.
///
/// Modern .NET repos hoist the TFM into a `Directory.Build.props` that MSBuild
/// imports into every project beneath it, so a `.csproj` that declares nothing
/// is not a project without a framework — reading only the `.csproj` made an
/// unbuildable `net10.0` look like "unspecified" and the harness referenced it
/// anyway.
fn declared_target_frameworks(csproj: &Path) -> Vec<String> {
    if let Some(found) = target_frameworks_in_file(csproj) {
        return found;
    }
    for props in imported_build_props(csproj) {
        if let Some(found) = target_frameworks_in_file(&props) {
            return found;
        }
    }
    Vec::new()
}

/// The `Directory.Build.props` / `.targets` files MSBuild imports into a
/// project, nearest first. Bounded: MSBuild itself stops at the first one, and
/// an unbounded walk would climb out of the project into the filesystem root.
fn imported_build_props(csproj: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut dir = csproj.parent();
    for _ in 0..12 {
        let Some(current) = dir else { break };
        for name in ["Directory.Build.props", "Directory.Build.targets"] {
            let path = current.join(name);
            if path.is_file() {
                out.push(path);
            }
        }
        dir = current.parent();
    }
    out
}

fn target_frameworks_in_file(path: &Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(path).ok()?;
    // An old-style (non-SDK) project spells it `<TargetFrameworkVersion>v4.7.2`.
    // Missing that made a .NET Framework project look like it declared no
    // framework at all, so the harness referenced it and MSBuild failed on
    // reference assemblies that do not exist off Windows (MSB3644) instead of
    // taking the source-inclusion path.
    if let Some(version) = xml_element(&text, "TargetFrameworkVersion") {
        let digits: String = version.chars().filter(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return Some(vec![format!("net{digits}")]);
        }
    }
    let raw =
        xml_element(&text, "TargetFrameworks").or_else(|| xml_element(&text, "TargetFramework"))?;
    let list: Vec<String> = raw
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.contains('$'))
        .map(str::to_owned)
        .collect();
    (!list.is_empty()).then_some(list)
}

/// The assembly name a project builds: its `<AssemblyName>` if set, else the
/// `.csproj` file stem (dotnet's default).
fn target_assembly_name(csproj: &Path) -> String {
    if let Ok(text) = std::fs::read_to_string(csproj) {
        if let Some(start) = text.find("<AssemblyName>") {
            if let Some(end) = text[start..].find("</AssemblyName>") {
                let inner = text[start + "<AssemblyName>".len()..start + end].trim();
                if !inner.is_empty() {
                    return inner.to_owned();
                }
            }
        }
    }
    csproj
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "target".to_owned())
}

/// Re-parse the source and find the discovered method by (qualified name, line).
fn resolve_target(candidate: &Candidate) -> Result<CSharpMethod, String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let methods = parse_csharp(&source);
    methods
        .iter()
        .find(|m| m.qualified() == candidate.name && m.line == candidate.line)
        .or_else(|| methods.iter().find(|m| m.qualified() == candidate.name))
        .cloned()
        .ok_or_else(|| format!("C# target `{}` no longer present in source", candidate.name))
}

/// An instance method needs a no-argument-*constructible* declaring type — the
/// entry shim emits `new <Type>()`. That compiles iff the type has an accessible
/// (public/internal) parameterless constructor, OR declares no constructor at all
/// (the implicit public default). It does NOT compile when the only constructors
/// are parameterized (needs args) or inaccessible (a `private` ctor + a static
/// `Instance` singleton — YamlDotNet's naming conventions). In those cases skip
/// cleanly (mirrors the Python/Java no-arg-ctor first cut). Scans the declaring
/// file's constructors; a receiver whose ctor lives in another partial file may
/// still slip through to a clean FailedBuild.
fn instance_receiver_ok(
    method: &CSharpMethod,
    source: &str,
    force: bool,
) -> Result<Receiver, String> {
    if method.is_static {
        return Ok(Receiver::Static);
    }
    let leaf = method
        .type_name
        .rsplit('.')
        .next()
        .unwrap_or(&method.type_name);
    // An abstract type (or an interface) has no instance to obtain by ANY route:
    // `new T()` does not compile and `GetUninitializedObject` throws at runtime,
    // which would make every input "crash" in the shim rather than in the target.
    // Checked ahead of the constructor scan because an abstract class that declares
    // no constructor at all would otherwise look default-constructible.
    if declares_abstract_type(source, leaf) {
        return Err(format!(
            "instance method `{}` is declared on abstract/interface type `{leaf}`, \
             which has no instance to allocate (skipped cleanly)",
            method.qualified()
        ));
    }
    let mut has_explicit_ctor = false;
    let mut has_accessible_noarg = false;
    for access in ["public", "private", "protected", "internal"] {
        let needle = format!("{access} {leaf}(");
        let mut from = 0usize;
        while let Some(rel) = source[from..].find(&needle) {
            let pos = from + rel;
            has_explicit_ctor = true;
            let after = &source[pos + needle.len()..];
            let args = after.split(')').next().unwrap_or("");
            let noarg = args.trim().is_empty();
            let accessible = matches!(access, "public" | "internal");
            if noarg && accessible {
                has_accessible_noarg = true;
            }
            from = pos + needle.len();
        }
    }
    if !has_explicit_ctor || has_accessible_noarg {
        return Ok(Receiver::New);
    }
    // No usable constructor. Unforced this is a clean skip. Forced, allocate the
    // receiver WITHOUT running any constructor
    // (`RuntimeHelpers.GetUninitializedObject`, the runtime's own deserialization
    // primitive) — the method under test is then reached with every field at its
    // default. That is exactly the force contract: a driver that runs, with value
    // correctness explicitly not a goal.
    if !force {
        return Err(format!(
            "instance method `{}` needs a receiver, but `{leaf}` has no accessible \
             parameterless constructor (only a parameterized or private one); pass \
             --force to call it on an uninitialized receiver (skipped cleanly)",
            method.qualified()
        ));
    }
    Ok(Receiver::Uninitialized)
}

/// How the entry shim obtains the receiver to call the target on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Receiver {
    /// A static method — the type name IS the receiver.
    Static,
    /// `new T()`: an accessible parameterless constructor exists.
    New,
    /// `--force` only: allocate `T` without running a constructor.
    Uninitialized,
}

/// Whether `leaf` is declared `abstract` (or as an `interface`) in this source.
/// Textual, like the constructor scan above: it only inspects the line that
/// DECLARES the type, so an `abstract`/`virtual` member never matches.
fn declares_abstract_type(source: &str, leaf: &str) -> bool {
    source.lines().any(|line| {
        let line = line.trim();
        for keyword in ["interface", "class", "record", "struct"] {
            let Some(head) = declaration_head(line, keyword, leaf) else {
                continue;
            };
            if keyword == "interface" {
                return true;
            }
            if head.split_whitespace().any(|token| token == "abstract") {
                return true;
            }
        }
        false
    })
}

/// The modifiers preceding `<keyword> <leaf>` on a declaration line, or `None`
/// when the line does not declare that exact name (`class FooBar` must not match
/// `Foo`).
fn declaration_head<'a>(line: &'a str, keyword: &str, leaf: &str) -> Option<&'a str> {
    let needle = format!("{keyword} {leaf}");
    let at = line.find(&needle)?;
    let after = line[at + needle.len()..].trim_start();
    let boundary = after
        .chars()
        .next()
        .is_none_or(|ch| !ch.is_alphanumeric() && ch != '_');
    boundary.then(|| &line[..at])
}

/// The C# expression that decodes the fuzz bytes (`data`) to `param`'s type. The
/// parameter `name` disambiguates an integer role: an offset/index/position starts
/// at 0, a count/length spans the input.
fn decode_expr(kind: CSharpParamKind, raw_type: &str, name: &str) -> String {
    match kind {
        CSharpParamKind::Bytes => "data".to_owned(),
        CSharpParamKind::ByteSpan => {
            let t = raw_type;
            if t.contains("ReadOnlyMemory") {
                "new System.ReadOnlyMemory<byte>(data)".to_owned()
            } else if t.contains("Memory") {
                "new System.Memory<byte>(data)".to_owned()
            } else if t.starts_with("Span") || t.contains(".Span<") || t == "Span<byte>" {
                "new System.Span<byte>(data)".to_owned()
            } else {
                "new System.ReadOnlySpan<byte>(data)".to_owned()
            }
        }
        CSharpParamKind::Str => "System.Text.Encoding.UTF8.GetString(data)".to_owned(),
        CSharpParamKind::Stream => "new System.IO.MemoryStream(data, false)".to_owned(),
        CSharpParamKind::Int => {
            // An offset/index/position into the buffer must start at 0 (passing the
            // length throws ArgumentOutOfRange); a count/length/size spans the input.
            let n = name.to_ascii_lowercase();
            if n.contains("offset")
                || n.contains("index")
                || n == "pos"
                || n.contains("position")
                || n == "start"
                || n == "from"
            {
                "0".to_owned()
            } else {
                "data.Length".to_owned()
            }
        }
        CSharpParamKind::Bool => "false".to_owned(),
        // is_fuzzable() excludes Other, but keep the shim total: pass default.
        CSharpParamKind::Other => format!("default({raw_type})"),
    }
}

/// Generate the `GovfuzzEntry.Run(byte[])` shim: a static call into the target.
fn generate_entry(method: &CSharpMethod, receiver_kind: Receiver) -> String {
    let (receiver_setup, receiver) = match receiver_kind {
        Receiver::Static => (String::new(), format!("global::{}", method.type_name)),
        Receiver::New => (
            format!(
                "    var govfuzzReceiver = new global::{}();\n",
                method.type_name
            ),
            "govfuzzReceiver".to_owned(),
        ),
        Receiver::Uninitialized => (
            format!(
                "    var govfuzzReceiver = ((global::{}) GovfuzzUninitialized(typeof(global::{})));\n",
                method.type_name, method.type_name
            ),
            "govfuzzReceiver".to_owned(),
        ),
    };
    let decoded_args: Vec<String> = method
        .params
        .iter()
        .map(|p| decode_expr(p.kind, &p.raw_type, &p.name))
        .collect();
    let arg_setup = decoded_args
        .iter()
        .enumerate()
        .map(|(index, expression)| format!("    var govfuzzArg{index} = {expression};\n"))
        .collect::<String>();
    let args = (0..decoded_args.len())
        .map(|index| format!("govfuzzArg{index}"))
        .collect::<Vec<_>>();
    // `--force` only. Resolved by reflection rather than named directly so the shim
    // compiles against ANY target framework: `RuntimeHelpers.GetUninitializedObject`
    // is .NET 5+, `FormatterServices.GetUninitializedObject` is the older spelling
    // (obsolete since .NET 5), and the harness is pinned to the TARGET's TFM, which
    // may be either.
    let helper = if receiver_kind == Receiver::Uninitialized {
        "\x20   static object GovfuzzUninitialized(System.Type t) {\n\
         \x20     var rh = typeof(System.Runtime.CompilerServices.RuntimeHelpers)\n\
         \x20       .GetMethod(\"GetUninitializedObject\", new[] { typeof(System.Type) });\n\
         \x20     if (rh != null) return rh.Invoke(null, new object[] { t });\n\
         \x20     var fs = System.Type.GetType(\"System.Runtime.Serialization.FormatterServices\");\n\
         \x20     var fm = fs?.GetMethod(\"GetUninitializedObject\", new[] { typeof(System.Type) });\n\
         \x20     if (fm != null) return fm.Invoke(null, new object[] { t });\n\
         \x20     throw new System.NotSupportedException(\"govfuzz: no uninitialized-object primitive\");\n\
         \x20   }\n"
    } else {
        ""
    };
    format!(
        "// SPDX-License-Identifier: Apache-2.0\n\
         // Generated by govfuzz — do not edit. Calls the discovered target with the\n\
         // fuzz bytes decoded to each parameter's static type.\n\
         namespace Govfuzzgen {{\n\
         \x20 public static class GovfuzzEntry {{\n\
         {helper}\
         \x20   static bool GovfuzzTargetEntered;\n\
         \x20   static void GovfuzzMarkTargetEntry() {{\n\
         \x20     if (GovfuzzTargetEntered) return;\n\
         \x20     var path = System.Environment.GetEnvironmentVariable(\"GOVFUZZ_TARGET_ENTRY_SHM\");\n\
         \x20     if (string.IsNullOrEmpty(path)) return;\n\
         \x20     try {{ System.IO.File.WriteAllBytes(path, new byte[] {{ 1 }}); GovfuzzTargetEntered = true; }}\n\
         \x20     catch (System.IO.IOException) {{ }}\n\
         \x20     catch (System.UnauthorizedAccessException) {{ }}\n\
         \x20   }}\n\
         \x20   public static void Run(byte[] data) {{\n\
         {receiver_setup}\
         {arg_setup}\
         \x20     GovfuzzMarkTargetEntry();\n\
         \x20     {receiver}.{method}({args});\n\
         \x20   }}\n\
         \x20 }}\n\
         }}\n",
        helper = helper,
        receiver_setup = receiver_setup,
        arg_setup = arg_setup,
        receiver = receiver,
        method = method.method,
        args = args.join(", "),
    )
}

/// The harness `.csproj`: an exe referencing the target project + SharpFuzz +
/// the fixed Driver.cs + the generated GovfuzzEntry.cs. When the target project
/// multi-targets, the reference is pinned to `pinned_tfm` (via `SetTargetFramework`)
/// so the SDK never tries to build a framework it doesn't support.
/// How the harness gets at the target's code.
enum TargetLinkage {
    /// Reference the project and let the SDK build it. Pinned to one TFM when
    /// the project multi-targets, so the SDK never builds a framework it can't.
    ProjectReference { pinned_tfm: Option<String> },
    /// Compile the project's own `.cs` into the harness assembly.
    ///
    /// Used when NO declared TFM is buildable here — a project targeting
    /// `net10.0-windows` on a host with the .NET 8 SDK, which is otherwise a
    /// hard zero: the reference fails, so every target in the project fails.
    /// Most library types are ordinary C# that compiles fine against a
    /// supported framework, and a type that genuinely needs the newer BCL now
    /// fails with a real compiler diagnostic instead of an SDK banner.
    ///
    /// `excluded` holds files ejected because they could not compile — a UI
    /// view model needing a source generator, say — while the target's own file
    /// is never ejected.
    SourceInclusion { excluded: Vec<PathBuf> },
}

/// `<PackageReference>` entries declared by the target project, so
/// source-inclusion still resolves the types those packages provide. Entries
/// without a version come from central package management, which the harness
/// project does not inherit; they are skipped rather than guessed at.
fn target_package_references(csproj_text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for chunk in csproj_text.split("<PackageReference").skip(1) {
        let Some(end) = chunk.find('>') else { continue };
        let attrs = &chunk[..end];
        let include = xml_attribute(attrs, "Include");
        let version = xml_attribute(attrs, "Version");
        if let (Some(include), Some(version)) = (include, version) {
            if include != "SharpFuzz" {
                out.push((include, version));
            }
        }
    }
    out
}

/// Packages the project gets from its own file AND from the
/// `Directory.Build.props` MSBuild would import for it.
fn effective_package_references(csproj: &Path) -> Vec<(String, String)> {
    let mut out = std::fs::read_to_string(csproj)
        .map(|text| target_package_references(&text))
        .unwrap_or_default();
    for props in imported_build_props(csproj) {
        let Ok(text) = std::fs::read_to_string(&props) else {
            continue;
        };
        for entry in target_package_references(&text) {
            if !out.iter().any(|(name, _)| *name == entry.0) {
                out.push(entry);
            }
        }
    }
    out
}

/// Copy the harness's build output (`bin/Release/<tfm>/`) into `out_dir`, which
/// the rest of the lane treats as the single place the assemblies live.
fn collect_build_output(proj_dir: &Path, out_dir: &Path) -> Result<(), String> {
    let release = proj_dir.join("bin").join("Release");
    let tfm_dir = std::fs::read_dir(&release)
        .map_err(|e| format!("read {}: {e}", release.display()))?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .ok_or_else(|| format!("no framework directory under {}", release.display()))?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("create {}: {e}", out_dir.display()))?;
    for entry in std::fs::read_dir(&tfm_dir)
        .map_err(|e| format!("read {}: {e}", tfm_dir.display()))?
        .flatten()
    {
        let from = entry.path();
        if from.is_dir() {
            continue; // satellite/runtime subdirectories are not needed to load
        }
        let to = out_dir.join(entry.file_name());
        std::fs::copy(&from, &to).map_err(|e| format!("copy {}: {e}", from.display()))?;
    }
    Ok(())
}

/// Line numbers MSBuild reported errors on, within one specific file.
fn error_lines_in_file(build_output: &str, file: &Path) -> Vec<usize> {
    let prefix = file.display().to_string();
    let mut out = Vec::new();
    for line in build_output.lines() {
        let Some(rest) = line.strip_prefix(prefix.as_str()) else {
            continue;
        };
        if !rest.contains("): error CS") {
            continue;
        }
        let number: String = rest
            .trim_start_matches('(')
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(n) = number.parse::<usize>() {
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

/// Source files MSBuild named in `error CSxxxx` diagnostics.
///
/// Compiling a whole project into the harness drags in every file, including
/// ones that need a source generator or a UI framework the harness has no
/// business building (v2rayN's ReactiveUI view models produced 2008 errors
/// while the target sat in a plain `Common/` helper). Ejecting the files that
/// fail — never the target's own — converges on the subset that compiles.
fn error_source_files(build_output: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for line in build_output.lines() {
        let Some(paren) = line.find('(') else {
            continue;
        };
        let rest = &line[paren..];
        if !rest.contains("): error CS") {
            continue;
        }
        let path = PathBuf::from(line[..paren].trim());
        if path.extension().and_then(|e| e.to_str()) != Some("cs") {
            continue;
        }
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

/// Normalize one project-wide using for source-inclusion recovery. Visual Studio
/// commonly writes `GlobalUsings.cs` as UTF-8 with a BOM; `str::trim` does not
/// remove U+FEFF, so the first (often foundational) namespace used to disappear
/// when that file was ejected. The remaining sources then failed misleadingly
/// with "type or namespace not found" even though their defining file remained.
fn recoverable_global_using(line: &str) -> Option<String> {
    let trimmed = line.trim().trim_start_matches('\u{feff}').trim_start();
    trimmed
        .starts_with("global using")
        .then(|| trimmed.to_owned())
}

fn xml_attribute(attrs: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let at = attrs.find(&needle)?;
    let rest = &attrs[at + needle.len()..];
    let end = rest.find('"')?;
    let value = rest[..end].trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// The harness `.csproj`.
///
/// `GenerateAssemblyInfo` is off deliberately. The SDK synthesizes
/// `[assembly: AssemblyTitle]` and friends by default, and a classic
/// (pre-SDK-style) project keeps its own hand-written `Properties/AssemblyInfo.cs`
/// declaring exactly those attributes — so compiling the project's sources into
/// the harness produced `error CS0579: Duplicate 'AssemblyTitleAttribute'
/// attribute` and failed every target in it. 17 targets across four Windows C#
/// projects in the 500-project sweep. The harness assembly has no use for the
/// generated metadata either way.
fn generate_csproj(target_csproj: &Path, linkage: &TargetLinkage) -> String {
    let reference = match linkage {
        TargetLinkage::ProjectReference {
            pinned_tfm: Some(tfm),
        } => format!(
            "<ProjectReference Include=\"{target}\" \
             SetTargetFramework=\"TargetFramework={tfm}\" />",
            target = target_csproj.display(),
        ),
        TargetLinkage::ProjectReference { pinned_tfm: None } => format!(
            "<ProjectReference Include=\"{target}\" />",
            target = target_csproj.display(),
        ),
        TargetLinkage::SourceInclusion { .. } => {
            "<ProjectReference Include=\"target/govfuzz_target.csproj\" />".to_owned()
        }
    };
    let target_framework = format!("net{}.0", host_max_net_major());
    // A project's own sources are written against the implicit-usings default
    // of a modern SDK; compiling them with usings disabled fails on types the
    // author never had to import.
    let implicit_usings = match linkage {
        TargetLinkage::SourceInclusion { .. } => "enable",
        TargetLinkage::ProjectReference { .. } => "disable",
    };
    format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n\
         \x20 <PropertyGroup>\n\
         \x20   <OutputType>Exe</OutputType>\n\
         \x20   <TargetFramework>{target_framework}</TargetFramework>\n\
         \x20   <LangVersion>latest</LangVersion>\n\
         \x20   <EnableDefaultCompileItems>false</EnableDefaultCompileItems>\n\
         \x20   <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n\
         \x20   <Nullable>disable</Nullable>\n\
         \x20   <AssemblyName>govfuzz_harness</AssemblyName>\n\
         \x20   <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n\
         \x20   <ImplicitUsings>{implicit_usings}</ImplicitUsings>\n\
         \x20   <GenerateDocumentationFile>false</GenerateDocumentationFile>\n\
         \x20   <NoWarn>$(NoWarn);CS0618;CS0612;CS8032</NoWarn>\n\
         \x20   <SatelliteResourceLanguages>en</SatelliteResourceLanguages>\n\
         \x20 </PropertyGroup>\n\
         \x20 <ItemGroup>\n\
         \x20   <Compile Include=\"Driver.cs;GovfuzzEntry.cs\" />\n\
         \x20   <PackageReference Include=\"SharpFuzz\" Version=\"2.3.0\" />\n\
         \x20   {reference}\n\
         \x20 </ItemGroup>\n\
         </Project>\n",
        reference = reference,
    )
}

/// Target-only library for source inclusion. Keeping Driver/GovfuzzEntry in a
/// separate executable is essential: SharpFuzz must instrument project code but
/// not the driver that initializes `Trace.SharedMem` before any instrumented edge
/// executes.
fn generate_source_target_csproj(target_csproj: &Path, excluded: &[PathBuf]) -> String {
    let dir = target_csproj
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let packages: String = effective_package_references(target_csproj)
        .into_iter()
        .map(|(name, version)| {
            format!("\n    <PackageReference Include=\"{name}\" Version=\"{version}\" />")
        })
        .collect();
    let mut exclude = format!("{dir}/bin/**/*.cs;{dir}/obj/**/*.cs", dir = dir.display());
    for path in excluded {
        exclude.push(';');
        exclude.push_str(&path.display().to_string());
    }
    format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n\
         \x20 <PropertyGroup>\n\
         \x20   <TargetFramework>net{host}.0</TargetFramework>\n\
         \x20   <LangVersion>latest</LangVersion>\n\
         \x20   <EnableDefaultCompileItems>true</EnableDefaultCompileItems>\n\
         \x20   <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n\
         \x20   <Nullable>disable</Nullable>\n\
         \x20   <AssemblyName>govfuzz_target</AssemblyName>\n\
         \x20   <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n\
         \x20   <ImplicitUsings>enable</ImplicitUsings>\n\
         \x20   <NoWarn>$(NoWarn);CS0618;CS0612;CS8032</NoWarn>\n\
         \x20 </PropertyGroup>\n\
         \x20 <ItemGroup>\n\
         \x20   <Compile Include=\"{dir}/**/*.cs\" Exclude=\"{exclude}\" />{packages}\n\
         \x20 </ItemGroup>\n\
         </Project>\n",
        host = host_max_net_major(),
        dir = dir.display(),
    )
}

/// The single public entry point of the lane.
pub fn build_csharp_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    force: bool,
) -> CSharpBuildResult {
    if !have("dotnet", "--version") {
        return CSharpBuildResult::Skip(
            "no `dotnet` SDK found; install the .NET SDK to fuzz C# (the lane skips \
             cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
        );
    }
    let Some(sharpfuzz) = locate_sharpfuzz() else {
        return CSharpBuildResult::Skip(
            "SharpFuzz instrumentation tool not found (install with \
             `dotnet tool install --global SharpFuzz.CommandLine`); the C# lane skips \
             cleanly"
                .to_owned(),
        );
    };
    let Some(runtime) = locate_csharp_runtime() else {
        return CSharpBuildResult::Failed(
            "could not locate the bundled csharp_runtime/Driver.cs".to_owned(),
        );
    };

    let source = match crate::source_text::read_source_text(&candidate.source_path) {
        Ok(s) => s,
        Err(e) => {
            return CSharpBuildResult::Failed(format!(
                "read {}: {e}",
                candidate.source_path.display()
            ))
        }
    };
    let method = match resolve_target(candidate) {
        Ok(m) => m,
        Err(reason) => return CSharpBuildResult::Skip(reason),
    };
    if !method.is_fuzzable() {
        return CSharpBuildResult::Skip(format!(
            "C# target `{}` has no single byte[]/string/Stream input parameter with \
             synthesizable siblings",
            method.qualified()
        ));
    }
    let receiver_kind = match instance_receiver_ok(&method, &source, force) {
        Ok(kind) => kind,
        Err(reason) => return CSharpBuildResult::Skip(reason),
    };
    let Some(target_csproj) = find_target_csproj(&candidate.source_path) else {
        return CSharpBuildResult::Skip(format!(
            "no owning .csproj found for {} — the C# lane builds through a project \
             reference (skipped cleanly)",
            candidate.source_path.display()
        ));
    };

    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let proj_dir = hdir.join("proj");
    let source_target_dir = proj_dir.join("target");
    let out_dir = hdir.join("out");
    if let Err(e) = std::fs::create_dir_all(&proj_dir) {
        return CSharpBuildResult::Failed(format!("create {}: {e}", proj_dir.display()));
    }

    // Write the harness project sources.
    if let Err(e) = std::fs::copy(runtime.join("Driver.cs"), proj_dir.join("Driver.cs")) {
        return CSharpBuildResult::Failed(format!("copy Driver.cs: {e}"));
    }
    if let Err(e) = std::fs::write(
        proj_dir.join("GovfuzzEntry.cs"),
        generate_entry(&method, receiver_kind),
    ) {
        return CSharpBuildResult::Failed(format!("write GovfuzzEntry.cs: {e}"));
    }
    // Prefer referencing the project. When the project declares only TFMs this
    // host cannot build (a newer .NET than the installed SDK, or a
    // platform-specific `-windows` framework), referencing it fails every
    // target in the project, so compile its sources into the harness instead.
    let pinned_tfm = choose_target_framework(&target_csproj);
    let declares_tfm = declared_target_frameworks(&target_csproj);
    let linkage = if pinned_tfm.is_none() && !declares_tfm.is_empty() {
        gfeprintln!(
            "govfuzz auto: C# project {} targets {} which the installed .NET SDK \
             (max net{}.0) cannot build; compiling its sources into the harness instead",
            target_csproj.display(),
            declares_tfm.join(";"),
            host_max_net_major(),
        );
        TargetLinkage::SourceInclusion {
            excluded: Vec::new(),
        }
    } else {
        TargetLinkage::ProjectReference { pinned_tfm }
    };
    if let Err(e) = std::fs::write(
        proj_dir.join("govfuzz_harness.csproj"),
        generate_csproj(&target_csproj, &linkage),
    ) {
        return CSharpBuildResult::Failed(format!("write harness csproj: {e}"));
    }
    if let TargetLinkage::SourceInclusion { excluded } = &linkage {
        if let Err(error) = std::fs::create_dir_all(&source_target_dir) {
            return CSharpBuildResult::Failed(format!(
                "create source target {}: {error}",
                source_target_dir.display()
            ));
        }
        if let Err(error) = std::fs::write(
            source_target_dir.join("govfuzz_target.csproj"),
            generate_source_target_csproj(&target_csproj, excluded),
        ) {
            return CSharpBuildResult::Failed(format!("write source target csproj: {error}"));
        }
    }

    // Build. `--nologo`, restore from the local NuGet cache; keep the CLI quiet.
    // Under source-inclusion the first build often fails on project files that
    // are nothing to do with the target (view models needing a source
    // generator); those get ejected and the build retried until the compiling
    // subset is found, or the target's own file is what fails.
    const MAX_EJECT_ROUNDS: usize = 6;
    let mut linkage = linkage;
    let mut recovered_usings: Vec<String> = Vec::new();
    for round in 0..=MAX_EJECT_ROUNDS {
        // No `-o`: forcing one output directory across a project GRAPH also
        // redirects the referenced project's output, and the second harness to
        // build the same project hits MSB4018 in GetAssemblyAttributes because
        // its `obj/` still describes the first harness's layout. Build into the
        // default per-project locations and copy the harness's own output out.
        let build = crate::command_output::output_with_timeout(
            Command::new("dotnet")
                .arg("build")
                .arg(proj_dir.join("govfuzz_harness.csproj"))
                .arg("-c")
                .arg("Release")
                .arg("--nologo")
                .arg("-v")
                .arg("quiet")
                .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
                .env("DOTNET_NOLOGO", "1"),
            std::time::Duration::from_secs(30 * 60),
        );
        let output = match build {
            Ok(o) if o.status.success() => {
                if let Err(e) = collect_build_output(&proj_dir, &out_dir) {
                    return CSharpBuildResult::Failed(e);
                }
                break;
            }
            Ok(o) => {
                let mut msg = String::from_utf8_lossy(&o.stdout).to_string();
                msg.push_str(&String::from_utf8_lossy(&o.stderr));
                msg
            }
            Err(e) => return CSharpBuildResult::Failed(format!("spawn dotnet build: {e}")),
        };

        let TargetLinkage::SourceInclusion { excluded } = &mut linkage else {
            return CSharpBuildResult::Failed(format!(
                "dotnet build failed:\n{}",
                tail(&output, 4000)
            ));
        };
        // A `global using` the compiler rejected takes only that line with it.
        // Ejecting the whole GlobalUsings.cs would strip EVERY project-wide
        // using — including `System.Collections.Concurrent` — and break files
        // that were compiling fine.
        let recovered_path = source_target_dir.join("GovfuzzRecoveredUsings.cs");
        let rejected_usings = error_lines_in_file(&output, &recovered_path);
        if !rejected_usings.is_empty() {
            recovered_usings = recovered_usings
                .into_iter()
                .enumerate()
                .filter(|(index, _)| !rejected_usings.contains(&(index + 1)))
                .map(|(_, line)| line)
                .collect();
            if let Err(e) = std::fs::write(&recovered_path, recovered_usings.join("\n") + "\n") {
                return CSharpBuildResult::Failed(format!("write recovered usings: {e}"));
            }
            continue;
        }
        let failing: Vec<PathBuf> = error_source_files(&output)
            .into_iter()
            .filter(|p| *p != candidate.source_path && !excluded.contains(p))
            .filter(|p| *p != recovered_path)
            .collect();
        // Keep the project-wide usings the ejected files declared.
        let mut new_usings = Vec::new();
        for path in &failing {
            if let Ok(text) = std::fs::read_to_string(path) {
                for line in text.lines() {
                    if let Some(using) = recoverable_global_using(line) {
                        if !recovered_usings.iter().any(|present| present == &using) {
                            new_usings.push(using);
                        }
                    }
                }
            }
        }
        if !new_usings.is_empty() {
            recovered_usings.extend(new_usings);
            if let Err(e) = std::fs::write(&recovered_path, recovered_usings.join("\n") + "\n") {
                return CSharpBuildResult::Failed(format!("write recovered usings: {e}"));
            }
        }
        if failing.is_empty() || round == MAX_EJECT_ROUNDS {
            // Either the target's own file is what fails, or ejecting stopped
            // helping: report the real diagnostic.
            return CSharpBuildResult::Failed(format!(
                "dotnet build failed:\n{}",
                tail(&output, 4000)
            ));
        }
        gfeprintln!(
            "govfuzz auto: C# source-inclusion: ejecting {} file(s) that do not compile \
             into the harness (round {})",
            failing.len(),
            round + 1,
        );
        excluded.extend(failing);
        if let Err(e) = std::fs::write(
            source_target_dir.join("govfuzz_target.csproj"),
            generate_source_target_csproj(&target_csproj, excluded),
        ) {
            return CSharpBuildResult::Failed(format!("rewrite source target csproj: {e}"));
        }
    }

    // Instrument the assembly the target's IL actually landed in: its own when
    // the project was referenced, the harness itself under source-inclusion.
    let asm = match linkage {
        TargetLinkage::SourceInclusion { .. } => "govfuzz_target".to_owned(),
        TargetLinkage::ProjectReference { .. } => target_assembly_name(&target_csproj),
    };
    let target_dll = out_dir.join(format!("{asm}.dll"));
    if !target_dll.is_file() {
        return CSharpBuildResult::Failed(format!(
            "target assembly {} not found after build (assembly name `{asm}`)",
            target_dll.display()
        ));
    }
    let instr = crate::command_output::output_with_timeout(
        Command::new(&sharpfuzz)
            .arg(&target_dll)
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            // The `sharpfuzz` global tool targets an older runtime than the SDK may
            // ship (e.g. a net8.0 tool on a host with only the .NET 10 runtime); roll
            // it forward so instrumentation works whatever runtime is installed.
            .env("DOTNET_ROLL_FORWARD", "Major"),
        std::time::Duration::from_secs(10 * 60),
    );
    match instr {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let mut msg = String::from_utf8_lossy(&o.stdout).to_string();
            msg.push_str(&String::from_utf8_lossy(&o.stderr));
            return CSharpBuildResult::Failed(format!(
                "sharpfuzz instrumentation of {} failed:\n{}",
                target_dll.display(),
                tail(&msg, 2000)
            ));
        }
        Err(e) => return CSharpBuildResult::Failed(format!("spawn sharpfuzz: {e}")),
    }

    // Emit the launcher `main`.
    let main_path = hdir.join("main");
    let harness_dll = out_dir.join("govfuzz_harness.dll");
    let script = format!(
        "#!/bin/sh\n\
         # GOVFUZZ_FRAMED GOVFUZZ_CS_LAUNCHER govfuzz .NET driver launcher (native C# lane).\n\
         # The engine sets GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM in the environment; the CLR\n\
         # inherits them across this exec. The Driver mmaps the file-backed\n\
         # GOVFUZZ_COV_SHM map into SharpFuzz.Common.Trace.SharedMem and speaks the\n\
         # framed fork-server protocol. GOVFUZZ_CS_NAMESPACE = the target's root\n\
         # namespace, whose own exceptions are treated as declared input rejection.\n\
         GOVFUZZ_CS_NAMESPACE=\"{ns}\" \\\n\
         GOVFUZZ_EXPECTED_EXCEPTIONS=\"{expected}\" \\\n\
         DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_ROLL_FORWARD=Major \\\n\
         exec dotnet \"{dll}\" \"$@\"\n",
        ns = method.namespace,
        expected = "",
        dll = harness_dll.display(),
    );
    if let Err(e) = std::fs::write(&main_path, script) {
        return CSharpBuildResult::Failed(format!("write launcher {}: {e}", main_path.display()));
    }
    if let Err(e) = make_executable(&main_path) {
        return CSharpBuildResult::Failed(format!("chmod +x {}: {e}", main_path.display()));
    }
    CSharpBuildResult::Built {
        forced: (receiver_kind == Receiver::Uninitialized).then(|| {
            format!(
                "c#: uninitialized receiver for `{}` (no accessible parameterless constructor)",
                method.type_name
            )
        }),
    }
}

/// Last `n` bytes of a diagnostic string, at a char boundary.
fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_owned();
    }
    let start = s.len() - n;
    let start = (start..s.len())
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(s.len());
    format!("…{}", &s[start..])
}

#[cfg(unix)]
fn make_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::csharp::CSharpParam;

    fn m(is_static: bool, params: Vec<CSharpParam>) -> CSharpMethod {
        CSharpMethod {
            namespace: "Acme".to_owned(),
            type_name: "Acme.Parser".to_owned(),
            method: "Parse".to_owned(),
            line: 1,
            params,
            is_static,
        }
    }

    fn p(kind: CSharpParamKind, raw: &str) -> CSharpParam {
        CSharpParam {
            name: "x".to_owned(),
            kind,
            raw_type: raw.to_owned(),
        }
    }

    #[test]
    fn recovers_first_global_using_after_utf8_bom() {
        assert_eq!(
            recoverable_global_using("\u{feff}global using Acme.Domain.Common;"),
            Some("global using Acme.Domain.Common;".to_owned())
        );
        assert_eq!(recoverable_global_using("using System;"), None);
    }

    #[test]
    fn entry_static_byte_array() {
        let src = generate_entry(
            &m(true, vec![p(CSharpParamKind::Bytes, "byte[]")]),
            Receiver::Static,
        );
        assert!(src.contains("var govfuzzArg0 = data;"));
        assert!(src.contains("global::Acme.Parser.Parse(govfuzzArg0)"));
        let checkpoint = src.find("GovfuzzMarkTargetEntry();").unwrap();
        let call = src.find("global::Acme.Parser.Parse(govfuzzArg0)").unwrap();
        assert!(
            checkpoint < call,
            "checkpoint must precede target call: {src}"
        );
        assert!(
            !src.contains("GovfuzzUninitialized"),
            "no forced helper: {src}"
        );
    }

    #[test]
    fn entry_instance_string() {
        let src = generate_entry(
            &m(false, vec![p(CSharpParamKind::Str, "string")]),
            Receiver::New,
        );
        assert!(src.contains("var govfuzzReceiver = new global::Acme.Parser();"));
        assert!(src.contains("govfuzzReceiver.Parse(govfuzzArg0)"));
        assert!(src.contains("System.Text.Encoding.UTF8.GetString(data)"));
        assert!(
            !src.contains("GovfuzzUninitialized"),
            "no forced helper: {src}"
        );
    }

    #[test]
    fn forced_entry_allocates_an_uninitialized_receiver() {
        // 31 residual C# targets are instance methods on a type with no usable
        // constructor. Forced, the receiver is allocated WITHOUT running one.
        let src = generate_entry(
            &m(false, vec![p(CSharpParamKind::Str, "string")]),
            Receiver::Uninitialized,
        );
        assert!(
            src.contains("var govfuzzReceiver = ((global::Acme.Parser) GovfuzzUninitialized(typeof(global::Acme.Parser)));"),
            "{src}"
        );
        assert!(src.contains("govfuzzReceiver.Parse(govfuzzArg0)"), "{src}");
        // Resolved by reflection so the shim compiles on any TFM: the modern
        // primitive is .NET 5+, the FormatterServices spelling covers older ones.
        assert!(src.contains("RuntimeHelpers"), "{src}");
        assert!(src.contains("FormatterServices"), "{src}");
        assert!(!src.contains("new global::Acme.Parser()"), "{src}");
    }

    #[test]
    fn entry_span_and_stream_and_len() {
        let ros = decode_expr(CSharpParamKind::ByteSpan, "ReadOnlySpan<byte>", "s");
        assert_eq!(ros, "new System.ReadOnlySpan<byte>(data)");
        let rom = decode_expr(CSharpParamKind::ByteSpan, "ReadOnlyMemory<byte>", "s");
        assert_eq!(rom, "new System.ReadOnlyMemory<byte>(data)");
        let st = decode_expr(CSharpParamKind::Stream, "Stream", "s");
        assert_eq!(st, "new System.IO.MemoryStream(data, false)");
        let len = decode_expr(CSharpParamKind::Int, "int", "count");
        assert_eq!(len, "data.Length");
    }

    #[test]
    fn int_offset_is_zero_count_is_length_and_bool_false() {
        assert_eq!(decode_expr(CSharpParamKind::Int, "int", "offset"), "0");
        assert_eq!(decode_expr(CSharpParamKind::Int, "int", "startIndex"), "0");
        assert_eq!(
            decode_expr(CSharpParamKind::Int, "int", "count"),
            "data.Length"
        );
        assert_eq!(
            decode_expr(CSharpParamKind::Int, "int", "length"),
            "data.Length"
        );
        assert_eq!(
            decode_expr(CSharpParamKind::Bool, "bool", "ignoreCase"),
            "false"
        );
    }

    #[test]
    fn instance_ctor_guard_skips_param_only_ctor() {
        let method = m(false, vec![p(CSharpParamKind::Bytes, "byte[]")]);
        let src = "public class Parser { public Parser(int cfg) { } }";
        assert!(instance_receiver_ok(&method, src, false).is_err());
    }

    #[test]
    fn instance_ctor_guard_ok_with_noarg() {
        let method = m(false, vec![p(CSharpParamKind::Bytes, "byte[]")]);
        let src = "public class Parser { public Parser(int cfg) { } public Parser() { } }";
        assert_eq!(
            instance_receiver_ok(&method, src, false).unwrap(),
            Receiver::New
        );
    }

    #[test]
    fn instance_ctor_guard_skips_private_singleton() {
        // Singleton pattern: only a private parameterless ctor + a static Instance —
        // `new Parser()` does not compile, so the target must be skipped, not built.
        let method = m(false, vec![p(CSharpParamKind::Str, "string")]);
        let src = "public sealed class Parser { private Parser() { } \
                   public static readonly Parser Instance = new Parser(); \
                   public string Apply(string v) { return v; } }";
        assert!(instance_receiver_ok(&method, src, false).is_err());
        // Forced, the singleton's private ctor is bypassed rather than skipped.
        assert_eq!(
            instance_receiver_ok(&method, src, true).unwrap(),
            Receiver::Uninitialized
        );
    }

    #[test]
    fn instance_ctor_guard_ok_with_no_explicit_ctor() {
        // No declared ctor at all => the implicit public default => constructible.
        let method = m(false, vec![p(CSharpParamKind::Bytes, "byte[]")]);
        let src = "public class Parser { public void Feed(byte[] d) { } }";
        assert_eq!(
            instance_receiver_ok(&method, src, false).unwrap(),
            Receiver::New
        );
    }

    #[test]
    fn forced_receiver_refuses_a_type_with_no_instance_to_allocate() {
        // `new T()` does not compile and `GetUninitializedObject` throws for an
        // abstract type or an interface, which would make every input "crash" in the
        // shim instead of in the target — so neither arm may accept one.
        let method = m(false, vec![p(CSharpParamKind::Bytes, "byte[]")]);
        for src in [
            "public abstract class Parser { protected Parser(int cfg) { } }",
            "public abstract class Parser { public void Parse(byte[] d) { } }",
            "public interface Parser { void Parse(byte[] d); }",
        ] {
            for force in [false, true] {
                assert!(
                    instance_receiver_ok(&method, src, force).is_err(),
                    "force={force}: {src}"
                );
            }
        }
        // A concrete class whose name merely CONTAINS an abstract one is unaffected.
        let src = "public abstract class ParserBase { } \
                   public class Parser : ParserBase { public Parser(int cfg) { } }";
        assert_eq!(
            instance_receiver_ok(&method, src, true).unwrap(),
            Receiver::Uninitialized
        );
    }

    /// The TFM a host definitively CANNOT build: two majors above its newest
    /// SDK. Hardcoding one (`net10.0`) asserted a fact about the machine rather
    /// than about the code, so these tests passed on a .NET 8 box and failed on
    /// a CI runner that ships a .NET 10 SDK — where picking net10.0 is correct.
    fn unbuildable_tfm() -> String {
        format!("net{}.0", host_max_net_major() + 2)
    }

    /// The host's own newest major, which `choose_target_framework` must prefer.
    fn host_tfm() -> String {
        format!("net{}.0", host_max_net_major())
    }

    #[test]
    fn choose_tfm_prefers_supported_over_preview() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir = dir.path();
        let host = host_tfm();
        let unbuildable = unbuildable_tfm();

        // Multi-target including a framework newer than this SDK: take the
        // newest the host can actually build.
        let csproj = dir.join("Multi.csproj");
        std::fs::write(
            &csproj,
            format!(
                "<Project><PropertyGroup><TargetFrameworks>netstandard2.0;{host};{unbuildable}\
                 </TargetFrameworks></PropertyGroup></Project>"
            ),
        )
        .unwrap();
        assert_eq!(choose_target_framework(&csproj).as_deref(), Some(&*host));

        // Only netstandard — pick it; every supported host can load it.
        let ns = dir.join("Ns.csproj");
        std::fs::write(
            &ns,
            "<Project><PropertyGroup><TargetFramework>netstandard2.0</TargetFramework></PropertyGroup></Project>",
        )
        .unwrap();
        assert_eq!(
            choose_target_framework(&ns).as_deref(),
            Some("netstandard2.0")
        );

        // Only a framework this SDK cannot build — no compatible TFM.
        let only_preview = dir.join("Preview.csproj");
        std::fs::write(
            &only_preview,
            format!(
                "<Project><PropertyGroup><TargetFramework>{unbuildable}</TargetFramework>\
                 </PropertyGroup></Project>"
            ),
        )
        .unwrap();
        assert_eq!(choose_target_framework(&only_preview), None);
    }

    #[test]
    fn csproj_pins_tfm_when_supplied() {
        let dir = std::env::temp_dir();
        let csproj = dir.join("Target.csproj");
        let out = generate_csproj(
            &csproj,
            &TargetLinkage::ProjectReference {
                pinned_tfm: Some("net8.0".to_owned()),
            },
        );
        assert!(out.contains("SetTargetFramework=\"TargetFramework=net8.0\""));
        let out_none = generate_csproj(
            &csproj,
            &TargetLinkage::ProjectReference { pinned_tfm: None },
        );
        assert!(!out_none.contains("SetTargetFramework"));
    }

    /// A classic project keeps a hand-written `Properties/AssemblyInfo.cs`
    /// declaring `[assembly: AssemblyTitle]`, and the SDK synthesizes the same
    /// attributes by default — so compiling those sources into the harness gave
    /// `error CS0579: Duplicate 'AssemblyTitleAttribute' attribute` and failed
    /// every target in the project. 17 across four Windows C# projects.
    #[test]
    fn the_sdk_never_synthesizes_attributes_the_target_already_declares() {
        let csproj = std::env::temp_dir().join("Target.csproj");
        for linkage in [
            TargetLinkage::SourceInclusion {
                excluded: Vec::new(),
            },
            TargetLinkage::ProjectReference { pinned_tfm: None },
        ] {
            let out = generate_csproj(&csproj, &linkage);
            assert!(
                out.contains("<GenerateAssemblyInfo>false</GenerateAssemblyInfo>"),
                "{out}"
            );
        }
    }

    #[test]
    fn an_old_style_project_declares_its_framework_differently() {
        // A non-SDK csproj says `<TargetFrameworkVersion>v4.7.2`. Reading only
        // <TargetFramework> made it look like no framework was declared, so the
        // harness referenced the project and MSBuild failed on .NET Framework
        // reference assemblies that do not exist off Windows.
        let dir = tempfile::tempdir().expect("tempdir");
        let csproj = dir.path().join("Legacy.csproj");
        std::fs::write(
            &csproj,
            "<Project><PropertyGroup>\
             <TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion>\
             </PropertyGroup></Project>",
        )
        .expect("write");
        assert_eq!(
            declared_target_frameworks(&csproj),
            vec!["net472".to_owned()]
        );
        assert_eq!(
            choose_target_framework(&csproj),
            None,
            ".NET Framework is not buildable here, so source-inclusion applies"
        );
    }

    #[test]
    fn a_platform_or_too_new_framework_is_not_buildable_here() {
        // A `-windows` TFM needs Windows however new the SDK is, so it must not
        // be chosen on Linux — referencing it fails every target in the project.
        if !cfg!(target_os = "windows") {
            assert_eq!(tfm_rank("net8.0-windows10.0.19041.0"), None);
            assert_eq!(tfm_rank("net6.0-android"), None);
        }
        // Past the installed SDK: unbuildable. At or below it: fine, and newer
        // ranks higher so a multi-target project picks the best one.
        let host = host_max_net_major();
        assert_eq!(tfm_rank(&format!("net{}.0", host + 1)), None);
        assert!(tfm_rank(&format!("net{host}.0")).is_some());
        assert!(tfm_rank("netstandard2.0").is_some());
        assert!(
            tfm_rank("net48").is_none(),
            ".NET Framework is not buildable"
        );
        if host >= 8 {
            assert!(tfm_rank("net8.0") > tfm_rank("net6.0"));
            assert!(tfm_rank("net6.0") > tfm_rank("netstandard2.0"));
        }
    }

    #[test]
    fn an_unbuildable_project_falls_back_to_compiling_its_sources() {
        // v2rayN targets a platform TFM newer than the host SDK; the
        // ProjectReference is then a guaranteed failure for every target in the
        // project, while its ordinary C# types compile fine into the harness
        // assembly. The version is derived from the HOST, not hardcoded: written
        // as `net10.0` this asserted a fact about the machine, and CI runners
        // ship a .NET 10 SDK where building it is correct.
        let dir = tempfile::tempdir().expect("tempdir");
        let unbuildable = unbuildable_tfm();
        let platform_tfm = format!("{unbuildable}-windows10.0.19041.0");
        let csproj = dir.path().join("ServiceLib.csproj");
        std::fs::write(
            &csproj,
            format!(
                "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>\
                 <TargetFramework>{platform_tfm}</TargetFramework></PropertyGroup>\
                 <ItemGroup><PackageReference Include=\"YamlDotNet\" Version=\"15.1.0\" />\
                 <PackageReference Include=\"Central\" /></ItemGroup></Project>"
            ),
        )
        .expect("write csproj");

        assert_eq!(choose_target_framework(&csproj), None);
        assert_eq!(declared_target_frameworks(&csproj), vec![platform_tfm]);

        // v2rayN hoists its TFM into Directory.Build.props, which MSBuild
        // imports into every project beneath it; a csproj that declares nothing
        // is still pinned to it and must be recognised as unbuildable.
        let nested = dir.path().join("src/ServiceLib");
        std::fs::create_dir_all(&nested).expect("mkdir");
        std::fs::write(
            dir.path().join("src/Directory.Build.props"),
            format!(
                "<Project><PropertyGroup><TargetFramework>{unbuildable}</TargetFramework>\
                 </PropertyGroup></Project>"
            ),
        )
        .expect("write props");
        let bare = nested.join("ServiceLib.csproj");
        std::fs::write(&bare, "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>").expect("write");
        assert_eq!(declared_target_frameworks(&bare), vec![unbuildable.clone()]);
        assert_eq!(choose_target_framework(&bare), None);

        let out = generate_csproj(
            &csproj,
            &TargetLinkage::SourceInclusion {
                excluded: Vec::new(),
            },
        );
        assert!(
            out.contains("<ProjectReference Include=\"target/govfuzz_target.csproj\""),
            "{out}"
        );
        assert!(
            out.contains("<Compile Include=\"Driver.cs;GovfuzzEntry.cs\""),
            "{out}"
        );
        let target_out = generate_source_target_csproj(&csproj, &[]);
        assert!(target_out.contains("<Compile Include="), "{target_out}");
        assert!(
            target_out.contains("Exclude="),
            "bin/obj must be excluded: {target_out}"
        );
        // Packages the project declares carry over so its types still resolve;
        // a centrally-versioned entry has no version to copy and is skipped.
        assert!(
            target_out.contains("Include=\"YamlDotNet\" Version=\"15.1.0\""),
            "{target_out}"
        );
        assert!(!target_out.contains("Central"), "{target_out}");
        // The harness itself targets a framework this host can build.
        assert!(out.contains(&format!("<TargetFramework>net{}.0", host_max_net_major())));
    }

    #[test]
    fn assembly_name_from_csproj() {
        let dir = std::env::temp_dir().join("gf_cs_asmname_test");
        let _ = std::fs::create_dir_all(&dir);
        let csproj = dir.join("Foo.csproj");
        std::fs::write(
            &csproj,
            "<Project><PropertyGroup><AssemblyName>Bar</AssemblyName></PropertyGroup></Project>",
        )
        .unwrap();
        assert_eq!(target_assembly_name(&csproj), "Bar");
        let csproj2 = dir.join("Baz.csproj");
        std::fs::write(&csproj2, "<Project></Project>").unwrap();
        assert_eq!(target_assembly_name(&csproj2), "Baz");
    }
}
