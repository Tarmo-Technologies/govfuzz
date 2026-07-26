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

pub enum CSharpBuildResult {
    Built,
    /// Not fuzzable here (no `dotnet`/`sharpfuzz`, no owning project, an instance
    /// method whose type needs constructor arguments) — skip cleanly.
    Skip(String),
    /// A genuine build/instrument failure.
    Failed(String),
}

fn have(bin: &str, arg: &str) -> bool {
    Command::new(bin)
        .arg(arg)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Resolve the `sharpfuzz` instrumentation tool: on PATH, or the default dotnet
/// global-tools location `~/.dotnet/tools/sharpfuzz`.
fn locate_sharpfuzz() -> Option<PathBuf> {
    if let Ok(paths) = std::env::var("PATH") {
        for dir in std::env::split_paths(&paths) {
            let c = dir.join("sharpfuzz");
            if c.is_file() {
                return Some(c);
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let c = PathBuf::from(home).join(".dotnet/tools/sharpfuzz");
        if c.is_file() {
            return Some(c);
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
        let Ok(out) = Command::new("dotnet").arg("--list-sdks").output() else {
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
fn instance_receiver_ok(method: &CSharpMethod, source: &str) -> Result<(), String> {
    if method.is_static {
        return Ok(());
    }
    let leaf = method
        .type_name
        .rsplit('.')
        .next()
        .unwrap_or(&method.type_name);
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
    if has_explicit_ctor && !has_accessible_noarg {
        return Err(format!(
            "instance method `{}` needs a receiver, but `{leaf}` has no accessible \
             parameterless constructor (only a parameterized or private one); only \
             no-arg-constructible receivers are supported (skipped cleanly)",
            method.qualified()
        ));
    }
    Ok(())
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
fn generate_entry(method: &CSharpMethod) -> String {
    let receiver = if method.is_static {
        format!("global::{}", method.type_name)
    } else {
        format!("new global::{}()", method.type_name)
    };
    let args: Vec<String> = method
        .params
        .iter()
        .map(|p| decode_expr(p.kind, &p.raw_type, &p.name))
        .collect();
    format!(
        "// SPDX-License-Identifier: Apache-2.0\n\
         // Generated by govfuzz — do not edit. Calls the discovered target with the\n\
         // fuzz bytes decoded to each parameter's static type.\n\
         namespace Govfuzzgen {{\n\
         \x20 public static class GovfuzzEntry {{\n\
         \x20   public static void Run(byte[] data) {{\n\
         \x20     {receiver}.{method}({args});\n\
         \x20   }}\n\
         \x20 }}\n\
         }}\n",
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

fn xml_attribute(attrs: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let at = attrs.find(&needle)?;
    let rest = &attrs[at + needle.len()..];
    let end = rest.find('"')?;
    let value = rest[..end].trim();
    (!value.is_empty()).then(|| value.to_owned())
}

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
        TargetLinkage::SourceInclusion { excluded } => {
            let dir = target_csproj
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default();
            let packages: String = effective_package_references(target_csproj)
                .into_iter()
                .map(|(name, version)| {
                    format!(
                        "\n\x20   <PackageReference Include=\"{name}\" Version=\"{version}\" />"
                    )
                })
                .collect();
            let mut exclude = format!("{dir}/bin/**/*.cs;{dir}/obj/**/*.cs", dir = dir.display());
            for path in excluded {
                exclude.push(';');
                exclude.push_str(&path.display().to_string());
            }
            format!(
                "<Compile Include=\"{dir}/**/*.cs\" Exclude=\"{exclude}\" />{packages}",
                dir = dir.display(),
                exclude = exclude,
                packages = packages,
            )
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
         \x20   <EnableDefaultCompileItems>true</EnableDefaultCompileItems>\n\
         \x20   <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n\
         \x20   <Nullable>disable</Nullable>\n\
         \x20   <AssemblyName>govfuzz_harness</AssemblyName>\n\
         \x20   <ImplicitUsings>{implicit_usings}</ImplicitUsings>\n\
         \x20   <GenerateDocumentationFile>false</GenerateDocumentationFile>\n\
         \x20   <NoWarn>$(NoWarn);CS0618;CS0612;CS8032</NoWarn>\n\
         \x20   <SatelliteResourceLanguages>en</SatelliteResourceLanguages>\n\
         \x20 </PropertyGroup>\n\
         \x20 <ItemGroup>\n\
         \x20   <PackageReference Include=\"SharpFuzz\" Version=\"2.3.0\" />\n\
         \x20   {reference}\n\
         \x20 </ItemGroup>\n\
         </Project>\n",
        reference = reference,
    )
}

/// The single public entry point of the lane.
pub fn build_csharp_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
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
    if let Err(reason) = instance_receiver_ok(&method, &source) {
        return CSharpBuildResult::Skip(reason);
    }
    let Some(target_csproj) = find_target_csproj(&candidate.source_path) else {
        return CSharpBuildResult::Skip(format!(
            "no owning .csproj found for {} — the C# lane builds through a project \
             reference (skipped cleanly)",
            candidate.source_path.display()
        ));
    };

    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let proj_dir = hdir.join("proj");
    let out_dir = hdir.join("out");
    if let Err(e) = std::fs::create_dir_all(&proj_dir) {
        return CSharpBuildResult::Failed(format!("create {}: {e}", proj_dir.display()));
    }

    // Write the harness project sources.
    if let Err(e) = std::fs::copy(runtime.join("Driver.cs"), proj_dir.join("Driver.cs")) {
        return CSharpBuildResult::Failed(format!("copy Driver.cs: {e}"));
    }
    if let Err(e) = std::fs::write(proj_dir.join("GovfuzzEntry.cs"), generate_entry(&method)) {
        return CSharpBuildResult::Failed(format!("write GovfuzzEntry.cs: {e}"));
    }
    // Prefer referencing the project. When the project declares only TFMs this
    // host cannot build (a newer .NET than the installed SDK, or a
    // platform-specific `-windows` framework), referencing it fails every
    // target in the project, so compile its sources into the harness instead.
    let pinned_tfm = choose_target_framework(&target_csproj);
    let declares_tfm = declared_target_frameworks(&target_csproj);
    let linkage = if pinned_tfm.is_none() && !declares_tfm.is_empty() {
        eprintln!(
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
        let recovered_path = proj_dir.join("GovfuzzRecoveredUsings.cs");
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
                    let trimmed = line.trim();
                    if trimmed.starts_with("global using")
                        && !recovered_usings.iter().any(|u| u == trimmed)
                    {
                        new_usings.push(trimmed.to_owned());
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
        eprintln!(
            "govfuzz auto: C# source-inclusion: ejecting {} file(s) that do not compile \
             into the harness (round {})",
            failing.len(),
            round + 1,
        );
        excluded.extend(failing);
        if let Err(e) = std::fs::write(
            proj_dir.join("govfuzz_harness.csproj"),
            generate_csproj(&target_csproj, &linkage),
        ) {
            return CSharpBuildResult::Failed(format!("rewrite harness csproj: {e}"));
        }
    }

    // Instrument the assembly the target's IL actually landed in: its own when
    // the project was referenced, the harness itself under source-inclusion.
    let asm = match linkage {
        TargetLinkage::SourceInclusion { .. } => "govfuzz_harness".to_owned(),
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
    CSharpBuildResult::Built
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
    fn entry_static_byte_array() {
        let src = generate_entry(&m(true, vec![p(CSharpParamKind::Bytes, "byte[]")]));
        assert!(src.contains("global::Acme.Parser.Parse(data)"));
    }

    #[test]
    fn entry_instance_string() {
        let src = generate_entry(&m(false, vec![p(CSharpParamKind::Str, "string")]));
        assert!(src.contains("new global::Acme.Parser().Parse("));
        assert!(src.contains("System.Text.Encoding.UTF8.GetString(data)"));
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
        assert!(instance_receiver_ok(&method, src).is_err());
    }

    #[test]
    fn instance_ctor_guard_ok_with_noarg() {
        let method = m(false, vec![p(CSharpParamKind::Bytes, "byte[]")]);
        let src = "public class Parser { public Parser(int cfg) { } public Parser() { } }";
        assert!(instance_receiver_ok(&method, src).is_ok());
    }

    #[test]
    fn instance_ctor_guard_skips_private_singleton() {
        // Singleton pattern: only a private parameterless ctor + a static Instance —
        // `new Parser()` does not compile, so the target must be skipped, not built.
        let method = m(false, vec![p(CSharpParamKind::Str, "string")]);
        let src = "public sealed class Parser { private Parser() { } \
                   public static readonly Parser Instance = new Parser(); \
                   public string Apply(string v) { return v; } }";
        assert!(instance_receiver_ok(&method, src).is_err());
    }

    #[test]
    fn instance_ctor_guard_ok_with_no_explicit_ctor() {
        // No declared ctor at all => the implicit public default => constructible.
        let method = m(false, vec![p(CSharpParamKind::Bytes, "byte[]")]);
        let src = "public class Parser { public void Feed(byte[] d) { } }";
        assert!(instance_receiver_ok(&method, src).is_ok());
    }

    #[test]
    fn choose_tfm_prefers_supported_over_preview() {
        let dir = std::env::temp_dir().join("gf_cs_tfm_test");
        let _ = std::fs::create_dir_all(&dir);
        // Multi-target incl. a preview net10.0 the net8.0 SDK can't build.
        let csproj = dir.join("Multi.csproj");
        std::fs::write(
            &csproj,
            "<Project><PropertyGroup><TargetFrameworks>netstandard2.0;net8.0;net10.0</TargetFrameworks></PropertyGroup></Project>",
        )
        .unwrap();
        assert_eq!(choose_target_framework(&csproj).as_deref(), Some("net8.0"));

        // Only netstandard — pick it (net8.0 host can load it).
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

        // Only an unsupported preview — no compatible TFM.
        let only_preview = dir.join("Preview.csproj");
        std::fs::write(
            &only_preview,
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>",
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
        // v2rayN targets net10.0-windows; on a .NET 8 host the ProjectReference
        // is a guaranteed failure for every target in the project, while its
        // ordinary C# types compile fine into the harness assembly.
        let dir = tempfile::tempdir().expect("tempdir");
        let csproj = dir.path().join("ServiceLib.csproj");
        std::fs::write(
            &csproj,
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>\
             <TargetFramework>net10.0-windows10.0.19041.0</TargetFramework></PropertyGroup>\
             <ItemGroup><PackageReference Include=\"YamlDotNet\" Version=\"15.1.0\" />\
             <PackageReference Include=\"Central\" /></ItemGroup></Project>",
        )
        .expect("write csproj");

        assert_eq!(choose_target_framework(&csproj), None);
        assert_eq!(
            declared_target_frameworks(&csproj),
            vec!["net10.0-windows10.0.19041.0".to_owned()]
        );

        // v2rayN hoists its TFM into Directory.Build.props, which MSBuild
        // imports into every project beneath it; a csproj that declares nothing
        // is still pinned to net10.0 and must be recognised as unbuildable.
        let nested = dir.path().join("src/ServiceLib");
        std::fs::create_dir_all(&nested).expect("mkdir");
        std::fs::write(
            dir.path().join("src/Directory.Build.props"),
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework>\
             </PropertyGroup></Project>",
        )
        .expect("write props");
        let bare = nested.join("ServiceLib.csproj");
        std::fs::write(&bare, "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>").expect("write");
        assert_eq!(
            declared_target_frameworks(&bare),
            vec!["net10.0".to_owned()]
        );
        assert_eq!(choose_target_framework(&bare), None);

        let out = generate_csproj(
            &csproj,
            &TargetLinkage::SourceInclusion {
                excluded: Vec::new(),
            },
        );
        assert!(out.contains("<Compile Include="), "{out}");
        assert!(out.contains("Exclude="), "bin/obj must be excluded: {out}");
        assert!(!out.contains("ProjectReference"), "{out}");
        // Packages the project declares carry over so its types still resolve;
        // a centrally-versioned entry has no version to copy and is skipped.
        assert!(
            out.contains("Include=\"YamlDotNet\" Version=\"15.1.0\""),
            "{out}"
        );
        assert!(!out.contains("Central"), "{out}");
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
