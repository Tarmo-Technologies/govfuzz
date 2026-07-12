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
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..6 {
            if let Some(d) = &dir {
                let cand = d.join("csharp_runtime");
                if cand.join("Driver.cs").is_file() {
                    return Some(cand);
                }
                dir = d.parent().map(Path::to_path_buf);
            }
        }
    }
    let from_manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("csharp_runtime"));
    if let Some(p) = &from_manifest {
        if p.join("Driver.cs").is_file() {
            return from_manifest;
        }
    }
    None
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
fn tfm_rank(tfm: &str) -> Option<u32> {
    let t = tfm.trim().to_ascii_lowercase();
    match t.as_str() {
        "net8.0" => Some(100),
        "net7.0" => Some(90),
        "net6.0" => Some(80),
        "net5.0" => Some(70),
        "netcoreapp3.1" => Some(60),
        "netcoreapp3.0" => Some(55),
        "netstandard2.1" => Some(50),
        "netstandard2.0" => Some(40),
        "netstandard1.6" => Some(30),
        _ => None,
    }
}

/// Choose the best framework to pin the target `ProjectReference` to. A .NET
/// library often multi-targets (`netstandard2.0;net8.0;net10.0`); without pinning,
/// the reference builds *every* framework — including any the installed SDK can't
/// build (a preview `net10.0`), failing the whole harness. Parse the declared
/// `<TargetFramework(s)>` and return the highest one the net8.0 host supports.
fn choose_target_framework(csproj: &Path) -> Option<String> {
    let text = std::fs::read_to_string(csproj).ok()?;
    let raw =
        xml_element(&text, "TargetFrameworks").or_else(|| xml_element(&text, "TargetFramework"))?;
    raw.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|tfm| tfm_rank(tfm).map(|r| (r, tfm.to_owned())))
        .max_by_key(|(r, _)| *r)
        .map(|(_, tfm)| tfm)
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
    let source = std::fs::read_to_string(&candidate.source_path)
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

/// The C# expression that decodes the fuzz bytes (`data`) to `param`'s type.
fn decode_expr(kind: CSharpParamKind, raw_type: &str) -> String {
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
        CSharpParamKind::Int => "data.Length".to_owned(),
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
        .map(|p| decode_expr(p.kind, &p.raw_type))
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
fn generate_csproj(target_csproj: &Path, pinned_tfm: Option<&str>) -> String {
    let reference = match pinned_tfm {
        Some(tfm) => format!(
            "<ProjectReference Include=\"{target}\" \
             SetTargetFramework=\"TargetFramework={tfm}\" />",
            target = target_csproj.display(),
        ),
        None => format!(
            "<ProjectReference Include=\"{target}\" />",
            target = target_csproj.display(),
        ),
    };
    format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n\
         \x20 <PropertyGroup>\n\
         \x20   <OutputType>Exe</OutputType>\n\
         \x20   <TargetFramework>net8.0</TargetFramework>\n\
         \x20   <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n\
         \x20   <Nullable>disable</Nullable>\n\
         \x20   <AssemblyName>govfuzz_harness</AssemblyName>\n\
         \x20   <ImplicitUsings>disable</ImplicitUsings>\n\
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

    let source = match std::fs::read_to_string(&candidate.source_path) {
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
    let pinned_tfm = choose_target_framework(&target_csproj);
    if let Err(e) = std::fs::write(
        proj_dir.join("govfuzz_harness.csproj"),
        generate_csproj(&target_csproj, pinned_tfm.as_deref()),
    ) {
        return CSharpBuildResult::Failed(format!("write harness csproj: {e}"));
    }

    // Build. `--nologo`, restore from the local NuGet cache; keep the CLI quiet.
    let build = Command::new("dotnet")
        .arg("build")
        .arg(proj_dir.join("govfuzz_harness.csproj"))
        .arg("-c")
        .arg("Release")
        .arg("-o")
        .arg(&out_dir)
        .arg("--nologo")
        .arg("-v")
        .arg("quiet")
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .env("DOTNET_NOLOGO", "1")
        .output();
    match build {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let mut msg = String::from_utf8_lossy(&o.stdout).to_string();
            msg.push_str(&String::from_utf8_lossy(&o.stderr));
            return CSharpBuildResult::Failed(format!(
                "dotnet build failed:\n{}",
                tail(&msg, 4000)
            ));
        }
        Err(e) => return CSharpBuildResult::Failed(format!("spawn dotnet build: {e}")),
    }

    // Instrument the target assembly's IL (edge coverage into the shared map).
    let asm = target_assembly_name(&target_csproj);
    let target_dll = out_dir.join(format!("{asm}.dll"));
    if !target_dll.is_file() {
        return CSharpBuildResult::Failed(format!(
            "target assembly {} not found after build (assembly name `{asm}`)",
            target_dll.display()
        ));
    }
    let instr = Command::new(&sharpfuzz)
        .arg(&target_dll)
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        // The `sharpfuzz` global tool targets an older runtime than the SDK may
        // ship (e.g. a net8.0 tool on a host with only the .NET 10 runtime); roll
        // it forward so instrumentation works whatever runtime is installed.
        .env("DOTNET_ROLL_FORWARD", "Major")
        .output();
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
        let ros = decode_expr(CSharpParamKind::ByteSpan, "ReadOnlySpan<byte>");
        assert_eq!(ros, "new System.ReadOnlySpan<byte>(data)");
        let rom = decode_expr(CSharpParamKind::ByteSpan, "ReadOnlyMemory<byte>");
        assert_eq!(rom, "new System.ReadOnlyMemory<byte>(data)");
        let st = decode_expr(CSharpParamKind::Stream, "Stream");
        assert_eq!(st, "new System.IO.MemoryStream(data, false)");
        let len = decode_expr(CSharpParamKind::Int, "int");
        assert_eq!(len, "data.Length");
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
        let out = generate_csproj(&csproj, Some("net8.0"));
        assert!(out.contains("SetTargetFramework=\"TargetFramework=net8.0\""));
        let out_none = generate_csproj(&csproj, None);
        assert!(!out_none.contains("SetTargetFramework"));
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
