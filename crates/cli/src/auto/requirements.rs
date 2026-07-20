// SPDX-License-Identifier: Apache-2.0

//! Early, read-only discovery of offline content requirements.
//!
//! This pass runs before the target sweep so `missing-deps.*` exists even if the
//! parent process is later killed. It records only requirements supported by an
//! executable preflight probe, explicit project metadata, or a conservative
//! platform/build declaration. Per-target compiler/runtime diagnostics are folded
//! into the same manifest by `report::write_dependency_checkpoint`.

use crate::auto::candidate::{Candidate, Lang};
use crate::auto::dep_manifest::{DepKind, DependencyManifest, RequirementBasis};
use crate::auto::preflight::PreflightReport;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Build the manifest seed that is durable before the first target starts.
pub fn scan(
    source_root: &Path,
    candidates: &[Candidate],
    preflight: &PreflightReport,
    extra_ada_dirs: &[PathBuf],
    work_dir: &Path,
    include_probe_evidence: bool,
) -> DependencyManifest {
    let mut manifest = DependencyManifest::new();
    add_target_requirements(&mut manifest, candidates, preflight);
    add_missing_git_submodules(&mut manifest, source_root);
    add_missing_alire_sources(&mut manifest, source_root, extra_ada_dirs, work_dir);
    add_declared_generated_outputs(&mut manifest, source_root, work_dir);
    if include_probe_evidence {
        add_probe_requirements(&mut manifest, source_root);
    }
    manifest.mark_checkpoint(0, false);
    manifest
}

/// Add requirements that can only be established after target discovery and
/// toolchain preflight. This lets the caller preserve an already-checkpointed
/// project-metadata/probe seed without rescanning the tree.
pub fn add_target_requirements(
    manifest: &mut DependencyManifest,
    candidates: &[Candidate],
    preflight: &PreflightReport,
) {
    add_host_toolchains(manifest, preflight);
    add_cross_requirements(manifest, candidates);
}

fn add_probe_requirements(manifest: &mut DependencyManifest, source_root: &Path) {
    for requirement in crate::auto::build_probe::load_probe_requirements(source_root) {
        manifest.push_merge_detailed(
            requirement.kind,
            requirement.name,
            vec!["project build probe".to_owned()],
            false,
            Some(requirement.acquisition_hint),
            RequirementBasis::Observed,
            Some(requirement.evidence),
        );
    }
}

fn add_host_toolchains(manifest: &mut DependencyManifest, preflight: &PreflightReport) {
    for lane in preflight.missing_lanes() {
        for tool in &lane.missing {
            manifest.push_merge_detailed(
                DepKind::Toolchain,
                (*tool).to_owned(),
                vec![format!(
                    "preflight: {} ({} target(s))",
                    lane.lang, lane.targets
                )],
                false,
                Some(lane.install_hint.to_owned()),
                RequirementBasis::Observed,
                Some(format!(
                    "no executable satisfying the {} lane's required '{}' tool group was found on PATH",
                    lane.lang, tool
                )),
            );
        }
    }
}

fn add_cross_requirements(manifest: &mut DependencyManifest, candidates: &[Candidate]) {
    for candidate in candidates {
        let Some(guard) = candidate.foreign_guard.as_deref() else {
            continue;
        };
        let reference = vec![candidate.harness_id.clone()];
        if candidate.lang == Lang::Ada {
            let target = crate::auto::cross_target::resolve_cross_target(guard);
            let target_name = target
                .as_ref()
                .map(|target| target.triple.as_str())
                .unwrap_or(guard);
            manifest.push_merge_detailed(
                DepKind::Runtime,
                format!("matching GNAT cross toolchain/runtime for {target_name}"),
                reference,
                false,
                Some(format!(
                    "stage a GNAT cross compiler and Ada runtime matching '{target_name}'; GovFuzz auto does not yet drive foreign Ada targets automatically"
                )),
                RequirementBasis::Inferred,
                Some(format!(
                    "candidate is guarded for foreign platform/architecture '{guard}'"
                )),
            );
            continue;
        }

        if let Some(target) = crate::auto::cross_target::resolve_cross_target(guard) {
            let can_stub = crate::auto::cross_target::foreign_platform_stub(guard).is_some();
            if !crate::auto::cross_target::executable_on_path(&target.cc) {
                manifest.push_merge_detailed(
                    DepKind::Toolchain,
                    target.cc.clone(),
                    reference.clone(),
                    can_stub,
                    Some(format!(
                        "install the {} cross toolchain ({}, {})",
                        target.triple, target.cc, target.cxx
                    )),
                    RequirementBasis::Inferred,
                    Some(format!(
                        "candidate guard '{guard}' maps to {}",
                        target.triple
                    )),
                );
            }
            if candidate.lang == Lang::Cpp
                && !crate::auto::cross_target::executable_on_path(&target.cxx)
            {
                manifest.push_merge_detailed(
                    DepKind::Toolchain,
                    target.cxx.clone(),
                    reference.clone(),
                    can_stub,
                    Some(format!("install the {} C++ cross compiler", target.triple)),
                    RequirementBasis::Inferred,
                    Some(format!(
                        "C++ candidate guard '{guard}' maps to {}",
                        target.triple
                    )),
                );
            }
            if !crate::auto::cross_target::executable_on_path(target.runner.exe()) {
                manifest.push_merge_detailed(
                    DepKind::Runtime,
                    target.runner.exe().to_owned(),
                    reference,
                    can_stub,
                    Some(format!(
                        "install {} to execute {} harnesses on this host",
                        target.runner.exe(),
                        target.triple
                    )),
                    RequirementBasis::Inferred,
                    Some(format!(
                        "candidate guard '{guard}' maps to {}",
                        target.triple
                    )),
                );
            }
        } else if let Some(stub) = crate::auto::cross_target::foreign_platform_stub(guard) {
            manifest.push_merge_detailed(
                DepKind::Runtime,
                format!("{} SDK/runtime", stub.platform),
                reference,
                true,
                Some(format!(
                    "stage a compatible {} SDK/runtime and a runnable target environment; GovFuzz used a host-side platform stub",
                    stub.platform
                )),
                RequirementBasis::Inferred,
                Some(format!("candidate is guarded by '{guard}'")),
            );
        } else {
            manifest.push_merge_detailed(
                DepKind::Runtime,
                format!("toolchain/runtime for platform guard {guard}"),
                reference,
                false,
                Some(
                    "identify and stage the vendor compiler, target runtime, and runner matching this project guard"
                        .to_owned(),
                ),
                RequirementBasis::Inferred,
                Some("GovFuzz has no exact cross-target mapping for this guard".to_owned()),
            );
        }
    }
}

fn add_missing_git_submodules(manifest: &mut DependencyManifest, source_root: &Path) {
    let path = source_root.join(".gitmodules");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let mut current = String::new();
    let mut sections: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current = line.to_owned();
            sections.entry(current.clone()).or_default();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let entry = sections.entry(current.clone()).or_default();
        match key.trim() {
            "path" => entry.0 = Some(value.trim().to_owned()),
            "url" => entry.1 = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    for (_section, (rel, url)) in sections {
        let Some(rel) = rel else {
            continue;
        };
        let checkout = source_root.join(&rel);
        if directory_has_payload(&checkout) {
            continue;
        }
        let url_text = url.as_deref().unwrap_or("URL not recorded");
        manifest.push_merge_detailed(
            DepKind::VendorSource,
            rel.clone(),
            vec![".gitmodules".to_owned()],
            false,
            Some(format!(
                "initialize/copy the submodule from '{url_text}' at the commit pinned by the superproject"
            )),
            RequirementBasis::Declared,
            Some(format!(
                ".gitmodules declares path '{rel}' with URL '{url_text}', but that directory has no source payload"
            )),
        );
    }
}

fn directory_has_payload(path: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        return false;
    };
    entries.flatten().any(|entry| entry.file_name() != ".git")
}

fn add_missing_alire_sources(
    manifest: &mut DependencyManifest,
    source_root: &Path,
    extra_ada_dirs: &[PathBuf],
    work_dir: &Path,
) {
    let project = source_root.join("alire.toml");
    let Some(declared) = alire_dependencies(&project) else {
        return;
    };
    let available = available_alire_crates(source_root, extra_ada_dirs, work_dir);
    for (name, constraint) in declared {
        if is_alire_toolchain(&name) || available.contains(&name) {
            continue;
        }
        let requirement = if constraint.is_empty() {
            name.clone()
        } else {
            format!("{name} {constraint}")
        };
        manifest.push_merge_detailed(
            DepKind::VendorSource,
            requirement,
            vec!["alire.toml [depends-on]".to_owned()],
            false,
            Some(format!(
                "on a connected host run `alr get {name}` (respecting {constraint}), transfer the crate source closure, then pass its directory with --ada-deps"
            )),
            RequirementBasis::Declared,
            Some(format!(
                "alire.toml declares crate '{name}' constraint '{constraint}', but no matching local crate source manifest was found"
            )),
        );
    }
}

fn alire_dependencies(path: &Path) -> Option<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: toml::Value = toml::from_str(&text).ok()?;
    let mut out = BTreeMap::new();
    match value.get("depends-on") {
        Some(toml::Value::Table(table)) => collect_alire_dep_table(table, &mut out),
        Some(toml::Value::Array(tables)) => {
            for table in tables.iter().filter_map(toml::Value::as_table) {
                collect_alire_dep_table(table, &mut out);
            }
        }
        _ => {}
    }
    Some(out.into_iter().collect())
}

fn collect_alire_dep_table(
    table: &toml::map::Map<String, toml::Value>,
    out: &mut BTreeMap<String, String>,
) {
    for (name, value) in table {
        let constraint = value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string());
        out.insert(name.to_ascii_lowercase(), constraint);
    }
}

fn is_alire_toolchain(name: &str) -> bool {
    matches!(
        name,
        "gnat" | "gnat_native" | "gnat_external" | "gprbuild" | "gnatcov" | "gnatprove"
    )
}

fn available_alire_crates(
    source_root: &Path,
    extra_dirs: &[PathBuf],
    work_dir: &Path,
) -> BTreeSet<String> {
    let mut roots = vec![source_root.to_path_buf()];
    roots.extend(extra_dirs.iter().cloned());
    for base in alire_cache_roots() {
        if base.is_dir() {
            roots.push(base);
        }
    }
    let mut names = BTreeSet::new();
    let mut seen = 0usize;
    let mut stack: Vec<(PathBuf, usize)> = roots.into_iter().map(|root| (root, 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        if seen > 100_000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            let path = entry.path();
            if path.starts_with(work_dir) {
                continue;
            }
            if path.is_dir() && depth < 6 {
                stack.push((path, depth + 1));
            } else if entry.file_name() == "alire.toml" {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    if let Ok(value) = toml::from_str::<toml::Value>(&text) {
                        if let Some(name) = value.get("name").and_then(toml::Value::as_str) {
                            names.insert(name.to_ascii_lowercase());
                        }
                    }
                }
            }
        }
    }
    names
}

fn alire_cache_roots() -> Vec<PathBuf> {
    let mut bases = Vec::new();
    if let Some(dir) = std::env::var_os("ALIRE_SETTINGS_DIR") {
        bases.push(PathBuf::from(dir));
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for sub in [
            ".config/alire",
            ".local/share/alire",
            ".alire",
            ".cache/alire",
        ] {
            bases.push(home.join(sub));
        }
    }
    let mut roots = Vec::new();
    for base in bases {
        roots.push(base.join("cache/releases"));
        roots.push(base.join("cache/dependencies"));
        roots.push(base.join("cache/builds"));
        roots.push(base.join("builds"));
    }
    roots
}

fn add_declared_generated_outputs(
    manifest: &mut DependencyManifest,
    source_root: &Path,
    work_dir: &Path,
) {
    let mut stack = vec![(source_root.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 150_000 {
                return;
            }
            let path = entry.path();
            if path.starts_with(work_dir) {
                continue;
            }
            if path.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if depth < 8
                    && !matches!(
                        name.as_ref(),
                        ".git"
                            | ".govfuzz-build"
                            | "target"
                            | "node_modules"
                            | "CMakeFiles"
                            | "govfuzz_work"
                    )
                {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if entry.file_name() == "CMakeLists.txt" {
                scan_cmake_generated_outputs(manifest, source_root, &path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("in") {
                scan_configure_template(manifest, source_root, &path);
            }
        }
    }
}

fn scan_configure_template(manifest: &mut DependencyManifest, source_root: &Path, template: &Path) {
    let Some(name) = template.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let Some(output_name) = name.strip_suffix(".in") else {
        return;
    };
    if !is_generated_source_name(output_name) {
        return;
    }
    let output = template.with_file_name(output_name);
    if output.is_file() {
        return;
    }
    let rel_template = template.strip_prefix(source_root).unwrap_or(template);
    let rel_output = output.strip_prefix(source_root).unwrap_or(&output);
    manifest.push_merge_detailed(
        DepKind::GeneratedSource,
        rel_output.display().to_string(),
        vec![rel_template.display().to_string()],
        false,
        Some(format!(
            "run the project's configure/CMake step to generate '{}' from '{}' (or transfer that exact generated output)",
            rel_output.display(),
            rel_template.display()
        )),
        RequirementBasis::Declared,
        Some(format!(
            "generation template '{}' exists, but its output '{}' does not",
            rel_template.display(),
            rel_output.display()
        )),
    );
}

fn is_generated_source_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".h", ".hpp", ".hh", ".c", ".cc", ".cpp", ".ads", ".adb"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

fn scan_cmake_generated_outputs(
    manifest: &mut DependencyManifest,
    source_root: &Path,
    cmake_file: &Path,
) {
    let Ok(text) = std::fs::read_to_string(cmake_file) else {
        return;
    };
    let rel = cmake_file.strip_prefix(source_root).unwrap_or(cmake_file);
    let mut generated_outputs = BTreeSet::new();
    let configure = Regex::new(r"(?is)configure_file\s*\(\s*([^\s\)]+)\s+([^\s\)]+)")
        .expect("configure_file regex");
    for captures in configure.captures_iter(&text) {
        let input = trim_cmake_token(&captures[1]);
        let output = trim_cmake_token(&captures[2]);
        generated_outputs.insert(output.to_owned());
        if generated_output_present(source_root, cmake_file, output) {
            continue;
        }
        manifest.push_merge_detailed(
            DepKind::GeneratedSource,
            output.to_owned(),
            vec![rel.display().to_string()],
            false,
            Some(format!(
                "run CMake/configure to produce '{output}' from '{input}', then transfer the generated output if the offline host cannot run that step"
            )),
            RequirementBasis::Declared,
            Some(format!("{} declares configure_file({input} {output})", rel.display())),
        );
        add_missing_codegen_tool(manifest, "cmake", rel);
    }

    let custom =
        Regex::new(r"(?is)add_custom_command\s*\((.*?)\)").expect("add_custom_command regex");
    for captures in custom.captures_iter(&text) {
        let body = &captures[1];
        let tokens = cmake_tokens(body);
        let Some(output_at) = tokens
            .iter()
            .position(|token| token.eq_ignore_ascii_case("OUTPUT"))
        else {
            continue;
        };
        let end = tokens[output_at + 1..]
            .iter()
            .position(|token| cmake_keyword(token))
            .map(|offset| output_at + 1 + offset)
            .unwrap_or(tokens.len());
        for output in &tokens[output_at + 1..end] {
            generated_outputs.insert(output.clone());
            if output.starts_with('$') || generated_output_present(source_root, cmake_file, output)
            {
                continue;
            }
            manifest.push_merge_detailed(
                DepKind::GeneratedSource,
                output.clone(),
                vec![rel.display().to_string()],
                false,
                Some(format!(
                    "run the add_custom_command declared in {} to materialize '{output}'",
                    rel.display()
                )),
                RequirementBasis::Declared,
                Some(format!(
                    "{} declares add_custom_command(OUTPUT {output} ...)",
                    rel.display()
                )),
            );
        }
        if let Some(command_at) = tokens
            .iter()
            .position(|token| token.eq_ignore_ascii_case("COMMAND"))
        {
            if let Some(tool) = tokens.get(command_at + 1) {
                if literal_tool_name(tool).is_some() {
                    add_missing_codegen_tool(manifest, tool, rel);
                }
            }
        }
    }
    scan_cmake_missing_literal_sources(
        manifest,
        source_root,
        cmake_file,
        &text,
        &generated_outputs,
    );
}

fn scan_cmake_missing_literal_sources(
    manifest: &mut DependencyManifest,
    source_root: &Path,
    cmake_file: &Path,
    text: &str,
    generated_outputs: &BTreeSet<String>,
) {
    let commands = Regex::new(r"(?is)(?:add_library|add_executable|target_sources)\s*\((.*?)\)")
        .expect("CMake source command regex");
    let declared_by = cmake_file.strip_prefix(source_root).unwrap_or(cmake_file);
    for captures in commands.captures_iter(text) {
        let tokens = cmake_tokens(&captures[1]);
        // The first token is the target name for all three commands.
        for token in tokens.iter().skip(1) {
            for source in token.split(';') {
                let source = trim_cmake_token(source);
                if source.is_empty()
                    || source.contains('$')
                    || cmake_source_keyword(source)
                    || !is_semantic_source_name(source)
                    || generated_outputs.contains(source)
                    || declared_source_present(source_root, cmake_file, source)
                {
                    continue;
                }
                manifest.push_merge_detailed(
                    DepKind::VendorSource,
                    source.to_owned(),
                    vec![declared_by.display().to_string()],
                    false,
                    Some(format!(
                        "restore or transfer the exact source '{source}' declared by {}; GovFuzz cannot synthesize its implementation semantics",
                        declared_by.display()
                    )),
                    RequirementBasis::Declared,
                    Some(format!(
                        "{} names '{source}' as target source, but it is absent from the source drop and is not a declared generated output",
                        declared_by.display()
                    )),
                );
            }
        }
    }
}

fn cmake_source_keyword(token: &str) -> bool {
    matches!(
        token.to_ascii_uppercase().as_str(),
        "STATIC"
            | "SHARED"
            | "MODULE"
            | "OBJECT"
            | "INTERFACE"
            | "IMPORTED"
            | "ALIAS"
            | "EXCLUDE_FROM_ALL"
            | "WIN32"
            | "MACOSX_BUNDLE"
            | "PRIVATE"
            | "PUBLIC"
            | "BEFORE"
            | "SYSTEM"
    )
}

fn is_semantic_source_name(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".s", ".asm", ".ads", ".adb",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
}

fn declared_source_present(source_root: &Path, cmake_file: &Path, source: &str) -> bool {
    let source = Path::new(source);
    if source.is_absolute() {
        return source.is_file();
    }
    let base = cmake_file.parent().unwrap_or(source_root);
    base.join(source).is_file()
        || source_root.join(source).is_file()
        || source_root
            .join(crate::auto::build_probe::PROBE_DIR)
            .join(source)
            .is_file()
}

fn trim_cmake_token(token: &str) -> &str {
    token.trim_matches(['"', '\''])
}

fn cmake_tokens(body: &str) -> Vec<String> {
    body.split_whitespace()
        .map(|token| trim_cmake_token(token.trim_matches(['(', ')'])).to_owned())
        .filter(|token| !token.is_empty())
        .collect()
}

fn cmake_keyword(token: &str) -> bool {
    matches!(
        token.to_ascii_uppercase().as_str(),
        "COMMAND"
            | "DEPENDS"
            | "BYPRODUCTS"
            | "WORKING_DIRECTORY"
            | "COMMENT"
            | "VERBATIM"
            | "MAIN_DEPENDENCY"
            | "IMPLICIT_DEPENDS"
            | "DEPFILE"
            | "JOB_POOL"
    )
}

fn literal_tool_name(tool: &str) -> Option<&str> {
    if tool.starts_with('$') || tool.contains('/') || tool.contains('\\') || tool.starts_with('-') {
        None
    } else {
        Some(tool)
    }
}

fn add_missing_codegen_tool(manifest: &mut DependencyManifest, tool: &str, declared_by: &Path) {
    let tool = trim_cmake_token(tool);
    if literal_tool_name(tool).is_none() || which::which(tool).is_ok() {
        return;
    }
    manifest.push_merge_detailed(
        DepKind::CodegenTool,
        tool.to_owned(),
        vec![declared_by.display().to_string()],
        false,
        Some(format!(
            "install '{tool}' on the isolated build host and re-run with --run-untrusted"
        )),
        RequirementBasis::Declared,
        Some(format!(
            "{} names '{tool}' as a generation command",
            declared_by.display()
        )),
    );
}

fn generated_output_present(source_root: &Path, cmake_file: &Path, output: &str) -> bool {
    let output = trim_cmake_token(output);
    if output.contains("${") || output.contains("$<") {
        let Some(leaf) = Path::new(output).file_name().and_then(|leaf| leaf.to_str()) else {
            return false;
        };
        return find_leaf(source_root, leaf);
    }
    let base = cmake_file.parent().unwrap_or(source_root);
    base.join(output).is_file()
        || source_root.join(output).is_file()
        || source_root
            .join(crate::auto::build_probe::PROBE_DIR)
            .join(output)
            .is_file()
}

fn find_leaf(root: &Path, leaf: &str) -> bool {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 100_000 {
                return false;
            }
            if entry.file_name() == leaf {
                return true;
            }
            if entry.path().is_dir() && depth < 8 {
                stack.push((entry.path(), depth + 1));
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::candidate::Candidate;
    use crate::auto::preflight::{LaneStatus, PreflightReport};

    fn tmpdir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "govfuzz-requirements-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn seed_records_missing_toolchain_submodule_and_generated_output() {
        let root = tmpdir();
        std::fs::write(
            root.join(".gitmodules"),
            "[submodule \"vendor/codec\"]\n path = vendor/codec\n url = https://example.invalid/codec.git\n",
        )
        .unwrap();
        std::fs::write(root.join("config.h.in"), "#undef FEATURE\n").unwrap();
        let preflight = PreflightReport {
            lanes: vec![LaneStatus {
                lang: "Ada",
                targets: 2,
                missing: vec!["definitely-missing-gnat-test"],
                install_hint: "install GNAT",
            }],
        };
        let manifest = scan(&root, &[], &preflight, &[], &root.join("work"), false);
        assert!(manifest.has(DepKind::Toolchain, "definitely-missing-gnat-test"));
        assert!(manifest.has(DepKind::VendorSource, "vendor/codec"));
        assert!(manifest.has(DepKind::GeneratedSource, "config.h"));
        let text = manifest.render_text();
        let critical = text.find("Required toolchains").unwrap();
        let ordinary = text.find("Other blocking").unwrap_or(text.len());
        assert!(critical < ordinary, "{text}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cmake_missing_literal_source_is_semantic_but_declared_output_is_generated() {
        let root = tmpdir();
        std::fs::write(
            root.join("CMakeLists.txt"),
            "add_custom_command(OUTPUT generated.c COMMAND codegen input.idl)\n\
             add_library(codec STATIC vendor/codec.c generated.c)\n",
        )
        .unwrap();
        let manifest = scan(
            &root,
            &[],
            &PreflightReport { lanes: Vec::new() },
            &[],
            &root.join("work"),
            false,
        );
        assert!(manifest.has(DepKind::VendorSource, "vendor/codec.c"));
        assert!(manifest.has(DepKind::GeneratedSource, "generated.c"));
        assert!(!manifest
            .entries
            .iter()
            .any(|entry| entry.kind == DepKind::VendorSource && entry.name == "generated.c"));
        let semantic = manifest
            .entries
            .iter()
            .find(|entry| entry.kind == DepKind::VendorSource && entry.name == "vendor/codec.c")
            .unwrap();
        assert_eq!(semantic.basis, RequirementBasis::Declared);
        assert!(semantic
            .evidence
            .as_deref()
            .unwrap()
            .contains("CMakeLists.txt"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn foreign_candidate_names_missing_cross_runtime() {
        let root = tmpdir();
        let candidate = Candidate {
            harness_id: "H-C0001".to_owned(),
            lang: Lang::C,
            source_path: root.join("arm.c"),
            line: 1,
            name: "decode".to_owned(),
            score: 1,
            is_static: false,
            foreign_guard: Some("__aarch64__".to_owned()),
            input_reachability: None,
            dialect: None,
        };
        let manifest = scan(
            &root,
            &[candidate],
            &PreflightReport { lanes: Vec::new() },
            &[],
            &root.join("work"),
            false,
        );
        assert!(manifest
            .entries
            .iter()
            .any(|entry| { entry.kind == DepKind::Runtime && entry.name == "qemu-aarch64" }));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn requested_probe_evidence_is_folded_into_seed() {
        let root = tmpdir();
        let probe = root.join(crate::auto::build_probe::PROBE_DIR);
        std::fs::create_dir_all(&probe).unwrap();
        let requirements = vec![crate::auto::build_probe::ProbeRequirement {
            kind: DepKind::SharedLibrary,
            name: "ZLIB".to_owned(),
            acquisition_hint: "stage zlib development package".to_owned(),
            evidence: "CMake Could NOT find ZLIB".to_owned(),
        }];
        std::fs::write(
            probe.join("missing-requirements.json"),
            serde_json::to_vec(&requirements).unwrap(),
        )
        .unwrap();
        let manifest = scan(
            &root,
            &[],
            &PreflightReport { lanes: Vec::new() },
            &[],
            &root.join("work"),
            true,
        );
        let entry = manifest
            .entries
            .iter()
            .find(|entry| entry.name == "ZLIB")
            .expect("probe dependency folded");
        assert_eq!(entry.kind, DepKind::SharedLibrary);
        assert_eq!(entry.basis, RequirementBasis::Observed);
        assert!(entry
            .evidence
            .as_deref()
            .unwrap()
            .contains("Could NOT find"));
        let _ = std::fs::remove_dir_all(root);
    }
}
