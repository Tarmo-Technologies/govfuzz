// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, clap::Args, PartialEq)]
pub struct FakeCorbaArgs {
    /// Path to govfuzz_work directory.
    pub work_dir: PathBuf,

    /// Source directory to scan. Defaults to <work-dir>/src_instrumented.
    #[arg(long)]
    pub source_dir: Option<PathBuf>,

    /// Optional IDL file to parse and emit Helper/Skel/Stub Ada mapping packages for.
    #[arg(long)]
    pub idl: Option<PathBuf>,

    /// ROS .msg/.srv/.action interface file to translate through the IDL mapping pipeline.
    #[arg(long = "ros-interface")]
    pub ros_interfaces: Vec<PathBuf>,

    /// Predefine an IDL preprocessor symbol, as NAME or NAME=VALUE. Repeatable.
    #[arg(long = "idl-define")]
    pub idl_defines: Vec<String>,

    /// Directory to search for IDL #include files.
    #[arg(long = "idl-include-dir")]
    pub idl_include_dirs: Vec<PathBuf>,
}

pub fn run(args: FakeCorbaArgs) -> i32 {
    let work_dir = absolutize(&args.work_dir);
    let source_dir = args
        .source_dir
        .as_deref()
        .map(absolutize)
        .unwrap_or_else(|| work_dir.join("src_instrumented"));
    let output_dir = work_dir.join("fake_corba");

    if let Err(error) = std::fs::create_dir_all(&work_dir) {
        eprintln!("create work directory '{}': {error}", work_dir.display());
        return 1;
    }

    if !source_dir.is_dir() {
        if (args.idl.is_some() || !args.ros_interfaces.is_empty()) && args.source_dir.is_none() {
            if let Err(error) = std::fs::create_dir_all(&source_dir) {
                eprintln!(
                    "create default source directory '{}': {error}",
                    source_dir.display()
                );
                return 1;
            }
        } else {
            eprintln!(
                "source directory '{}' does not exist; run instrumentation first or pass --source-dir",
                source_dir.display()
            );
            return 1;
        }
    }

    match ::fake_corba::generate_fake_corba(&source_dir, &output_dir) {
        Ok(output) => {
            match write_idl_mapping(
                args.idl.as_deref(),
                &args.ros_interfaces,
                &args.idl_defines,
                &args.idl_include_dirs,
                &output_dir,
            ) {
                Ok(idl_count) => {
                    if idl_count == 0 {
                        println!(
                            "generated {} fake CORBA files under {}",
                            output.written_files.len(),
                            output_dir.display()
                        );
                    } else {
                        println!(
                            "generated {} fake CORBA files and {} IDL mapping files under {}",
                            output.written_files.len(),
                            idl_count,
                            output_dir.display()
                        );
                    }
                    0
                }
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            }
        }
        Err(error) => {
            eprintln!(
                "generate fake CORBA under '{}': {error}",
                output_dir.display()
            );
            1
        }
    }
}

/// Auto-generate CORBA/IDL scaffolding from a source tree during `auto`, so an
/// Ada CORBA project's harnesses can build without a manual `fake-corba` step:
/// the base fake-CORBA packages (from detected CORBA usage in the tree) plus the
/// Ada mapping packages for every `.idl` found under `source_root`, all written
/// to `<work>/fake_corba/` (which the Ada build adds as a Source_Dir). This is
/// govfuzz's own IDL parser — it executes no project code — so it runs by default
/// when `.idl` files are present. Returns the number of `.idl` files mapped.
/// Best-effort: a per-file parse failure is logged and skipped.
pub fn auto_generate_from_tree(source_root: &Path, work_dir: &Path) -> usize {
    let idls = find_idl_files(source_root);
    if idls.is_empty() {
        return 0;
    }
    let output_dir = work_dir.join("fake_corba");
    if std::fs::create_dir_all(&output_dir).is_err() {
        return 0;
    }
    // Base fake-CORBA packages from CORBA usage detected in the tree.
    if let Err(error) = ::fake_corba::generate_fake_corba(source_root, &output_dir) {
        eprintln!("govfuzz auto: fake-corba base generation: {error}");
    }
    // Resolve cross-directory `#include "other.idl"` against EVERY directory that
    // holds an .idl in the tree, not just the current file's own dir (see
    // [`idl_include_dirs`]).
    let include_dirs = idl_include_dirs(&idls);
    let mut mapped = 0;
    for idl in &idls {
        match write_idl_mapping(Some(idl), &[], &[], &include_dirs, &output_dir) {
            Ok(_) => mapped += 1,
            Err(error) => eprintln!("govfuzz auto: skipping {}: {error}", idl.display()),
        }
    }
    mapped
}

/// The IDL `#include` search path for a whole tree: every distinct directory that
/// contains an `.idl` (in first-seen order). A CORBA project routinely
/// `#include`s a shared/sibling types IDL — e.g. `ss_smc_common_types.idl` under
/// `idl/common/` from `idl/smc/*.idl`. Passing only each file's OWN parent left
/// those cross-directory includes unresolved, so the preprocessor emitted a
/// `#pragma govfuzz_warning "include ... not found"` breadcrumb and the mapping
/// silently dropped the included types (cascading into unbuildable servant
/// harnesses). The quoted-include current-file-parent still takes precedence in
/// the preprocessor's `resolve_include`, so a same-named local file wins.
fn idl_include_dirs(idls: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for idl in idls {
        if let Some(parent) = idl.parent() {
            let parent = parent.to_path_buf();
            if !dirs.contains(&parent) {
                dirs.push(parent);
            }
        }
    }
    dirs
}

/// Recursively collect `.idl` files under `root` (bounded; skips VCS/build dirs).
fn find_idl_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 200_000 {
                return out;
            }
            let path = entry.path();
            if path.is_dir() {
                let skip = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    matches!(
                        n,
                        ".git" | "govfuzz_work" | "target" | "build" | "node_modules"
                    )
                });
                if !skip {
                    stack.push(path);
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("idl") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn write_idl_mapping(
    idl_path: Option<&Path>,
    ros_interfaces: &[PathBuf],
    idl_defines: &[String],
    idl_include_dirs: &[PathBuf],
    output_dir: &Path,
) -> Result<usize, String> {
    if idl_path.is_none() && ros_interfaces.is_empty() {
        return Ok(0);
    }
    let mut ast = idl_parser::IdlFile {
        declarations: Vec::new(),
        pragmas: Vec::new(),
        warnings: Vec::new(),
    };
    let defines = parse_idl_defines(idl_defines)?;
    let include_dirs = idl_include_dirs
        .iter()
        .map(|path| absolutize(path))
        .collect::<Vec<_>>();

    if let Some(idl_path) = idl_path {
        let idl_path = absolutize(idl_path);
        let idl_ast =
            idl_parser::parse_idl_file_recovering_with_options(&idl_path, &defines, &include_dirs)
                .map_err(|error| format!("parse IDL '{}': {error}", idl_path.display()))?;
        ast.declarations.extend(idl_ast.declarations);
        ast.pragmas.extend(idl_ast.pragmas);
        ast.warnings.extend(idl_ast.warnings);
    }
    for ros_interface in ros_interfaces {
        let ros_interface = absolutize(ros_interface);
        let ros_ast = idl_parser::parse_ros_interface_file(&ros_interface).map_err(|error| {
            format!("parse ROS interface '{}': {error}", ros_interface.display())
        })?;
        ast.declarations.extend(ros_ast.declarations);
        ast.pragmas.extend(ros_ast.pragmas);
        ast.warnings.extend(ros_ast.warnings);
    }

    let dictionary_tokens = idl_parser::extract_idl_dictionary_tokens_from_ast(&ast);
    let output = idl_parser::emit_ada_packages(&ast);
    if !output_dir.join("corba-any.ads").is_file() {
        let files = [::fake_corba::render_corba_any_file()];
        ::fake_corba::write_generated_files(output_dir, &files).map_err(|error| {
            format!(
                "write CORBA Any support under '{}': {error}",
                output_dir.display()
            )
        })?;
    }
    for warning in &output.warnings {
        eprintln!("IDL mapping warning: {warning}");
    }
    let written =
        idl_parser::write_generated_ada_units(output_dir, &output.units).map_err(|error| {
            format!(
                "write IDL mapping under '{}': {error}",
                output_dir.display()
            )
        })?;
    write_idl_dictionary(output_dir, &dictionary_tokens)?;
    Ok(written.len())
}

fn write_idl_dictionary(output_dir: &Path, tokens: &[String]) -> Result<(), String> {
    if tokens.is_empty() {
        return Ok(());
    }
    let mut out = String::new();
    for token in tokens {
        out.push('"');
        out.push_str(&escape_afl_dictionary_token(token.as_bytes()));
        out.push_str("\"\n");
    }
    std::fs::write(output_dir.join("dictionary.txt"), out).map_err(|error| {
        format!(
            "write IDL dictionary under '{}': {error}",
            output_dir.display()
        )
    })
}

fn escape_afl_dictionary_token(token: &[u8]) -> String {
    let mut out = String::new();
    for byte in token {
        match *byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(*byte)),
            other => out.push_str(&format!("\\x{other:02x}")),
        }
    }
    out
}

fn parse_idl_defines(values: &[String]) -> Result<Vec<(String, String)>, String> {
    values
        .iter()
        .map(|value| {
            let (name, replacement) = value
                .split_once('=')
                .map_or((value.as_str(), ""), |(name, replacement)| {
                    (name, replacement)
                });
            if !is_idl_identifier(name) {
                return Err(format!(
                    "invalid --idl-define '{}': expected NAME or NAME=VALUE",
                    value
                ));
            }
            Ok((name.to_owned(), replacement.to_owned()))
        })
        .collect()
}

fn is_idl_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::{auto_generate_from_tree, find_idl_files, idl_include_dirs, write_idl_mapping};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn auto_generate_maps_in_tree_idl_into_fake_corba() {
        let root = temp_dir("idl-auto");
        let src = root.join("src");
        fs::create_dir_all(src.join("ignored.git")).unwrap();
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("bank.idl"),
            "module Bank { struct Account { long id; }; interface Teller { long balance(in Account a); }; };\n",
        )
        .unwrap();
        // A .git dir's .idl must be skipped by the walk.
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git").join("stale.idl"), "module X {};\n").unwrap();
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();

        let mapped = auto_generate_from_tree(&root, &work);
        assert_eq!(mapped, 1, "only the real .idl is mapped (.git skipped)");
        let out = work.join("fake_corba");
        assert!(out.join("bank.ads").is_file(), "module package generated");
        assert!(
            out.join("bank-teller-stub.ads").is_file(),
            "interface stub generated"
        );
        // No .idl anywhere -> no work, returns 0.
        let empty = temp_dir("idl-none");
        fs::create_dir_all(empty.join("a")).unwrap();
        assert_eq!(auto_generate_from_tree(&empty, &empty.join("w")), 0);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&empty);
    }

    #[test]
    fn idl_include_dirs_unions_all_idl_directories_deduped() {
        // Every directory holding an .idl becomes a search dir (first-seen order,
        // deduped) so a cross-directory `#include "common.idl"` resolves.
        let base = PathBuf::from("/tree");
        let idls = vec![
            base.join("idl/smc/ss_smc.idl"),
            base.join("idl/common/ss_smc_common_types.idl"),
            base.join("idl/smc/other.idl"), // same dir as the first -> deduped
        ];
        let dirs = idl_include_dirs(&idls);
        assert_eq!(
            dirs,
            vec![base.join("idl/smc"), base.join("idl/common")],
            "sibling idl/common/ must be on the include path, idl/smc/ deduped"
        );
    }

    #[test]
    fn auto_generate_resolves_cross_directory_idl_include() {
        // A servant IDL that `#include`s a sibling-directory types IDL must map
        // WITHOUT the "include not found" fallback: the included struct's package
        // is generated and the servant's operation references it.
        let root = temp_dir("idl-crossdir");
        let common = root.join("idl/common");
        let smc = root.join("idl/smc");
        fs::create_dir_all(&common).unwrap();
        fs::create_dir_all(&smc).unwrap();
        fs::write(
            common.join("ss_smc_common_types.idl"),
            "module SS_Smc { struct SmcHeader { long id; }; };\n",
        )
        .unwrap();
        fs::write(
            smc.join("ss_smc.idl"),
            "#include \"ss_smc_common_types.idl\"\nmodule SS_Smc { interface SmcService { boolean handle(in SmcHeader h); }; };\n",
        )
        .unwrap();
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();

        let mapped = auto_generate_from_tree(&root, &work);
        assert_eq!(mapped, 2, "both .idl files map");
        let out = work.join("fake_corba");
        // The common types package is generated (mapped from its own file), and the
        // servant interface stub is generated — proving the cross-dir include
        // resolved rather than dropping SmcHeader.
        assert!(
            out.join("ss_smc.ads").is_file(),
            "SS_Smc module package generated"
        );
        assert!(
            out.join("ss_smc-smcservice-stub.ads").is_file(),
            "servant interface stub generated (include resolved): {:?}",
            fs::read_dir(&out).map(|d| d
                .filter_map(|e| e.ok().map(|e| e.file_name()))
                .collect::<Vec<_>>())
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn find_idl_files_skips_vcs_and_build_dirs() {
        let root = temp_dir("idl-find");
        for d in ["src", ".git", "target", "build", "node_modules"] {
            fs::create_dir_all(root.join(d)).unwrap();
            fs::write(root.join(d).join("x.idl"), "module M {};\n").unwrap();
        }
        let found = find_idl_files(&root);
        let dirs: Vec<String> = found
            .iter()
            .filter_map(|p| p.parent()?.file_name()?.to_str().map(str::to_owned))
            .collect();
        assert_eq!(
            dirs,
            vec!["src".to_owned()],
            "only src/ .idl found: {dirs:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn idl_mapping_writes_dictionary_from_constants_and_enums() {
        let root = temp_dir("idl-dictionary");
        let idl = root.join("demo.idl");
        fs::write(
            &idl,
            r#"
            module Demo {
              enum Mode { MODE_FAST, MODE_SAFE };
              const string Ready = "READY";
              const unsigned long Magic = 0x42;
              interface Service {};
            };
            "#,
        )
        .unwrap();
        let out = root.join("fake_corba");
        fs::create_dir_all(&out).unwrap();

        let written = write_idl_mapping(Some(&idl), &[], &[], &[], &out).unwrap();

        assert!(written > 0);
        let dictionary = fs::read_to_string(out.join("dictionary.txt")).unwrap();
        assert!(dictionary.contains("\"MODE_FAST\""));
        assert!(dictionary.contains("\"MODE_SAFE\""));
        assert!(dictionary.contains("\"READY\""));
        assert!(dictionary.contains("\"66\""));
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-fake-corba-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
