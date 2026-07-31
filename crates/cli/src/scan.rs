// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::UnitKind;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

const SCAN_INDEX_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, clap::Args)]
pub struct ScanArgs {
    /// Path to scan: a source file or a directory tree.
    pub path: PathBuf,

    /// GovFuzz work directory where scan_index.json is written.
    #[arg(long, default_value = "govfuzz_work")]
    pub work_dir: PathBuf,
}

#[derive(Debug, Serialize)]
struct ScanIndex {
    schema_version: u32,
    root: PathBuf,
    files: Vec<ScannedFile>,
    skipped: Vec<SkippedFile>,
    total_files: usize,
    total_units: usize,
    total_packages: usize,
    total_subprograms: usize,
    total_handlers: usize,
    total_raises: usize,
    total_types: usize,
    total_targets: usize,
}

#[derive(Debug, Serialize)]
struct ScannedFile {
    path: PathBuf,
    language: String,
    ada_standard: Option<String>,
    unit_kind: Option<UnitKind>,
    units: usize,
    packages: usize,
    subprograms: usize,
    handlers: usize,
    raises: usize,
    types: usize,
    targets: usize,
    target_details: Vec<ScannedTarget>,
}

#[derive(Debug, Serialize)]
struct ScannedTarget {
    name: String,
    line: Option<u32>,
    score: Option<i32>,
}

#[derive(Debug, Serialize)]
struct SkippedFile {
    path: PathBuf,
    reason: String,
}

pub fn run(args: ScanArgs) -> i32 {
    match scan_and_write(&args.path, &args.work_dir) {
        Ok(index) => {
            match serde_json::to_string_pretty(&index) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    gfeprintln!("failed to render scan summary: {error}");
                    return 1;
                }
            }

            if index.total_files == 0 {
                1
            } else {
                0
            }
        }
        Err(error) => {
            gfeprintln!("{error:#}");
            1
        }
    }
}

fn scan_and_write(path: &Path, work_dir: &Path) -> Result<ScanIndex> {
    let index = scan_path(path)?;
    write_scan_index(&index, work_dir)?;
    Ok(index)
}

fn scan_path(path: &Path) -> Result<ScanIndex> {
    let mut index = ScanIndex {
        schema_version: SCAN_INDEX_SCHEMA_VERSION,
        root: path.to_path_buf(),
        files: Vec::new(),
        skipped: Vec::new(),
        total_files: 0,
        total_units: 0,
        total_packages: 0,
        total_subprograms: 0,
        total_handlers: 0,
        total_raises: 0,
        total_types: 0,
        total_targets: 0,
    };

    for path in walk_source_files(path)? {
        match scan_file(&path) {
            Ok(file) => index.files.push(file),
            Err(reason) => {
                gfeprintln!("skipping source {}: {reason}", path.display());
                index.skipped.push(SkippedFile { path, reason });
            }
        }
    }

    index.recompute_totals();
    Ok(index)
}

fn scan_file(path: &Path) -> std::result::Result<ScannedFile, String> {
    // Latin-1 fallback keeps non-UTF-8 legacy sources in the scan index instead
    // of dropping them; only genuine I/O errors surface here.
    let source = crate::source_text::read_source_text(path)
        .map_err(|error| format!("read failed ({error})"))?;
    if is_c_source_file(path) {
        let functions = c_parser::parse_c_functions(&source)
            .map_err(|error| format!("scan failed ({error})"))?;
        return Ok(scanned_c_family_file(
            path,
            "c",
            functions
                .into_iter()
                .map(|function| ScannedTarget {
                    name: function.name,
                    line: Some(function.line),
                    score: None,
                })
                .collect(),
        ));
    }
    if is_cpp_file(path) {
        let functions = cpp_parser::parse_cpp_functions(&source)
            .map_err(|error| format!("scan failed ({error})"))?;
        return Ok(scanned_c_family_file(
            path,
            "cpp",
            functions
                .into_iter()
                .map(|function| ScannedTarget {
                    name: function.name,
                    line: Some(function.line),
                    score: None,
                })
                .collect(),
        ));
    }
    if is_c_header_file(path) {
        let c_functions = c_parser::parse_c_functions(&source)
            .map_err(|error| format!("scan failed ({error})"))?;
        let cpp_functions = cpp_parser::parse_cpp_functions(&source)
            .map_err(|error| format!("scan failed ({error})"))?;

        if should_treat_header_as_cpp(&source, c_functions.len(), cpp_functions.len()) {
            return Ok(scanned_c_family_file(
                path,
                "cpp",
                cpp_functions
                    .into_iter()
                    .map(|function| ScannedTarget {
                        name: function.name,
                        line: Some(function.line),
                        score: None,
                    })
                    .collect(),
            ));
        }

        return Ok(scanned_c_family_file(
            path,
            "c",
            c_functions
                .into_iter()
                .map(|function| ScannedTarget {
                    name: function.name,
                    line: Some(function.line),
                    score: None,
                })
                .collect(),
        ));
    }

    let ast = ada_parser::reconcile::build_structural_ast(&source, None, path)
        .map_err(|error| format!("scan failed ({error:#})"))?;
    let targets = target_rank::rank_targets(&ast);
    let target_details = targets
        .iter()
        .map(|target| {
            let line = ast
                .subprograms
                .iter()
                .find(|subprogram| subprogram.id == target.subprogram_id)
                .map(|subprogram| subprogram.decl_span.start_line);
            ScannedTarget {
                name: target.name.clone(),
                line,
                score: Some(target.score),
            }
        })
        .collect();
    let unit = ast.units.first();

    Ok(ScannedFile {
        path: path.to_path_buf(),
        language: "ada".to_owned(),
        ada_standard: unit.map(|unit| unit.ada_standard.to_string()),
        unit_kind: unit.map(|unit| unit.kind.clone()),
        units: ast.units.len(),
        packages: ast.packages.len(),
        subprograms: ast.subprograms.len(),
        handlers: ast.handlers.len(),
        raises: ast.raises.len(),
        types: ast.types.len(),
        targets: targets.len(),
        target_details,
    })
}

fn scanned_c_family_file(
    path: &Path,
    language: &str,
    target_details: Vec<ScannedTarget>,
) -> ScannedFile {
    let target_count = target_details.len();
    ScannedFile {
        path: path.to_path_buf(),
        language: language.to_owned(),
        ada_standard: None,
        unit_kind: None,
        units: 1,
        packages: 0,
        subprograms: target_count,
        handlers: 0,
        raises: 0,
        types: 0,
        targets: target_count,
        target_details,
    }
}

fn write_scan_index(index: &ScanIndex, work_dir: &Path) -> Result<()> {
    fs::create_dir_all(work_dir)
        .with_context(|| format!("create work directory {}", work_dir.display()))?;
    let json = serde_json::to_string_pretty(index).context("render scan index JSON")?;
    let output_path = work_dir.join("scan_index.json");
    fs::write(&output_path, format!("{json}\n"))
        .with_context(|| format!("write scan index {}", output_path.display()))?;
    Ok(())
}

fn walk_source_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        if is_supported_source_file(path) {
            return Ok(vec![path.to_path_buf()]);
        }
        return Ok(Vec::new());
    }
    if !path.is_dir() {
        bail!("path is neither file nor directory: {}", path.display());
    }

    let mut files = Vec::new();
    collect_source_files(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_source_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read directory {}", path.display()))? {
        let entry = entry.with_context(|| format!("read directory entry in {}", path.display()))?;
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("read file type for {}", entry_path.display()))?;

        if file_type.is_dir() {
            if dir_is_excluded(&entry_path) {
                continue;
            }
            collect_source_files(&entry_path, files)?;
        } else if file_type.is_file() && is_supported_source_file(&entry_path) {
            files.push(entry_path);
        }
    }

    Ok(())
}

/// Skip govfuzz-owned output trees, common build/CI bookkeeping
/// directories, and VCS metadata so a scan run from a project root
/// doesn't trip over its own previously-generated harnesses.
fn dir_is_excluded(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(
        name,
        // `.govfuzz-build` = build_probe::PROBE_DIR (the --probe-build output).
        "generated_harnesses"
            | "harnesses"
            | "govfuzz_work"
            | "target"
            | ".git"
            | "node_modules"
            | "build"
            | ".govfuzz-build"
    )
}

fn is_supported_source_file(path: &Path) -> bool {
    is_ada_file(path) || is_c_source_file(path) || is_c_header_file(path) || is_cpp_file(path)
}

fn is_ada_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("ads") || ext.eq_ignore_ascii_case("adb"))
}

fn is_c_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == "c")
}

fn is_c_header_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("h"))
}

fn is_cpp_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            if ext == "C" {
                return true;
            }
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx"
            )
        })
}

fn should_treat_header_as_cpp(source: &str, c_targets: usize, cpp_targets: usize) -> bool {
    cpp_targets > c_targets || has_cpp_header_marker(source)
}

fn has_cpp_header_marker(source: &str) -> bool {
    let source = source_without_comments(source);
    [
        "namespace ",
        "template <",
        "template<",
        "class ",
        "typename ",
        "public:",
        "private:",
        "protected:",
        "constexpr",
        "noexcept",
        "operator",
    ]
    .iter()
    .any(|marker| source.contains(marker))
}

fn source_without_comments(source: &str) -> String {
    let mut stripped = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                stripped.push('\n');
            }
            continue;
        }

        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            } else if ch == '\n' {
                stripped.push('\n');
            }
            continue;
        }

        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
        } else {
            stripped.push(ch);
        }
    }

    stripped
}

impl ScanIndex {
    fn recompute_totals(&mut self) {
        self.total_files = self.files.len();
        self.total_units = self.files.iter().map(|file| file.units).sum();
        self.total_packages = self.files.iter().map(|file| file.packages).sum();
        self.total_subprograms = self.files.iter().map(|file| file.subprograms).sum();
        self.total_handlers = self.files.iter().map(|file| file.handlers).sum();
        self.total_raises = self.files.iter().map(|file| file.raises).sum();
        self.total_types = self.files.iter().map(|file| file.types).sum();
        self.total_targets = self.files.iter().map(|file| file.targets).sum();
    }
}

#[cfg(test)]
mod tests {
    use super::scan_path;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn scan_counts_c_function_definitions() {
        let dir = temp_dir("c-functions");
        let source = dir.join("demo.c");
        fs::write(
            &source,
            "static int helper(int x) { return x + 1; }\nvoid run(void) { helper(1); }\n",
        )
        .expect("C source is written");

        let index = scan_path(&dir).expect("scan succeeds");

        assert_eq!(index.total_files, 1);
        assert_eq!(index.files[0].language, "c");
        assert_eq!(index.files[0].subprograms, 2);
        assert_eq!(index.files[0].targets, 2);
        assert_eq!(index.files[0].target_details[0].name, "helper");
        assert_eq!(index.files[0].target_details[0].line, Some(1));
        assert_eq!(index.total_targets, 2);
    }

    #[test]
    fn scan_counts_cpp_function_definitions() {
        let dir = temp_dir("cpp-functions");
        let source = dir.join("demo.cpp");
        fs::write(
            &source,
            "namespace demo { int helper(int x) { return x + 1; } }\nint main() { return demo::helper(1); }\n",
        )
        .expect("C++ source is written");

        let index = scan_path(&dir).expect("scan succeeds");

        assert_eq!(index.total_files, 1);
        assert_eq!(index.files[0].language, "cpp");
        assert_eq!(index.files[0].subprograms, 2);
        assert_eq!(index.files[0].targets, 2);
        assert_eq!(index.files[0].target_details[0].name, "helper");
        assert_eq!(index.files[0].target_details[0].line, Some(1));
        assert_eq!(index.total_targets, 2);
    }

    #[test]
    fn scan_classifies_uppercase_c_extension_as_cpp() {
        let dir = temp_dir("uppercase-c-extension");
        let source = dir.join("demo.C");
        fs::write(&source, "int main() { return 0; }\n").expect("C++ source is written");

        let index = scan_path(&dir).expect("scan succeeds");

        assert_eq!(index.total_files, 1);
        assert_eq!(index.files[0].language, "cpp");
        assert_eq!(index.files[0].targets, 1);
    }

    #[test]
    fn scan_classifies_cpp_header_by_content() {
        let dir = temp_dir("cpp-header");
        let source = dir.join("demo.h");
        fs::write(
            &source,
            "namespace demo { class Widget { public: int run() const { return 1; } }; }\n",
        )
        .expect("C++ header is written");

        let index = scan_path(&dir).expect("scan succeeds");

        assert_eq!(index.total_files, 1);
        assert_eq!(index.files[0].language, "cpp");
        assert_eq!(index.files[0].targets, 1);
    }

    #[test]
    fn scan_keeps_plain_c_header_as_c() {
        let dir = temp_dir("c-header");
        let source = dir.join("demo.h");
        fs::write(&source, "static inline int run(void) { return 1; }\n")
            .expect("C header is written");

        let index = scan_path(&dir).expect("scan succeeds");

        assert_eq!(index.total_files, 1);
        assert_eq!(index.files[0].language, "c");
        assert_eq!(index.files[0].targets, 1);
    }

    #[test]
    fn scan_ignores_cpp_markers_inside_c_header_comments() {
        let dir = temp_dir("c-header-comments");
        let source = dir.join("demo.h");
        fs::write(
            &source,
            "/* class CPUs */\nstatic inline int run(void) { return 1; }\n",
        )
        .expect("C header is written");

        let index = scan_path(&dir).expect("scan succeeds");

        assert_eq!(index.total_files, 1);
        assert_eq!(index.files[0].language, "c");
        assert_eq!(index.files[0].targets, 1);
    }

    #[test]
    fn scan_classifies_declaration_only_cpp_header_as_cpp() {
        let dir = temp_dir("cpp-declaration-header");
        let source = dir.join("demo.h");
        fs::write(
            &source,
            "class Reader {\npublic:\n    explicit Reader(const char* path);\n    int ParseError() const;\n};\n",
        )
        .expect("C++ header is written");

        let index = scan_path(&dir).expect("scan succeeds");

        assert_eq!(index.total_files, 1);
        assert_eq!(index.files[0].language, "cpp");
        assert_eq!(index.files[0].targets, 0);
        assert!(index.files[0].target_details.is_empty());
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-scan-{name}-{nonce}"));
        fs::create_dir_all(&dir).expect("temporary directory is created");
        dir
    }
}
