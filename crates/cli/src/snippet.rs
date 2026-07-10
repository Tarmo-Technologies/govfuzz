// SPDX-License-Identifier: Apache-2.0

//! `govfuzz snippet` — fuzz ONE pasted function with no project, build, or
//! dependencies present.
//!
//! The flagship `auto` path already recovers a build for a whole tree by stubbing
//! whatever is missing. `snippet` is the smallest possible front door onto that
//! machinery: paste a single function (from stdin or a file), and govfuzz detects
//! the language, materializes a throwaway one-file project around it (adding a
//! module manifest for the lanes that need one), and runs the normal
//! discover → harness → repair → fuzz pipeline with maximum-aggression stubbing so
//! that undefined helpers the snippet calls are stubbed rather than fatal.
//!
//! Nothing here re-implements the pipeline: it builds an [`AutoArgs`] and calls
//! `auto::cli::run`. That keeps `snippet` a thin, always-in-sync wrapper — every
//! future `auto` capability (new sanitizers, new repair steps) reaches `snippet`
//! for free.

use clap::Parser;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::auto::candidate::LangSelector;

/// `govfuzz snippet [INPUT]` — fuzz a single pasted function.
#[derive(Debug, clap::Args)]
pub struct SnippetArgs {
    /// File containing the function to fuzz. Omit to read the snippet from stdin
    /// (e.g. `pbpaste | govfuzz snippet --lang c`).
    pub input: Option<PathBuf>,

    /// Source language of the snippet. Auto-detected from the input file's
    /// extension or the snippet's content when omitted; pass it explicitly for a
    /// stdin paste whose language is ambiguous. One of: ada, c, cpp, rust, java,
    /// python, perl, go.
    #[arg(long, visible_alias = "lang", value_enum)]
    pub language: Option<LangSelector>,

    /// Per-target fuzz wall-clock budget in seconds (default 15 — a snippet is one
    /// function, so a short budget usually suffices). Threaded straight through to
    /// `auto --per-target-time`.
    #[arg(long = "per-target-time", default_value_t = 15)]
    pub per_target_time: u64,

    /// Work directory for the synthesized project, harnesses, and report. Default
    /// `./govfuzz_snippet`. Kept after the run so you can inspect the generated
    /// harness and re-run `govfuzz report` over `<work-dir>`.
    #[arg(long = "work-dir", default_value = "govfuzz_snippet")]
    pub work_dir: PathBuf,

    /// Print the per-target outcome detail (repairs applied, per-pass exec/finding
    /// counts) — forwarded to `auto --verbose`.
    #[arg(short, long)]
    pub verbose: bool,
}

/// Read the snippet source from the input file or stdin.
fn read_snippet(input: Option<&Path>) -> anyhow::Result<String> {
    match input {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read snippet '{}': {e}", path.display())),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| anyhow::anyhow!("cannot read snippet from stdin: {e}"))?;
            if buf.trim().is_empty() {
                anyhow::bail!(
                    "no snippet on stdin — pass a file path or pipe a function in, e.g. \
                     `govfuzz snippet fn.c` or `cat fn.c | govfuzz snippet --lang c`"
                );
            }
            Ok(buf)
        }
    }
}

/// Resolve the snippet language from (in priority order) the explicit `--language`
/// flag, the input file's extension, then a content heuristic.
pub fn resolve_language(
    explicit: Option<LangSelector>,
    input: Option<&Path>,
    source: &str,
) -> anyhow::Result<LangSelector> {
    if let Some(lang) = explicit {
        return Ok(lang);
    }
    if let Some(ext) = input.and_then(|p| p.extension()).and_then(|e| e.to_str()) {
        if let Some(lang) = lang_from_extension(ext) {
            return Ok(lang);
        }
    }
    detect_language(source).ok_or_else(|| {
        anyhow::anyhow!(
            "could not detect the snippet language — pass it explicitly with \
             `--lang <ada|c|cpp|rust|java|python|perl|go>`"
        )
    })
}

/// Map a source extension onto a language selector (same set discovery walks).
fn lang_from_extension(ext: &str) -> Option<LangSelector> {
    Some(match ext.to_ascii_lowercase().as_str() {
        "ads" | "adb" => LangSelector::Ada,
        "c" => LangSelector::C,
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => LangSelector::Cpp,
        // A bare `.h` is ambiguous C/C++; treat as C++ so class/template snippets
        // in headers parse (a pure-C header still compiles as C++).
        "h" => LangSelector::Cpp,
        "rs" => LangSelector::Rust,
        "java" => LangSelector::Java,
        "py" => LangSelector::Python,
        "pl" | "pm" => LangSelector::Perl,
        "go" => LangSelector::Go,
        _ => return None,
    })
}

/// Heuristic language sniffer for a pasted snippet with no filename. Scores each
/// language by counting language-distinctive signals in the source and returns the
/// unambiguous top scorer, or `None` when nothing scores or the top two tie (the
/// caller then asks for `--lang`). Deliberately conservative: a wrong guess wastes
/// a run, so an ambiguous paste should fall through to an explicit flag.
pub fn detect_language(source: &str) -> Option<LangSelector> {
    let s = source;
    let has = |needle: &str| s.contains(needle);
    // Each entry: (selector, score). Signals are weighted by how uniquely they
    // pin the language; shared tokens (`func`, `fn`, `{`) are disambiguated by
    // co-occurring exclusives.
    let mut scores: Vec<(LangSelector, i32)> = Vec::new();

    let mut go = 0;
    if has("package ") {
        go += 2;
    }
    if has("func ") {
        go += 2;
    }
    if has(":=") {
        go += 2;
    }
    if has("import (") || has("fmt.") {
        go += 1;
    }
    scores.push((LangSelector::Go, go));

    let mut rust = 0;
    if has("fn ") {
        rust += 2;
    }
    if has("let mut ") || has("let ") {
        rust += 1;
    }
    if has("->") && has("fn ") {
        rust += 1;
    }
    if has("impl ") || has("use std::") || has("pub fn ") || has("&str") || has("Vec<") {
        rust += 2;
    }
    if has("println!") || has("unwrap()") {
        rust += 1;
    }
    scores.push((LangSelector::Rust, rust));

    let mut cpp = 0;
    if has("std::") || has("template<") || has("template <") {
        cpp += 3;
    }
    if has("namespace ") || has("::") || has("nullptr") || has("cout") {
        cpp += 2;
    }
    if has("class ") && (has("public:") || has("private:")) {
        cpp += 2;
    }
    if has("#include") {
        cpp += 1;
    }
    scores.push((LangSelector::Cpp, cpp));

    let mut c = 0;
    if has("#include") {
        c += 2;
    }
    if has("malloc(") || has("printf(") || has("size_t") || has("char *") || has("struct ") {
        c += 1;
    }
    if has("int main") || has("void ") || has("uint8_t") || has("const char") {
        c += 1;
    }
    scores.push((LangSelector::C, c));

    let mut java = 0;
    if has("public class ") || has("class ") && has("public static") {
        java += 3;
    }
    if has("System.out") || has("import java") || has("String[]") {
        java += 2;
    }
    if has("public ") || has("private ") || has("void ") {
        java += 1;
    }
    scores.push((LangSelector::Java, java));

    let mut python = 0;
    if has("def ") {
        python += 2;
    }
    if has("import ") && !has("import (") && !has("#include") {
        python += 1;
    }
    if has("print(") || has("self.") || has("elif ") || has("__") {
        python += 1;
    }
    if has("):\n") || has(":\n    ") {
        python += 1;
    }
    scores.push((LangSelector::Python, python));

    let mut perl = 0;
    if has("sub ") {
        perl += 2;
    }
    if has("my $") || has("my @") || has("my %") {
        perl += 2;
    }
    if has("use strict") || has("=~") || has("->{") || has("$_") {
        perl += 1;
    }
    scores.push((LangSelector::Perl, perl));

    let mut ada = 0;
    if has("procedure ") || has("function ") && has(" return ") {
        ada += 2;
    }
    if has(" is\n") || has("begin\n") || has(" := ") {
        ada += 1;
    }
    if has("with Ada") || has("package ") && has(" is") {
        ada += 2;
    }
    if has("end;") || has("end ") {
        ada += 1;
    }
    scores.push((LangSelector::Ada, ada));

    scores.sort_by(|a, b| b.1.cmp(&a.1));
    let (best, best_score) = scores[0];
    let (_, second_score) = scores[1];
    // Need a real signal and a clear winner — a tie is "ambiguous, ask the user".
    if best_score >= 2 && best_score > second_score {
        Some(best)
    } else {
        None
    }
}

/// Canonical file extension for a synthesized snippet of the given language.
fn snippet_extension(lang: LangSelector) -> &'static str {
    match lang {
        LangSelector::Ada => "adb",
        LangSelector::C => "c",
        LangSelector::Cpp => "cpp",
        LangSelector::Rust => "rs",
        LangSelector::Java => "java",
        LangSelector::Python => "py",
        LangSelector::Perl => "pl",
        LangSelector::Go => "go",
    }
}

/// The `--languages` token `auto` accepts for this selector.
fn lang_token(lang: LangSelector) -> &'static str {
    match lang {
        LangSelector::Ada => "ada",
        LangSelector::C => "c",
        LangSelector::Cpp => "cpp",
        LangSelector::Rust => "rust",
        LangSelector::Java => "java",
        LangSelector::Python => "python",
        LangSelector::Perl => "perl",
        LangSelector::Go => "go",
    }
}

/// Materialize a throwaway one-source project for `source` under `src_dir`,
/// returning the source directory `auto` should sweep. Adds the module manifest /
/// package wrapper that each lane needs to build a bare function, and lightly
/// rewrites the snippet where a lane requires the target to be externally visible
/// (Rust `fn` → `pub fn`, a bare Go body → `package snippet`).
pub fn materialize(lang: LangSelector, source: &str, src_dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(src_dir)
        .map_err(|e| anyhow::anyhow!("cannot create snippet dir '{}': {e}", src_dir.display()))?;
    let ext = snippet_extension(lang);
    match lang {
        LangSelector::Rust => {
            // The Rust lane builds in-crate, so the snippet needs a crate around
            // it. Make the target reachable by promoting bare top-level `fn` to
            // `pub fn` (an unexported fn is not a fuzzable entry point).
            let lib = src_dir.join("src");
            std::fs::create_dir_all(&lib)?;
            write(&lib.join("lib.rs"), &rustify(source))?;
            write(
                &src_dir.join("Cargo.toml"),
                "[package]\nname = \"snippet\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
                 [lib]\npath = \"src/lib.rs\"\n",
            )?;
        }
        LangSelector::Go => {
            // Go needs a module + a package clause. Prepend one if the paste has
            // no `package` declaration of its own.
            let body = if source
                .lines()
                .any(|l| l.trim_start().starts_with("package "))
            {
                source.to_owned()
            } else {
                format!("package snippet\n\n{source}")
            };
            write(&src_dir.join(format!("snippet.{ext}")), &body)?;
            write(&src_dir.join("go.mod"), "module snippet\n\ngo 1.21\n")?;
        }
        LangSelector::Java => {
            // The public class name must match the filename. Reuse the paste's own
            // class name when it declares one; otherwise wrap the bare method(s) in
            // a `Snippet` class.
            let (file_stem, body) = javaify(source);
            write(&src_dir.join(format!("{file_stem}.java")), &body)?;
        }
        _ => {
            // C / C++ / Python / Perl / Ada: a single source file is enough — the
            // pipeline discovers, harnesses, and (for compiled lanes) stubs the
            // rest.
            write(&src_dir.join(format!("snippet.{ext}")), source)?;
        }
    }
    Ok(src_dir.to_path_buf())
}

fn write(path: &Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents)
        .map_err(|e| anyhow::anyhow!("cannot write '{}': {e}", path.display()))
}

/// Promote bare top-level `fn name(` declarations to `pub fn` so the Rust lane can
/// reach them. Only column-0 `fn ` lines are touched (nested/impl fns and already
/// `pub`/`pub(crate)` fns are left alone).
fn rustify(source: &str) -> String {
    source
        .lines()
        .map(|line| {
            if line.starts_with("fn ") {
                format!("pub {line}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Decide the Java file stem + full source. If the paste declares a top-level
/// class, keep it as-is and name the file after that class. Otherwise wrap the
/// bare member(s) in a `public class Snippet`.
fn javaify(source: &str) -> (String, String) {
    if let Some(name) = java_class_name(source) {
        return (name, source.to_owned());
    }
    let wrapped = format!("public class Snippet {{\n{source}\n}}\n");
    ("Snippet".to_owned(), wrapped)
}

/// Extract the name from a top-level `class NAME` / `public class NAME`
/// declaration, if present.
fn java_class_name(source: &str) -> Option<String> {
    for line in source.lines() {
        let t = line.trim_start();
        let rest = t
            .strip_prefix("public final class ")
            .or_else(|| t.strip_prefix("public class "))
            .or_else(|| t.strip_prefix("final class "))
            .or_else(|| t.strip_prefix("class "))?;
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

/// Build the `auto` arg vector for a materialized snippet project.
fn auto_argv(args: &SnippetArgs, lang: LangSelector, src_dir: &Path) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "snippet".into(), // clap program-name slot for the flatten wrapper
        src_dir.to_string_lossy().into_owned(),
        "--work-dir".into(),
        args.work_dir.to_string_lossy().into_owned(),
        "--per-target-time".into(),
        args.per_target_time.to_string(),
        "--languages".into(),
        lang_token(lang).into(),
        // A single function has no vendored deps to skip, and discovery's default
        // dir exclusions (tests/examples/...) would drop a file literally named to
        // match — so don't let the snippet's own dir name exclude it.
        "--include-dir".into(),
        "snippet_src".into(),
    ];
    if args.verbose {
        argv.push("--verbose".into());
    }
    argv
}

/// Flatten wrapper: lets us build a full [`AutoArgs`] by parsing a synthetic argv,
/// so `snippet` stays correct as `auto` gains flags (every field it doesn't set
/// keeps its `auto` default) instead of duplicating the struct's field list.
#[derive(Debug, Parser)]
struct AutoArgsCarrier {
    #[command(flatten)]
    inner: crate::auto::cli::AutoArgs,
}

pub fn run(args: SnippetArgs) -> i32 {
    let source = match read_snippet(args.input.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 1;
        }
    };
    let lang = match resolve_language(args.language, args.input.as_deref(), &source) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 1;
        }
    };
    let src_dir = args.work_dir.join("snippet_src");
    // Fresh materialization each run so a re-paste never mixes with a stale one.
    let _ = std::fs::remove_dir_all(&src_dir);
    let src_dir = match materialize(lang, &source, &src_dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 1;
        }
    };
    eprintln!(
        "govfuzz snippet: detected {}, fuzzing for up to {}s (project at {})",
        lang_token(lang),
        args.per_target_time,
        src_dir.display()
    );
    let argv = auto_argv(&args, lang, &src_dir);
    let auto_args = match AutoArgsCarrier::try_parse_from(&argv) {
        Ok(carrier) => carrier.inner,
        Err(error) => {
            // A parse failure here is a govfuzz bug (we built the argv), not user
            // error — surface it rather than printing clap usage for `auto`.
            eprintln!("internal error: could not construct auto args: {error}");
            return 2;
        }
    };
    crate::auto::cli::run(auto_args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_c_from_content() {
        let src = "#include <string.h>\nint parse(const char *p, size_t n) { return p[n]; }\n";
        assert_eq!(detect_language(src), Some(LangSelector::C));
    }

    #[test]
    fn detects_python_from_content() {
        let src = "def parse(data):\n    return data[0]\n";
        assert_eq!(detect_language(src), Some(LangSelector::Python));
    }

    #[test]
    fn detects_go_from_content() {
        let src = "func Parse(b []byte) int {\n\tx := b[0]\n\treturn int(x)\n}\n";
        assert_eq!(detect_language(src), Some(LangSelector::Go));
    }

    #[test]
    fn detects_rust_from_content() {
        let src = "pub fn parse(data: &[u8]) -> u8 {\n    data[0]\n}\n";
        assert_eq!(detect_language(src), Some(LangSelector::Rust));
    }

    #[test]
    fn detects_perl_from_content() {
        let src = "sub parse {\n    my $s = shift;\n    return substr($s, 0, 1);\n}\n";
        assert_eq!(detect_language(src), Some(LangSelector::Perl));
    }

    #[test]
    fn ambiguous_content_is_undetected() {
        // No language-distinctive tokens -> caller must ask for --lang.
        assert_eq!(detect_language("x = 1\n"), None);
    }

    #[test]
    fn explicit_flag_wins_over_extension() {
        let p = PathBuf::from("thing.c");
        let lang = resolve_language(Some(LangSelector::Cpp), Some(&p), "int x;").unwrap();
        assert_eq!(lang, LangSelector::Cpp);
    }

    #[test]
    fn extension_wins_over_content() {
        let p = PathBuf::from("thing.py");
        // Content looks C-ish, but the .py extension is authoritative.
        let lang = resolve_language(None, Some(&p), "int main() {}").unwrap();
        assert_eq!(lang, LangSelector::Python);
    }

    #[test]
    fn rustify_publishes_bare_fn() {
        let out = rustify("fn foo() {}\n    fn bar() {}\npub fn baz() {}");
        assert!(out.contains("pub fn foo()"));
        // Indented (nested) fn and already-pub fn are untouched.
        assert!(out.contains("    fn bar()"));
        assert_eq!(out.matches("pub fn baz()").count(), 1);
        assert!(!out.contains("pub pub"));
    }

    #[test]
    fn javaify_wraps_bare_method() {
        let (stem, body) = javaify("static int f(byte[] b) { return b[0]; }");
        assert_eq!(stem, "Snippet");
        assert!(body.contains("public class Snippet"));
    }

    #[test]
    fn javaify_keeps_declared_class() {
        let (stem, body) = javaify("public class Parser {\n  static int f() { return 0; }\n}");
        assert_eq!(stem, "Parser");
        assert!(!body.contains("class Snippet"));
    }

    #[test]
    fn materialize_go_adds_module_and_package() {
        let dir = std::env::temp_dir().join(format!("gfsnip-go-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        materialize(LangSelector::Go, "func F(b []byte) {}\n", &dir).unwrap();
        let gomod = std::fs::read_to_string(dir.join("go.mod")).unwrap();
        assert!(gomod.contains("module snippet"));
        let src = std::fs::read_to_string(dir.join("snippet.go")).unwrap();
        assert!(src.starts_with("package snippet"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn materialize_rust_adds_manifest() {
        let dir = std::env::temp_dir().join(format!("gfsnip-rs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        materialize(
            LangSelector::Rust,
            "fn parse(b: &[u8]) -> u8 { b[0] }\n",
            &dir,
        )
        .unwrap();
        assert!(dir.join("Cargo.toml").is_file());
        let lib = std::fs::read_to_string(dir.join("src/lib.rs")).unwrap();
        assert!(lib.contains("pub fn parse"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
