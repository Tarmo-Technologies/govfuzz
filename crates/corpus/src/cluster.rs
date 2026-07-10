// SPDX-License-Identifier: Apache-2.0

//! Root-cause clustering on top of govfuzz's per-input signature.
//! See docs/superpowers/specs/2026-05-13-crash-dedup-clustering-design.md.
//!
//! `signature` (from `crate::signature`) identifies a specific
//! `(input -> behaviour)` pair and drives corpus growth.
//! `ClusterKey` (this module) is a coarser, root-cause identifier
//! derived from the normalized top-N stack frames; two findings with
//! the same `ClusterKey` are likely the same bug.

use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
use event_log::{HandlerEvent, Testcase};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TOP_FRAMES: usize = 3;
const CLUSTER_KEY_VERSION_PREFIX: &str = "govfuzz-cluster-v1\n";

/// A frame fed into the clustering pipeline. Real sanitizer frames
/// arrive via `From<&StackFrame>`; synthesized Ada frames are built
/// with `InputFrame::symbol`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFrame {
    pub function: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl InputFrame {
    pub fn symbol(function: impl Into<String>) -> Self {
        Self {
            function: function.into(),
            file: None,
            line: None,
        }
    }
}

impl From<&StackFrame> for InputFrame {
    fn from(value: &StackFrame) -> Self {
        InputFrame {
            function: value.function.clone(),
            file: value.file.clone(),
            line: value.line,
        }
    }
}

/// Result of clustering a single finding. `short` is the 16-character
/// lowercase-hex display key; `full` is the 64-character SHA-256 hex
/// digest. `frames` preserves the normalized frame list the key was
/// hashed over so consumers can inspect why two findings clustered
/// together (or didn't). `fallback = true` means normalization
/// produced no informative frames; the caller is expected to
/// substitute the per-input signature short before persisting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterKey {
    pub short: String,
    pub full: String,
    pub frames: Vec<String>,
    pub fallback: bool,
}

/// Function-name prefixes that identify uninformative scaffolding
/// frames the user does not care about when clustering by root
/// cause. Matched as a left-anchored prefix on the raw function
/// string after toolchain decoration has been stripped.
const NOISE_PREFIXES: &[&str] = &[
    // Sanitizer runtimes: both the C `__asan_*` interceptor form and the
    // C++ `__asan::*` namespace form (e.g. `__asan::Allocator::Deallocate`).
    "__asan",
    "__sanitizer",
    "__interceptor",
    "__ubsan",
    "__lsan",
    "__hwasan",
    "__tsan",
    // libFuzzer driver: `LLVMFuzzer*` entrypoints and the whole `fuzzer::*`
    // namespace (`fuzzer::RunOneTest`, `fuzzer::Fuzzer::ExecuteCallback`, ...).
    "LLVMFuzzer",
    "fuzzer::",
    "_dl_",
    "__GI_",
    "__libc_",
];

/// Exact function names dropped even when no `NOISE_PREFIXES` match.
const NOISE_EXACT: &[&str] = &["main", "_start"];

/// Function-name prefixes that unambiguously identify a libFuzzer / sanitizer
/// *driver* frame (as opposed to generic libc/startup noise). A crash whose
/// stack contains one of these and *no* target frame is a harness/driver
/// fault, not a target bug — see [`is_driver_glue_crash`].
const DRIVER_PREFIXES: &[&str] = &[
    "fuzzer::",
    "LLVMFuzzer",
    "__asan",
    "__ubsan",
    "__lsan",
    "__tsan",
    "__hwasan",
    "__sanitizer",
];

/// libc / C++ allocator-runtime frames. On their own (with no target frame
/// and a driver frame present) these signal allocator-glue corruption rather
/// than a target double-free, which always carries the target caller above.
const ALLOC_RUNTIME: &[&str] = &[
    "free",
    "malloc",
    "calloc",
    "realloc",
    "reallocarray",
    "aligned_alloc",
    "posix_memalign",
    "memalign",
    "valloc",
    "pvalloc",
    "cfree",
    "operator new",
    "operator delete",
    "operator new[]",
    "operator delete[]",
];

/// Drop noise, strip toolchain decoration, strip C++ argument lists,
/// and truncate to the top `TOP_FRAMES` frames. Returns an empty
/// `Vec` when every frame was noise — callers fall back to the
/// per-input signature in that case.
pub fn normalize_frames(input: &[InputFrame]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for frame in input {
        let stripped = strip_toolchain_decoration(frame.function.as_str());
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            continue;
        }
        if NOISE_EXACT.contains(&trimmed) {
            continue;
        }
        if NOISE_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
            continue;
        }
        let no_args = strip_cpp_args(trimmed);
        if no_args.is_empty() {
            continue;
        }
        // Drop runtime and govfuzz harness frames so one root cause doesn't
        // over-split into multiple issue rows depending on which allocator,
        // formatting, or generated-driver frame the PC landed in. The key must
        // start at the first in-project frame (#31, #44).
        if is_runtime_or_harness_noise(&no_args) {
            continue;
        }
        out.push(no_args);
        if out.len() >= TOP_FRAMES {
            break;
        }
    }
    out
}

/// Runtime (`printf`/`fprintf`/`vfprintf`, the `str*`/`mem*` builtins, glibc
/// `_IO_*` stdio internals, Rust std allocation/string conversion frames, ASan's
/// `printf_common` interceptor) and govfuzz harness (`gf_*`/`govfuzz_*`/
/// `rust_runtime::*`/`LLVMFuzzerTestOneInput`) frames are scaffolding, never the
/// project's root-cause site — the real caller is the frame above them. Dropping
/// them keeps the cluster key anchored at the first in-project frame so a single
/// bug clusters to one issue regardless of which runtime frame the PC landed in
/// (#31, #44). Mirrors actionability's `is_libc_runtime_function` /
/// `is_harness_frame` for the clustering pipeline.
fn is_runtime_or_harness_noise(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("govfuzz_")
        || lower.starts_with("gf_")
        || lower.starts_with("rust_runtime::")
        || lower.starts_with("<rust_runtime::")
        || lower.starts_with("_io_")
        || lower.contains("printf_common")
        || lower == "llvmfuzzertestoneinput"
        || ALLOC_RUNTIME.contains(&lower.as_str())
        || is_rust_std_allocator_noise(&lower)
    {
        return true;
    }
    matches!(
        lower.as_str(),
        "printf"
            | "fprintf"
            | "vfprintf"
            | "vprintf"
            | "sprintf"
            | "snprintf"
            | "vsnprintf"
            | "vsprintf"
            | "dprintf"
            | "vdprintf"
            | "puts"
            | "fputs"
            | "fwrite"
            | "fread"
            | "fputc"
            | "fgetc"
            | "getc"
            | "putc"
            | "putchar"
            | "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
            | "memchr"
            | "strlen"
            | "strnlen"
            | "strcmp"
            | "strncmp"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "strchr"
            | "strrchr"
            | "strstr"
            | "strdup"
            | "strndup"
    )
}

fn is_rust_std_allocator_noise(lower_name: &str) -> bool {
    lower_name.starts_with("alloc::")
        || lower_name.starts_with("<alloc::")
        || lower_name.contains(" as alloc::")
        || lower_name.starts_with("<[u8]>::to_vec")
        || lower_name.starts_with("<u8 as <[_]>::to_vec")
}

/// True when an LSan leak's entire allocation stack is govfuzz's own decode /
/// harness scaffolding (`gf_*`/`govfuzz_*`/`LLVMFuzzerTestOneInput` frames plus
/// allocator/runtime noise) with NO target frame. Such a leak is the decoder
/// buffer the harness allocates and WOULD free, left dangling only because an
/// `exit()`/`abort()`-only target (e.g. tomlc99 `fatal()`) terminates before the
/// harness's free() runs — govfuzz manufactured it, so it must be suppressed, not
/// reported as a target CWE-401 (#49).
///
/// Conservative, like [`is_driver_glue_crash`]: requires a POSITIVE harness frame
/// and bails the instant any real target/library frame resolves.
pub fn is_harness_scaffolding_leak(report: &SanitizerReport) -> bool {
    if report.sanitizer != Sanitizer::LeakSanitizer {
        return false;
    }
    let mut saw_harness = false;
    let mut saw_rust_std_allocator = false;
    for frame in &report.stack {
        let stripped = strip_toolchain_decoration(frame.function.as_str());
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            continue; // unsymbolized — neutral
        }
        let no_args = strip_cpp_args(trimmed);
        if no_args.is_empty() {
            continue;
        }
        let lower = no_args.to_ascii_lowercase();
        if lower.starts_with("gf_")
            || lower.starts_with("govfuzz_")
            || lower.starts_with("rust_runtime::")
            || lower.starts_with("<rust_runtime::")
            || lower == "llvmfuzzertestoneinput"
        {
            saw_harness = true;
            continue;
        }
        if is_rust_std_allocator_noise(&lower) {
            saw_rust_std_allocator = true;
            continue;
        }
        // Allocator / libc / sanitizer / startup noise — neutral.
        if ALLOC_RUNTIME.contains(&no_args.as_str())
            || NOISE_EXACT.contains(&trimmed)
            || NOISE_PREFIXES.iter().any(|p| trimmed.starts_with(p))
            || is_runtime_or_harness_noise(&no_args)
        {
            continue;
        }
        // A genuine target / library frame: this is a real leak.
        return false;
    }
    saw_harness || saw_rust_std_allocator
}

/// Hash the supplied normalized frame list into a `ClusterKey`. An
/// empty frame list produces a placeholder all-zero key and sets
/// `fallback = true`; callers are responsible for substituting the
/// per-input signature short before persisting.
pub fn cluster_key_from_frames(frames: &[String]) -> ClusterKey {
    if frames.is_empty() {
        return ClusterKey {
            short: "0".repeat(16),
            full: "0".repeat(64),
            frames: Vec::new(),
            fallback: true,
        };
    }
    let mut hasher = Sha256::new();
    hasher.update(CLUSTER_KEY_VERSION_PREFIX.as_bytes());
    for (i, f) in frames.iter().enumerate() {
        if i > 0 {
            hasher.update(b"\n");
        }
        hasher.update(f.as_bytes());
    }
    let digest = hasher.finalize();
    let full = hex_lower(&digest);
    let short = full.chars().take(16).collect();
    ClusterKey {
        short,
        full,
        frames: frames.to_vec(),
        fallback: false,
    }
}

/// Cluster a C/C++ sanitizer crash by normalizing its frame list.
pub fn cluster_for_sanitizer(report: &SanitizerReport) -> ClusterKey {
    let input: Vec<InputFrame> = report.stack.iter().map(InputFrame::from).collect();
    let frames = normalize_frames(&input);
    cluster_key_from_frames(&frames)
}

/// True when a sanitizer crash is entirely libFuzzer / sanitizer / allocator
/// driver glue with no target frame — a harness fault, not a target bug.
///
/// The classic case is a passthrough libFuzzer harness whose own `main` /
/// `RunOneTest` corrupts allocator state, producing a SEGV in
/// `[__asan::Allocator::Deallocate, free, fuzzer::RunOneTest]` even on empty
/// input. Such "findings" do not reproduce and are not in target code.
///
/// To avoid dropping a genuine but *unsymbolized* target crash, this returns
/// true only when (a) every symbolized frame is driver / sanitizer / startup
/// or allocator-runtime, and (b) at least one frame is an unambiguous libFuzzer
/// or sanitizer *driver* frame. A crash with only `module+offset` frames (no
/// driver frame) is left for replay-verification to judge.
pub fn is_driver_glue_crash(report: &SanitizerReport) -> bool {
    let mut saw_driver = false;
    for frame in &report.stack {
        let stripped = strip_toolchain_decoration(frame.function.as_str());
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            // Unsymbolized (module+offset) frame — neither confirms nor denies.
            continue;
        }
        if DRIVER_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
            saw_driver = true;
            continue;
        }
        if NOISE_EXACT.contains(&trimmed) || NOISE_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
            // libc startup / interceptor noise — neutral.
            continue;
        }
        let no_args = strip_cpp_args(trimmed);
        if ALLOC_RUNTIME.contains(&no_args.as_str()) {
            continue;
        }
        // A genuine target / library frame: this is a real crash.
        return false;
    }
    saw_driver
}

/// Cluster an Ada exception by synthesizing a logical frame list
/// from the handler location plus up to the two earliest preceding
/// raises (filtered to those strictly before the handler's
/// `sequence_index`).
pub fn cluster_for_ada(testcase: &Testcase, handler: &HandlerEvent) -> ClusterKey {
    let mut frames: Vec<InputFrame> = Vec::new();
    frames.push(InputFrame::symbol(handler.exception_name.clone()));
    frames.push(InputFrame::symbol(format!(
        "{}:{}",
        handler.handler_file, handler.handler_line
    )));
    let mut raises: Vec<&event_log::RaiseEvent> = testcase
        .raises
        .iter()
        .filter(|r| r.sequence_index < handler.sequence_index)
        .collect();
    raises.sort_by_key(|r| r.sequence_index);
    for raise in raises.iter().take(2) {
        frames.push(InputFrame::symbol(format!("{}:{}", raise.file, raise.line)));
    }
    let normalized = normalize_frames(&frames);
    cluster_key_from_frames(&normalized)
}

/// Reconstruct a `ClusterKey` from a `finding.json` value. Order of
/// precedence:
/// 1. `cluster_key_full` + `cluster_normalized_frames` already on
///    the record — return them as-is.
/// 2. `exception.stack` array — normalize and hash.
/// 3. `handler` + `raises` (Ada path) — synthesize and hash.
/// 4. Otherwise return `None`; the caller falls back to the
///    per-input signature.
pub fn cluster_from_finding_json(raw: &serde_json::Value) -> Option<ClusterKey> {
    if let (Some(full), Some(frames)) = (
        raw.get("cluster_key_full").and_then(|v| v.as_str()),
        raw.get("cluster_normalized_frames")
            .and_then(|v| v.as_array()),
    ) {
        let frames: Vec<String> = frames
            .iter()
            .filter_map(|f| f.as_str().map(str::to_owned))
            .collect();
        let fallback = raw
            .get("cluster_fallback")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let short = raw
            .get("cluster_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| full.chars().take(16).collect());
        return Some(ClusterKey {
            short,
            full: full.to_owned(),
            frames,
            fallback,
        });
    }
    if let Some(stack) = raw
        .get("exception")
        .and_then(|e| e.get("stack"))
        .and_then(|s| s.as_array())
    {
        let input: Vec<InputFrame> = stack.iter().filter_map(input_frame_from_json).collect();
        if !input.is_empty() {
            let frames = normalize_frames(&input);
            return Some(cluster_key_from_frames(&frames));
        }
    }
    if let Some(handler) = raw.get("handler").and_then(|v| v.as_object()) {
        let exception_name = handler
            .get("exception_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let handler_file = handler
            .get("handler_file")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let handler_line = handler
            .get("handler_line")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let sequence_index = handler
            .get("sequence_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let raises = raw
            .get("raises")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut frames: Vec<InputFrame> = Vec::new();
        frames.push(InputFrame::symbol(exception_name));
        frames.push(InputFrame::symbol(format!(
            "{}:{}",
            handler_file, handler_line
        )));
        let mut raise_pairs: Vec<(usize, String)> = raises
            .iter()
            .filter_map(|r| {
                let seq = r.get("sequence_index").and_then(|v| v.as_u64())? as usize;
                if seq >= sequence_index {
                    return None;
                }
                let file = r.get("file").and_then(|v| v.as_str())?.to_owned();
                let line = r.get("line").and_then(|v| v.as_u64())? as u32;
                Some((seq, format!("{}:{}", file, line)))
            })
            .collect();
        raise_pairs.sort_by_key(|(s, _)| *s);
        for (_, label) in raise_pairs.iter().take(2) {
            frames.push(InputFrame::symbol(label.clone()));
        }
        let normalized = normalize_frames(&frames);
        if !normalized.is_empty() {
            return Some(cluster_key_from_frames(&normalized));
        }
    }
    None
}

fn input_frame_from_json(v: &serde_json::Value) -> Option<InputFrame> {
    let function = v.get("function").and_then(|f| f.as_str())?;
    if function.is_empty() {
        return None;
    }
    let file = v.get("file").and_then(|f| f.as_str()).map(str::to_owned);
    let line = v.get("line").and_then(|l| l.as_u64()).map(|n| n as u32);
    Some(InputFrame {
        function: function.to_owned(),
        file,
        line,
    })
}

/// Remove trailing whitespace-preceded balanced paren groups
/// (`(/path/build/main+0xfec85)`, `(BuildId: ...)`, etc.). C++
/// argument lists glued to the function name without whitespace
/// stay intact at this stage — they are stripped in `strip_cpp_args`.
fn strip_toolchain_decoration(raw: &str) -> String {
    let mut cursor = raw.trim_end();
    while let Some(stripped) = strip_one_trailing_paren_group(cursor) {
        cursor = stripped;
    }
    cursor.to_owned()
}

fn strip_one_trailing_paren_group(s: &str) -> Option<&str> {
    let trimmed = s.trim_end();
    if !trimmed.ends_with(')') {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut depth = 0_i32;
    let mut open_idx: Option<usize> = None;
    for (i, b) in bytes.iter().enumerate().rev() {
        match b {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open_idx = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let open = open_idx?;
    let preceding = &trimmed[..open];
    if !preceding.ends_with(char::is_whitespace) {
        return None;
    }
    Some(preceding.trim_end())
}

/// Strip a trailing C++ argument list and any trailing CV/ref
/// qualifiers (`const`, `&`, `&&`, `noexcept`). Preserves `operator`
/// overloads — if the substring immediately preceding the first
/// top-level `(` is `operator`, the original string is returned
/// unchanged.
fn strip_cpp_args(raw: &str) -> String {
    let trimmed = raw.trim();
    let Some(open) = find_top_level_open_paren(trimmed) else {
        return trimmed.to_owned();
    };
    let preceding = &trimmed[..open];
    if preceding.ends_with("operator") {
        return trimmed.to_owned();
    }
    preceding.trim_end().to_owned()
}

/// Byte index of the `(` that opens the argument list at template depth 0 in
/// `s`, skipping the literal `(anonymous namespace)` scope token — a
/// non-argument parenthetical embedded in a qualified C++ name (e.g.
/// `pugi::impl::(anonymous namespace)::strlength_wide(...)`), which would
/// otherwise be mistaken for the argument list and collapse the top frame.
fn find_top_level_open_paren(s: &str) -> Option<usize> {
    const ANON: &str = "(anonymous namespace)";
    let bytes = s.as_bytes();
    let mut angle = 0_i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => angle += 1,
            b'>' => angle -= 1,
            b'(' if angle <= 0 => {
                if s[i..].starts_with(ANON) {
                    i += ANON.len();
                    continue;
                }
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
    use event_log::{HandlerEvent, RaiseEvent, Testcase};

    fn fr(function: &str) -> InputFrame {
        InputFrame::symbol(function)
    }

    #[test]
    fn input_frame_symbol_constructor_omits_file_and_line() {
        let frame = InputFrame::symbol("foo");
        assert_eq!(frame.function, "foo");
        assert!(frame.file.is_none());
        assert!(frame.line.is_none());
    }

    #[test]
    fn normalize_strips_module_offset_annotation() {
        let frames = vec![fr("foo (/tmp/build/main+0xfec85)")];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["foo".to_owned()]);
    }

    #[test]
    fn normalize_strips_buildid_blob() {
        let frames = vec![fr("foo (BuildId: deadbeef)")];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["foo".to_owned()]);
    }

    #[test]
    fn normalize_drops_sanitizer_infrastructure_frames() {
        let frames = vec![
            fr("__asan_memcpy"),
            fr("__sanitizer_internal"),
            fr("__interceptor_strlen"),
            fr("__ubsan_handle_signed_overflow"),
            fr("real_target_fn"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["real_target_fn".to_owned()]);
    }

    #[test]
    fn normalize_drops_libfuzzer_scaffolding() {
        let frames = vec![
            fr("LLVMFuzzerTestOneInput"),
            fr("LLVMFuzzerRunDriver"),
            fr("fuzzer::Fuzzer::ExecuteCallback"),
            fr("main"),
            fr("__libc_start_main"),
            fr("_start"),
            fr("my_target_parse"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["my_target_parse".to_owned()]);
    }

    #[test]
    fn normalize_strips_cpp_arg_list_but_keeps_operator_call() {
        let frames = vec![
            fr("Foo::Bar(int, char const*)"),
            fr("Baz::operator()(int)"),
            fr("Qux::operator()"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(
            out,
            vec![
                "Foo::Bar".to_owned(),
                "Baz::operator()(int)".to_owned(),
                "Qux::operator()".to_owned(),
            ]
        );
    }

    #[test]
    fn normalize_keeps_anonymous_namespace_and_strips_only_arg_list() {
        // The "(anonymous namespace)" scope token must not be mistaken for the
        // argument list — only the trailing "(const wchar_t*)" is stripped.
        let frames = vec![fr(
            "pugi::impl::(anonymous namespace)::strlength_wide(wchar_t const*)",
        )];
        let out = normalize_frames(&frames);
        assert_eq!(
            out,
            vec!["pugi::impl::(anonymous namespace)::strlength_wide".to_owned()]
        );
    }

    #[test]
    fn normalize_strips_cpp_trailing_qualifiers() {
        let frames = vec![fr("Foo::Bar(int) const noexcept")];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["Foo::Bar".to_owned()]);
    }

    #[test]
    fn normalize_truncates_to_top_3() {
        let frames = vec![fr("a"), fr("b"), fr("c"), fr("d"), fr("e")];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn normalize_returns_empty_when_only_noise_present() {
        let frames = vec![fr("__asan_memcpy"), fr("LLVMFuzzerTestOneInput")];
        let out = normalize_frames(&frames);
        assert!(out.is_empty());
    }

    #[test]
    fn normalize_drops_libc_runtime_and_govfuzz_harness_frames() {
        // #31: fprintf (libc) + govfuzz_run_one (harness) are scaffolding — the key
        // must start at the first in-project frame (stdout_callback).
        let frames = vec![
            fr("fprintf"),
            fr("govfuzz_run_one"),
            fr("stdout_callback"),
            fr("log_log"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(
            out,
            vec!["stdout_callback".to_owned(), "log_log".to_owned()]
        );
    }

    #[test]
    fn normalize_drops_rust_allocator_and_runtime_scaffolding() {
        let frames = vec![
            fr("malloc"),
            fr("<alloc::raw_vec::RawVecInner>::try_allocate_in"),
            fr("<alloc::vec::Vec<u8>>::with_capacity_in"),
            fr("<str as alloc::borrow::ToOwned>::to_owned"),
            fr("<rust_runtime::Cursor>::string"),
            fr("govfuzz_run_one"),
            fr("govfuzz_run_one_bytes"),
            fr("main"),
        ];
        let out = normalize_frames(&frames);
        assert!(
            out.is_empty(),
            "scaffolding frames must not form a cluster: {out:?}"
        );
    }

    #[test]
    fn normalize_keeps_rust_target_frame_after_allocator_noise() {
        let frames = vec![
            fr("malloc"),
            fr("<alloc::raw_vec::RawVecInner>::try_allocate_in"),
            fr("<alloc::vec::Vec<u8>>::with_capacity_in"),
            fr("roxmltree::ExpandedName::from_static"),
            fr("govfuzz_run_one"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["roxmltree::ExpandedName::from_static".to_owned()]);
    }

    #[test]
    fn cluster_one_root_cause_regardless_of_runtime_pc_landing() {
        // #31: the same log.c bug crashing inside the format machinery on one input
        // and at the project array load on another must cluster to ONE issue.
        let in_fprintf = cluster_for_sanitizer(&sample_sanitizer_report(vec![
            "fprintf",
            "stdout_callback",
            "log_log",
        ]));
        let in_array =
            cluster_for_sanitizer(&sample_sanitizer_report(vec!["stdout_callback", "log_log"]));
        assert!(!in_fprintf.fallback);
        assert_eq!(in_fprintf.full, in_array.full);
    }

    fn sample_leak_report(frames: Vec<&str>) -> SanitizerReport {
        SanitizerReport {
            sanitizer: Sanitizer::LeakSanitizer,
            kind: "memory-leak".to_owned(),
            rule_id: "GF-208",
            stack: frames
                .into_iter()
                .map(|f| StackFrame {
                    function: f.to_owned(),
                    file: None,
                    line: None,
                })
                .collect(),
            message: "ERROR: LeakSanitizer: detected memory leaks".to_owned(),
        }
    }

    #[test]
    fn harness_scaffolding_leak_suppressed_when_every_frame_is_govfuzz() {
        // #49: a leak whose whole allocation stack is govfuzz's gf_* decoder +
        // harness scaffolding (unfreed because an exit()-only target died first) is
        // suppressed, not reported as a target CWE-401.
        let report = sample_leak_report(vec!["malloc", "gf_c_string", "govfuzz_run_one"]);
        assert!(is_harness_scaffolding_leak(&report));
    }

    #[test]
    fn rust_static_decoder_leak_is_harness_scaffolding() {
        // #44: Rust &'static decoders intentionally Box::leak fuzz-owned strings.
        // LSan reports those allocations through Rust std/allocator frames before
        // reaching rust_runtime::Cursor and govfuzz_run_one; that is generated
        // harness scaffolding, not a target CWE-401.
        let report = sample_leak_report(vec![
            "malloc",
            "<alloc::raw_vec::RawVecInner>::try_allocate_in",
            "<alloc::vec::Vec<u8>>::with_capacity_in",
            "<str as alloc::borrow::ToOwned>::to_owned",
            "<rust_runtime::Cursor>::string",
            "govfuzz_run_one",
            "govfuzz_run_one_bytes",
            "main",
        ]);
        assert!(is_harness_scaffolding_leak(&report));
    }

    #[test]
    fn rust_static_decoder_shrink_leak_with_allocator_only_stack_is_scaffolding() {
        // #44: into_boxed_str may shrink through realloc and produce a symbolized
        // LSan stack containing only Rust std allocator frames. With no target
        // frame, this is still the generated Box::leak decoder allocation.
        let report = sample_leak_report(vec![
            "realloc",
            "alloc::alloc::realloc_nonnull",
            "<alloc::alloc::Global>::shrink_impl_runtime",
            "<alloc::alloc::Global>::shrink_impl",
            "<alloc::alloc::Global as core::alloc::Allocator>::shrink",
            "<alloc::raw_vec::RawVecInner>::shrink_unchecked",
        ]);
        assert!(is_harness_scaffolding_leak(&report));
    }

    #[test]
    fn harness_scaffolding_leak_false_with_a_target_frame() {
        // #49 guard: a leak WITH a real target frame is genuine — never suppressed.
        let report = sample_leak_report(vec!["malloc", "gf_c_string", "toml_parse_table"]);
        assert!(!is_harness_scaffolding_leak(&report));
    }

    #[test]
    fn harness_scaffolding_leak_false_for_non_leak_sanitizer() {
        // Only LSan leaks are in scope; an ASan overflow with gf_ frames is handled
        // by the harness-cleanup-artifact verdict path, not suppressed here.
        let report = sample_sanitizer_report(vec!["gf_c_string", "govfuzz_run_one"]);
        assert!(!is_harness_scaffolding_leak(&report));
    }

    #[test]
    fn cluster_key_from_frames_is_deterministic() {
        let a = cluster_key_from_frames(&["foo".to_owned(), "bar".to_owned()]);
        let b = cluster_key_from_frames(&["foo".to_owned(), "bar".to_owned()]);
        assert_eq!(a.short, b.short);
        assert_eq!(a.full, b.full);
        assert_eq!(a.frames, vec!["foo", "bar"]);
        assert!(!a.fallback);
    }

    #[test]
    fn cluster_key_short_is_16_hex_chars() {
        let key = cluster_key_from_frames(&["foo".to_owned()]);
        assert_eq!(key.short.len(), 16);
        assert!(key.short.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(key.short.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn cluster_key_changes_when_frames_differ() {
        let a = cluster_key_from_frames(&["foo".to_owned()]);
        let b = cluster_key_from_frames(&["bar".to_owned()]);
        assert_ne!(a.short, b.short);
    }

    #[test]
    fn cluster_key_full_is_64_hex_chars() {
        let key = cluster_key_from_frames(&["foo".to_owned()]);
        assert_eq!(key.full.len(), 64);
    }

    #[test]
    fn cluster_key_from_empty_frames_marks_fallback_with_zero_padding() {
        let key = cluster_key_from_frames(&[]);
        assert!(key.fallback);
        assert!(key.frames.is_empty());
        assert_eq!(key.short, "0000000000000000");
    }

    #[test]
    fn cluster_key_struct_serializes_short_as_string() {
        let key = ClusterKey {
            short: "abcd1234deadbeef".to_owned(),
            full: "abcd1234deadbeef".repeat(4),
            frames: vec!["foo".to_owned()],
            fallback: false,
        };
        let v = serde_json::to_value(&key).unwrap();
        assert_eq!(v["short"], "abcd1234deadbeef");
        assert_eq!(v["fallback"], false);
        assert_eq!(v["frames"][0], "foo");
    }

    fn sample_sanitizer_report(frames: Vec<&str>) -> SanitizerReport {
        SanitizerReport {
            sanitizer: Sanitizer::AddressSanitizer,
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "GF-201",
            stack: frames
                .into_iter()
                .map(|f| StackFrame {
                    function: f.to_owned(),
                    file: None,
                    line: None,
                })
                .collect(),
            message: "ERROR: AddressSanitizer: heap-buffer-overflow".to_owned(),
        }
    }

    #[test]
    fn cluster_for_sanitizer_drops_scaffolding_and_keeps_target_frames() {
        let report = sample_sanitizer_report(vec![
            "__asan_memcpy",
            "real_parse",
            "real_dispatch",
            "LLVMFuzzerTestOneInput",
        ]);
        let key = cluster_for_sanitizer(&report);
        assert!(!key.fallback);
        assert_eq!(key.frames, vec!["real_parse", "real_dispatch"]);
    }

    #[test]
    fn cluster_for_sanitizer_equal_for_same_target_frames_with_different_scaffolding() {
        let a = cluster_for_sanitizer(&sample_sanitizer_report(vec![
            "__asan_memcpy",
            "real_parse",
            "main",
        ]));
        let b = cluster_for_sanitizer(&sample_sanitizer_report(vec![
            "__sanitizer_internal",
            "real_parse",
            "_start",
        ]));
        assert_eq!(a.short, b.short);
    }

    #[test]
    fn cluster_for_sanitizer_differs_when_target_frames_differ() {
        let a = cluster_for_sanitizer(&sample_sanitizer_report(vec!["real_parse_v1"]));
        let b = cluster_for_sanitizer(&sample_sanitizer_report(vec!["real_parse_v2"]));
        assert_ne!(a.short, b.short);
    }

    #[test]
    fn cluster_for_sanitizer_marks_fallback_when_all_noise() {
        let report = sample_sanitizer_report(vec!["__asan_memcpy", "main"]);
        let key = cluster_for_sanitizer(&report);
        assert!(key.fallback);
    }

    #[test]
    fn normalize_drops_cpp_namespace_sanitizer_and_fuzzer_frames() {
        let frames = vec![
            fr("__asan::Allocator::Deallocate"),
            fr("fuzzer::RunOneTest"),
            fr("real_target"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["real_target".to_owned()]);
    }

    #[test]
    fn is_driver_glue_crash_true_for_allocator_glue_stack() {
        let report = sample_sanitizer_report(vec![
            "__asan::Allocator::Deallocate",
            "free",
            "fuzzer::RunOneTest",
        ]);
        assert!(is_driver_glue_crash(&report));
    }

    #[test]
    fn is_driver_glue_crash_false_when_target_frame_present() {
        let report =
            sample_sanitizer_report(vec!["cJSON_GetObjectItem", "free", "fuzzer::RunOneTest"]);
        assert!(!is_driver_glue_crash(&report));
    }

    #[test]
    fn is_driver_glue_crash_false_for_unsymbolized_only_stack() {
        // module+offset frames with no recognizable driver frame: leave the
        // verdict to replay-verification rather than silently dropping it.
        let report = sample_sanitizer_report(vec!["(/opt/build/main+0x12ab)"]);
        assert!(!is_driver_glue_crash(&report));
    }

    fn handler_event(name: &str, file: &str, line: u32, last_breadcrumb: u32) -> HandlerEvent {
        HandlerEvent {
            sequence_index: 3,
            exception_name: name.to_owned(),
            exception_message: "msg".to_owned(),
            handler_file: file.to_owned(),
            handler_line: line,
            last_breadcrumb,
            target_id: 0x42,
            testcase_id: 1,
        }
    }

    fn testcase_with(handlers: Vec<HandlerEvent>, raises: Vec<RaiseEvent>) -> Testcase {
        Testcase {
            testcase_id: 1,
            target_id: 0x42,
            crumbs: vec![1],
            handlers,
            raises,
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }

    #[test]
    fn cluster_for_ada_uses_exception_name_and_handler_location() {
        let h = handler_event("CONSTRAINT_ERROR", "pkg.adb", 9, 1);
        let key = cluster_for_ada(&testcase_with(vec![h.clone()], vec![]), &h);
        assert!(!key.fallback);
        assert_eq!(
            key.frames,
            vec!["CONSTRAINT_ERROR".to_owned(), "pkg.adb:9".to_owned(),]
        );
    }

    #[test]
    fn cluster_for_ada_includes_preceding_raise_chain() {
        let h = handler_event("CONSTRAINT_ERROR", "pkg.adb", 9, 1);
        let raises = vec![RaiseEvent {
            sequence_index: 1,
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            file: "inner.adb".to_owned(),
            line: 22,
            breadcrumb: 7,
        }];
        let key = cluster_for_ada(&testcase_with(vec![h.clone()], raises), &h);
        assert_eq!(
            key.frames,
            vec![
                "CONSTRAINT_ERROR".to_owned(),
                "pkg.adb:9".to_owned(),
                "inner.adb:22".to_owned(),
            ]
        );
    }

    #[test]
    fn cluster_for_ada_distinguishes_different_raise_sites_same_handler() {
        let h = handler_event("CONSTRAINT_ERROR", "pkg.adb", 9, 1);
        let a = cluster_for_ada(
            &testcase_with(
                vec![h.clone()],
                vec![RaiseEvent {
                    sequence_index: 1,
                    exception_name: "CONSTRAINT_ERROR".to_owned(),
                    file: "a.adb".to_owned(),
                    line: 1,
                    breadcrumb: 1,
                }],
            ),
            &h,
        );
        let b = cluster_for_ada(
            &testcase_with(
                vec![h.clone()],
                vec![RaiseEvent {
                    sequence_index: 1,
                    exception_name: "CONSTRAINT_ERROR".to_owned(),
                    file: "b.adb".to_owned(),
                    line: 1,
                    breadcrumb: 1,
                }],
            ),
            &h,
        );
        assert_ne!(a.short, b.short);
    }

    #[test]
    fn cluster_from_finding_json_uses_existing_cluster_key_full_when_present() {
        let raw = serde_json::json!({
            "cluster_key_full": "ab".repeat(32),
            "cluster_normalized_frames": ["foo", "bar"],
        });
        let key = cluster_from_finding_json(&raw).expect("present");
        assert_eq!(key.full, "ab".repeat(32));
        assert_eq!(key.short, &"ab".repeat(32)[..16]);
        assert_eq!(key.frames, vec!["foo", "bar"]);
        assert!(!key.fallback);
    }

    #[test]
    fn cluster_from_finding_json_backfills_from_exception_stack() {
        let raw = serde_json::json!({
            "exception": {
                "stack": [
                    { "function": "__asan_memcpy" },
                    { "function": "target_parse", "file": "/src/p.c", "line": 9 },
                    { "function": "LLVMFuzzerTestOneInput" },
                ]
            }
        });
        let key = cluster_from_finding_json(&raw).expect("present");
        assert_eq!(key.frames, vec!["target_parse"]);
        assert!(!key.fallback);
    }

    #[test]
    fn cluster_from_finding_json_backfills_from_handler_for_ada() {
        let raw = serde_json::json!({
            "exception": { "name": "CONSTRAINT_ERROR" },
            "handler": {
                "exception_name": "CONSTRAINT_ERROR",
                "handler_file": "pkg.adb",
                "handler_line": 9,
                "sequence_index": 3
            },
            "raises": []
        });
        let key = cluster_from_finding_json(&raw).expect("present");
        assert_eq!(
            key.frames,
            vec!["CONSTRAINT_ERROR".to_owned(), "pkg.adb:9".to_owned()]
        );
    }

    #[test]
    fn cluster_from_finding_json_returns_none_when_nothing_usable() {
        let raw = serde_json::json!({ "id": "F-0001", "signature": "deadbeef" });
        assert!(cluster_from_finding_json(&raw).is_none());
    }
}
