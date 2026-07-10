// SPDX-License-Identifier: Apache-2.0

//! `govfuzz explain` — a deterministic, offline "why did it crash?" for a finding.
//!
//! Every other tool's answer to "explain this crash" is either a raw sanitizer
//! dump or an LLM round-trip. govfuzz already holds every fact needed to answer it
//! precisely and reproducibly, with NO model: the minimized input, the comparison
//! constants the engine mined to get past the target's gates (cmplog / value
//! profile → `dictionary.txt`), the byte-origin taint the shim recorded at each
//! resource call (#422), the virtualized environment the sandbox served, the sink
//! site + call frames, and the build-recovery provenance verdict. This joins them
//! through a FIXED narrative grammar into a triage-ready explanation.
//!
//! Deterministic by construction: the same finding always yields the same text.
//! Best-effort per section — a missing artifact drops that section, never the
//! whole explanation.

use crate::auto::runtrace::{self, RuntraceEvent};
use serde_json::Value;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// `govfuzz explain` — explain, offline and deterministically, why a crash fired.
#[derive(Debug, clap::Args)]
pub struct ExplainArgs {
    /// Work directory of a prior `auto` run.
    #[arg(long = "work-dir", default_value = "govfuzz_work")]
    pub work_dir: PathBuf,

    /// Explain only this finding id (default: every reproducible runtime crash).
    #[arg(long = "finding-id", value_name = "ID")]
    pub finding_id: Option<String>,
}

pub fn run(args: ExplainArgs) -> i32 {
    let findings = match collect(&args.work_dir, args.finding_id.as_deref()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if findings.is_empty() {
        eprintln!(
            "govfuzz explain: no runtime crash findings in {} to explain",
            args.work_dir.display()
        );
        return 0;
    }
    let mut first = true;
    for f in &findings {
        if !first {
            println!();
        }
        first = false;
        print!("{}", explain_one(&args.work_dir, f));
    }
    0
}

/// A finding to explain.
struct Finding {
    id: String,
    dir: PathBuf,
    raw: Value,
}

fn collect(work_dir: &Path, only: Option<&str>) -> anyhow::Result<Vec<Finding>> {
    let dir = work_dir.join("findings");
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let fdir = entry.path();
        let Some(raw) = read_json(&fdir.join("finding.json")) else {
            continue;
        };
        // Runtime crashes / oracle hits — the things that "crashed". Static rows are
        // explained by their own report text, not this crash narrative.
        let class = raw.get("classification").and_then(Value::as_str);
        if !matches!(class, Some("unhandled") | Some("oracle")) {
            continue;
        }
        let id = raw
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if let Some(want) = only {
            if id != want {
                continue;
            }
        }
        out.push(Finding { id, dir: fdir, raw });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Render the full fixed-grammar narrative for one finding.
fn explain_one(work_dir: &Path, f: &Finding) -> String {
    let mut s = String::new();
    let rule = str_at(&f.raw, "/rule_id").unwrap_or("");
    let cwe = f
        .raw
        .pointer("/actionability/cwe/0")
        .and_then(Value::as_str)
        .unwrap_or("");
    let cwe_name = str_at(&f.raw, "/actionability/cwe_name").unwrap_or("crash");
    let _ = writeln!(s, "━━━ {} — {cwe_name} ({cwe}, {rule}) ━━━", f.id);

    // WHAT HAPPENED
    let exc = str_at(&f.raw, "/exception/name").unwrap_or("");
    let sink_file = str_at(&f.raw, "/actionability/sink/file").unwrap_or("");
    let sink_fn = str_at(&f.raw, "/actionability/sink/function").unwrap_or("");
    let sink_line = f
        .raw
        .pointer("/actionability/sink/line")
        .and_then(Value::as_u64);
    let _ = writeln!(s, "\nWHAT HAPPENED");
    if let Some(expl) = str_at(&f.raw, "/actionability/explanation") {
        for line in wrap(expl, 76) {
            let _ = writeln!(s, "  {line}");
        }
    }
    if !sink_file.is_empty() {
        let where_ = match sink_line {
            Some(l) => format!("{}:{l}", basename(sink_file)),
            None => basename(sink_file).to_owned(),
        };
        let _ = writeln!(s, "  Sink: {sink_fn}() at {where_}");
    }
    if let Some(frames) = f
        .raw
        .get("cluster_normalized_frames")
        .and_then(Value::as_array)
    {
        let names: Vec<&str> = frames.iter().filter_map(Value::as_str).collect();
        if !names.is_empty() {
            let _ = writeln!(s, "  Call frames: {}", dedup_chain(&names).join(" → "));
        }
    }
    if !exc.is_empty() {
        let _ = writeln!(s, "  Sanitizer verdict: {exc}");
    }

    // THE INPUT THAT TRIGGERS IT
    let input = f.dir.join("testcase.bin");
    let harness_id = str_at(&f.raw, "/harness_id").unwrap_or("").to_owned();
    if let Ok(bytes) = std::fs::read(&input) {
        let _ = writeln!(s, "\nTHE INPUT THAT TRIGGERS IT  ({} byte(s))", bytes.len());
        for line in hexdump(&bytes, 6) {
            let _ = writeln!(s, "  {line}");
        }
        // Input-to-state: which recovered comparison constants the input satisfies.
        let dict = load_dictionary(work_dir, &harness_id);
        let gates = matched_gates(&bytes, &dict);
        if gates.is_empty() {
            let _ = writeln!(
                s,
                "  (no recovered gate constants matched — the crash is not gated \
                 behind a magic value)"
            );
        } else {
            let _ = writeln!(
                s,
                "  Input-to-state — the engine solved these gates to reach the sink:"
            );
            for (off, tok) in gates {
                let _ = writeln!(s, "    byte {off}: matched recovered constant {tok}");
            }
        }
    }

    // FAKED ENVIRONMENT + byte-origin taint
    let events = harness_id
        .is_empty()
        .then(Vec::new)
        .unwrap_or_else(|| load_events(work_dir, &harness_id));
    let env = summarize_env(&events);
    let _ = writeln!(s, "\nFAKED ENVIRONMENT  (served by the govfuzz sandbox)");
    if env.is_empty() {
        let _ = writeln!(
            s,
            "  the target touched no external resources before the crash"
        );
    } else {
        for line in env {
            let _ = writeln!(s, "  {line}");
        }
    }

    // REACHABILITY & PROVENANCE
    let _ = writeln!(s, "\nREACHABILITY & PROVENANCE");
    let verdict = str_at(&f.raw, "/actionability/verdict").unwrap_or("");
    let _ = writeln!(s, "  Verdict: {}", humanize_verdict(verdict));
    if let Some(prov) = str_at(&f.raw, "/provenance") {
        let note = str_at(&f.raw, "/stub_provenance/note").unwrap_or("");
        let _ = writeln!(s, "  Build-recovery provenance: {}", humanize_prov(prov));
        for line in wrap(note, 74) {
            let _ = writeln!(s, "    {line}");
        }
    }

    // HOW TO FIX
    if let Some(hints) = f
        .raw
        .pointer("/actionability/patch_hints")
        .and_then(Value::as_array)
    {
        if !hints.is_empty() {
            let _ = writeln!(s, "\nHOW TO FIX");
            for h in hints {
                if let Some(g) = h.get("guidance").and_then(Value::as_str) {
                    for line in wrap(g, 76) {
                        let _ = writeln!(s, "  {line}");
                    }
                }
            }
        }
    }

    // REPRODUCE
    let _ = writeln!(s, "\nREPRODUCE OFFLINE");
    let _ = writeln!(
        s,
        "  govfuzz capsule --work-dir {} --finding-id {}",
        work_dir.display(),
        f.id
    );
    let _ = writeln!(
        s,
        "  govfuzz verify-poc {}/capsules/capsule_{}",
        work_dir.display(),
        f.id
    );
    s
}

/// Distinct env/resource interactions the shim virtualized, as narrative lines.
/// Byte-origin taint (#422) is surfaced where present — it is the machine-checked
/// link from an input byte to a sink operand.
fn summarize_env(events: &[RuntraceEvent]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for ev in events {
        let line = match ev {
            RuntraceEvent::EnvVarAccess { name, .. } => {
                format!("getenv {name} → served (value withheld)")
            }
            RuntraceEvent::EnvVarMissing { name, .. } => format!("getenv {name} → served empty"),
            RuntraceEvent::FileOpened {
                path, taint_offset, ..
            } => taint_note("opened file", path, *taint_offset),
            RuntraceEvent::FileMissing {
                path, taint_offset, ..
            } => taint_note("probed missing file", path, *taint_offset),
            RuntraceEvent::PathChecked { path, .. } => format!("access-checked {path}"),
            RuntraceEvent::NetworkUnreachable { address, .. } => {
                format!("connect {address} → refused (offline)")
            }
            RuntraceEvent::DlopenFailed { library } => format!("dlopen {library} → NULL"),
            RuntraceEvent::CommandExecuted { command, .. } => {
                format!("executed command: {command}")
            }
            RuntraceEvent::FormatString {
                format, controlled, ..
            } => {
                let tag = if *controlled {
                    " (INPUT-CONTROLLED)"
                } else {
                    ""
                };
                format!("format string{tag}: {format}")
            }
            _ => continue,
        };
        if seen.insert(line.clone()) {
            lines.push(line);
        }
        if lines.len() >= 20 {
            break;
        }
    }
    lines
}

/// A resource-interaction line, annotated with byte-origin taint when the path was
/// derived from the fuzz input.
fn taint_note(verb: &str, path: &str, taint: Option<u32>) -> String {
    match taint {
        Some(off) => format!("{verb} {path}  ← input byte {off} controls this path"),
        None => format!("{verb} {path}"),
    }
}

/// Parse the fuzz dictionary (`dictionary.txt`, one `"..."`-quoted token per line)
/// into raw byte tokens.
fn load_dictionary(work_dir: &Path, harness_id: &str) -> Vec<Vec<u8>> {
    if harness_id.is_empty() {
        return Vec::new();
    }
    let path = crate::auto::layout::harness_dir(work_dir, harness_id).join("dictionary.txt");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // Drop an optional `name=` prefix, then the surrounding quotes.
        let quoted = line.split_once('=').map(|(_, v)| v).unwrap_or(line).trim();
        if let Some(tok) = unquote_dict_token(quoted) {
            if !tok.is_empty() {
                out.push(tok);
            }
        }
    }
    out
}

/// Unescape an AFL/libFuzzer dictionary token `"...\xNN..."` into raw bytes.
fn unquote_dict_token(quoted: &str) -> Option<Vec<u8>> {
    let inner = quoted.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let h: String = (0..2).filter_map(|_| chars.next()).collect();
                    if let Ok(b) = u8::from_str_radix(&h, 16) {
                        out.push(b);
                    }
                }
                Some('\\') => out.push(b'\\'),
                Some('"') => out.push(b'"'),
                Some('n') => out.push(b'\n'),
                Some('t') => out.push(b'\t'),
                Some(other) => out.push(other as u8),
                None => {}
            }
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    Some(out)
}

/// Find dictionary tokens present in the input, returning `(offset, printable
/// token)` for the notable matches (longest first, deduped by token). A token that
/// appears in the input is a comparison constant the engine had to place there.
fn matched_gates(input: &[u8], dict: &[Vec<u8>]) -> Vec<(usize, String)> {
    let mut tokens: Vec<&Vec<u8>> = dict.iter().filter(|t| !t.is_empty()).collect();
    // Longest tokens are the most informative gates; report those first.
    tokens.sort_by_key(|t| std::cmp::Reverse(t.len()));
    let mut out = Vec::new();
    let mut used = std::collections::BTreeSet::new();
    for tok in tokens {
        if let Some(off) = find_sub(input, tok) {
            let rendered = render_token(tok);
            if used.insert(rendered.clone()) {
                out.push((off, rendered));
            }
        }
        if out.len() >= 8 {
            break;
        }
    }
    out.sort_by_key(|(off, _)| *off);
    out
}

/// First offset of `needle` in `haystack`.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Render a token as `"printable"` or `\xNN` bytes.
fn render_token(tok: &[u8]) -> String {
    if tok.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        format!("\"{}\"", String::from_utf8_lossy(tok))
    } else {
        let hex: Vec<String> = tok.iter().map(|b| format!("\\x{b:02x}")).collect();
        hex.join("")
    }
}

fn load_events(work_dir: &Path, harness_id: &str) -> Vec<RuntraceEvent> {
    let log = crate::auto::layout::harness_dir(work_dir, harness_id).join("runtrace.jsonl");
    let mut events = runtrace::parse_log(&log).unwrap_or_default();
    runtrace::dedupe_in_place(&mut events);
    events
}

/// Collapse consecutive duplicate frames (`handle → handle` → `handle`).
fn dedup_chain<'a>(frames: &[&'a str]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for f in frames {
        if out.last() != Some(f) {
            out.push(f);
        }
    }
    out
}

fn humanize_verdict(v: &str) -> &str {
    match v {
        "likely_reachable" => "attacker-reachable via the fuzzed input channel",
        "lab_only" => "reproducible in the lab; attacker-reachability unproven",
        "reachability_unproven" => "reachability from attacker input unproven",
        _ if v.is_empty() => "unassessed",
        other => other,
    }
}

fn humanize_prov(p: &str) -> &str {
    match p {
        "real_defect" => "real_defect (independent of every injected build-recovery stub)",
        "stub_artifact" => "stub_artifact (the crash needed a value a recovery stub fabricated)",
        other => other,
    }
}

/// Wrap text to `width` columns on whitespace.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// A compact hex+ascii dump, capped to `max_rows` rows of 16 bytes.
fn hexdump(bytes: &[u8], max_rows: usize) -> Vec<String> {
    let mut rows = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        if i >= max_rows {
            rows.push(format!("... ({} more byte(s))", bytes.len() - i * 16));
            break;
        }
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        rows.push(format!("{:04x}  {:<47}  {ascii}", i * 16, hex.join(" ")));
    }
    rows
}

fn basename(p: &str) -> &str {
    Path::new(p)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(p)
}

fn str_at<'a>(v: &'a Value, ptr: &str) -> Option<&'a str> {
    v.pointer(ptr).and_then(Value::as_str)
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquotes_dictionary_tokens() {
        assert_eq!(unquote_dict_token("\"BOOM\""), Some(b"BOOM".to_vec()));
        assert_eq!(unquote_dict_token("\"\\x04\""), Some(vec![0x04]));
        assert_eq!(unquote_dict_token("\"A\\x00B\""), Some(vec![b'A', 0, b'B']));
        assert_eq!(unquote_dict_token("notquoted"), None);
    }

    #[test]
    fn matches_gate_constants_in_input() {
        let input = b"BOOM\xfe\x4d";
        let dict = vec![b"BOOM".to_vec(), b"XY".to_vec(), b"B".to_vec()];
        let gates = matched_gates(input, &dict);
        // "BOOM" (longest) matches at 0; "XY" is absent. "B" is deduped-in by offset
        // order but distinct token, so it also appears — both at offset 0.
        assert!(gates.iter().any(|(o, t)| *o == 0 && t == "\"BOOM\""));
        assert!(!gates.iter().any(|(_, t)| t == "\"XY\""));
    }

    #[test]
    fn renders_binary_token_as_hex() {
        assert_eq!(render_token(&[0xfe, 0x00]), "\\xfe\\x00");
        assert_eq!(render_token(b"GET"), "\"GET\"");
    }

    #[test]
    fn dedups_consecutive_frames() {
        assert_eq!(dedup_chain(&["a", "a", "b", "a"]), vec!["a", "b", "a"]);
    }

    #[test]
    fn summarize_env_surfaces_taint_and_env() {
        let events = vec![
            RuntraceEvent::EnvVarAccess {
                api: "getenv".into(),
                name: "APP_MODE".into(),
            },
            RuntraceEvent::FileOpened {
                syscall: "open".into(),
                fd: 3,
                path: "/etc/passwd".into(),
                taint_offset: Some(5),
            },
        ];
        let lines = summarize_env(&events);
        assert!(lines.iter().any(|l| l.contains("getenv APP_MODE")));
        assert!(lines
            .iter()
            .any(|l| l.contains("/etc/passwd") && l.contains("input byte 5")));
    }

    #[test]
    fn wrap_breaks_on_width() {
        let out = wrap("aaaa bbbb cccc", 9);
        assert_eq!(out, vec!["aaaa bbbb".to_owned(), "cccc".to_owned()]);
    }

    #[test]
    fn hexdump_caps_rows() {
        let bytes = vec![0u8; 200];
        let rows = hexdump(&bytes, 2);
        assert_eq!(rows.len(), 3); // 2 rows + a "... more" line
        assert!(rows.last().unwrap().contains("more byte"));
    }
}
