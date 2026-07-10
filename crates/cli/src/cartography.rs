// SPDX-License-Identifier: Apache-2.0

//! `govfuzz cartography` — a byte-control card for a crash: which input bytes
//! control which sink operand (offset / size / index), and what exploit primitive
//! that implies.
//!
//! A crash tells you *where* memory safety broke; an exploit developer needs to
//! know *what they control*. govfuzz answers this offline and deterministically by
//! PERTURBATION: it replays the minimized crashing input with each byte flipped and
//! reads how the sanitizer's report changes. The signal is ASLR-independent — not
//! the absolute faulting address (which moves every run) but the RELATIVE operand
//! the sanitizer names: the access size (`READ/WRITE of size N`) and the offset from
//! the object (`located N bytes after a M-byte region`, `at offset N in frame`).
//!
//!   * flipping a byte removes the crash        ⇒ STRUCTURAL (a gate to reach the sink)
//!   * flipping a byte moves the relative offset ⇒ controls the ACCESS OFFSET/INDEX
//!   * flipping a byte changes the access size   ⇒ controls the ACCESS SIZE/LENGTH
//!   * flipping a byte changes nothing           ⇒ don't-care (payload/filler)
//!
//! From the controlled operand + access direction it classifies the exploit
//! primitive (a WRITE whose offset an attacker byte controls is a controlled
//! relative write, CWE-787), writes a `<finding>/byte-control.json` card, and
//! enriches the finding with a `primitive` object. C lane, best-effort: a min input
//! that no longer reproduces, or a non-C finding, skips cleanly.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Cap the number of input bytes perturbed so a large min input can't stall.
const MAX_BYTES: usize = 256;

/// `govfuzz cartography` — map which input bytes control which sink operand.
#[derive(Debug, clap::Args)]
pub struct CartographyArgs {
    /// Work directory of a prior `auto` run.
    #[arg(long = "work-dir", default_value = "govfuzz_work")]
    pub work_dir: PathBuf,

    /// Map only this finding id (default: every reproducible C crash).
    #[arg(long = "finding-id", value_name = "ID")]
    pub finding_id: Option<String>,
}

pub fn run(args: CartographyArgs) -> i32 {
    let findings = match collect(&args.work_dir, args.finding_id.as_deref()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if findings.is_empty() {
        eprintln!(
            "govfuzz cartography: no reproducible C crash findings in {}",
            args.work_dir.display()
        );
        return 0;
    }
    let mut mapped = 0usize;
    let mut first = true;
    for f in &findings {
        if let Some(card) = map_finding(&args.work_dir, f) {
            if !first {
                println!();
            }
            first = false;
            print!("{}", render_card(&f.id, &card));
            write_card(f, &card);
            mapped += 1;
        }
    }
    if mapped == 0 {
        eprintln!("govfuzz cartography: no finding reproduced under perturbation analysis");
    }
    0
}

struct FindingRef {
    id: String,
    dir: PathBuf,
    harness_id: String,
}

fn collect(work_dir: &Path, only: Option<&str>) -> anyhow::Result<Vec<FindingRef>> {
    let dir = work_dir.join("findings");
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let fdir = entry.path();
        let Some(raw) = read_json(&fdir.join("finding.json")) else {
            continue;
        };
        if raw.get("classification").and_then(Value::as_str) != Some("unhandled") {
            continue;
        }
        let harness_id = match raw.get("harness_id").and_then(Value::as_str) {
            Some(h) if h.starts_with("H-C") => h.to_owned(),
            _ => continue,
        };
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
        if fdir.join("testcase.bin").is_file() {
            out.push(FindingRef {
                id,
                dir: fdir,
                harness_id,
            });
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// The ASLR-independent facts of one crash, parsed from the sanitizer report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct CrashFacts {
    class: String,
    access: Option<String>,
    size: Option<u64>,
    /// Signed offset of the faulting access from the object it overflowed (+ =
    /// after/right, - = before/left). ASLR-independent.
    rel_offset: Option<i64>,
}

/// Per-byte control classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteClass {
    Structural,
    ControlsOffset,
    ControlsSize,
    ControlsClass,
    DontCare,
}

impl ByteClass {
    fn tag(self) -> &'static str {
        match self {
            ByteClass::Structural => "structural",
            ByteClass::ControlsOffset => "controls_offset",
            ByteClass::ControlsSize => "controls_size",
            ByteClass::ControlsClass => "controls_class",
            ByteClass::DontCare => "dont_care",
        }
    }
}

struct Card {
    input_len: usize,
    analyzed: usize,
    baseline: CrashFacts,
    classes: Vec<ByteClass>,
    primitive: Primitive,
}

struct Primitive {
    kind: &'static str,
    cwe: &'static str,
    exploitability: &'static str,
    summary: String,
    controlling_bytes: Vec<usize>,
}

fn map_finding(work_dir: &Path, f: &FindingRef) -> Option<Card> {
    let bin = crate::auto::layout::harness_dir(work_dir, &f.harness_id).join("main");
    if !bin.is_file() {
        return None;
    }
    let input = std::fs::read(f.dir.join("testcase.bin")).ok()?;
    let baseline = replay_facts(&bin, &input)?; // must reproduce a crash to map it.
    let analyzed = input.len().min(MAX_BYTES);

    let mut classes = Vec::with_capacity(analyzed);
    for i in 0..analyzed {
        classes.push(classify_byte(&bin, &input, i, &baseline));
    }
    let primitive = classify_primitive(&baseline, &classes);
    Some(Card {
        input_len: input.len(),
        analyzed,
        baseline,
        classes,
        primitive,
    })
}

/// Classify one byte by perturbing it (XOR 0xFF and XOR 0x01) and comparing the
/// resulting crash facts to the baseline.
fn classify_byte(bin: &Path, input: &[u8], i: usize, baseline: &CrashFacts) -> ByteClass {
    let mut crashed_variants = Vec::new();
    for delta in [0xFFu8, 0x01u8] {
        let mut mutated = input.to_vec();
        mutated[i] ^= delta;
        if let Some(facts) = replay_facts(bin, &mutated) {
            crashed_variants.push(facts);
        }
    }
    if crashed_variants.is_empty() {
        return ByteClass::Structural; // every perturbation removed the crash.
    }
    // Prefer the strongest operand-control signal observed across perturbations.
    let mut seen_offset = false;
    let mut seen_size = false;
    let mut seen_class = false;
    for v in &crashed_variants {
        if v.rel_offset.is_some() && v.rel_offset != baseline.rel_offset {
            seen_offset = true;
        }
        if v.size.is_some() && v.size != baseline.size {
            seen_size = true;
        }
        if v.class != baseline.class {
            seen_class = true;
        }
    }
    if seen_offset {
        ByteClass::ControlsOffset
    } else if seen_size {
        ByteClass::ControlsSize
    } else if seen_class {
        ByteClass::ControlsClass
    } else {
        ByteClass::DontCare
    }
}

/// Replay one input and parse its crash facts, or `None` if it did not crash.
///
/// `symbolize=0` is load-bearing: the coverage-instrumented `main` otherwise hangs
/// in the ASan crash symbolizer (llvm-symbolizer, run without the shim here), and
/// the memory-locator line we parse (`located N bytes after region`) is emitted by
/// ASan's shadow analysis, NOT symbolization, so it survives. A `timeout` wrapper
/// is a belt-and-suspenders guard against an input that genuinely loops.
fn replay_facts(bin: &Path, input: &[u8]) -> Option<CrashFacts> {
    let dir = bin.parent()?;
    let scratch = dir.join("cart_input.bin");
    std::fs::write(&scratch, input).ok()?;
    let out = replay_command(bin)
        .arg(&scratch)
        .env(
            "ASAN_OPTIONS",
            "abort_on_error=1:symbolize=0:detect_leaks=0",
        )
        .output()
        .ok()?;
    let _ = std::fs::remove_file(&scratch);
    let stderr = String::from_utf8_lossy(&out.stderr);
    parse_crash(&stderr)
}

/// Build the replay command, wrapping in `timeout` when it is available so a
/// pathological input can never wedge the analysis.
fn replay_command(bin: &Path) -> Command {
    if which::which("timeout").is_ok() {
        let mut cmd = Command::new("timeout");
        cmd.arg("-s").arg("KILL").arg("10").arg(bin);
        cmd
    } else {
        Command::new(bin)
    }
}

/// Parse the ASLR-independent crash facts from a sanitizer report.
fn parse_crash(stderr: &str) -> Option<CrashFacts> {
    let pos = stderr.find("AddressSanitizer: ")?;
    let class: String = stderr[pos + "AddressSanitizer: ".len()..]
        .split(|c: char| c.is_whitespace())
        .next()?
        .to_owned();
    if class.is_empty() {
        return None;
    }
    let mut facts = CrashFacts {
        class,
        ..CrashFacts::default()
    };
    // "READ of size 4 at 0x..." / "WRITE of size 9 at 0x..."
    for dir in ["READ", "WRITE"] {
        if let Some(p) = stderr.find(&format!("{dir} of size ")) {
            facts.access = Some(dir.to_owned());
            let rest = &stderr[p + format!("{dir} of size ").len()..];
            facts.size = rest
                .split(|c: char| !c.is_ascii_digit())
                .find(|s| !s.is_empty())
                .and_then(|s| s.parse::<u64>().ok());
            break;
        }
    }
    facts.rel_offset = parse_rel_offset(stderr);
    Some(facts)
}

/// Extract the signed relative offset of the faulting access from the object it
/// overflowed. Handles heap (`N bytes after/before an M-byte region`), stack (`at
/// offset N in frame`), and global (`N bytes to the right/left of global`).
fn parse_rel_offset(stderr: &str) -> Option<i64> {
    // Heap: "is located 21 bytes after 16-byte region" / "... before ...".
    for (needle, sign) in [
        (" bytes after ", 1i64),
        (" bytes before ", -1),
        (" bytes to the right of ", 1),
        (" bytes to the left of ", -1),
        (" bytes inside of ", 1),
    ] {
        if let Some(p) = stderr.find(needle) {
            // The number precedes the needle: "...located <N> bytes after...".
            if let Some(n) = trailing_number_before(&stderr[..p]) {
                return Some(sign * n);
            }
        }
    }
    // Stack: "at offset 96 in frame".
    if let Some(p) = stderr.find("at offset ") {
        let rest = &stderr[p + "at offset ".len()..];
        if let Some(n) = rest
            .split(|c: char| !c.is_ascii_digit())
            .find(|s| !s.is_empty())
            .and_then(|s| s.parse::<i64>().ok())
        {
            return Some(n);
        }
    }
    None
}

/// The integer that ends the string `s` (skipping trailing whitespace).
fn trailing_number_before(s: &str) -> Option<i64> {
    let t = s.trim_end();
    let digits: String = t
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    digits.parse::<i64>().ok()
}

/// Classify the exploit primitive from the baseline access + the per-byte control map.
fn classify_primitive(baseline: &CrashFacts, classes: &[ByteClass]) -> Primitive {
    let controlling: Vec<usize> = classes
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            matches!(
                c,
                ByteClass::ControlsOffset | ByteClass::ControlsSize | ByteClass::ControlsClass
            )
        })
        .map(|(i, _)| i)
        .collect();
    let controls_offset = classes.contains(&ByteClass::ControlsOffset);
    let controls_size = classes.contains(&ByteClass::ControlsSize);
    let is_write = baseline.access.as_deref() == Some("WRITE");
    let operand = if controls_offset {
        "offset/index"
    } else if controls_size {
        "size/length"
    } else {
        ""
    };

    if !controlling.is_empty() && is_write {
        Primitive {
            kind: "controlled_relative_write",
            cwe: "CWE-787",
            exploitability: "high",
            summary: format!(
                "input byte(s) {} control the {operand} of an out-of-bounds WRITE — a controlled relative write",
                span_list(&controlling)
            ),
            controlling_bytes: controlling,
        }
    } else if !controlling.is_empty() {
        Primitive {
            kind: "controlled_relative_read",
            cwe: "CWE-125",
            exploitability: "medium",
            summary: format!(
                "input byte(s) {} control the {operand} of an out-of-bounds READ — a controlled relative read (info leak)",
                span_list(&controlling)
            ),
            controlling_bytes: controlling,
        }
    } else if is_write {
        Primitive {
            kind: "fixed_write",
            cwe: "CWE-787",
            exploitability: "low",
            summary:
                "an out-of-bounds WRITE whose operand no single input byte controls (fixed offset)"
                    .to_owned(),
            controlling_bytes: Vec::new(),
        }
    } else {
        Primitive {
            kind: "gated_crash",
            cwe: baseline_cwe(baseline),
            exploitability: "low",
            summary: "a gated crash with no byte-level operand control found by perturbation"
                .to_owned(),
            controlling_bytes: Vec::new(),
        }
    }
}

fn baseline_cwe(baseline: &CrashFacts) -> &'static str {
    match baseline.access.as_deref() {
        Some("WRITE") => "CWE-787",
        Some("READ") => "CWE-125",
        _ => "CWE-119",
    }
}

/// Coalesce contiguous byte offsets into `a-b` spans for a compact summary.
fn span_list(offs: &[usize]) -> String {
    if offs.is_empty() {
        return "(none)".to_owned();
    }
    let mut spans = Vec::new();
    let mut start = offs[0];
    let mut prev = offs[0];
    for &o in &offs[1..] {
        if o == prev + 1 {
            prev = o;
        } else {
            spans.push(fmt_span(start, prev));
            start = o;
            prev = o;
        }
    }
    spans.push(fmt_span(start, prev));
    spans.join(", ")
}

fn fmt_span(a: usize, b: usize) -> String {
    if a == b {
        format!("{a}")
    } else {
        format!("{a}-{b}")
    }
}

/// Render the human-readable card.
fn render_card(id: &str, card: &Card) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let b = &card.baseline;
    let _ = writeln!(s, "━━━ Byte-control card — {id} ━━━");
    let _ = writeln!(
        s,
        "  crash: {} ({} of size {}{})",
        b.class,
        b.access.as_deref().unwrap_or("?"),
        b.size.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
        b.rel_offset
            .map(|o| format!(", offset {o:+}"))
            .unwrap_or_default(),
    );
    let _ = writeln!(
        s,
        "  input: {} byte(s){}",
        card.input_len,
        if card.analyzed < card.input_len {
            format!(" (first {} analyzed)", card.analyzed)
        } else {
            String::new()
        }
    );
    let _ = writeln!(
        s,
        "  primitive: {} ({}, exploitability {})",
        card.primitive.kind, card.primitive.cwe, card.primitive.exploitability
    );
    let _ = writeln!(s, "    {}", card.primitive.summary);
    let _ = writeln!(s, "  byte map:");
    for (label, class) in [
        ("structural (gate)", ByteClass::Structural),
        ("controls offset/index", ByteClass::ControlsOffset),
        ("controls size/length", ByteClass::ControlsSize),
        ("controls crash kind", ByteClass::ControlsClass),
    ] {
        let offs: Vec<usize> = card
            .classes
            .iter()
            .enumerate()
            .filter(|(_, c)| **c == class)
            .map(|(i, _)| i)
            .collect();
        if !offs.is_empty() {
            let _ = writeln!(s, "    {label}: bytes {}", span_list(&offs));
        }
    }
    s
}

/// Write the machine-readable card + enrich the finding with a `primitive` object.
fn write_card(f: &FindingRef, card: &Card) {
    let bytes: Vec<Value> = card
        .classes
        .iter()
        .enumerate()
        .map(|(i, c)| json!({ "offset": i, "class": c.tag() }))
        .collect();
    let card_json = json!({
        "schema": "govfuzz.byte-control/v1",
        "finding_id": f.id,
        "input_len": card.input_len,
        "analyzed_bytes": card.analyzed,
        "crash": {
            "class": card.baseline.class,
            "access": card.baseline.access,
            "size": card.baseline.size,
            "rel_offset": card.baseline.rel_offset,
        },
        "primitive": {
            "kind": card.primitive.kind,
            "cwe": card.primitive.cwe,
            "exploitability": card.primitive.exploitability,
            "summary": card.primitive.summary,
            "controlling_bytes": card.primitive.controlling_bytes,
        },
        "bytes": bytes,
    });
    let _ = std::fs::write(
        f.dir.join("byte-control.json"),
        serde_json::to_vec_pretty(&card_json).unwrap_or_default(),
    );
    // Enrich the finding record itself so the primitive travels with the finding.
    if let Some(mut raw) = read_json(&f.dir.join("finding.json")) {
        if let Some(obj) = raw.as_object_mut() {
            obj.insert(
                "primitive".to_owned(),
                json!({
                    "kind": card.primitive.kind,
                    "cwe": card.primitive.cwe,
                    "exploitability": card.primitive.exploitability,
                    "controlling_bytes": card.primitive.controlling_bytes,
                }),
            );
            let _ = std::fs::write(
                f.dir.join("finding.json"),
                serde_json::to_vec_pretty(&raw).unwrap_or_default(),
            );
        }
    }
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_heap_read_facts_with_relative_offset() {
        let report = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000035\n\
READ of size 1 at 0x502000000035 thread T0\n\
0x502000000035 is located 21 bytes after 16-byte region [0x..,0x..)\n";
        let f = parse_crash(report).unwrap();
        assert_eq!(f.class, "heap-buffer-overflow");
        assert_eq!(f.access.as_deref(), Some("READ"));
        assert_eq!(f.size, Some(1));
        assert_eq!(f.rel_offset, Some(21));
    }

    #[test]
    fn parses_stack_write_and_before_region() {
        let write = "AddressSanitizer: stack-buffer-overflow\nWRITE of size 9 at 0x..\nAddress 0x.. at offset 96 in frame";
        let f = parse_crash(write).unwrap();
        assert_eq!(f.access.as_deref(), Some("WRITE"));
        assert_eq!(f.size, Some(9));
        assert_eq!(f.rel_offset, Some(96));

        let before = "AddressSanitizer: heap-buffer-overflow\nREAD of size 4 at 0x..\n0x.. is located 8 bytes before 32-byte region";
        assert_eq!(parse_crash(before).unwrap().rel_offset, Some(-8));
    }

    #[test]
    fn no_crash_yields_none() {
        assert!(parse_crash("all fine\n").is_none());
    }

    #[test]
    fn primitive_controlled_read_from_offset_bytes() {
        let baseline = CrashFacts {
            class: "heap-buffer-overflow".into(),
            access: Some("READ".into()),
            size: Some(1),
            rel_offset: Some(21),
        };
        let classes = vec![
            ByteClass::Structural,
            ByteClass::ControlsOffset,
            ByteClass::DontCare,
        ];
        let p = classify_primitive(&baseline, &classes);
        assert_eq!(p.kind, "controlled_relative_read");
        assert_eq!(p.cwe, "CWE-125");
        assert_eq!(p.controlling_bytes, vec![1]);
    }

    #[test]
    fn primitive_controlled_write_is_high() {
        let baseline = CrashFacts {
            class: "heap-buffer-overflow".into(),
            access: Some("WRITE".into()),
            size: Some(4),
            rel_offset: Some(0),
        };
        let classes = vec![ByteClass::ControlsSize];
        let p = classify_primitive(&baseline, &classes);
        assert_eq!(p.kind, "controlled_relative_write");
        assert_eq!(p.cwe, "CWE-787");
        assert_eq!(p.exploitability, "high");
    }

    #[test]
    fn span_list_coalesces_ranges() {
        assert_eq!(span_list(&[0, 1, 2, 5, 7, 8]), "0-2, 5, 7-8");
        assert_eq!(span_list(&[]), "(none)");
    }
}
