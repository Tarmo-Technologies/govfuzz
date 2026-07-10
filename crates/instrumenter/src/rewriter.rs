// SPDX-License-Identifier: Apache-2.0

use crate::InstrumenterError;
use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insertion {
    pub byte_offset: u32,
    pub text: String,
    pub kind: InsertionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertionKind {
    BreadcrumbBefore,
    ContextClause,
    HandlerProbe,
    RaiseProbe,
    BindOccurrence,
}

pub struct SourceRewriter<'a> {
    source: &'a str,
    ops: Vec<RewriteOp>,
}

/// Maps a 1-based line number in the *instrumented* output back to the
/// corresponding 1-based line in the *original* source. Instrumentation only
/// ever inserts text (breadcrumb calls, context clauses, handler probes) or
/// replaces single-line spans, so the only thing that shifts line numbers is
/// inserted newlines. We record an anchor `(instrumented_line, original_line)`
/// each time the two diverge; between anchors the mapping is 1:1.
///
/// GNAT embeds the instrumented file's line in runtime exception messages
/// (`bzip2-decoding.adb:646 index check failed`); this map lets the reporter
/// rewrite that to the line a developer actually sees in their source.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LineMap {
    /// Sorted by `instr_line`. For a query L, the original line is
    /// `orig_line + (L - instr_line)` of the last anchor with `instr_line <= L`.
    anchors: Vec<(u32, u32)>,
}

impl LineMap {
    /// The list of `(instrumented_line, original_line)` anchors (1-based),
    /// sorted by instrumented line. Exposed for sidecar serialization.
    pub fn anchors(&self) -> &[(u32, u32)] {
        &self.anchors
    }

    /// Rebuild a `LineMap` from previously-serialized anchors.
    pub fn from_anchors(mut anchors: Vec<(u32, u32)>) -> Self {
        anchors.sort_unstable_by_key(|&(instr, _)| instr);
        Self { anchors }
    }

    /// Map a 1-based instrumented line to its 1-based original line. Lines
    /// before the first anchor (or with no anchors) map to themselves.
    pub fn to_original(&self, instr_line: u32) -> u32 {
        match self.anchors.binary_search_by_key(&instr_line, |&(i, _)| i) {
            Ok(idx) => self.anchors[idx].1,
            Err(0) => instr_line,
            Err(idx) => {
                let (anchor_instr, anchor_orig) = self.anchors[idx - 1];
                anchor_orig.saturating_add(instr_line.saturating_sub(anchor_instr))
            }
        }
    }
}

fn count_newlines(text: &str) -> u32 {
    text.bytes().filter(|&byte| byte == b'\n').count() as u32
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RewriteOp {
    Insert(Insertion),
    Replace {
        byte_range: Range<u32>,
        replacement: String,
        kind: InsertionKind,
    },
}

impl<'a> SourceRewriter<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            source,
            ops: Vec::new(),
        }
    }

    pub fn add_insertion(&mut self, insertion: Insertion) {
        self.ops.push(RewriteOp::Insert(insertion));
    }

    pub fn add_replacement(
        &mut self,
        byte_range: Range<u32>,
        replacement: String,
        kind: InsertionKind,
    ) {
        self.ops.push(RewriteOp::Replace {
            byte_range,
            replacement,
            kind,
        });
    }

    pub fn apply(self) -> Result<String, InstrumenterError> {
        Ok(self.apply_with_line_map()?.0)
    }

    /// Like [`apply`](Self::apply) but also returns a [`LineMap`] from the
    /// instrumented output's line numbers back to the original source's.
    pub fn apply_with_line_map(mut self) -> Result<(String, LineMap), InstrumenterError> {
        self.ops.sort_by_key(RewriteOp::start_byte);
        validate_rewrites(&self.ops)?;

        let mut out = String::with_capacity(self.source.len() + 256);
        let mut cursor = 0usize;
        let mut index = 0usize;
        // Line cursors (1-based) advance in lockstep while copying source, then
        // diverge when an insertion/replacement adds or drops lines. An anchor
        // records the post-divergence offset so later lines map correctly.
        let mut out_line = 1u32;
        let mut src_line = 1u32;
        let mut anchors: Vec<(u32, u32)> = Vec::new();
        while index < self.ops.len() {
            let group_start = self.ops[index].start_byte() as usize;
            if group_start > cursor {
                let slice = source_slice(self.source, cursor, group_start)?;
                let lines = count_newlines(slice);
                out.push_str(slice);
                out_line = out_line.saturating_add(lines);
                src_line = src_line.saturating_add(lines);
                cursor = group_start;
            }

            while index < self.ops.len() && self.ops[index].start_byte() as usize == group_start {
                match &self.ops[index] {
                    RewriteOp::Insert(insertion) => {
                        out.push_str(&insertion.text);
                        let inserted = count_newlines(&insertion.text);
                        if inserted > 0 {
                            // Inserted lines have no original; resync afterwards.
                            out_line = out_line.saturating_add(inserted);
                            push_anchor(&mut anchors, out_line, src_line);
                        }
                    }
                    RewriteOp::Replace {
                        byte_range,
                        replacement,
                        ..
                    } => {
                        out.push_str(replacement);
                        let replaced = source_slice(
                            self.source,
                            cursor.min(byte_range.end as usize),
                            byte_range.end as usize,
                        )
                        .map(count_newlines)
                        .unwrap_or(0);
                        let added = count_newlines(replacement);
                        out_line = out_line.saturating_add(added);
                        src_line = src_line.saturating_add(replaced);
                        if added != replaced {
                            push_anchor(&mut anchors, out_line, src_line);
                        }
                        cursor = cursor.max(byte_range.end as usize);
                    }
                }
                let _ = self.ops[index].kind();
                index = index.saturating_add(1);
            }
        }
        if cursor < self.source.len() {
            out.push_str(source_slice(self.source, cursor, self.source.len())?);
        }

        Ok((out, LineMap { anchors }))
    }
}

/// Record an anchor, collapsing a repeated instrumented-line key (multiple
/// insertions at one point) to the latest mapping.
fn push_anchor(anchors: &mut Vec<(u32, u32)>, instr_line: u32, src_line: u32) {
    if let Some(last) = anchors.last_mut() {
        if last.0 == instr_line {
            last.1 = src_line;
            return;
        }
    }
    anchors.push((instr_line, src_line));
}

impl RewriteOp {
    fn start_byte(&self) -> u32 {
        match self {
            RewriteOp::Insert(insertion) => insertion.byte_offset,
            RewriteOp::Replace { byte_range, .. } => byte_range.start,
        }
    }

    fn kind(&self) -> InsertionKind {
        match self {
            RewriteOp::Insert(insertion) => insertion.kind,
            RewriteOp::Replace { kind, .. } => *kind,
        }
    }
}

fn validate_rewrites(ops: &[RewriteOp]) -> Result<(), InstrumenterError> {
    let replacements = ops
        .iter()
        .filter_map(|op| match op {
            RewriteOp::Replace { byte_range, .. } => Some(byte_range.clone()),
            RewriteOp::Insert(_) => None,
        })
        .collect::<Vec<_>>();

    for pair in replacements.windows(2) {
        let first = &pair[0];
        let second = &pair[1];
        if first.end > second.start {
            return Err(InstrumenterError::OverlappingRewrites {
                first_start: first.start,
                first_end: first.end,
                second_start: second.start,
                second_end: second.end,
            });
        }
    }

    for op in ops {
        let RewriteOp::Insert(insertion) = op else {
            continue;
        };
        for replacement in &replacements {
            if insertion.byte_offset > replacement.start && insertion.byte_offset < replacement.end
            {
                return Err(InstrumenterError::OverlappingRewrites {
                    first_start: replacement.start,
                    first_end: replacement.end,
                    second_start: insertion.byte_offset,
                    second_end: insertion.byte_offset,
                });
            }
        }
    }

    Ok(())
}

fn source_slice(source: &str, start: usize, end: usize) -> Result<&str, InstrumenterError> {
    source
        .get(start..end)
        .ok_or_else(|| InstrumenterError::AstSourceMismatch("source byte offsets".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{Insertion, InsertionKind, SourceRewriter};

    fn insertion(byte_offset: u32, text: &str) -> Insertion {
        Insertion {
            byte_offset,
            text: text.to_owned(),
            kind: InsertionKind::BreadcrumbBefore,
        }
    }

    #[test]
    fn rewriter_with_no_insertions_returns_original() {
        let rewritten = SourceRewriter::new("begin\nend;").apply().unwrap();

        assert_eq!(rewritten, "begin\nend;");
    }

    #[test]
    fn rewriter_inserts_text_at_byte_offset() {
        let mut rewriter = SourceRewriter::new("ab");
        rewriter.add_insertion(insertion(1, "X"));

        assert_eq!(rewriter.apply().unwrap(), "aXb");
    }

    #[test]
    fn rewriter_sorts_insertions_by_offset_when_added_out_of_order() {
        let mut rewriter = SourceRewriter::new("abcd");
        rewriter.add_insertion(insertion(3, "Y"));
        rewriter.add_insertion(insertion(1, "X"));

        assert_eq!(rewriter.apply().unwrap(), "aXbcYd");
    }

    #[test]
    fn rewriter_handles_multiple_insertions_at_same_offset() {
        let mut rewriter = SourceRewriter::new("ab");
        rewriter.add_insertion(insertion(1, "X"));
        rewriter.add_insertion(insertion(1, "Y"));

        assert_eq!(rewriter.apply().unwrap(), "aXYb");
    }

    #[test]
    fn rewriter_handles_insertion_at_end_of_source() {
        let mut rewriter = SourceRewriter::new("ab");
        rewriter.add_insertion(insertion(2, "X"));

        assert_eq!(rewriter.apply().unwrap(), "abX");
    }

    #[test]
    fn rewriter_with_replacement_substitutes_byte_range() {
        let mut rewriter = SourceRewriter::new("when others =>");
        rewriter.add_replacement(
            5..11,
            "AdaFuzz_E : others".to_owned(),
            InsertionKind::BindOccurrence,
        );

        assert_eq!(rewriter.apply().unwrap(), "when AdaFuzz_E : others =>");
    }

    #[test]
    fn rewriter_with_replacement_and_insertion_at_same_offset_preserves_order() {
        let mut rewriter = SourceRewriter::new("ab");
        rewriter.add_insertion(insertion(0, "X"));
        rewriter.add_replacement(0..1, "A".to_owned(), InsertionKind::BindOccurrence);

        assert_eq!(rewriter.apply().unwrap(), "XAb");
    }

    #[test]
    fn rewriter_detects_overlapping_replacements() {
        let mut rewriter = SourceRewriter::new("abcd");
        rewriter.add_replacement(0..2, "X".to_owned(), InsertionKind::BindOccurrence);
        rewriter.add_replacement(1..3, "Y".to_owned(), InsertionKind::BindOccurrence);

        let error = rewriter.apply().unwrap_err();

        assert!(error.to_string().contains("overlapping rewrites"));
    }

    #[test]
    fn rewriter_handles_replacement_at_end_of_source() {
        let mut rewriter = SourceRewriter::new("abcd");
        rewriter.add_replacement(2..4, "XY".to_owned(), InsertionKind::BindOccurrence);

        assert_eq!(rewriter.apply().unwrap(), "abXY");
    }

    #[test]
    fn line_map_with_no_insertions_is_identity() {
        let (_out, map) = SourceRewriter::new("a;\nb;\nc;\n")
            .apply_with_line_map()
            .unwrap();
        for line in 1..=4 {
            assert_eq!(map.to_original(line), line);
        }
    }

    #[test]
    fn line_map_accounts_for_inserted_breadcrumb_lines() {
        // Insert a one-newline breadcrumb before `b;` (byte offset 3) and before
        // `c;` (byte offset 6). Each insertion pushes the following original
        // line down by one in the instrumented output.
        let source = "a;\nb;\nc;\n";
        let mut rewriter = SourceRewriter::new(source);
        rewriter.add_insertion(insertion(3, "BC1;\n"));
        rewriter.add_insertion(insertion(6, "BC2;\n"));
        let (out, map) = rewriter.apply_with_line_map().unwrap();
        assert_eq!(out, "a;\nBC1;\nb;\nBC2;\nc;\n");
        // Instrumented: 1=a; 2=BC1; 3=b; 4=BC2; 5=c;
        // Original:     1=a;        2=b;        3=c;
        assert_eq!(map.to_original(1), 1); // a;
        assert_eq!(map.to_original(3), 2); // b;
        assert_eq!(map.to_original(5), 3); // c;
    }

    #[test]
    fn line_map_round_trips_through_anchors() {
        let mut rewriter = SourceRewriter::new("a;\nb;\nc;\n");
        rewriter.add_insertion(insertion(3, "BC1;\n"));
        let (_out, map) = rewriter.apply_with_line_map().unwrap();
        let rebuilt = super::LineMap::from_anchors(map.anchors().to_vec());
        assert_eq!(rebuilt.to_original(3), map.to_original(3));
        assert_eq!(rebuilt.to_original(1), 1);
    }
}
