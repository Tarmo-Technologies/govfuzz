// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::{StatementSpan, StructuralAst, Subprogram};

pub fn breadcrumb_injection_safe(
    source: &str,
    statement: &StatementSpan,
    _ast: &StructuralAst,
) -> bool {
    if statement.file_byte_offset >= statement.end_byte_offset {
        return false;
    }
    let start = statement.file_byte_offset as usize;
    let end = statement.end_byte_offset as usize;
    if end > source.len() || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return false;
    }

    // A "statement" whose start token is `begin` is a block's begin keyword, not a
    // real statement. Inserting a breadcrumb there lands in the DECLARATIVE part of
    // a `declare … begin … end` block ("declaration expected"), failing the build.
    // Skip it — the statements INSIDE the block are still instrumented, so coverage
    // is preserved. (Seen on a generated Ada encode harness: a `declare … begin`
    // block nested in a `return … do … end return` extended return.)
    if keyword_at(source, statement.file_byte_offset, "begin") {
        return false;
    }

    !inside_pragma_argument_list(source, statement.file_byte_offset)
}

/// True when the token at `offset` (after any leading blanks) is the Ada keyword
/// `keyword`, delimited by a non-identifier char. Ada keywords are
/// case-insensitive.
fn keyword_at(source: &str, offset: u32, keyword: &str) -> bool {
    let Some(rest) = source.get(offset as usize..).map(str::trim_start) else {
        return false;
    };
    let Some(head) = rest.get(..keyword.len()) else {
        return false;
    };
    head.eq_ignore_ascii_case(keyword)
        && rest[keyword.len()..]
            .chars()
            .next()
            .is_none_or(|ch| !ch.is_alphanumeric() && ch != '_')
}

pub fn is_expression_function(subprogram: &Subprogram, source: &str) -> bool {
    let Some(body_span) = subprogram.body_span else {
        return false;
    };
    let start = body_span.start_byte as usize;
    let end = body_span.end_byte as usize;
    let Some(body_text) = source.get(start..end) else {
        return false;
    };
    let lower = body_text.to_ascii_lowercase();
    if lower.contains("begin") {
        return false;
    }
    let Some(is_index) = find_ascii_keyword(body_text, "is") else {
        return false;
    };

    body_text[is_index + "is".len()..]
        .trim_start()
        .starts_with('(')
}

pub fn between_label_and_statement(source: &str, offset: u32) -> bool {
    label_start_offset(source, offset).is_some()
}

pub fn label_start_offset(source: &str, offset: u32) -> Option<u32> {
    let offset = offset as usize;
    let prefix = source.get(..offset)?;
    let line_start = prefix
        .rfind('\n')
        .map_or(0, |index| index.saturating_add(1));
    let line_prefix = &prefix[line_start..];
    let trimmed_end = line_prefix.trim_end();
    if !trimmed_end.ends_with(':') {
        return None;
    }

    let before_colon = trimmed_end[..trimmed_end.len().saturating_sub(1)].trim_end();
    let ident_end = before_colon.len();
    let ident_start = before_colon
        .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .map_or(0, |index| index.saturating_add(1));
    if ident_start == ident_end {
        return None;
    }

    u32::try_from(line_start + ident_start).ok()
}

fn inside_pragma_argument_list(source: &str, offset: u32) -> bool {
    let offset = offset as usize;
    let Some(prefix) = source.get(..offset) else {
        return false;
    };
    let line_start = prefix
        .rfind('\n')
        .map_or(0, |index| index.saturating_add(1));
    let line_prefix = &prefix[line_start..];
    let lower = line_prefix.to_ascii_lowercase();
    let Some(pragma_index) = lower.find("pragma") else {
        return false;
    };
    let after_pragma = &lower[pragma_index..];

    after_pragma.contains('(') && !after_pragma.contains(')') && !after_pragma.contains(';')
}

fn find_ascii_keyword(haystack: &str, keyword: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(keyword.len())
        .enumerate()
        .find_map(|(index, window)| {
            if !window.eq_ignore_ascii_case(keyword.as_bytes()) {
                return None;
            }
            let before = index
                .checked_sub(1)
                .and_then(|previous| haystack.as_bytes().get(previous));
            let after = haystack.as_bytes().get(index + keyword.len());
            if before.is_some_and(is_identifier_byte) || after.is_some_and(is_identifier_byte) {
                None
            } else {
                Some(index)
            }
        })
}

fn is_identifier_byte(byte: &u8) -> bool {
    byte.is_ascii_alphanumeric() || *byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::{
        between_label_and_statement, breadcrumb_injection_safe, is_expression_function,
        label_start_offset,
    };
    use ada_parser::ast::{StatementId, StatementOwner, StatementSpan, StructuralAst};
    use std::path::Path;

    fn statement(offset: u32) -> StatementSpan {
        StatementSpan {
            id: StatementId(0),
            owner: StatementOwner::Subprogram(ada_parser::ast::SubprogramId(0)),
            file_byte_offset: offset,
            end_byte_offset: offset + 2,
            line: 1,
            col: 1,
            depth: 0,
            index_in_block: 0,
        }
    }

    #[test]
    fn breadcrumb_safe_for_normal_top_level_statement() {
        let source = "begin\n   A;\nend;";
        let ast = StructuralAst::new();
        let statement = statement(9);

        assert!(breadcrumb_injection_safe(source, &statement, &ast));
    }

    #[test]
    fn breadcrumb_unsafe_when_statement_starts_on_block_begin() {
        // A `declare … begin … end` block whose "statement" start lands on the
        // block's `begin` keyword: a breadcrumb there sits in the declarative part
        // (after the nested `end P;`), which is illegal Ada ("declaration
        // expected"). The guard must reject it.
        let source = "declare\n   procedure P is begin null; end P;\nbegin\n   A;\nend;";
        let begin_off = source.rfind("begin\n").unwrap() as u32;
        let ast = StructuralAst::new();
        assert!(!breadcrumb_injection_safe(
            source,
            &statement(begin_off),
            &ast
        ));
        // Case-insensitive: `BEGIN` is the same keyword.
        let upper = source.replace("begin\n", "BEGIN\n");
        let upper_off = upper.rfind("BEGIN\n").unwrap() as u32;
        assert!(!breadcrumb_injection_safe(
            &upper,
            &statement(upper_off),
            &ast
        ));
    }

    #[test]
    fn breadcrumb_unsafe_inside_pragma_argument_list() {
        let source = "pragma Assert (X);\n";
        let ast = StructuralAst::new();
        let statement = statement(source.find('X').unwrap() as u32);

        assert!(!breadcrumb_injection_safe(source, &statement, &ast));
    }

    #[test]
    fn is_expression_function_detects_paren_body_at_2012() {
        let source = "pragma Ada_2012;\nfunction Is_Zero (X : Integer) return Boolean is (X = 0);";
        let ast =
            ada_parser::reconcile::build_structural_ast(source, None, Path::new("p.ads")).unwrap();

        assert!(is_expression_function(&ast.subprograms[0], source));
    }

    #[test]
    fn is_expression_function_returns_false_for_normal_function() {
        let source = "function F return Integer is begin return 1; end F;";
        let ast =
            ada_parser::reconcile::build_structural_ast(source, None, Path::new("p.adb")).unwrap();

        assert!(!is_expression_function(&ast.subprograms[0], source));
    }

    #[test]
    fn between_label_and_statement_detects_label_pattern() {
        let source = "begin\n   Retry : A;\nend;";
        let offset = source.find('A').unwrap() as u32;

        assert!(between_label_and_statement(source, offset));
    }

    #[test]
    fn between_label_and_statement_false_for_unlabeled_statement() {
        let source = "begin\n   A;\nend;";
        let offset = source.find('A').unwrap() as u32;

        assert!(!between_label_and_statement(source, offset));
    }

    #[test]
    fn label_start_offset_returns_label_identifier_offset() {
        let source = "begin\n   Retry : A;\nend;";
        let offset = source.find('A').unwrap() as u32;

        assert_eq!(
            label_start_offset(source, offset),
            source.find("Retry").map(|item| item as u32)
        );
    }
}
