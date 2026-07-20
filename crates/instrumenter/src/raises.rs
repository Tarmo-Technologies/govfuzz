// SPDX-License-Identifier: Apache-2.0

use crate::breadcrumbs::leading_indent;
use crate::rewriter::{Insertion, InsertionKind, SourceRewriter};
use crate::InstrumenterError;
use ada_parser::ast::{RaiseKind, RaiseSite, StructuralAst};
use std::path::Path;

pub fn collect_raise_insertions(
    ast: &StructuralAst,
    source: &str,
    source_path: &Path,
    rewriter: &mut SourceRewriter<'_>,
) -> Result<usize, InstrumenterError> {
    let mut inserted = 0usize;
    for raise in &ast.raises {
        if !valid_raise_span(source, raise) {
            continue;
        }
        if !is_raise_statement(ast, source, raise) {
            // Ada 2012 permits `raise` anywhere an expression is accepted,
            // including a conditional arm (`if Bad then raise E else Value`).
            // A textual check for a preceding `(` misses those forms. Only a
            // raise whose byte offset is one of the parser's statement starts
            // can safely receive a statement-form probe.
            continue;
        }

        rewriter.add_insertion(Insertion {
            byte_offset: raise.span.start_byte,
            text: raise_probe_text(source, source_path, raise)?,
            kind: InsertionKind::RaiseProbe,
        });
        inserted = inserted.saturating_add(1);
    }

    Ok(inserted)
}

fn is_raise_statement(ast: &StructuralAst, source: &str, raise: &RaiseSite) -> bool {
    ada_parser::raise_is_statement(source, raise.span.start_byte).unwrap_or_else(|| {
        raise.kind == RaiseKind::Reraise
            || ast
                .statements
                .iter()
                .any(|statement| statement.file_byte_offset == raise.span.start_byte)
    })
}

fn valid_raise_span(source: &str, raise: &RaiseSite) -> bool {
    if raise.span.start_byte >= raise.span.end_byte {
        return false;
    }

    let start = raise.span.start_byte as usize;
    let end = raise.span.end_byte as usize;
    end <= source.len() && source.is_char_boundary(start) && source.is_char_boundary(end)
}

fn raise_probe_text(
    source: &str,
    source_path: &Path,
    raise: &RaiseSite,
) -> Result<String, InstrumenterError> {
    let file_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| InstrumenterError::NonUtf8Path(source_path.to_path_buf()))?;
    let indent = leading_indent(source, raise.span.start_byte);
    let exception_name = raise_exception_name(source, raise);

    Ok(format!(
        "AdaFuzz.Probe.On_Explicit_Raise\n\
{indent}  (Exception_Name => \"{}\",\n\
{indent}   File           => \"{}\",\n\
{indent}   Line           => {},\n\
{indent}   Breadcrumb     => AdaFuzz.Probe.Last_Breadcrumb);\n\
{indent}",
        ada_string_literal_text(&exception_name),
        ada_string_literal_text(file_name),
        raise.span.start_line
    ))
}

fn raise_exception_name(source: &str, raise: &RaiseSite) -> String {
    if raise.kind == RaiseKind::Reraise {
        return "<reraise>".to_owned();
    }

    raise_exception_text(source, raise)
        .or_else(|| raise.exception.clone())
        .unwrap_or_else(|| "<unknown>".to_owned())
}

fn raise_exception_text(source: &str, raise: &RaiseSite) -> Option<String> {
    let start = raise.span.start_byte as usize;
    let end = raise.span.end_byte as usize;
    let text = source.get(start..end)?;
    let raise_index = find_ascii_case_insensitive(text, "raise")?;
    let mut cursor = raise_index + "raise".len();
    let bytes = text.as_bytes();

    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor = cursor.saturating_add(1);
    }

    let name_start = cursor;
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.'))
    {
        cursor = cursor.saturating_add(1);
    }

    if cursor == name_start {
        None
    } else {
        text.get(name_start..cursor).map(ToOwned::to_owned)
    }
}

fn ada_string_literal_text(text: &str) -> String {
    text.replace('"', "\"\"")
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::collect_raise_insertions;
    use crate::rewriter::SourceRewriter;
    use std::path::Path;

    fn rewrite(source: &str) -> String {
        let path = Path::new("src.adb");
        let ast = ada_parser::reconcile::build_structural_ast(source, None, path).unwrap();
        let mut rewriter = SourceRewriter::new(source);
        collect_raise_insertions(&ast, source, path, &mut rewriter).unwrap();
        rewriter.apply().unwrap()
    }

    #[test]
    fn raise_expression_in_expression_function_is_not_instrumented() {
        // An Ada 2012 raise *expression* (expression function body). Injecting a
        // statement-form probe here corrupts the source ("missing )").
        let source = "package body P is\n\
            \x20  function F (X : Integer) return Integer is (raise Constraint_Error with \"bad\");\n\
            end P;\n";
        let out = rewrite(source);
        assert_eq!(
            out, source,
            "raise expression must be left untouched:\n{out}"
        );
        assert!(!out.contains("On_Explicit_Raise"));
    }

    #[test]
    fn raise_in_conditional_expression_is_not_instrumented() {
        let source = "package P is\n\
            \x20  function F (Bad : Boolean) return Natural is\n\
            \x20    (if Bad then raise Constraint_Error else 1);\n\
            end P;\n";
        let out = rewrite(source);
        assert_eq!(out, source, "conditional raise expression was corrupted");
        assert!(!out.contains("On_Explicit_Raise"));
    }

    #[test]
    fn raise_statement_is_still_instrumented_alongside_a_raise_expression() {
        let source = "package body P is\n\
            \x20  function F return Integer is (raise Program_Error);\n\
            \x20  procedure G is\n   begin\n      raise Constraint_Error;\n   end G;\n\
            end P;\n";
        let out = rewrite(source);
        assert!(
            out.contains("On_Explicit_Raise"),
            "the raise statement must still be instrumented: {out}"
        );
        assert!(
            out.contains("is (raise Program_Error)"),
            "the raise expression must remain intact: {out}"
        );
    }

    #[test]
    fn nested_raise_statement_is_instrumented() {
        let source = "procedure P is\nbegin\n   if Bad then\n      raise Constraint_Error;\n   end if;\nend P;";
        let out = rewrite(source);

        assert!(
            out.contains("On_Explicit_Raise"),
            "nested raise was missed: {out}"
        );
    }

    #[test]
    fn explicit_raise_with_name_emits_probe_with_string_literal() {
        let rewritten = rewrite("procedure P is begin raise Constraint_Error; end P;");

        assert!(rewritten.contains("Exception_Name => \"Constraint_Error\""));
    }

    #[test]
    fn bare_reraise_inside_handler_emits_probe_with_reraise_name() {
        let rewritten = rewrite("procedure P is begin A; exception when others => raise; end P;");

        assert!(rewritten.contains("Exception_Name => \"<reraise>\""));
    }

    #[test]
    fn explicit_raise_with_message_at_2005_still_emits_probe_with_name_only() {
        let rewritten = rewrite(
            "pragma Ada_2005;\nprocedure P is begin raise Constraint_Error with \"bad\"; end P;",
        );

        assert!(rewritten.contains("Exception_Name => \"Constraint_Error\""));
        assert!(!rewritten.contains("Exception_Name => \"Constraint_Error with \"\"bad\"\"\""));
    }

    #[test]
    fn raise_probe_inserted_before_raise_statement() {
        let rewritten = rewrite("procedure P is\nbegin\n   raise Constraint_Error;\nend P;");
        let probe_index = rewritten.find("AdaFuzz.Probe.On_Explicit_Raise").unwrap();
        let raise_index = rewritten.find("raise Constraint_Error;").unwrap();

        assert!(probe_index < raise_index);
    }

    #[test]
    fn raise_probe_indentation_matches_source_line() {
        let rewritten = rewrite("procedure P is\nbegin\n      raise Constraint_Error;\nend P;");

        assert!(rewritten
            .contains("\n      AdaFuzz.Probe.On_Explicit_Raise\n        (Exception_Name =>"));
    }
}
