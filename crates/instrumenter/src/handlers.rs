// SPDX-License-Identifier: Apache-2.0

use crate::breadcrumbs::leading_indent;
use crate::rewriter::{Insertion, InsertionKind, SourceRewriter};
use crate::InstrumenterError;
use ada_parser::ast::{Choice, ExceptionHandler, StructuralAst};
use std::path::Path;

const DEFAULT_BINDING: &str = "AdaFuzz_E";

pub fn collect_handler_rewrites(
    ast: &StructuralAst,
    source: &str,
    source_path: &Path,
    rewriter: &mut SourceRewriter<'_>,
) -> Result<usize, InstrumenterError> {
    let mut inserted = 0usize;
    for handler in &ast.handlers {
        if !valid_handler_span(source, handler) {
            continue;
        }

        let binding = binding_name(source, handler);
        if handler.binds.is_none() {
            if let Some(byte_offset) = binding_insertion_offset(source, handler) {
                rewriter.add_insertion(Insertion {
                    byte_offset,
                    text: format!("{DEFAULT_BINDING} : "),
                    kind: InsertionKind::BindOccurrence,
                });
            }
        }

        rewriter.add_insertion(Insertion {
            byte_offset: handler.body_span.start_byte,
            text: handler_probe_text(source, source_path, handler, &binding)?,
            kind: InsertionKind::HandlerProbe,
        });
        inserted = inserted.saturating_add(1);
    }

    Ok(inserted)
}

fn valid_handler_span(source: &str, handler: &ExceptionHandler) -> bool {
    if handler.span.start_byte >= handler.span.end_byte
        || handler.body_span.start_byte >= handler.body_span.end_byte
    {
        return false;
    }

    let span_start = handler.span.start_byte as usize;
    let span_end = handler.span.end_byte as usize;
    let body_start = handler.body_span.start_byte as usize;
    let body_end = handler.body_span.end_byte as usize;

    body_start <= source.len()
        && body_end <= source.len()
        && span_start <= source.len()
        && span_end <= source.len()
        && source.is_char_boundary(span_start)
        && source.is_char_boundary(span_end)
        && source.is_char_boundary(body_start)
        && source.is_char_boundary(body_end)
}

fn binding_name(source: &str, handler: &ExceptionHandler) -> String {
    if handler.binds.is_some() {
        if let Some(binding) = existing_binding_text(source, handler) {
            return binding;
        }
    }

    DEFAULT_BINDING.to_owned()
}

fn existing_binding_text(source: &str, handler: &ExceptionHandler) -> Option<String> {
    let start = handler.span.start_byte as usize;
    let body_start = handler.body_span.start_byte as usize;
    let head = source.get(start..body_start)?;
    let when_index = find_ascii_case_insensitive(head, "when")?;
    let mut cursor = when_index + "when".len();
    let bytes = head.as_bytes();
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor = cursor.saturating_add(1);
    }
    let ident_start = cursor;
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        cursor = cursor.saturating_add(1);
    }
    let candidate = head.get(ident_start..cursor)?;
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor = cursor.saturating_add(1);
    }
    if bytes.get(cursor) == Some(&b':') {
        Some(candidate.to_owned())
    } else {
        None
    }
}

fn binding_insertion_offset(source: &str, handler: &ExceptionHandler) -> Option<u32> {
    let start = handler.span.start_byte as usize;
    let body_start = handler.body_span.start_byte as usize;
    let head = source.get(start..body_start)?;
    let when_index = find_ascii_case_insensitive(head, "when")?;
    let mut offset = start + when_index + "when".len();

    while source
        .as_bytes()
        .get(offset)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        offset = offset.saturating_add(1);
    }

    u32::try_from(offset).ok()
}

fn handler_probe_text(
    source: &str,
    source_path: &Path,
    handler: &ExceptionHandler,
    binding: &str,
) -> Result<String, InstrumenterError> {
    let file_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| InstrumenterError::NonUtf8Path(source_path.to_path_buf()))?;
    let indent = leading_indent(source, handler.body_span.start_byte);
    let exception_name = exception_name_expr(&handler.choices, binding);

    Ok(format!(
        "AdaFuzz.Probe.On_Handler_Entry\n\
{indent}  (Exception_Name    => {exception_name},\n\
{indent}   Exception_Message => Ada.Exceptions.Exception_Message ({binding}),\n\
{indent}   Handler_File      => \"{}\",\n\
{indent}   Handler_Line      => {},\n\
{indent}   Last_Breadcrumb   => AdaFuzz.Probe.Last_Breadcrumb,\n\
{indent}   Target_Id         => AdaFuzz.Probe.Current_Target,\n\
{indent}   Testcase_Id       => AdaFuzz.Probe.Current_Testcase);\n\
{indent}",
        ada_string_literal_text(file_name),
        handler.span.start_line
    ))
}

fn exception_name_expr(choices: &[Choice], binding: &str) -> String {
    if choices.len() == 1 && !choices[0].0.eq_ignore_ascii_case("others") {
        return format!("\"{}\"", choices[0].0.to_ascii_uppercase());
    }

    format!("Ada.Exceptions.Exception_Name ({binding})")
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
    use super::collect_handler_rewrites;
    use crate::rewriter::SourceRewriter;
    use std::path::Path;

    fn rewrite(source: &str) -> String {
        let path = Path::new("src.adb");
        let ast = ada_parser::reconcile::build_structural_ast(source, None, path).unwrap();
        let mut rewriter = SourceRewriter::new(source);
        collect_handler_rewrites(&ast, source, path, &mut rewriter).unwrap();
        rewriter.apply().unwrap()
    }

    #[test]
    fn handler_with_no_binding_introduces_adafuzz_e() {
        let rewritten =
            rewrite("procedure P is begin A; exception when Constraint_Error => return; end P;");

        assert!(rewritten.contains("when AdaFuzz_E : Constraint_Error =>"));
    }

    #[test]
    fn handler_with_existing_binding_keeps_user_name_and_uses_it() {
        let rewritten =
            rewrite("procedure P is begin A; exception when E : others => return; end P;");

        assert!(rewritten.contains("when E : others =>"));
        assert!(rewritten.contains("Exception_Message => Ada.Exceptions.Exception_Message (E)"));
    }

    #[test]
    fn handler_for_single_named_choice_emits_uppercase_string_literal() {
        let rewritten =
            rewrite("procedure P is begin A; exception when Constraint_Error => return; end P;");

        assert!(rewritten.contains("Exception_Name    => \"CONSTRAINT_ERROR\""));
    }

    #[test]
    fn handler_for_others_uses_dynamic_exception_name() {
        let rewritten = rewrite("procedure P is begin A; exception when others => return; end P;");

        assert!(
            rewritten.contains("Exception_Name    => Ada.Exceptions.Exception_Name (AdaFuzz_E)")
        );
    }

    #[test]
    fn handler_for_multi_choice_uses_dynamic_exception_name() {
        let rewritten = rewrite(
            "procedure P is begin A; exception when Constraint_Error | Program_Error => return; end P;",
        );

        assert!(
            rewritten.contains("Exception_Name    => Ada.Exceptions.Exception_Name (AdaFuzz_E)")
        );
    }

    #[test]
    fn handler_probe_inserted_as_first_statement_of_body() {
        let rewritten = rewrite(
            "procedure P is\nbegin\n   A;\nexception\n   when others =>\n      return;\nend P;",
        );
        let probe_index = rewritten.find("AdaFuzz.Probe.On_Handler_Entry").unwrap();
        let return_index = rewritten.find("return;").unwrap();

        assert!(probe_index < return_index);
    }

    #[test]
    fn handler_probe_includes_file_basename() {
        let rewritten = rewrite("procedure P is begin A; exception when others => return; end P;");

        assert!(rewritten.contains("Handler_File      => \"src.adb\""));
    }

    #[test]
    fn handler_probe_includes_handler_line_number() {
        let rewritten = rewrite(
            "procedure P is\nbegin\n   A;\nexception\n   when others =>\n      return;\nend P;",
        );

        assert!(rewritten.contains("Handler_Line      => 5"));
    }
}
