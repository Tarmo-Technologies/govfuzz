// SPDX-License-Identifier: Apache-2.0

use crate::error::InstrumenterError;
use crate::rewriter::{Insertion, InsertionKind, SourceRewriter};
use ada_parser::ast::{StructuralAst, Unit};
use ada_parser::lexer::{Token, TokenKind};

const ADAFUZZ_PROBE_WITH: &str = "AdaFuzz.Probe";
const ADA_EXCEPTIONS_WITH: &str = "Ada.Exceptions";

pub fn library_item_offset(_source: &str, tokens: &[Token]) -> Option<u32> {
    let mut index = 0usize;
    while let Some(token) = tokens.get(index) {
        match &token.effective_kind {
            TokenKind::Comment(_) => index = index.saturating_add(1),
            TokenKind::KwPragma | TokenKind::KwWith | TokenKind::KwUse => {
                index = token_after_semicolon(tokens, index)?;
            }
            TokenKind::Eof => return None,
            _ => return Some(token.text_span.start),
        }
    }

    None
}

pub fn missing_with_clauses(
    unit: &Unit,
    needs_probe: bool,
    needs_ada_exceptions: bool,
) -> Vec<String> {
    let mut clauses = Vec::new();
    if needs_probe && !has_with(unit, ADAFUZZ_PROBE_WITH) {
        clauses.push(ADAFUZZ_PROBE_WITH.to_owned());
    }
    if needs_ada_exceptions && !has_with(unit, ADA_EXCEPTIONS_WITH) {
        clauses.push(ADA_EXCEPTIONS_WITH.to_owned());
    }

    clauses
}

pub fn collect_context_clause_insertions(
    source: &str,
    ast: &StructuralAst,
    tokens: &[Token],
    needs_probe: bool,
    needs_ada_exceptions: bool,
    rewriter: &mut SourceRewriter<'_>,
) -> Result<(), InstrumenterError> {
    if !needs_probe && !needs_ada_exceptions {
        return Ok(());
    }

    let Some(unit) = ast.units.first() else {
        return Ok(());
    };
    let missing = missing_with_clauses(unit, needs_probe, needs_ada_exceptions);
    if missing.is_empty() {
        return Ok(());
    }
    let Some(byte_offset) = library_item_offset(source, tokens) else {
        return Ok(());
    };

    let text = missing
        .into_iter()
        .map(|name| format!("with {name};\n"))
        .collect::<String>();
    rewriter.add_insertion(Insertion {
        byte_offset,
        text,
        kind: InsertionKind::ContextClause,
    });

    Ok(())
}

fn has_with(unit: &Unit, name: &str) -> bool {
    unit.withs
        .iter()
        .any(|unit_ref| unit_ref.name.eq_ignore_ascii_case(name))
}

fn token_after_semicolon(tokens: &[Token], mut index: usize) -> Option<usize> {
    while let Some(token) = tokens.get(index) {
        if token.effective_kind == TokenKind::Semicolon {
            return Some(index.saturating_add(1));
        }
        if token.effective_kind == TokenKind::Eof {
            return None;
        }
        index = index.saturating_add(1);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{collect_context_clause_insertions, library_item_offset, missing_with_clauses};
    use crate::rewriter::SourceRewriter;
    use crate::{instrument_unit, InstrumentArgs};
    use ada_parser::ast::{AdaStandard, StructuralAst};
    use ada_parser::lexer::{lex, Token, TokenKind};
    use std::path::Path;

    #[test]
    fn breadcrumb_only_unit_adds_with_adafuzz_probe() {
        let result = instrument("procedure P is begin A; end P;");

        assert!(result.contains("with AdaFuzz.Probe;\nprocedure P is"));
        assert!(!result.contains("with Ada.Exceptions;"));
    }

    #[test]
    fn handler_unit_adds_with_adafuzz_probe_and_ada_exceptions() {
        let result =
            instrument("procedure P is begin A; exception when Constraint_Error => return; end P;");

        assert!(result.contains("with AdaFuzz.Probe;\n"));
        assert!(result.contains("with Ada.Exceptions;\n"));
    }

    #[test]
    fn existing_with_adafuzz_probe_is_not_duplicated() {
        let result = instrument("with AdaFuzz.Probe;\nprocedure P is begin A; end P;");

        assert_eq!(result.matches("with AdaFuzz.Probe;").count(), 1);
    }

    #[test]
    fn existing_with_ada_exceptions_is_not_duplicated() {
        let result = instrument(
            "with Ada.Exceptions;\nprocedure P is begin A; exception when others => return; end P;",
        );

        assert_eq!(result.matches("with Ada.Exceptions;").count(), 1);
    }

    #[test]
    fn case_insensitive_match_for_existing_with() {
        let result = instrument(
            "with adafuzz.probe;\nwith ada.exceptions;\nprocedure P is begin A; exception when others => return; end P;",
        );

        assert_eq!(result.matches("with adafuzz.probe;").count(), 1);
        assert_eq!(result.matches("with ada.exceptions;").count(), 1);
        assert!(!result.contains("with AdaFuzz.Probe;"));
        assert!(!result.contains("with Ada.Exceptions;"));
    }

    #[test]
    fn library_item_offset_skips_leading_configuration_pragma() {
        let source = "pragma Ada_95;\npackage body P is begin null; end P;";
        let offset = library_item_offset(source, &tokens(source)).unwrap();

        assert!(source[offset as usize..].starts_with("package body"));
    }

    #[test]
    fn library_item_offset_after_existing_with_clauses() {
        let source = "with Ada.Text_IO;\nuse Ada.Text_IO;\npackage body P is begin null; end P;";
        let offset = library_item_offset(source, &tokens(source)).unwrap();

        assert!(source[offset as usize..].starts_with("package body"));
    }

    #[test]
    fn instrumented_swallowed_ce_compiles_through_ada_parser_with_new_withs() {
        let source =
            include_str!("../../ada_parser/tests/golden/ada95/swallowed_constraint_error/src.adb");
        let path = Path::new("src.adb");
        let ast = ast_for(source);

        let result = instrument_unit(InstrumentArgs {
            source,
            ast: &ast,
            source_path: path,
        })
        .unwrap();

        assert!(result.rewritten_source.contains("with AdaFuzz.Probe;"));
        assert!(result.rewritten_source.contains("with Ada.Exceptions;"));
        ada_parser::reconcile::build_structural_ast(&result.rewritten_source, None, path).unwrap();
    }

    #[test]
    fn missing_with_clauses_uses_existing_unit_withs_case_insensitively() {
        let source = "with adafuzz.probe;\nprocedure P is begin null; end P;";
        let ast = ast_for(source);
        let unit = ast.units.first().unwrap();

        assert_eq!(
            missing_with_clauses(unit, true, true),
            vec!["Ada.Exceptions".to_owned()]
        );
    }

    #[test]
    fn collect_context_clause_insertions_inserts_before_library_item() {
        let source = "pragma Ada_95;\nprocedure P is begin null; end P;";
        let ast = ast_for(source);
        let mut rewriter = SourceRewriter::new(source);

        collect_context_clause_insertions(
            source,
            &ast,
            &tokens(source),
            true,
            false,
            &mut rewriter,
        )
        .unwrap();

        assert_eq!(
            rewriter.apply().unwrap(),
            "pragma Ada_95;\nwith AdaFuzz.Probe;\nprocedure P is begin null; end P;"
        );
    }

    fn instrument(source: &str) -> String {
        let ast = ast_for(source);
        instrument_unit(InstrumentArgs {
            source,
            ast: &ast,
            source_path: Path::new("src.adb"),
        })
        .unwrap()
        .rewritten_source
    }

    fn ast_for(source: &str) -> StructuralAst {
        ada_parser::reconcile::build_structural_ast(source, None, Path::new("src.adb")).unwrap()
    }

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2022)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }
}
