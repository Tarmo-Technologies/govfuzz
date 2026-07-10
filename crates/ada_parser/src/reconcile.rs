// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    AdaStandard, ExceptionHandler, HandlerOwner, Package, PackageId, RaiseSite, Span,
    StructuralAst, Subprogram, TypeOwner, Unit, UnitId, UnitKind, UnitRef,
};
use crate::extract::{
    build_scope_tree, extract_constants, extract_handlers, extract_packages, extract_raises,
    extract_representation_clauses, extract_statements, extract_subprograms, extract_types,
    extract_unit_pragmas, extract_use_clauses,
};
use crate::lexer::{lex, Token, TokenKind};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScanError {
    #[error("{0}")]
    Other(String),
}

pub fn build_structural_ast(
    source: &str,
    dialect_hint: Option<AdaStandard>,
    path: &Path,
) -> Result<StructuralAst, ScanError> {
    let _tree = crate::parse_with_tree_sitter(source)
        .ok_or_else(|| ScanError::Other("tree-sitter Ada parse failed".to_owned()))?;
    // Phase 2 will reconcile tree-sitter node spans against lexer byte offsets here.

    let probe_tokens = significant_tokens(lex(source, AdaStandard::Ada2022));
    let ada_standard = detect_ada_standard(&probe_tokens, dialect_hint)?;
    let unit_tokens = significant_tokens(lex(source, ada_standard));
    let kind = detect_unit_kind(&unit_tokens, path);
    let withs = extract_with_clauses(source, &unit_tokens);
    let uses = extract_use_clauses(source, &unit_tokens);
    let scope_tree = build_scope_tree(&unit_tokens);
    let packages = extract_packages(&scope_tree, source, &unit_tokens);
    let package_ids = packages.iter().map(|package| package.id).collect();
    let mut subprograms = extract_subprograms(&scope_tree, source, &unit_tokens, ada_standard);
    let handlers = extract_handlers(&scope_tree, &packages, &subprograms, source, &unit_tokens);
    let raises = extract_raises(
        &scope_tree,
        &subprograms,
        &handlers,
        source,
        &unit_tokens,
        ada_standard,
    );
    let statements = extract_statements(&scope_tree, source, &unit_tokens, &subprograms, &packages);
    let pragmas = extract_unit_pragmas(source, &unit_tokens);
    let constants = extract_constants(&scope_tree, source, &unit_tokens);
    let mut types = extract_types(&scope_tree, source, &unit_tokens, ada_standard);
    for clause in extract_representation_clauses(source, &unit_tokens) {
        let scoped_match = types.iter().position(|item| {
            type_name_matches(item, &clause.target_name)
                && type_owner_contains_byte(
                    &item.owner,
                    clause.byte_offset,
                    &scope_tree,
                    &packages,
                    &subprograms,
                )
        });
        let fallback_match = scoped_match.or_else(|| {
            types
                .iter()
                .position(|item| type_name_matches(item, &clause.target_name))
        });

        if let Some(type_index) = fallback_match {
            types[type_index].aspects.0.push(clause.clause_text);
        }
    }
    link_subprogram_handlers(&mut subprograms, &handlers);
    link_subprogram_raises(&mut subprograms, &raises);

    let mut ast = StructuralAst::new();
    ast.units.push(Unit {
        id: UnitId(0),
        path: path.to_path_buf(),
        kind,
        ada_standard,
        withs,
        uses,
        packages: package_ids,
        pragmas,
    });
    ast.packages = packages;
    ast.subprograms = subprograms;
    ast.types = types;
    ast.constants = constants;
    ast.handlers = handlers;
    ast.raises = raises;
    ast.statements = statements;

    Ok(ast)
}

fn link_subprogram_handlers(subprograms: &mut [Subprogram], handlers: &[ExceptionHandler]) {
    for subprogram in subprograms {
        subprogram.handlers = handlers
            .iter()
            .filter(|handler| {
                matches!(
                    &handler.owner,
                    HandlerOwner::Subprogram(id) if *id == subprogram.id
                )
            })
            .map(|handler| handler.id)
            .collect();
    }
}

fn link_subprogram_raises(subprograms: &mut [Subprogram], raises: &[RaiseSite]) {
    for raise in raises {
        if let Some(owner_index) = innermost_subprogram_for_span(subprograms, raise.span) {
            subprograms[owner_index].raises.push(raise.id);
        }
    }
}

fn innermost_subprogram_for_span(subprograms: &[Subprogram], span: Span) -> Option<usize> {
    subprograms
        .iter()
        .enumerate()
        .filter_map(|(index, subprogram)| {
            let body_span = subprogram.body_span?;
            if span_contains_byte(body_span, span.start_byte) {
                Some((
                    index,
                    body_span.end_byte.saturating_sub(body_span.start_byte),
                ))
            } else {
                None
            }
        })
        .min_by_key(|(_, len)| *len)
        .map(|(index, _)| index)
}

fn type_name_matches(type_ref: &crate::ast::TypeRef, target_name: &str) -> bool {
    type_ref
        .name_path
        .last()
        .is_some_and(|name| name == target_name)
}

fn type_owner_contains_byte(
    owner: &TypeOwner,
    byte_offset: u32,
    scope_tree: &crate::extract::ScopeTree,
    packages: &[Package],
    subprograms: &[Subprogram],
) -> bool {
    match owner {
        TypeOwner::LibraryLevel => false,
        TypeOwner::Package(package_id) => {
            package_contains_byte(*package_id, byte_offset, scope_tree, packages)
        }
        TypeOwner::Subprogram(subprogram_id) => subprograms
            .iter()
            .find(|subprogram| subprogram.id == *subprogram_id)
            .is_some_and(|subprogram| {
                let span = match subprogram.body_span {
                    Some(body_span) => body_span,
                    None => subprogram.decl_span,
                };
                span_contains_byte(span, byte_offset)
            }),
    }
}

fn package_contains_byte(
    package_id: PackageId,
    byte_offset: u32,
    scope_tree: &crate::extract::ScopeTree,
    packages: &[Package],
) -> bool {
    let Some(package) = packages.iter().find(|package| package.id == package_id) else {
        return false;
    };

    scope_tree.scopes.iter().any(|scope| {
        matches!(
            scope.kind,
            crate::extract::ScopeKind::PackageSpec | crate::extract::ScopeKind::PackageBody
        ) && scope.name == package.name
            && (scope
                .declarative_span
                .is_some_and(|span| span_contains_byte(span, byte_offset))
                || scope
                    .private_declarative_span
                    .is_some_and(|span| span_contains_byte(span, byte_offset)))
    })
}

fn span_contains_byte(span: Span, byte: u32) -> bool {
    byte >= span.start_byte && byte < span.end_byte
}

fn detect_ada_standard(
    tokens: &[Token],
    dialect_hint: Option<AdaStandard>,
) -> Result<AdaStandard, ScanError> {
    if let Some(pragma_standard) = detect_pragma_standard(tokens)? {
        return Ok(pragma_standard);
    }

    if contains_parallel_block(tokens) {
        return Ok(AdaStandard::Ada2022);
    }

    if contains_aspect_specification(tokens) {
        return Ok(AdaStandard::Ada2012);
    }

    if tokens
        .iter()
        .any(|token| token.effective_kind == TokenKind::KwInterface)
    {
        return Ok(AdaStandard::Ada2005);
    }

    Ok(dialect_hint.unwrap_or(AdaStandard::Ada2012))
}

fn detect_pragma_standard(tokens: &[Token]) -> Result<Option<AdaStandard>, ScanError> {
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index].effective_kind != TokenKind::KwPragma {
            index += 1;
            continue;
        }

        let mut pragma_index = index + 1;
        while pragma_index < tokens.len()
            && tokens[pragma_index].effective_kind != TokenKind::Semicolon
        {
            if let TokenKind::Identifier(name) = &tokens[pragma_index].effective_kind {
                match name.as_str() {
                    // M22: Ada 83 is accepted (best-effort), lexed with the
                    // reduced 83 keyword set and built with -gnat83. Legacy 83
                    // targets are discovered + reported on (report-only).
                    "ada_83" | "ada83" => return Ok(Some(AdaStandard::Ada83)),
                    "ada_95" | "ada95" => return Ok(Some(AdaStandard::Ada95)),
                    "ada_05" | "ada05" | "ada_2005" | "ada2005" => {
                        return Ok(Some(AdaStandard::Ada2005));
                    }
                    "ada_12" | "ada12" | "ada_2012" | "ada2012" => {
                        return Ok(Some(AdaStandard::Ada2012));
                    }
                    "ada_2022" | "ada2022" => return Ok(Some(AdaStandard::Ada2022)),
                    _ => {}
                }
            }
            pragma_index += 1;
        }

        index = pragma_index.saturating_add(1);
    }

    Ok(None)
}

fn contains_parallel_block(tokens: &[Token]) -> bool {
    tokens.windows(2).any(|window| {
        window[0].effective_kind == TokenKind::KwParallel
            && window[1].effective_kind == TokenKind::KwDo
    })
}

fn contains_aspect_specification(tokens: &[Token]) -> bool {
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index].effective_kind != TokenKind::KwWith {
            index += 1;
            continue;
        }

        let mut cursor = index + 1;
        let mut saw_identifier = false;
        while cursor < tokens.len() && tokens[cursor].effective_kind != TokenKind::Semicolon {
            match &tokens[cursor].effective_kind {
                TokenKind::Identifier(_) => saw_identifier = true,
                TokenKind::Arrow if saw_identifier => return true,
                _ => {}
            }
            cursor += 1;
        }

        index = cursor.saturating_add(1);
    }

    false
}

fn detect_unit_kind(tokens: &[Token], path: &Path) -> UnitKind {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);

    // .ads files are always specs in legal Ada — specs are never subunits.
    if extension.as_deref() == Some("ads") {
        return UnitKind::Spec;
    }

    // For bodies and unknown extensions, an opening `separate (...)` clause
    // makes this a subunit regardless of file extension. Subunits commonly
    // live in .adb files alongside ordinary bodies.
    if opens_with_separate(tokens) {
        return UnitKind::Subunit;
    }

    UnitKind::Body
}

fn opens_with_separate(tokens: &[Token]) -> bool {
    tokens
        .iter()
        .find(|token| token.effective_kind != TokenKind::Eof)
        .is_some_and(|token| token.effective_kind == TokenKind::KwSeparate)
}

fn extract_with_clauses(source: &str, tokens: &[Token]) -> Vec<UnitRef> {
    let mut withs = Vec::new();
    let mut index = 0;
    let mut paren_depth = 0u32;

    while index < tokens.len() {
        match tokens[index].effective_kind {
            TokenKind::LParen => {
                paren_depth += 1;
                index += 1;
            }
            TokenKind::RParen => {
                paren_depth = paren_depth.saturating_sub(1);
                index += 1;
            }
            ref kind if paren_depth == 0 && is_library_item_start(kind) => break,
            TokenKind::KwWith if paren_depth == 0 => {
                if let Some((mut units, next_index)) = parse_with_clause(source, tokens, index + 1)
                {
                    withs.append(&mut units);
                    index = next_index;
                } else {
                    index += 1;
                }
            }
            TokenKind::KwLimited
                if paren_depth == 0
                    && tokens
                        .get(index + 1)
                        .is_some_and(|token| token.effective_kind == TokenKind::KwWith) =>
            {
                if let Some((mut units, next_index)) = parse_with_clause(source, tokens, index + 2)
                {
                    withs.append(&mut units);
                    index = next_index;
                } else {
                    index += 1;
                }
            }
            _ => index += 1,
        }
    }

    withs
}

fn is_library_item_start(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::KwGeneric
            | TokenKind::KwPackage
            | TokenKind::KwProcedure
            | TokenKind::KwFunction
            | TokenKind::KwSeparate
            | TokenKind::KwProtected
            | TokenKind::KwTask
    )
}

/// Parse the body of a `with` (or `limited with`) clause: one or more
/// dotted unit names separated by commas and terminated by a semicolon.
/// Returns the collected `UnitRef`s and the index just past the semicolon.
fn parse_with_clause(
    source: &str,
    tokens: &[Token],
    mut index: usize,
) -> Option<(Vec<UnitRef>, usize)> {
    let mut units = Vec::new();

    loop {
        let (name, next_index) = parse_dotted_unit_name(source, tokens, index)?;
        units.push(UnitRef { name });
        index = next_index;

        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::Comma) => index += 1,
            Some(TokenKind::Semicolon) => return Some((units, index + 1)),
            _ => return None,
        }
    }
}

fn parse_dotted_unit_name(
    source: &str,
    tokens: &[Token],
    mut index: usize,
) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    parts.push(identifier_source_text(source, tokens.get(index)?)?);
    index += 1;

    while tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == TokenKind::Dot)
    {
        index += 1;
        parts.push(identifier_source_text(source, tokens.get(index)?)?);
        index += 1;
    }

    Some((parts.join("."), index))
}

fn identifier_source_text(source: &str, token: &Token) -> Option<String> {
    if !matches!(token.effective_kind, TokenKind::Identifier(_)) {
        return None;
    }

    source
        .get(token.text_span.start as usize..token.text_span.end as usize)
        .map(str::to_owned)
}

fn significant_tokens(tokens: Vec<Token>) -> Vec<Token> {
    tokens
        .into_iter()
        .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::build_structural_ast;
    use crate::ast::{AdaStandard, HandlerOwner, RaiseKind, StatementOwner, TypeOwner, UnitKind};
    use std::path::Path;

    #[test]
    fn pragma_ada95_selects_ada95() {
        let ast = build_structural_ast(
            "pragma Ada_95; package P is end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada95);
    }

    #[test]
    fn pragma_ada2022_selects_ada2022() {
        let ast = build_structural_ast(
            "pragma Ada_2022; package P is end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2022);
    }

    #[test]
    fn pragma_ada83_is_accepted_as_ada83_standard() {
        // M22: Ada 83 is no longer rejected — it parses (best-effort) and is
        // tagged Ada83 so legacy targets are discovered and reported on.
        let ast = build_structural_ast(
            "pragma Ada_83;\nprocedure P is begin null; end P;\n",
            None,
            Path::new("p.adb"),
        )
        .expect("Ada 83 source must parse");
        assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada83);
    }

    #[test]
    fn interface_feature_promotes_to_ada2005() {
        let ast = build_structural_ast(
            "package P is type T is interface; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2005);
    }

    #[test]
    fn aspect_feature_promotes_to_ada2012() {
        let ast =
            build_structural_ast("procedure P with Inline => True;", None, Path::new("p.ads"))
                .unwrap();

        assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2012);
    }

    #[test]
    fn parallel_block_feature_promotes_to_ada2022() {
        let ast = build_structural_ast(
            "procedure P is begin parallel do null; end do; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2022);
    }

    #[test]
    fn plain_source_defaults_to_ada2012_without_hint() {
        let ast = build_structural_ast("package P is end P;", None, Path::new("p.ads")).unwrap();

        assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2012);
    }

    #[test]
    fn plain_source_uses_dialect_hint_when_present() {
        let ast = build_structural_ast(
            "package P is end P;",
            Some(AdaStandard::Ada95),
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada95);
    }

    #[test]
    fn separate_clause_classifies_adb_as_subunit() {
        // Subunits live in .adb files in standard Ada. The source opening with
        // `separate (Parent)` is the authoritative signal; the file extension
        // only chooses between Spec/Body when no separate clause is present.
        let subunit_adb = build_structural_ast(
            "separate (Foo) procedure Bar is begin null; end Bar;",
            None,
            Path::new("bar.adb"),
        )
        .unwrap();
        let subunit_other = build_structural_ast(
            "separate (Foo) procedure Bar is begin null; end Bar;",
            None,
            Path::new("bar.ada"),
        )
        .unwrap();
        let spec = build_structural_ast("package P is end P;", None, Path::new("p.ads")).unwrap();
        let body =
            build_structural_ast("package body P is end P;", None, Path::new("p.adb")).unwrap();

        assert_eq!(subunit_adb.units[0].kind, UnitKind::Subunit);
        assert_eq!(subunit_other.units[0].kind, UnitKind::Subunit);
        assert_eq!(spec.units[0].kind, UnitKind::Spec);
        assert_eq!(body.units[0].kind, UnitKind::Body);
    }

    #[test]
    fn extracts_multiple_top_level_with_clauses() {
        let ast = build_structural_ast(
            "with Ada.Text_IO; with Ada.Strings.Unbounded; package P is end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        let withs: Vec<_> = ast.units[0]
            .withs
            .iter()
            .map(|unit_ref| unit_ref.name.as_str())
            .collect();
        assert_eq!(withs, vec!["Ada.Text_IO", "Ada.Strings.Unbounded"]);
    }

    #[test]
    fn extracts_comma_separated_with_clause() {
        let ast = build_structural_ast(
            "with Ada.Text_IO, Ada.Strings.Unbounded, Ada.Calendar; package P is end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        let withs: Vec<_> = ast.units[0]
            .withs
            .iter()
            .map(|unit_ref| unit_ref.name.as_str())
            .collect();
        assert_eq!(
            withs,
            vec!["Ada.Text_IO", "Ada.Strings.Unbounded", "Ada.Calendar"]
        );
    }

    #[test]
    fn limited_with_supports_comma_separated_units() {
        let ast = build_structural_ast(
            "limited with Foo, Bar.Baz; package P is end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        let withs: Vec<_> = ast.units[0]
            .withs
            .iter()
            .map(|unit_ref| unit_ref.name.as_str())
            .collect();
        assert_eq!(withs, vec!["Foo", "Bar.Baz"]);
    }

    #[test]
    fn limited_with_clause_extracts_target_name() {
        let ast = build_structural_ast(
            "limited with Foo; package P is end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.units[0].withs[0].name, "Foo");
    }

    #[test]
    fn record_aspect_is_not_extracted_as_with_clause() {
        let ast = build_structural_ast(
            "package P is type R is record A : Integer; end record with Pack; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert!(ast.units[0].withs.is_empty());
    }

    #[test]
    fn package_with_two_procedures_populates_packages_and_subprograms() {
        let ast = build_structural_ast(
            "package P is procedure A; procedure B; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.packages.len(), 1);
        assert_eq!(ast.subprograms.len(), 2);
        assert_eq!(ast.units[0].packages, vec![crate::ast::PackageId(0)]);
    }

    #[test]
    fn generic_package_populates_is_generic() {
        let ast = build_structural_ast(
            "generic type T is private; package P is end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.packages.len(), 1);
        assert!(ast.packages[0].is_generic);
    }

    #[test]
    fn nested_subprogram_populates_local_visibility() {
        let ast = build_structural_ast(
            "procedure Outer is procedure Inner; begin null; end Outer;",
            None,
            Path::new("outer.adb"),
        )
        .unwrap();

        let inner = ast
            .subprograms
            .iter()
            .find(|subprogram| subprogram.name == "inner")
            .unwrap();
        assert_eq!(inner.visibility, crate::ast::Visibility::Local);
    }

    #[test]
    fn handler_and_raise_counts_are_populated() {
        let ast = build_structural_ast(
            "procedure P is begin raise Constraint_Error; exception when others => raise; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.handlers.len(), 1);
        assert_eq!(ast.raises.len(), 2);
    }

    #[test]
    fn build_structural_ast_calls_extract_statements_and_populates_field() {
        let ast = build_structural_ast(
            "procedure P is begin null; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.statements.len(), 1);
        assert_eq!(
            ast.statements[0].owner,
            StatementOwner::Subprogram(ast.subprograms[0].id)
        );
    }

    #[test]
    fn package_body_initializer_raise_is_extracted() {
        let ast = build_structural_ast(
            r#"
package body P is
begin
   raise Constraint_Error;
exception
   when others =>
      raise;
end P;
"#,
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.raises.len(), 2);
        assert_eq!(ast.raises[0].kind, RaiseKind::Explicit);
        assert_eq!(ast.raises[0].exception.as_deref(), Some("constraint_error"));
        assert_eq!(ast.raises[1].kind, RaiseKind::Reraise);
        assert_eq!(ast.raises[1].exception, None);
    }

    #[test]
    fn package_body_raise_handler_consistency() {
        let ast = build_structural_ast(
            r#"
package body P is
   procedure Helper is
   begin
      null;
   end Helper;
begin
   Helper;
   raise Program_Error;
exception
   when Constraint_Error =>
      raise;
end P;
"#,
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.handlers.len(), 1);
        assert_eq!(ast.raises.len(), 2);
        assert_eq!(ast.raises[0].kind, RaiseKind::Explicit);
        assert_eq!(ast.raises[1].kind, RaiseKind::Reraise);
    }

    #[test]
    fn subprogram_handler_ids_link_to_global_handlers() {
        let ast = build_structural_ast(
            "procedure P is begin null; exception when others => null; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.subprograms[0].handlers, vec![ast.handlers[0].id]);
        assert_eq!(
            ast.handlers[0].owner,
            HandlerOwner::Subprogram(ast.subprograms[0].id)
        );
    }

    #[test]
    fn subprogram_handler_ids_do_not_include_package_body_handlers() {
        let ast = build_structural_ast(
            "package body P is procedure Inner is begin null; end Inner; begin null; exception when others => null; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.packages.len(), 1);
        assert_eq!(ast.subprograms.len(), 1);
        assert_eq!(ast.handlers.len(), 1);
        assert!(ast.subprograms[0].handlers.is_empty());
        assert!(matches!(
            &ast.handlers[0].owner,
            HandlerOwner::PackageBody(id) if *id == ast.packages[0].id
        ));
    }

    #[test]
    fn subprogram_raise_ids_link_to_global_raises() {
        let ast = build_structural_ast(
            "procedure P is begin raise Constraint_Error; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.subprograms[0].raises, vec![ast.raises[0].id]);
    }

    #[test]
    fn use_clauses_are_attached_to_unit() {
        let ast = build_structural_ast(
            "with Ada.Text_IO; use Ada.Text_IO, Ada.Calendar; package P is end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.units[0].uses.len(), 1);
        assert_eq!(
            ast.units[0].uses[0].names,
            vec!["ada.text_io", "ada.calendar"]
        );
    }

    #[test]
    fn package_with_three_types_extracted() {
        let ast = build_structural_ast(
            "package P is type A is range 1 .. 10; type B is (Red, Blue); type C is private; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.types.len(), 3);
    }

    #[test]
    fn subprogram_body_local_type_extracted() {
        let ast = build_structural_ast(
            "procedure P is type Local is range 1 .. 10; begin null; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.types.len(), 1);
        assert_eq!(ast.types[0].name_path, vec!["local"]);
    }

    #[test]
    fn representation_clause_attached_to_target_type() {
        let ast = build_structural_ast(
            "package P is type T is range 1 .. 10; for T'Size use 32; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.types[0].aspects.0, vec!["rep: for T'Size use 32;"]);
    }

    #[test]
    fn rep_clause_attaches_to_type_in_correct_scope() {
        let ast = build_structural_ast(
            "package B is type T is range 1 .. 10; end B; package A is type T is range 1 .. 10; for T'Size use 32; end A;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();
        let package_a = ast
            .packages
            .iter()
            .find(|package| package.name == "a")
            .unwrap();
        let package_b = ast
            .packages
            .iter()
            .find(|package| package.name == "b")
            .unwrap();
        let type_in_a = ast
            .types
            .iter()
            .find(|ty| {
                ty.name_path == vec!["t"]
                    && matches!(&ty.owner, TypeOwner::Package(id) if *id == package_a.id)
            })
            .unwrap();
        let type_in_b = ast
            .types
            .iter()
            .find(|ty| {
                ty.name_path == vec!["t"]
                    && matches!(&ty.owner, TypeOwner::Package(id) if *id == package_b.id)
            })
            .unwrap();

        assert_eq!(type_in_a.aspects.0, vec!["rep: for T'Size use 32;"]);
        assert!(type_in_b.aspects.0.is_empty());
    }

    #[test]
    fn unit_pragmas_populated() {
        let ast = build_structural_ast(
            "pragma Pure; pragma Restrictions (No_Allocators); package P is end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.units[0].pragmas.len(), 2);
        assert_eq!(ast.units[0].pragmas[0].name, "pure");
    }

    #[test]
    fn procedure_aspect_is_not_extracted_as_with_clause() {
        let ast = build_structural_ast(
            "with Ada.Text_IO; procedure P with Inline => True is begin null; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        let withs: Vec<_> = ast.units[0]
            .withs
            .iter()
            .map(|unit_ref| unit_ref.name.as_str())
            .collect();
        assert_eq!(withs, vec!["Ada.Text_IO"]);
    }

    #[test]
    fn object_size_aspect_is_not_extracted_as_with_clause() {
        let ast = build_structural_ast(
            "pragma Ada_2022; package P is type R is record A : Integer; end record with Object_Size => 32; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert!(ast.units[0].withs.is_empty());
    }

    #[test]
    fn protected_type_entry_and_procedure_are_subprograms() {
        let ast = build_structural_ast(
            "package P is protected type Gate is entry Lock; procedure Release; end Gate; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        let names: Vec<_> = ast
            .subprograms
            .iter()
            .map(|subprogram| subprogram.name.as_str())
            .collect();
        assert_eq!(names, vec!["lock", "release"]);
    }

    #[test]
    fn task_type_entry_is_a_subprogram() {
        let ast = build_structural_ast(
            "package P is task type Worker is entry Start; end Worker; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.subprograms.len(), 1);
        assert_eq!(ast.subprograms[0].name, "start");
    }

    #[test]
    fn subprogram_renaming_declaration_is_counted() {
        let ast = build_structural_ast(
            "package P is procedure Original; procedure Alias renames Original; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        let names: Vec<_> = ast
            .subprograms
            .iter()
            .map(|subprogram| subprogram.name.as_str())
            .collect();
        assert_eq!(names, vec!["original", "alias"]);
    }

    #[test]
    fn package_renaming_does_not_capture_later_subprograms() {
        // `package AS renames ...;` has no `end AS;`; it must not open a scope
        // that swallows subsequent declarations (json-ada's JSON.Streams).
        let ast = build_structural_ast(
            "package JSON.Streams is\n\
             package AS renames Ada.Streams;\n\
             function From_Text (Text : String) return Integer;\n\
             end JSON.Streams;",
            None,
            Path::new("json-streams.ads"),
        )
        .unwrap();

        let from_text = ast
            .subprograms
            .iter()
            .find(|s| s.name == "from_text")
            .expect("from_text discovered");
        // Owned by JSON.Streams, not the `AS` renaming.
        let owner = match &from_text.owner {
            crate::ast::SubprogramOwner::Package(id) => ast
                .packages
                .iter()
                .find(|p| &p.id == id)
                .map(|p| p.name.as_str()),
            _ => None,
        };
        assert_eq!(owner, Some("json.streams"), "owner: {:?}", from_text.owner);
        assert!(
            !ast.packages.iter().any(|p| p.name == "as"),
            "renaming must not become a package: {:?}",
            ast.packages.iter().map(|p| &p.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn child_package_subprogram_is_owned_by_child_package() {
        let ast = build_structural_ast(
            "package Parent.Child is procedure Run; end Parent.Child;",
            None,
            Path::new("parent-child.ads"),
        )
        .unwrap();

        assert_eq!(ast.packages[0].name, "parent.child");
        assert_eq!(ast.subprograms[0].name, "run");
    }

    #[test]
    fn derived_type_chain_extracts_root_and_child() {
        let ast = build_structural_ast(
            "package P is type Root is range 0 .. 10; type Child is new Root; end P;",
            None,
            Path::new("p.ads"),
        )
        .unwrap();

        assert_eq!(ast.types.len(), 2);
        assert!(matches!(ast.types[0].kind, crate::ast::TypeKind::Scalar(_)));
        assert!(matches!(
            ast.types[1].kind,
            crate::ast::TypeKind::Derived { .. }
        ));
    }

    #[test]
    fn target_name_at_sign_does_not_block_subprogram_extraction() {
        let ast = build_structural_ast(
            "pragma Ada_2022; procedure P is X : Integer := 0; begin X := @ + 1; end P;",
            Some(AdaStandard::Ada2022),
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.subprograms.len(), 1);
        assert_eq!(ast.subprograms[0].name, "p");
    }

    #[test]
    fn declare_expression_does_not_block_raise_extraction() {
        let ast = build_structural_ast(
            "pragma Ada_2022; procedure P is X : Integer := (declare Y : constant Integer := 1; begin Y); begin raise Program_Error; end P;",
            Some(AdaStandard::Ada2022),
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.subprograms.len(), 1);
        assert_eq!(ast.raises.len(), 1);
    }
}
