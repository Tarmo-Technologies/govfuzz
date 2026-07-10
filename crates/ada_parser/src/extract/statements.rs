// SPDX-License-Identifier: Apache-2.0

use crate::ast::{Package, Span, StatementId, StatementOwner, StatementSpan, Subprogram};
use crate::extract::scope::{ScopeKind, ScopeTree};
use crate::lexer::{Token, TokenKind};

pub fn extract_statements(
    scope_tree: &ScopeTree,
    _source: &str,
    tokens: &[Token],
    subprograms: &[Subprogram],
    packages: &[Package],
) -> Vec<StatementSpan> {
    let mut statements = Vec::new();

    for scope in &scope_tree.scopes {
        if scope.kind != ScopeKind::SubprogramBody {
            continue;
        };
        let Some(subprogram) = subprograms
            .iter()
            .find(|subprogram| subprogram.body_span == Some(scope.decl_span))
        else {
            continue;
        };
        collect_body_statements(
            tokens,
            scope.decl_span,
            executable_begin_search_start(scope.declarative_span, scope.decl_span),
            StatementOwner::Subprogram(subprogram.id),
            &mut statements,
        );
    }

    for scope in &scope_tree.scopes {
        if scope.kind != ScopeKind::PackageBody {
            continue;
        }
        let Some(package) = packages.iter().find(|package| package.name == scope.name) else {
            continue;
        };
        collect_body_statements(
            tokens,
            scope.decl_span,
            executable_begin_search_start(scope.declarative_span, scope.decl_span),
            StatementOwner::PackageBody(package.id),
            &mut statements,
        );
    }

    statements
}

fn collect_body_statements(
    tokens: &[Token],
    body_span: Span,
    begin_search_start: u32,
    owner: StatementOwner,
    statements: &mut Vec<StatementSpan>,
) {
    let Some(begin_index) = find_token_in_span(
        tokens,
        begin_search_start,
        body_span.end_byte,
        TokenKind::KwBegin,
    ) else {
        return;
    };

    let mut cursor = begin_index.saturating_add(1);
    let mut index_in_block = 0;
    while let Some(start_index) = next_statement_token(tokens, cursor, body_span.end_byte) {
        let Some(end_index) = find_statement_semicolon(tokens, start_index, body_span.end_byte)
        else {
            break;
        };
        push_statement(
            statements,
            owner.clone(),
            tokens,
            start_index,
            end_index,
            index_in_block,
        );
        index_in_block += 1;
        cursor = end_index.saturating_add(1);
    }
}

fn executable_begin_search_start(declarative_span: Option<Span>, body_span: Span) -> u32 {
    declarative_span
        .map(|span| span.end_byte)
        .unwrap_or(body_span.start_byte)
}

fn find_token_in_span(
    tokens: &[Token],
    start_byte: u32,
    end_byte: u32,
    kind: TokenKind,
) -> Option<usize> {
    tokens.iter().position(|token| {
        token.text_span.start >= start_byte
            && token.text_span.start < end_byte
            && token.effective_kind == kind
    })
}

fn next_statement_token(tokens: &[Token], index: usize, end_byte: u32) -> Option<usize> {
    if let Some(token) = tokens.get(index) {
        if token.text_span.start >= end_byte
            || matches!(
                token.effective_kind,
                TokenKind::KwEnd | TokenKind::KwException
            )
        {
            return None;
        }
        return Some(index);
    }

    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstructKind {
    If,
    Case,
    Loop,
    Select,
    Parallel,
    Declare,
    Block,
    Record,
}

fn find_statement_semicolon(tokens: &[Token], mut index: usize, end_byte: u32) -> Option<usize> {
    let mut construct_stack: Vec<ConstructKind> = Vec::new();

    while let Some(token) = tokens.get(index) {
        if token.text_span.start >= end_byte {
            return None;
        }

        match &token.effective_kind {
            TokenKind::KwException if construct_stack.is_empty() => return None,
            TokenKind::KwEnd if construct_stack.is_empty() => return None,
            TokenKind::Semicolon if construct_stack.is_empty() => return Some(index),
            TokenKind::KwEnd if close_statement_construct(tokens, index, &mut construct_stack) => {
                index = index.saturating_add(end_construct_width(tokens, index));
                continue;
            }
            TokenKind::KwIf => construct_stack.push(ConstructKind::If),
            TokenKind::KwCase => construct_stack.push(ConstructKind::Case),
            TokenKind::KwLoop => construct_stack.push(ConstructKind::Loop),
            TokenKind::KwSelect => construct_stack.push(ConstructKind::Select),
            TokenKind::KwParallel if kind_at(tokens, index.saturating_add(1), &TokenKind::KwDo) => {
                construct_stack.push(ConstructKind::Parallel);
                index = index.saturating_add(2);
                continue;
            }
            TokenKind::KwDeclare => construct_stack.push(ConstructKind::Declare),
            TokenKind::KwBegin => match construct_stack.last_mut() {
                Some(kind) if *kind == ConstructKind::Declare => *kind = ConstructKind::Block,
                Some(_) | None => construct_stack.push(ConstructKind::Block),
            },
            TokenKind::KwRecord if !is_null_record(tokens, index) => {
                construct_stack.push(ConstructKind::Record);
            }
            _ => {}
        }
        index = index.saturating_add(1);
    }

    None
}

fn close_statement_construct(
    tokens: &[Token],
    index: usize,
    construct_stack: &mut Vec<ConstructKind>,
) -> bool {
    match token_kind_at(tokens, index.saturating_add(1)) {
        Some(TokenKind::KwIf) => pop_matching_construct(construct_stack, ConstructKind::If),
        Some(TokenKind::KwCase) => pop_matching_construct(construct_stack, ConstructKind::Case),
        Some(TokenKind::KwLoop) => pop_matching_construct(construct_stack, ConstructKind::Loop),
        Some(TokenKind::KwSelect) => pop_matching_construct(construct_stack, ConstructKind::Select),
        Some(TokenKind::KwDo) => pop_matching_construct(construct_stack, ConstructKind::Parallel),
        Some(TokenKind::KwRecord) => pop_matching_construct(construct_stack, ConstructKind::Record),
        Some(TokenKind::Semicolon) => pop_block_construct(construct_stack),
        Some(TokenKind::Identifier(_)) if named_end_semicolon_index(tokens, index).is_some() => {
            pop_block_construct(construct_stack)
        }
        Some(_) | None => false,
    }
}

fn pop_matching_construct(
    construct_stack: &mut Vec<ConstructKind>,
    expected: ConstructKind,
) -> bool {
    if construct_stack.last().copied() == Some(expected) {
        construct_stack.pop();
        return true;
    }

    false
}

fn pop_block_construct(construct_stack: &mut Vec<ConstructKind>) -> bool {
    if matches!(
        construct_stack.last(),
        Some(ConstructKind::Declare | ConstructKind::Block)
    ) {
        construct_stack.pop();
        return true;
    }

    false
}

fn end_construct_width(tokens: &[Token], index: usize) -> usize {
    if matches!(
        token_kind_at(tokens, index.saturating_add(1)),
        Some(
            TokenKind::KwIf
                | TokenKind::KwCase
                | TokenKind::KwLoop
                | TokenKind::KwSelect
                | TokenKind::KwDo
                | TokenKind::KwRecord
        )
    ) {
        return 2;
    }

    named_end_semicolon_index(tokens, index)
        .map(|semicolon_index| semicolon_index.saturating_sub(index))
        .unwrap_or(1)
}

fn named_end_semicolon_index(tokens: &[Token], index: usize) -> Option<usize> {
    let mut cursor = index.saturating_add(1);
    if !matches!(
        token_kind_at(tokens, cursor),
        Some(TokenKind::Identifier(_))
    ) {
        return None;
    }
    cursor = cursor.saturating_add(1);

    while kind_at(tokens, cursor, &TokenKind::Dot)
        && matches!(
            token_kind_at(tokens, cursor.saturating_add(1)),
            Some(TokenKind::Identifier(_))
        )
    {
        cursor = cursor.saturating_add(2);
    }

    if kind_at(tokens, cursor, &TokenKind::Semicolon) {
        Some(cursor)
    } else {
        None
    }
}

fn is_null_record(tokens: &[Token], index: usize) -> bool {
    index
        .checked_sub(1)
        .is_some_and(|previous| kind_at(tokens, previous, &TokenKind::KwNull))
}

fn kind_at(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    token_kind_at(tokens, index).is_some_and(|actual| actual == kind)
}

fn token_kind_at(tokens: &[Token], index: usize) -> Option<&TokenKind> {
    tokens.get(index).map(|token| &token.effective_kind)
}

fn push_statement(
    statements: &mut Vec<StatementSpan>,
    owner: StatementOwner,
    tokens: &[Token],
    start_index: usize,
    end_index: usize,
    index_in_block: u32,
) {
    let Some(start) = tokens.get(start_index) else {
        return;
    };
    let Some(end) = tokens.get(end_index) else {
        return;
    };

    statements.push(StatementSpan {
        id: StatementId(statements.len() as u32),
        owner,
        file_byte_offset: start.text_span.start,
        end_byte_offset: end.text_span.end,
        line: start.line,
        col: start.col,
        depth: 0,
        index_in_block,
    });
}

#[cfg(test)]
mod tests {
    use crate::ast::{StatementOwner, StatementSpan};
    use crate::reconcile::build_structural_ast;
    use std::path::Path;

    #[test]
    fn top_level_statements_extracted_from_simple_procedure_body() {
        let ast = build_structural_ast(
            "procedure P is begin A; B; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.statements.len(), 2);
        assert_eq!(
            ast.statements[0].owner,
            StatementOwner::Subprogram(ast.subprograms[0].id)
        );
        assert_eq!(
            ast.statements[1].owner,
            StatementOwner::Subprogram(ast.subprograms[0].id)
        );
    }

    #[test]
    fn top_level_statements_in_package_body_initializer_use_package_body_owner() {
        let ast = build_structural_ast(
            "package body P is begin Initialize; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.statements.len(), 1);
        assert_eq!(
            ast.statements[0].owner,
            StatementOwner::PackageBody(ast.packages[0].id)
        );
    }

    #[test]
    fn multiple_statements_track_index_in_block_zero_to_n() {
        let ast = build_structural_ast(
            "procedure P is begin A; B; C; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        let indexes: Vec<_> = ast
            .statements
            .iter()
            .map(|statement| statement.index_in_block)
            .collect();
        assert_eq!(indexes, vec![0, 1, 2]);
    }

    #[test]
    fn statement_byte_offsets_match_source_substring() {
        let source = r#"
procedure P is
begin
   Tmp := 1;
   return;
end P;
"#;
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();
        let assignment = &ast.statements[0];
        let statement_text =
            &source[assignment.file_byte_offset as usize..assignment.end_byte_offset as usize];

        assert_eq!(statement_text, "Tmp := 1;");
    }

    #[test]
    fn declarative_part_local_type_does_not_emit_statement_span() {
        let ast = build_structural_ast(
            "procedure P is type Local is range 1 .. 10; begin A; end P;",
            None,
            Path::new("p.adb"),
        )
        .unwrap();

        assert_eq!(ast.statements.len(), 1);
        assert_eq!(ast.statements[0].index_in_block, 0);
    }

    #[test]
    fn nested_subprogram_declaration_does_not_emit_outer_statement_span() {
        let source = r#"
procedure Outer is
   procedure Inner is
   begin
      null;
   end Inner;
begin
   A;
end Outer;
"#;
        let ast = build_structural_ast(source, None, Path::new("outer.adb")).unwrap();
        let outer = ast
            .subprograms
            .iter()
            .find(|subprogram| subprogram.name == "outer")
            .unwrap();
        let outer_statements: Vec<_> = ast
            .statements
            .iter()
            .filter(|statement| statement.owner == StatementOwner::Subprogram(outer.id))
            .collect();

        assert_eq!(outer_statements.len(), 1);
        assert_eq!(statement_text(source, outer_statements[0]), "A;");
    }

    #[test]
    fn statements_after_local_record_type_still_extracted() {
        let source = r#"
procedure P is
   type Local is record
      X : Integer;
   end record;
begin
   A;
   B;
end P;
"#;
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();
        let texts: Vec<_> = ast
            .statements
            .iter()
            .map(|statement| statement_text(source, statement))
            .collect();

        assert_eq!(texts, vec!["A;", "B;"]);
    }

    #[test]
    fn statements_in_exception_part_not_emitted() {
        let source = r#"
procedure P is
begin
   A;
exception
   when others =>
      B;
end P;
"#;
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();
        let texts: Vec<_> = ast
            .statements
            .iter()
            .map(|statement| statement_text(source, statement))
            .collect();

        assert_eq!(texts, vec!["A;"]);
    }

    #[test]
    fn body_with_exception_part_emits_only_pre_exception_statements() {
        let source = r#"
procedure P is
begin
   A;
   B;
exception
   when Constraint_Error =>
      C;
end P;
"#;
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();
        let texts: Vec<_> = ast
            .statements
            .iter()
            .map(|statement| statement_text(source, statement))
            .collect();

        assert_eq!(texts, vec!["A;", "B;"]);
    }

    #[test]
    fn if_then_else_emits_one_statement_span() {
        let source = r#"
procedure P is
   X : Integer := 0;
begin
   if X = 0 then
      A;
   else
      B;
   end if;
end P;
"#;
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();

        assert_eq!(ast.statements.len(), 1);
        assert_eq!(
            statement_text(source, &ast.statements[0]),
            "if X = 0 then\n      A;\n   else\n      B;\n   end if;"
        );
    }

    #[test]
    fn loop_with_inner_statements_emits_one_outer_span() {
        let source = r#"
procedure P is
begin
   loop
      A;
      exit;
   end loop;
end P;
"#;
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();

        assert_eq!(ast.statements.len(), 1);
        assert_eq!(
            statement_text(source, &ast.statements[0]),
            "loop\n      A;\n      exit;\n   end loop;"
        );
    }

    #[test]
    fn case_statement_with_choices_emits_one_span() {
        let source = r#"
procedure P is
   X : Integer := 0;
begin
   case X is
      when 0 =>
         A;
      when others =>
         B;
   end case;
end P;
"#;
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();

        assert_eq!(ast.statements.len(), 1);
        assert_eq!(
            statement_text(source, &ast.statements[0]),
            "case X is\n      when 0 =>\n         A;\n      when others =>\n         B;\n   end case;"
        );
    }

    #[test]
    fn nested_if_inside_loop_emits_one_outer_loop_span() {
        let source = r#"
procedure P is
   X : Integer := 0;
begin
   loop
      if X = 0 then
         A;
      end if;
      exit;
   end loop;
end P;
"#;
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();

        assert_eq!(ast.statements.len(), 1);
        assert_eq!(
            statement_text(source, &ast.statements[0]),
            "loop\n      if X = 0 then\n         A;\n      end if;\n      exit;\n   end loop;"
        );
    }

    #[test]
    fn parallel_block_emits_one_outer_span() {
        let source = r#"
pragma Ada_2022;
procedure P is
begin
   parallel do
      A;
   end do;
end P;
"#;
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();

        assert_eq!(ast.statements.len(), 1);
        assert_eq!(
            statement_text(source, &ast.statements[0]),
            "parallel do\n      A;\n   end do;"
        );
    }

    #[test]
    fn unlabeled_bare_block_statement_emits_one_top_level_span() {
        let source = "procedure P is\nbegin\n   begin\n      A;\n   end;\n   B;\nend P;";
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();
        let p = ast
            .subprograms
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("P"))
            .unwrap();
        let stmts: Vec<_> = ast
            .statements
            .iter()
            .filter(|s| matches!(s.owner, StatementOwner::Subprogram(id) if id == p.id))
            .collect();
        assert_eq!(
            stmts.len(),
            2,
            "expected one block + one B; got {} spans: {:?}",
            stmts.len(),
            stmts
        );
    }

    #[test]
    fn labeled_bare_block_statement_emits_one_top_level_span() {
        let source =
            "procedure P is\nbegin\n   Block_Name : begin\n      A;\n   end Block_Name;\n   B;\nend P;";
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();
        let p = ast
            .subprograms
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("P"))
            .unwrap();
        let stmts: Vec<_> = ast
            .statements
            .iter()
            .filter(|s| matches!(s.owner, StatementOwner::Subprogram(id) if id == p.id))
            .collect();
        assert_eq!(
            stmts.len(),
            2,
            "labeled bare block should emit one block span + one B"
        );
        let first = &stmts[0];
        let block_text = &source[first.file_byte_offset as usize..first.end_byte_offset as usize];
        assert!(
            block_text.contains("Block_Name"),
            "block span should include label, got: {block_text}"
        );
        assert!(
            block_text.contains("end Block_Name"),
            "block span should include the closer"
        );
    }

    #[test]
    fn labeled_declare_block_emits_one_top_level_span() {
        let source = "procedure P is\nbegin\n   Block_Name : declare\n      X : Integer := 0;\n   begin\n      A;\n   end Block_Name;\n   B;\nend P;";
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();
        let p = ast
            .subprograms
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("P"))
            .unwrap();
        let stmts: Vec<_> = ast
            .statements
            .iter()
            .filter(|s| matches!(s.owner, StatementOwner::Subprogram(id) if id == p.id))
            .collect();
        assert_eq!(
            stmts.len(),
            2,
            "labeled declare block should emit one block span + one B"
        );
    }

    #[test]
    fn unlabeled_declare_block_emits_one_top_level_span() {
        let source = "procedure P is\nbegin\n   declare\n      X : Integer := 0;\n   begin\n      A;\n   end;\n   B;\nend P;";
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();
        let p = ast
            .subprograms
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("P"))
            .unwrap();
        let stmts: Vec<_> = ast
            .statements
            .iter()
            .filter(|s| matches!(s.owner, StatementOwner::Subprogram(id) if id == p.id))
            .collect();
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn statement_after_block_extracts_correctly() {
        let source = "procedure P is\nbegin\n   begin\n      A;\n   end;\n   X := 1;\n   Y := 2;\n   begin\n      Z := 3;\n   end;\nend P;";
        let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();
        let p = ast
            .subprograms
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("P"))
            .unwrap();
        let stmts: Vec<_> = ast
            .statements
            .iter()
            .filter(|s| matches!(s.owner, StatementOwner::Subprogram(id) if id == p.id))
            .collect();
        assert_eq!(
            stmts.len(),
            4,
            "expected 4 top-level statements: block, X:=1, Y:=2, block; got {}",
            stmts.len()
        );
    }

    fn statement_text<'source>(source: &'source str, statement: &StatementSpan) -> &'source str {
        &source[statement.file_byte_offset as usize..statement.end_byte_offset as usize]
    }
}
