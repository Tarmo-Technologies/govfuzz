// SPDX-License-Identifier: Apache-2.0

use crate::edge_cases;
use crate::rewriter::{Insertion, InsertionKind, SourceRewriter};
use crate::InstrumenterError;
use ada_parser::ast::{StatementOwner, StructuralAst};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Breadcrumb {
    pub id: u32,
    pub file: PathBuf,
    pub line: u32,
    pub col: u32,
    pub subprogram: String,
    pub depth: u32,
    pub idx: u32,
}

// Phase 2 instruments the StatementSpan values Phase 1 emits. Extended return
// statements therefore get the outer `return ... do` breadcrumb here, while
// breadcrumbs for statements inside the `do ... end return` body are deferred
// until nested statement extraction lands.
pub const EXTENDED_RETURN_PHASE2_LIMITATION: &str =
    "nested-statement breadcrumbs inside extended return statements are deferred";

pub fn collect_breadcrumb_insertions(
    ast: &StructuralAst,
    source: &str,
    source_path: &Path,
    rewriter: &mut SourceRewriter<'_>,
) -> Result<Vec<Breadcrumb>, InstrumenterError> {
    let mut statements = ast.statements.iter().collect::<Vec<_>>();
    statements.sort_by_key(|statement| (statement.file_byte_offset, statement.end_byte_offset));

    let mut breadcrumbs = Vec::new();
    for statement in statements {
        if !edge_cases::breadcrumb_injection_safe(source, statement, ast) {
            continue;
        }
        if statement_owner_is_expression_function(ast, source, &statement.owner) {
            continue;
        }

        let Some(subprogram) = owner_name(ast, &statement.owner) else {
            continue;
        };
        let id = breadcrumbs.len() as u32 + 1;
        let byte_offset = edge_cases::label_start_offset(source, statement.file_byte_offset)
            .unwrap_or(statement.file_byte_offset);
        let indent = leading_indent(source, byte_offset);
        rewriter.add_insertion(Insertion {
            byte_offset,
            text: format!("AdaFuzz.Probe.Breadcrumb ({id});\n{indent}"),
            kind: InsertionKind::BreadcrumbBefore,
        });
        breadcrumbs.push(Breadcrumb {
            id,
            file: source_path.to_path_buf(),
            line: statement.line,
            col: statement.col,
            subprogram,
            depth: u32::from(statement.depth),
            idx: statement.index_in_block,
        });
    }

    Ok(breadcrumbs)
}

pub fn leading_indent(source: &str, byte_offset: u32) -> &str {
    let offset = byte_offset as usize;
    let Some(prefix) = source.get(..offset) else {
        return "";
    };
    let line_start = prefix
        .rfind('\n')
        .map_or(0, |index| index.saturating_add(1));
    let line = &prefix[line_start..];
    let indent_len = line
        .bytes()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count();

    &line[..indent_len]
}

fn owner_name(ast: &StructuralAst, owner: &StatementOwner) -> Option<String> {
    match owner {
        StatementOwner::Subprogram(id) => ast
            .subprograms
            .iter()
            .find(|subprogram| subprogram.id == *id)
            .map(|subprogram| subprogram.name.clone()),
        StatementOwner::PackageBody(id) => ast
            .packages
            .iter()
            .find(|package| package.id == *id)
            .map(|package| format!("{}__init", package.name)),
    }
}

fn statement_owner_is_expression_function(
    ast: &StructuralAst,
    source: &str,
    owner: &StatementOwner,
) -> bool {
    let StatementOwner::Subprogram(id) = owner else {
        return false;
    };
    let Some(subprogram) = ast.subprograms.iter().find(|item| item.id == *id) else {
        return false;
    };

    // Phase 2 deliberately skips Ada 2012 expression functions. The future
    // --instrument-expr-fns flag needs a body-conversion rewrite, which is out
    // of scope for this phase.
    edge_cases::is_expression_function(subprogram, source)
}

#[cfg(test)]
mod tests {
    use super::{collect_breadcrumb_insertions, Breadcrumb, EXTENDED_RETURN_PHASE2_LIMITATION};
    use crate::rewriter::SourceRewriter;
    use ada_parser::ast::{
        Package, PackageId, Span, StatementId, StatementOwner, StatementSpan, StructuralAst,
        Subprogram, SubprogramId, SubprogramKind, SubprogramOwner, Visibility,
    };
    use std::path::Path;

    fn subprogram(id: u32, name: &str) -> Subprogram {
        Subprogram {
            id: SubprogramId(id),
            owner: SubprogramOwner::LibraryLevel,
            name: name.to_owned(),
            kind: SubprogramKind::Procedure,
            params: Vec::new(),
            return_type: None,
            is_abstract: false,
            is_dispatching: false,
            is_overriding: false,
            body_span: Some(Span::new(0, 10, 1, 1)),
            decl_span: Span::new(0, 10, 1, 1),
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility: Visibility::Public,
            is_generic: false,
        }
    }

    fn package(id: u32, name: &str) -> Package {
        Package {
            id: PackageId(id),
            name: name.to_owned(),
            parent: None,
            is_generic: false,
            is_private: false,
            formals: Vec::new(),
            decls: Vec::new(),
        }
    }

    fn statement(
        owner: StatementOwner,
        start: u32,
        end: u32,
        line: u32,
        col: u32,
    ) -> StatementSpan {
        StatementSpan {
            id: StatementId(start),
            owner,
            file_byte_offset: start,
            end_byte_offset: end,
            line,
            col,
            depth: 0,
            index_in_block: start,
        }
    }

    fn collect(ast: &StructuralAst, source: &str) -> (Vec<Breadcrumb>, String) {
        let mut rewriter = SourceRewriter::new(source);
        let breadcrumbs =
            collect_breadcrumb_insertions(ast, source, Path::new("pkg.adb"), &mut rewriter)
                .unwrap();
        (breadcrumbs, rewriter.apply().unwrap())
    }

    #[test]
    fn breadcrumb_ids_start_at_one() {
        let mut ast = StructuralAst::new();
        ast.subprograms.push(subprogram(0, "parse"));
        ast.statements.push(statement(
            StatementOwner::Subprogram(SubprogramId(0)),
            10,
            12,
            2,
            4,
        ));

        let (breadcrumbs, _) = collect(&ast, "begin\n   A;\nend;");

        assert_eq!(breadcrumbs[0].id, 1);
    }

    #[test]
    fn breadcrumb_ids_increment_in_source_order() {
        let mut ast = StructuralAst::new();
        ast.subprograms.push(subprogram(0, "parse"));
        ast.statements.push(statement(
            StatementOwner::Subprogram(SubprogramId(0)),
            14,
            16,
            3,
            4,
        ));
        ast.statements.push(statement(
            StatementOwner::Subprogram(SubprogramId(0)),
            8,
            10,
            2,
            4,
        ));

        let (breadcrumbs, _) = collect(&ast, "begin\n  A;\n  B;\nend;");

        assert_eq!(
            breadcrumbs.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            breadcrumbs.iter().map(|item| item.line).collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn breadcrumb_record_carries_subprogram_name() {
        let mut ast = StructuralAst::new();
        ast.subprograms.push(subprogram(0, "parse"));
        ast.statements.push(statement(
            StatementOwner::Subprogram(SubprogramId(0)),
            8,
            10,
            2,
            4,
        ));

        let (breadcrumbs, _) = collect(&ast, "begin\n  A;\nend;");

        assert_eq!(breadcrumbs[0].subprogram, "parse");
    }

    #[test]
    fn breadcrumb_record_carries_line_col() {
        let mut ast = StructuralAst::new();
        ast.subprograms.push(subprogram(0, "parse"));
        ast.statements.push(statement(
            StatementOwner::Subprogram(SubprogramId(0)),
            8,
            10,
            9,
            7,
        ));

        let (breadcrumbs, _) = collect(&ast, "begin\n  A;\nend;");

        assert_eq!(breadcrumbs[0].line, 9);
        assert_eq!(breadcrumbs[0].col, 7);
    }

    #[test]
    fn breadcrumb_record_for_package_body_initializer_uses_package_name() {
        let mut ast = StructuralAst::new();
        ast.packages.push(package(0, "pkg"));
        ast.statements.push(statement(
            StatementOwner::PackageBody(PackageId(0)),
            8,
            10,
            2,
            4,
        ));

        let (breadcrumbs, _) = collect(&ast, "begin\n  A;\nend;");

        assert_eq!(breadcrumbs[0].subprogram, "pkg__init");
    }

    #[test]
    fn breadcrumb_insertion_text_includes_id_and_call() {
        let mut ast = StructuralAst::new();
        ast.subprograms.push(subprogram(0, "parse"));
        ast.statements.push(statement(
            StatementOwner::Subprogram(SubprogramId(0)),
            8,
            10,
            2,
            4,
        ));

        let (_, rewritten) = collect(&ast, "begin\n  A;\nend;");

        assert!(rewritten.contains("AdaFuzz.Probe.Breadcrumb (1);"));
    }

    #[test]
    fn breadcrumb_insertion_offset_matches_statement_start() {
        let mut ast = StructuralAst::new();
        ast.subprograms.push(subprogram(0, "parse"));
        ast.statements.push(statement(
            StatementOwner::Subprogram(SubprogramId(0)),
            8,
            10,
            2,
            4,
        ));

        let (_, rewritten) = collect(&ast, "begin\n  A;\nend;");

        assert_eq!(
            rewritten,
            "begin\n  AdaFuzz.Probe.Breadcrumb (1);\n  A;\nend;"
        );
    }

    #[test]
    fn breadcrumb_insertion_text_indentation_matches_source_line() {
        let mut ast = StructuralAst::new();
        ast.subprograms.push(subprogram(0, "parse"));
        ast.statements.push(statement(
            StatementOwner::Subprogram(SubprogramId(0)),
            11,
            13,
            2,
            7,
        ));

        let (_, rewritten) = collect(&ast, "begin\n     A;\nend;");

        assert!(rewritten.contains("\n     AdaFuzz.Probe.Breadcrumb (1);\n     A;"));
    }

    #[test]
    fn breadcrumb_insertion_moves_before_label_prefix() {
        let source = "begin\n   Retry : A;\nend;";
        let mut ast = StructuralAst::new();
        ast.subprograms.push(subprogram(0, "parse"));
        ast.statements.push(statement(
            StatementOwner::Subprogram(SubprogramId(0)),
            source.find('A').unwrap() as u32,
            source.find("A;").unwrap() as u32 + 2,
            2,
            14,
        ));

        let (_, rewritten) = collect(&ast, source);

        assert_eq!(
            rewritten,
            "begin\n   AdaFuzz.Probe.Breadcrumb (1);\n   Retry : A;\nend;"
        );
    }

    #[test]
    fn expression_function_body_gets_no_breadcrumbs() {
        let source = "pragma Ada_2012;\nfunction Is_Zero (X : Integer) return Boolean is (X = 0);";
        let mut ast =
            ada_parser::reconcile::build_structural_ast(source, None, Path::new("p.ads")).unwrap();
        let subprogram_id = ast.subprograms[0].id;
        let start = source.find("X = 0").unwrap() as u32;
        ast.statements.push(statement(
            StatementOwner::Subprogram(subprogram_id),
            start,
            start + 5,
            2,
            67,
        ));

        let (breadcrumbs, rewritten) = collect(&ast, source);

        assert!(breadcrumbs.is_empty());
        assert_eq!(rewritten, source);
    }

    #[test]
    fn non_expression_function_body_gets_breadcrumbs_normally() {
        let source = "function F return Integer is begin return 1; end F;";
        let ast =
            ada_parser::reconcile::build_structural_ast(source, None, Path::new("f.adb")).unwrap();

        let (breadcrumbs, rewritten) = collect(&ast, source);

        assert_eq!(breadcrumbs.len(), 1);
        assert!(rewritten.contains("AdaFuzz.Probe.Breadcrumb (1);"));
    }

    #[test]
    fn extended_return_statement_gets_outer_breadcrumb_only_phase2_limitation() {
        let source = "\
function F return Integer is
begin
   return R : Integer do
      R := 1;
   end return;
end F;";
        let ast =
            ada_parser::reconcile::build_structural_ast(source, None, Path::new("f.adb")).unwrap();

        let (breadcrumbs, rewritten) = collect(&ast, source);

        assert_eq!(breadcrumbs.len(), 1);
        assert_eq!(rewritten.matches("AdaFuzz.Probe.Breadcrumb").count(), 1);
        assert!(EXTENDED_RETURN_PHASE2_LIMITATION.contains("nested-statement breadcrumbs"));
    }
}
