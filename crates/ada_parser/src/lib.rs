// SPDX-License-Identifier: Apache-2.0

pub mod ast;
pub mod extract;
pub mod lexer;
pub mod reconcile;

pub fn ada_language() -> tree_sitter::Language {
    extern "C" {
        fn tree_sitter_ada() -> tree_sitter::Language;
    }

    unsafe { tree_sitter_ada() }
}

pub fn parse_with_tree_sitter(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    let language = ada_language();
    if parser.set_language(&language).is_err() {
        return None;
    }

    parser.parse(source, None)
}

/// Classify the `raise` token at `start_byte` using the grammar node that owns
/// it. Ada 2012 raise expressions and raise statements share the same keyword,
/// so token context alone is not sufficient to distinguish them safely.
pub fn raise_is_statement(source: &str, start_byte: u32) -> Option<bool> {
    let start = start_byte as usize;
    let end = start.checked_add("raise".len())?;
    if end > source.len() || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return None;
    }

    let tree = parse_with_tree_sitter(source)?;
    let mut node = tree.root_node().descendant_for_byte_range(start, end)?;
    loop {
        match node.kind() {
            "raise_statement" => return Some(true),
            "raise_expression" => return Some(false),
            _ => node = node.parent()?,
        }
    }
}

pub fn crate_name() -> &'static str {
    "ada_parser"
}

#[cfg(test)]
mod tests {
    #[test]
    fn ada_language_is_callable() {
        let language = crate::ada_language();
        assert!(!format!("{language:?}").is_empty());
    }

    #[test]
    fn tree_sitter_parses_simple_package() {
        let tree = crate::parse_with_tree_sitter("package P is end P;");
        let root = tree.as_ref().map(|tree| tree.root_node());

        assert!(root.is_some_and(|node| !node.kind().is_empty()));
    }

    #[test]
    fn tree_sitter_parses_empty_source_with_root_node() {
        let tree = crate::parse_with_tree_sitter("");
        let root = tree.as_ref().map(|tree| tree.root_node());

        assert!(root.is_some_and(|node| !node.kind().is_empty()));
    }

    #[test]
    fn tree_sitter_distinguishes_nested_raise_statement_from_expression() {
        let statement = "procedure P is begin if Bad then raise Constraint_Error; end if; end P;";
        let statement_offset = statement.find("raise").unwrap() as u32;
        assert_eq!(
            crate::raise_is_statement(statement, statement_offset),
            Some(true)
        );

        let expression =
            "package P is function F return Integer is (raise Constraint_Error); end P;";
        let expression_offset = expression.find("raise").unwrap() as u32;
        assert_eq!(
            crate::raise_is_statement(expression, expression_offset),
            Some(false)
        );
    }
}
