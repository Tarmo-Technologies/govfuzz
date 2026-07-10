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
}
