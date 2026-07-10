// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::ast::{AdaStandard, FormalKind, InterfaceKind, TypeId, TypeKind};
    use crate::extract::{build_scope_tree, extract_types};
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str, dialect: AdaStandard) -> Vec<Token> {
        lex(source, dialect)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    fn first_type(source: &str, dialect: AdaStandard) -> crate::ast::TypeRef {
        let tokens = tokens(source, dialect);
        let tree = build_scope_tree(&tokens);
        extract_types(&tree, source, &tokens, dialect)
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn access_to_named_type() {
        let ty = first_type(
            "package P is type Ptr is access Target; end P;",
            AdaStandard::Ada2012,
        );

        assert_eq!(ty.kind, TypeKind::Access { target: TypeId(0) });
        assert_eq!(ty.constraints.0, "Target");
    }

    #[test]
    fn access_constant_marks_constant() {
        let ty = first_type(
            "package P is type Ptr is access constant Target; end P;",
            AdaStandard::Ada2012,
        );

        assert_eq!(ty.kind, TypeKind::Access { target: TypeId(0) });
        assert_eq!(ty.constraints.0, "constant Target");
    }

    #[test]
    fn access_all_marks_all() {
        let ty = first_type(
            "package P is type Ptr is access all Target; end P;",
            AdaStandard::Ada2012,
        );

        assert_eq!(ty.kind, TypeKind::Access { target: TypeId(0) });
        assert_eq!(ty.constraints.0, "all Target");
    }

    #[test]
    fn access_procedure_captures_profile() {
        let ty = first_type(
            "package P is type Callback is access procedure (X : Integer); end P;",
            AdaStandard::Ada2012,
        );

        assert_eq!(ty.kind, TypeKind::Access { target: TypeId(0) });
        assert_eq!(ty.constraints.0, "procedure (X : Integer)");
    }

    #[test]
    fn access_function_captures_return_type() {
        let ty = first_type(
            "package P is type Getter is access function (X : Integer) return Boolean; end P;",
            AdaStandard::Ada2012,
        );

        assert_eq!(ty.kind, TypeKind::Access { target: TypeId(0) });
        assert_eq!(ty.constraints.0, "function (X : Integer) return Boolean");
    }

    #[test]
    fn not_null_access_at_2005() {
        let ty = first_type(
            "package P is type Ptr is not null access Target; end P;",
            AdaStandard::Ada2005,
        );

        assert_eq!(ty.kind, TypeKind::Access { target: TypeId(0) });
        assert_eq!(ty.constraints.0, "not null access Target");
    }

    #[test]
    fn not_null_access_at_95_emits_unknown_or_skips_gracefully() {
        let source = "package P is type Ptr is not null access Target; end P;";
        let tokens = tokens(source, AdaStandard::Ada95);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada95);

        assert!(types.is_empty() || types[0].kind == TypeKind::Unknown);
    }

    #[test]
    fn interface_type_at_2005() {
        let ty = first_type(
            "package P is type I is interface; end P;",
            AdaStandard::Ada2005,
        );

        assert_eq!(
            ty.kind,
            TypeKind::Interface {
                parents: Vec::new(),
                kind: InterfaceKind::Plain
            }
        );
    }

    #[test]
    fn interface_type_with_parents() {
        let ty = first_type(
            "package P is type I is interface and Parent.One and Parent.Two; end P;",
            AdaStandard::Ada2005,
        );

        assert_eq!(
            ty.kind,
            TypeKind::Interface {
                parents: vec!["Parent.One".to_owned(), "Parent.Two".to_owned()],
                kind: InterfaceKind::Plain
            }
        );
    }

    #[test]
    fn limited_interface_recognises_kind() {
        let ty = first_type(
            "package P is type I is limited interface; end P;",
            AdaStandard::Ada2005,
        );

        assert_eq!(
            ty.kind,
            TypeKind::Interface {
                parents: Vec::new(),
                kind: InterfaceKind::Limited
            }
        );
    }

    #[test]
    fn private_type() {
        let ty = first_type(
            "package P is type T is private; end P;",
            AdaStandard::Ada2012,
        );

        assert_eq!(ty.kind, TypeKind::Private);
        assert_eq!(ty.constraints.0, "private");
    }

    #[test]
    fn limited_private_type_marks_constraints() {
        let ty = first_type(
            "package P is type T is limited private; end P;",
            AdaStandard::Ada2012,
        );

        assert_eq!(ty.kind, TypeKind::Private);
        assert_eq!(ty.constraints.0, "limited private");
    }

    #[test]
    fn generic_formal_type_inside_generic_package() {
        let source = "generic type T is private; package P is end P;";
        let tokens = tokens(source, AdaStandard::Ada2012);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(types.len(), 1);
        assert_eq!(types[0].kind, TypeKind::Generic(FormalKind::Type));
    }

    #[test]
    fn malformed_access_type_does_not_panic() {
        let source = "package P is type Broken is access ; type T is private; end P;";
        let tokens = tokens(source, AdaStandard::Ada2012);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name_path, vec!["t"]);
    }
}
