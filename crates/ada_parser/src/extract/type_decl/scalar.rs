// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::ast::{AdaStandard, ScalarKind, TypeKind, TypeOwner, Visibility};
    use crate::extract::{build_scope_tree, extract_types};
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2012)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    fn first_type(source: &str) -> crate::ast::TypeRef {
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        extract_types(&tree, source, &tokens, AdaStandard::Ada2012)
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn integer_range_type() {
        let ty = first_type("package P is type T is range -10 .. 10; end P;");

        assert_eq!(ty.name_path, vec!["t"]);
        assert_eq!(ty.kind, TypeKind::Scalar(ScalarKind::Integer));
        assert_eq!(ty.constraints.0, "-10 .. 10");
    }

    #[test]
    fn modular_type() {
        let ty = first_type("package P is type M is mod 256; end P;");

        assert_eq!(ty.kind, TypeKind::Scalar(ScalarKind::Modular));
        assert_eq!(ty.constraints.0, "256");
    }

    #[test]
    fn float_type_with_digits_only() {
        let ty = first_type("package P is type F is digits 6; end P;");

        assert_eq!(ty.kind, TypeKind::Scalar(ScalarKind::Float));
        assert_eq!(ty.constraints.0, "digits 6");
    }

    #[test]
    fn float_type_with_digits_and_range() {
        let ty = first_type("package P is type F is digits 6 range -1.0 .. 1.0; end P;");

        assert_eq!(ty.kind, TypeKind::Scalar(ScalarKind::Float));
        assert_eq!(ty.constraints.0, "digits 6 range -1.0 .. 1.0");
    }

    #[test]
    fn fixed_type() {
        let ty = first_type("package P is type Fx is delta 0.01 range -1.0 .. 1.0; end P;");

        assert_eq!(ty.kind, TypeKind::Scalar(ScalarKind::Fixed));
        assert_eq!(ty.constraints.0, "delta 0.01 range -1.0 .. 1.0");
    }

    #[test]
    fn decimal_type() {
        let ty = first_type("package P is type D is delta 0.01 digits 18; end P;");

        assert_eq!(ty.kind, TypeKind::Scalar(ScalarKind::Decimal));
        assert_eq!(ty.constraints.0, "delta 0.01 digits 18");
    }

    #[test]
    fn enum_type_three_literals() {
        let ty = first_type("package P is type Color is (Red, Green, Blue); end P;");

        assert_eq!(
            ty.kind,
            TypeKind::Enum(vec![
                "red".to_owned(),
                "green".to_owned(),
                "blue".to_owned()
            ])
        );
    }

    #[test]
    fn enum_type_with_character_literals() {
        let ty = first_type("package P is type Hex is ('0', '1', 'A', 'F'); end P;");

        assert_eq!(
            ty.kind,
            TypeKind::Enum(vec![
                "'0'".to_owned(),
                "'1'".to_owned(),
                "'A'".to_owned(),
                "'F'".to_owned()
            ])
        );
    }

    #[test]
    fn range_type_in_package_spec_declarative_part() {
        let source =
            "package P is type T is range 1 .. 10; private type Hidden is range 1 .. 2; end P;";
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(types.len(), 2);
        assert_eq!(types[0].name_path, vec!["t"]);
        assert_eq!(types[1].name_path, vec!["hidden"]);
    }

    #[test]
    fn private_type_in_package_spec_is_extracted_with_private_visibility() {
        let source = "package P is type Public_T is private; private type Hidden_T is range 1 .. 10; type Public_T is record A : Integer; end record; end P;";
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);

        let public_types = types
            .iter()
            .filter(|ty| ty.name_path == vec!["public_t"])
            .collect::<Vec<_>>();
        assert_eq!(public_types.len(), 2);
        assert_eq!(public_types[0].visibility, Visibility::Public);
        assert_eq!(public_types[0].kind, TypeKind::Private);
        assert_eq!(public_types[1].visibility, Visibility::Private);
        assert!(matches!(public_types[1].kind, TypeKind::Record(_)));

        let hidden = types
            .iter()
            .find(|ty| ty.name_path == vec!["hidden_t"])
            .unwrap();
        assert_eq!(hidden.visibility, Visibility::Private);
        assert_eq!(hidden.kind, TypeKind::Scalar(ScalarKind::Integer));
    }

    #[test]
    fn library_level_type_outside_any_package_has_library_level_owner() {
        let source = "procedure Main is type Local_T is range 1 .. 10; begin null; end Main;";
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);
        let local = types
            .iter()
            .find(|ty| ty.name_path == vec!["local_t"])
            .unwrap();

        assert!(matches!(&local.owner, TypeOwner::Subprogram(_)));
        assert_eq!(local.visibility, Visibility::Local);
    }

    #[test]
    fn malformed_scalar_type_does_not_panic() {
        let source = "package P is type Broken is range 1 .. ; type T is range 1 .. 2; end P;";
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name_path, vec!["t"]);
    }
}
