// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::ast::{AdaStandard, Fields, TypeId, TypeKind};
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
    fn array_constrained_type() {
        let ty = first_type("package P is type A is array (1 .. 10) of Integer; end P;");

        assert_eq!(
            ty.kind,
            TypeKind::Array {
                idx_types: Vec::new(),
                elem_type: TypeId(0),
                bounds: "1 .. 10".to_owned(),
                elem_name: "integer".to_owned()
            }
        );
    }

    #[test]
    fn array_unconstrained_type() {
        let ty = first_type("package P is type A is array (Positive range <>) of Integer; end P;");

        assert_eq!(
            ty.kind,
            TypeKind::Array {
                idx_types: Vec::new(),
                elem_type: TypeId(0),
                bounds: "Positive range <>".to_owned(),
                elem_name: "integer".to_owned()
            }
        );
    }

    #[test]
    fn record_with_two_fields() {
        let ty = first_type(
            "package P is type R is record A : Integer; B : Boolean; end record; end P;",
        );

        assert_eq!(
            ty.kind,
            TypeKind::Record(Fields(vec![
                "A : Integer".to_owned(),
                "B : Boolean".to_owned()
            ]))
        );
    }

    #[test]
    fn limited_record_marks_constraints_with_limited() {
        let ty =
            first_type("package P is type R is limited record A : Integer; end record; end P;");

        assert_eq!(
            ty.kind,
            TypeKind::Record(Fields(vec!["A : Integer".to_owned()]))
        );
        assert_eq!(ty.constraints.0, "limited");
    }

    #[test]
    fn discriminated_record_captures_discriminants() {
        let ty = first_type("package P is type R (Size : Positive; Flag : Boolean) is record A : Integer; end record; end P;");

        assert_eq!(
            ty.kind,
            TypeKind::Discriminated {
                base: TypeId(0),
                discriminants: Fields(vec![
                    "Size : Positive".to_owned(),
                    "Flag : Boolean".to_owned()
                ])
            }
        );
    }

    #[test]
    fn derived_type_records_base_name_in_name_path() {
        let ty = first_type("package P is type X is new Parent.T; end P;");

        assert_eq!(ty.kind, TypeKind::Derived { base: TypeId(0) });
        assert_eq!(ty.constraints.0, "Parent.T");
    }

    #[test]
    fn subtype_records_base_name_and_constraints() {
        let ty = first_type("package P is subtype Bytes_24 is Byte_Seq (Index_24); end P;");

        assert_eq!(ty.kind, TypeKind::Derived { base: TypeId(0) });
        assert_eq!(ty.constraints.0, "Byte_Seq (Index_24)");
    }

    #[test]
    fn tagged_record_type() {
        let ty = first_type("package P is type T is tagged record A : Integer; end record; end P;");

        assert_eq!(
            ty.kind,
            TypeKind::Tagged {
                base: TypeId(0),
                is_abstract: false
            }
        );
    }

    #[test]
    fn abstract_tagged_record_type() {
        let ty = first_type(
            "package P is type T is abstract tagged record A : Integer; end record; end P;",
        );

        assert_eq!(
            ty.kind,
            TypeKind::Tagged {
                base: TypeId(0),
                is_abstract: true
            }
        );
    }

    #[test]
    fn malformed_record_type_does_not_panic() {
        let source =
            "package P is type Broken is record A : Integer; type T is range 1 .. 2; end P;";
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name_path, vec!["t"]);
    }

    #[test]
    fn package_body_local_record_does_not_truncate_declarative_span() {
        let source = "package body P is type R is record A : Integer; end record; type Later is range 1 .. 10; begin null; end P;";
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);

        let names = types
            .iter()
            .map(|ty| ty.name_path.as_slice())
            .collect::<Vec<_>>();
        assert!(names.contains(&["r".to_owned()].as_slice()));
        assert!(names.contains(&["later".to_owned()].as_slice()));
    }

    #[test]
    fn subprogram_body_local_record_does_not_truncate_declarative_span() {
        let source = "procedure P is type R is record A : Integer; end record; type Later is range 1 .. 10; begin null; end P;";
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);

        let names = types
            .iter()
            .map(|ty| ty.name_path.as_slice())
            .collect::<Vec<_>>();
        assert!(names.contains(&["r".to_owned()].as_slice()));
        assert!(names.contains(&["later".to_owned()].as_slice()));
    }

    #[test]
    fn nested_subprogram_body_does_not_truncate_outer_declarative_span() {
        let source = "procedure Outer is procedure Inner is type Inner_T is range 1 .. 10; begin null; end; type Later is range 1 .. 10; begin null; end Outer;";
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        let types = extract_types(&tree, source, &tokens, AdaStandard::Ada2012);

        let names = types
            .iter()
            .map(|ty| ty.name_path.as_slice())
            .collect::<Vec<_>>();
        assert!(names.contains(&["inner_t".to_owned()].as_slice()));
        assert!(names.contains(&["later".to_owned()].as_slice()));
    }
}
