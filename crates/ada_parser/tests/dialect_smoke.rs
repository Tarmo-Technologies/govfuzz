// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::{AdaStandard, InterfaceKind, TypeKind};
use ada_parser::reconcile::build_structural_ast;
use std::path::Path;

#[test]
fn ada95_smoke_extracts_subprogram_handler_and_reraise() {
    let source = "pragma Ada_95; procedure P is begin raise Constraint_Error; exception when others => raise; end P;";

    let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada95);
    assert_eq!(ast.subprograms.len(), 1);
    assert_eq!(ast.handlers.len(), 1);
    assert_eq!(ast.raises.len(), 2);
    assert!(ast.raises.iter().all(|raise| raise.message.is_none()));
}

#[test]
fn ada2005_smoke_extracts_raise_message() {
    let source = "pragma Ada_2005; procedure P is begin raise Constraint_Error with \"bad\"; exception when others => null; end P;";

    let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2005);
    assert_eq!(ast.subprograms.len(), 1);
    assert_eq!(ast.handlers.len(), 1);
    assert_eq!(ast.raises.len(), 1);
    assert_eq!(
        ast.raises[0].message.as_ref().map(|expr| expr.0.as_str()),
        Some("\"bad\"")
    );
}

#[test]
fn ada2012_smoke_extracts_aspect_body_handler_and_raise() {
    let source =
        "procedure P with Inline => True is begin null; exception when others => raise; end P;";

    let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2012);
    assert_eq!(ast.subprograms.len(), 1);
    assert_eq!(ast.handlers.len(), 1);
    assert_eq!(ast.raises.len(), 1);
}

#[test]
fn ada2022_smoke_extracts_parallel_body_and_raise() {
    let source = "procedure P is begin parallel do null; end do; raise Constraint_Error; end P;";

    let ast = build_structural_ast(source, None, Path::new("p.adb")).unwrap();

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2022);
    assert_eq!(ast.subprograms.len(), 1);
    assert_eq!(ast.handlers.len(), 0);
    assert_eq!(ast.raises.len(), 1);
}

#[test]
fn dialect_95_extracts_record_and_enum() {
    let source = "pragma Ada_95; package P is type R is record A : Integer; end record; type Color is (Red, Blue); end P;";

    let ast = build_structural_ast(source, None, Path::new("p.ads")).unwrap();

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada95);
    assert_eq!(ast.types.len(), 2);
    assert!(matches!(ast.types[0].kind, TypeKind::Record(_)));
    assert!(matches!(ast.types[1].kind, TypeKind::Enum(_)));
}

#[test]
fn dialect_2005_extracts_interface_and_not_null_access() {
    let source =
        "pragma Ada_2005; package P is type I is interface; type Ptr is not null access I; end P;";

    let ast = build_structural_ast(source, None, Path::new("p.ads")).unwrap();

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2005);
    assert_eq!(ast.types.len(), 2);
    assert_eq!(
        ast.types[0].kind,
        TypeKind::Interface {
            parents: Vec::new(),
            kind: InterfaceKind::Plain
        }
    );
    assert!(matches!(ast.types[1].kind, TypeKind::Access { .. }));
}

#[test]
fn dialect_2012_extracts_record_with_aspect_specification() {
    let source =
        "pragma Ada_2012; package P is type R is record A : Integer; end record with Pack; end P;";

    let ast = build_structural_ast(source, None, Path::new("p.ads")).unwrap();

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2012);
    assert_eq!(ast.types.len(), 1);
    assert_eq!(ast.types[0].aspects.0, vec!["Pack"]);
}

#[test]
fn dialect_2022_extracts_record_with_modern_aspect() {
    let source = "pragma Ada_2022; package P is type R is record A : Integer; end record with Object_Size => 32; end P;";

    let ast = build_structural_ast(source, None, Path::new("p.ads")).unwrap();

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada2022);
    assert_eq!(ast.types.len(), 1);
    assert_eq!(ast.types[0].aspects.0, vec!["Object_Size => 32"]);
}
