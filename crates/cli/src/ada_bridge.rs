// SPDX-License-Identifier: Apache-2.0

//! Private-child harnessing for Ada **private child units**.
//!
//! A private child unit (`private package UnZip.Decompress`, `private package
//! UnZip.Decompress.Huffman`, `private procedure Zip.Compress.Shrink_E`) is
//! visible only inside its parent subsystem and to other PRIVATE descendants
//! (Ada RM 10.1.2), so a separately compiled `procedure Main` cannot `with` it.
//! A *public* re-export bridge does not help either: a public child's body may
//! not depend on a private sibling, so it cannot forward the call.
//!
//! The harness is therefore generated as a **private child subprogram** of the
//! parent — `private procedure UnZip.Decompress.Gf_Harness` — whose own
//! `private procedure` status lets its body see the parent's private part AND
//! `with` the private child it calls. The build picks that file as `Main`.
//! `virtual_bridge_target` re-homes the discovered target so the direct-harness
//! path `with`s the right unit and qualifies the call:
//!   * a target INSIDE a (private child) package re-homes onto a virtual package
//!     named for that unit (`UnZip.Decompress.Huffman.HufT_build`);
//!   * a STANDALONE private child subprogram IS its own unit, so it is called by
//!     its full dotted name directly (`Zip.Compress.Shrink_E (...)`).

use ada_parser::ast::{
    Package, PackageId, StructuralAst, Subprogram, SubprogramKind, SubprogramOwner,
};

/// Build the virtual `(ast, target)` pair the direct-harness path should use so
/// it `with`s the (private) child unit and qualifies the call correctly.
///
/// * A target declared INSIDE a (private child) package is re-homed onto a
///   virtual library-level package named for that unit, so `target_unit_withs`
///   emits `with UnZip.Decompress.Huffman` and the call qualifies as
///   `UnZip.Decompress.Huffman.HufT_build`.
/// * A STANDALONE private child SUBPROGRAM (`private procedure
///   Zip.Compress.Shrink_E`) IS its own compilation unit: it is renamed to its
///   full dotted unit name and kept library-level, so the harness `with`s
///   `Zip.Compress.Shrink_E` and calls `Zip.Compress.Shrink_E (...)` directly
///   (not `....Shrink_E.Shrink_E`).
pub fn virtual_bridge_target(
    ast: &StructuralAst,
    target: &Subprogram,
    unit_name: &str,
) -> (StructuralAst, Subprogram) {
    let mut virtual_target = target.clone();
    if matches!(target.owner, SubprogramOwner::LibraryLevel) {
        virtual_target.name = unit_name.to_owned();
        return (ast.clone(), virtual_target);
    }

    let mut virtual_ast = ast.clone();
    let bridge_id = PackageId(next_package_id(&virtual_ast));
    virtual_ast.packages.push(Package {
        id: bridge_id,
        name: unit_name.to_owned(),
        // No parent: `package_root_name` then returns the full dotted name, so
        // the harness `with`s the real child compilation unit rather than only
        // the root.
        parent: None,
        is_generic: false,
        is_private: false,
        formals: Vec::new(),
        decls: Vec::new(),
    });
    virtual_target.owner = SubprogramOwner::Package(bridge_id);
    (virtual_ast, virtual_target)
}

fn next_package_id(ast: &StructuralAst) -> u32 {
    ast.packages
        .iter()
        .map(|pkg| pkg.id.0)
        .max()
        .map(|max| max + 1)
        .unwrap_or(0)
}

/// Whether `target` is a plain subprogram (only subprograms are harnessable this
/// way, not entries/etc.).
pub fn target_is_bridgeable(target: &Subprogram) -> bool {
    matches!(
        target.kind,
        SubprogramKind::Procedure | SubprogramKind::Function
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ada_parser::ast::{
        Aspects, Constraints, Expr, ParamMode, Parameter, Span, TypeKind, TypeOwner, TypeRef,
        Visibility,
    };
    use ada_parser::ast::{SubprogramId, TypeId};

    fn type_ref(name: &str) -> TypeRef {
        TypeRef {
            id: TypeId(0),
            name_path: vec![name.to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind: TypeKind::Scalar(ada_parser::ast::ScalarKind::Integer),
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        }
    }

    fn target(name: &str, owner: SubprogramOwner) -> Subprogram {
        Subprogram {
            id: SubprogramId(1),
            owner,
            name: name.to_owned(),
            kind: SubprogramKind::Procedure,
            params: vec![Parameter {
                name: "N".to_owned(),
                mode: ParamMode::In,
                type_ref: type_ref("Integer"),
                default: None::<Expr>,
            }],
            return_type: None,
            is_abstract: false,
            is_dispatching: false,
            is_overriding: false,
            body_span: None,
            decl_span: Span::new(0, 10, 1, 1),
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility: Visibility::Public,
            is_generic: false,
        }
    }

    #[test]
    fn target_is_bridgeable_accepts_subprograms() {
        assert!(target_is_bridgeable(&target(
            "Op",
            SubprogramOwner::LibraryLevel
        )));
    }

    #[test]
    fn package_member_rehomes_onto_full_dotted_virtual_package() {
        // A target inside a (private child) package is called <unit>.<name>.
        let ast = StructuralAst::default();
        let tgt = target("HufT_build", SubprogramOwner::Package(PackageId(1)));
        let (vast, vtarget) = virtual_bridge_target(&ast, &tgt, "UnZip.Decompress.Huffman");

        let pkg = vast.packages.last().unwrap();
        assert_eq!(pkg.name, "UnZip.Decompress.Huffman");
        assert_eq!(pkg.parent, None);
        assert_eq!(vtarget.owner, SubprogramOwner::Package(pkg.id));
        assert_eq!(vtarget.name, "HufT_build");
    }

    #[test]
    fn standalone_subprogram_is_called_by_its_full_unit_name() {
        // A standalone private child subprogram IS its own unit: it is renamed to
        // the full dotted unit name and stays library-level, so it is `with`ed
        // and called as `Zip.Compress.Shrink_E`, not `...Shrink_E.Shrink_E`.
        let ast = StructuralAst::default();
        let tgt = target("Shrink_E", SubprogramOwner::LibraryLevel);
        let (vast, vtarget) = virtual_bridge_target(&ast, &tgt, "Zip.Compress.Shrink_E");

        assert_eq!(vtarget.name, "Zip.Compress.Shrink_E");
        assert_eq!(vtarget.owner, SubprogramOwner::LibraryLevel);
        // No virtual package is added for the standalone case.
        assert_eq!(vast.packages.len(), ast.packages.len());
    }
}
