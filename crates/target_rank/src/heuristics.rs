// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::{
    HandlerOwner, ParamMode, RaiseKind, Span, StructuralAst, Subprogram, SubprogramOwner, TypeKind,
    TypeRef, Visibility,
};

pub fn is_public(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    matches!(sp.visibility, Visibility::Public | Visibility::LibraryLevel) as i32
}

pub fn has_swallowed_when_others_in_pkg(ast: &StructuralAst, sp: &Subprogram) -> i32 {
    let SubprogramOwner::Package(package_id) = sp.owner else {
        return 0;
    };

    ast.handlers.iter().any(|handler| {
        let in_package = match handler.owner {
            HandlerOwner::Subprogram(owner_id) => ast.subprogram(owner_id).is_some_and(
                |owner| matches!(owner.owner, SubprogramOwner::Package(id) if id == package_id),
            ),
            HandlerOwner::PackageBody(id) => id == package_id,
        };
        let is_when_others = handler
            .choices
            .iter()
            .any(|choice| choice.0.eq_ignore_ascii_case("others"));
        let raises_in_body = ast
            .raises
            .iter()
            .any(|raise_site| span_contains(handler.body_span, raise_site.span));

        in_package && is_when_others && !raises_in_body
    }) as i32
}

fn span_contains(outer: Span, inner: Span) -> bool {
    inner.start_byte >= outer.start_byte && inner.end_byte <= outer.end_byte
}

pub fn count_explicit_raises_in_or_below(ast: &StructuralAst, sp: &Subprogram) -> i32 {
    let Some(body_span) = sp.body_span else {
        return 0;
    };

    ast.raises
        .iter()
        .filter(|raise_site| {
            raise_site.kind == RaiseKind::Explicit && span_contains(body_span, raise_site.span)
        })
        .count() as i32
}

pub fn count_handlers_in_or_below(ast: &StructuralAst, sp: &Subprogram) -> i32 {
    let Some(body_span) = sp.body_span else {
        return 0;
    };

    ast.handlers
        .iter()
        .filter(|handler| span_contains(body_span, handler.span))
        .count() as i32
}

pub fn count_fuzzable_params(ast: &StructuralAst, sp: &Subprogram) -> i32 {
    sp.params
        .iter()
        .filter(|param| {
            matches!(
                param.mode,
                ParamMode::In | ParamMode::InOut | ParamMode::AccessMode
            ) && ada_type_is_conservatively_decodable(ast, &param.type_ref, 0)
        })
        .count() as i32
}

pub fn has_unsupported_fuzz_input(ast: &StructuralAst, sp: &Subprogram) -> bool {
    sp.params.iter().any(|param| {
        matches!(
            param.mode,
            ParamMode::In | ParamMode::InOut | ParamMode::AccessMode
        ) && !ada_type_is_conservatively_decodable(ast, &param.type_ref, 0)
    })
}

fn ada_type_is_conservatively_decodable(
    ast: &StructuralAst,
    type_ref: &TypeRef,
    depth: usize,
) -> bool {
    if depth > 8 {
        return false;
    }
    if type_is_untrusted_input(type_ref) {
        return true;
    }
    match &type_ref.kind {
        TypeKind::Scalar(_)
        | TypeKind::Enum(_)
        | TypeKind::Array { .. }
        | TypeKind::Record(_)
        | TypeKind::Discriminated { .. } => true,
        TypeKind::Derived { base } | TypeKind::Access { target: base } => ast
            .types
            .iter()
            .find(|candidate| candidate.id == *base)
            .is_some_and(|base| ada_type_is_conservatively_decodable(ast, base, depth + 1)),
        TypeKind::Tagged { is_abstract, .. } => !is_abstract,
        TypeKind::Interface { .. }
        | TypeKind::Private
        | TypeKind::Generic(_)
        | TypeKind::Unknown => false,
    }
}

/// A subprogram that takes an untrusted-input parameter — the Ada analog of a
/// C byte buffer, and the strongest "this is a parse entry point" signal. An
/// `in`/`in out`/`access` parameter whose type names a string, byte/element
/// array, or stream (`String`, `Unbounded_String`, `Stream_Element_Array`,
/// `Root_Stream_Type`, ...).
pub fn has_untrusted_input_param(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    sp.params.iter().any(|param| {
        matches!(
            param.mode,
            ParamMode::In | ParamMode::InOut | ParamMode::AccessMode
        ) && type_is_untrusted_input(&param.type_ref)
    }) as i32
}

fn type_is_untrusted_input(type_ref: &TypeRef) -> bool {
    let last = type_ref
        .name_path
        .iter()
        .flat_map(|part| part.split('.'))
        .rfind(|part| !part.is_empty())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        last.as_str(),
        "string"
            | "wide_string"
            | "wide_wide_string"
            | "unbounded_string"
            | "unbounded_wide_string"
            | "stream_element_array"
            | "byte_array"
            | "byte_string"
            | "char_array"
    ) || last.contains("stream")
        || last.contains("input_source")
        || last == "buffer"
        || last.ends_with("_buffer")
}

/// The subprogram NAME marks an OUTPUT/serializer (`Write`, `Print`, `Dump`,
/// `Serialize`, `Emit`, `Output`, `To_String`/`To_JSON`/`To_XML`). It turns the
/// program's OWN data into bytes/text, so it is not the attack surface — the
/// Ada analog of the C ranker's `OutputSerializer`. Keeps a DOM `Write`/`Print`
/// from out-ranking the XML `Parse`. `image`/`put`/`encode` are intentionally
/// excluded as too ambiguous (an image-format parser, a container insert).
pub fn has_serializer_subprogram_name(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    const KW: &[&str] = &[
        "write",
        "print",
        "dump",
        "serialize",
        "serialise",
        "emit",
        "output",
        "to",
    ];
    crate::name_semantics::has_action_stem(&sp.name, KW) as i32
}

/// The subprogram NAME marks a parse/read/load entry point. Distinguishes the
/// real parser from same-shape data manipulators (a `Set`/`Merge` that also
/// takes a `String` key).
pub fn has_parser_subprogram_name(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    const KW: &[&str] = &[
        "parse",
        "read",
        "load",
        "decode",
        "lex",
        "scan",
        "deserialize",
        "from",
    ];
    crate::name_semantics::has_action_stem(&sp.name, KW) as i32
}

pub fn has_range_constrained_scalar(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    sp.params.iter().any(|param| {
        matches!(param.type_ref.kind, TypeKind::Scalar(_))
            && !param.type_ref.constraints.0.trim().is_empty()
    }) as i32
}

pub fn has_array_index_or_slice(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    sp.params
        .iter()
        .any(|param| matches!(param.type_ref.kind, TypeKind::Array { .. })) as i32
}

pub fn has_discriminant_or_variant(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    sp.params
        .iter()
        .any(|param| matches!(param.type_ref.kind, TypeKind::Discriminated { .. })) as i32
}

pub fn uses_unchecked_conversion(_ast: &StructuralAst, _sp: &Subprogram) -> i32 {
    // M3+ body-content analysis will detect references to Ada.Unchecked_Conversion.
    0
}

pub fn has_access_param(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    sp.params.iter().any(|param| {
        param.mode == ParamMode::AccessMode
            || matches!(param.type_ref.kind, TypeKind::Access { .. })
    }) as i32
}

pub fn has_tagged_dispatch(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    sp.params
        .iter()
        .any(|param| matches!(param.type_ref.kind, TypeKind::Tagged { .. })) as i32
}

pub fn is_corba_servant_op(_ast: &StructuralAst, _sp: &Subprogram) -> i32 {
    // M11/M12 CORBA analysis will classify servant operations from generated artifacts.
    0
}

pub fn is_idl_op_impl(_ast: &StructuralAst, _sp: &Subprogram) -> i32 {
    // M11/M12 CORBA/IDL analysis will link Ada implementations to IDL operations.
    0
}

pub fn uses_protected_or_task(_ast: &StructuralAst, _sp: &Subprogram) -> i32 {
    // M3+ AST extensions will expose protected/task usage without source re-lexing.
    0
}

pub fn is_trivial_getter_setter(ast: &StructuralAst, sp: &Subprogram) -> i32 {
    let Some(body_span) = sp.body_span else {
        return 0;
    };

    let name = sp.name.to_ascii_lowercase();
    let has_accessor_name = name.starts_with("get_") || name.starts_with("set_");
    let short_body = body_span.end_byte.saturating_sub(body_span.start_byte) < 80;
    let has_handler = ast
        .handlers
        .iter()
        .any(|handler| span_contains(body_span, handler.span));

    (has_accessor_name && short_body && !has_handler && sp.params.len() <= 1) as i32
}

pub fn unconstructible_limited_private(_ast: &StructuralAst, sp: &Subprogram) -> i32 {
    sp.return_type.as_ref().is_some_and(|return_type| {
        matches!(return_type.kind, TypeKind::Private)
            && return_type
                .constraints
                .0
                .to_ascii_lowercase()
                .contains("limited")
    }) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use ada_parser::ast::{
        Aspects, Choice, Constraints, ExceptionHandler, Fields, HandlerId, HandlerOwner, Package,
        PackageId, ParamMode, Parameter, RaiseKind, RaiseSite, RaiseSiteId, ScalarKind, Span,
        SubprogramId, SubprogramKind, SubprogramOwner, TypeId, TypeKind, TypeOwner, TypeRef,
        Visibility,
    };

    fn span(start_byte: u32, end_byte: u32) -> Span {
        Span::new(start_byte, end_byte, 1, 1)
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

    fn subprogram(
        id: u32,
        name: &str,
        owner: SubprogramOwner,
        body_span: Option<Span>,
    ) -> Subprogram {
        Subprogram {
            id: SubprogramId(id),
            owner,
            name: name.to_owned(),
            kind: SubprogramKind::Procedure,
            params: Vec::new(),
            return_type: None,
            is_abstract: false,
            is_dispatching: false,
            is_overriding: false,
            body_span,
            decl_span: span(0, 10),
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility: Visibility::Public,
            is_generic: false,
        }
    }

    fn sp_with_params(params: Vec<Parameter>) -> Subprogram {
        let mut sp = subprogram(
            1,
            "Target",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 80)),
        );
        sp.params = params;
        sp
    }

    fn type_ref(kind: TypeKind) -> TypeRef {
        TypeRef {
            id: TypeId(1),
            name_path: vec!["T".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind,
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        }
    }

    fn constrained_type_ref(kind: TypeKind, constraints: &str) -> TypeRef {
        let mut type_ref = type_ref(kind);
        type_ref.constraints = Constraints(constraints.to_owned());
        type_ref
    }

    fn param(mode: ParamMode, type_ref: TypeRef) -> Parameter {
        Parameter {
            name: "Value".to_owned(),
            mode,
            type_ref,
            default: None,
        }
    }

    fn handler(id: u32, owner: HandlerOwner, choice: &str, body_span: Span) -> ExceptionHandler {
        ExceptionHandler {
            id: HandlerId(id),
            owner,
            choices: vec![Choice(choice.to_owned())],
            binds: None,
            span: body_span,
            body_span,
        }
    }

    fn explicit_raise(id: u32, span: Span) -> RaiseSite {
        RaiseSite {
            id: RaiseSiteId(id),
            kind: RaiseKind::Explicit,
            exception: Some("Constraint_Error".to_owned()),
            message: None,
            span,
        }
    }

    fn reraise(id: u32, span: Span) -> RaiseSite {
        RaiseSite {
            id: RaiseSiteId(id),
            kind: RaiseKind::Reraise,
            exception: None,
            message: None,
            span,
        }
    }

    #[test]
    fn swallowed_when_others_detected_for_subprogram_in_same_package() {
        let pkg = package(1, "P");
        let sp = subprogram(
            1,
            "Dangerous",
            SubprogramOwner::Package(pkg.id),
            Some(span(10, 80)),
        );
        let ast = StructuralAst {
            packages: vec![pkg],
            subprograms: vec![sp.clone()],
            handlers: vec![handler(
                1,
                HandlerOwner::Subprogram(sp.id),
                "others",
                span(50, 70),
            )],
            ..StructuralAst::new()
        };

        assert_eq!(has_swallowed_when_others_in_pkg(&ast, &sp), 1);
    }

    #[test]
    fn non_swallowing_when_others_with_reraise_does_not_trigger() {
        let pkg = package(1, "P");
        let sp = subprogram(
            1,
            "Dangerous",
            SubprogramOwner::Package(pkg.id),
            Some(span(10, 80)),
        );
        let handler_span = span(50, 70);
        let ast = StructuralAst {
            packages: vec![pkg],
            subprograms: vec![sp.clone()],
            handlers: vec![handler(
                1,
                HandlerOwner::Subprogram(sp.id),
                "others",
                handler_span,
            )],
            raises: vec![explicit_raise(1, span(60, 65))],
            ..StructuralAst::new()
        };

        assert_eq!(has_swallowed_when_others_in_pkg(&ast, &sp), 0);
    }

    #[test]
    fn named_choice_handler_does_not_trigger_when_others_flag() {
        let pkg = package(1, "P");
        let sp = subprogram(
            1,
            "Dangerous",
            SubprogramOwner::Package(pkg.id),
            Some(span(10, 80)),
        );
        let ast = StructuralAst {
            packages: vec![pkg],
            subprograms: vec![sp.clone()],
            handlers: vec![handler(
                1,
                HandlerOwner::Subprogram(sp.id),
                "Constraint_Error",
                span(50, 70),
            )],
            ..StructuralAst::new()
        };

        assert_eq!(has_swallowed_when_others_in_pkg(&ast, &sp), 0);
    }

    #[test]
    fn swallowed_handler_in_package_body_initializer_triggers_for_pkg_subprograms() {
        let pkg = package(1, "P");
        let sp = subprogram(
            1,
            "Dangerous",
            SubprogramOwner::Package(pkg.id),
            Some(span(10, 80)),
        );
        let ast = StructuralAst {
            packages: vec![pkg],
            subprograms: vec![sp.clone()],
            handlers: vec![handler(
                1,
                HandlerOwner::PackageBody(PackageId(1)),
                "others",
                span(50, 70),
            )],
            ..StructuralAst::new()
        };

        assert_eq!(has_swallowed_when_others_in_pkg(&ast, &sp), 1);
    }

    #[test]
    fn subprogram_in_different_package_does_not_inherit_flag() {
        let pkg_with_handler = package(1, "P");
        let other_pkg = package(2, "Q");
        let owner_sp = subprogram(
            1,
            "Dangerous",
            SubprogramOwner::Package(pkg_with_handler.id),
            Some(span(10, 80)),
        );
        let other_sp = subprogram(
            2,
            "Boring",
            SubprogramOwner::Package(other_pkg.id),
            Some(span(90, 130)),
        );
        let ast = StructuralAst {
            packages: vec![pkg_with_handler, other_pkg],
            subprograms: vec![owner_sp.clone(), other_sp.clone()],
            handlers: vec![handler(
                1,
                HandlerOwner::Subprogram(owner_sp.id),
                "others",
                span(50, 70),
            )],
            ..StructuralAst::new()
        };

        assert_eq!(has_swallowed_when_others_in_pkg(&ast, &other_sp), 0);
    }

    #[test]
    fn count_explicit_raises_zero_when_none() {
        let sp = subprogram(
            1,
            "Target",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 80)),
        );
        let ast = StructuralAst::new();

        assert_eq!(count_explicit_raises_in_or_below(&ast, &sp), 0);
    }

    #[test]
    fn count_explicit_raises_one_for_single_raise() {
        let sp = subprogram(
            1,
            "Target",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 80)),
        );
        let ast = StructuralAst {
            raises: vec![explicit_raise(1, span(20, 25))],
            ..StructuralAst::new()
        };

        assert_eq!(count_explicit_raises_in_or_below(&ast, &sp), 1);
    }

    #[test]
    fn count_explicit_raises_excludes_reraise() {
        let sp = subprogram(
            1,
            "Target",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 80)),
        );
        let ast = StructuralAst {
            raises: vec![reraise(1, span(20, 25))],
            ..StructuralAst::new()
        };

        assert_eq!(count_explicit_raises_in_or_below(&ast, &sp), 0);
    }

    #[test]
    fn count_explicit_raises_includes_raises_in_nested_subprograms_by_span() {
        let outer = subprogram(
            1,
            "Outer",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 120)),
        );
        let ast = StructuralAst {
            subprograms: vec![
                outer.clone(),
                subprogram(
                    2,
                    "Inner",
                    SubprogramOwner::LibraryLevel,
                    Some(span(40, 80)),
                ),
            ],
            raises: vec![explicit_raise(1, span(50, 55))],
            ..StructuralAst::new()
        };

        assert_eq!(count_explicit_raises_in_or_below(&ast, &outer), 1);
    }

    #[test]
    fn count_handlers_zero_when_none() {
        let sp = subprogram(
            1,
            "Target",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 80)),
        );
        let ast = StructuralAst::new();

        assert_eq!(count_handlers_in_or_below(&ast, &sp), 0);
    }

    #[test]
    fn count_handlers_three_for_three_when_arms() {
        let sp = subprogram(
            1,
            "Target",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 120)),
        );
        let ast = StructuralAst {
            handlers: vec![
                handler(
                    1,
                    HandlerOwner::Subprogram(sp.id),
                    "Constraint_Error",
                    span(20, 30),
                ),
                handler(
                    2,
                    HandlerOwner::Subprogram(sp.id),
                    "Program_Error",
                    span(40, 50),
                ),
                handler(3, HandlerOwner::Subprogram(sp.id), "others", span(60, 70)),
            ],
            ..StructuralAst::new()
        };

        assert_eq!(count_handlers_in_or_below(&ast, &sp), 3);
    }

    #[test]
    fn count_handlers_excludes_other_subprograms() {
        let sp = subprogram(
            1,
            "Target",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 80)),
        );
        let ast = StructuralAst {
            handlers: vec![
                handler(
                    1,
                    HandlerOwner::Subprogram(sp.id),
                    "Constraint_Error",
                    span(20, 30),
                ),
                handler(
                    2,
                    HandlerOwner::Subprogram(SubprogramId(2)),
                    "others",
                    span(100, 120),
                ),
            ],
            ..StructuralAst::new()
        };

        assert_eq!(count_handlers_in_or_below(&ast, &sp), 1);
    }

    #[test]
    fn count_fuzzable_params_zero_for_no_params() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(Vec::new());

        assert_eq!(count_fuzzable_params(&ast, &sp), 0);
    }

    #[test]
    fn count_fuzzable_params_excludes_out_mode() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(ParamMode::Out, type_ref(TypeKind::Unknown))]);

        assert_eq!(count_fuzzable_params(&ast, &sp), 0);
    }

    #[test]
    fn count_fuzzable_params_counts_in_inout_access() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![
            param(
                ParamMode::In,
                type_ref(TypeKind::Scalar(ScalarKind::Integer)),
            ),
            param(
                ParamMode::InOut,
                type_ref(TypeKind::Scalar(ScalarKind::Integer)),
            ),
            param(
                ParamMode::AccessMode,
                type_ref(TypeKind::Scalar(ScalarKind::Integer)),
            ),
        ]);

        assert_eq!(count_fuzzable_params(&ast, &sp), 3);
    }

    #[test]
    fn count_fuzzable_params_counts_default_in_mode() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Scalar(ScalarKind::Integer)),
        )]);

        assert_eq!(count_fuzzable_params(&ast, &sp), 1);
    }

    #[test]
    fn opaque_named_input_is_not_scored_as_fuzzable_and_is_penalized() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(ParamMode::In, type_ref(TypeKind::Unknown))]);

        assert_eq!(count_fuzzable_params(&ast, &sp), 0);
        assert!(has_unsupported_fuzz_input(&ast, &sp));
    }

    #[test]
    fn viable_string_endpoint_outranks_many_opaque_parameters() {
        let ast = StructuralAst::new();
        let opaque = sp_with_params(
            (0..20)
                .map(|_| param(ParamMode::In, type_ref(TypeKind::Unknown)))
                .collect(),
        );
        let mut string = type_ref(TypeKind::Unknown);
        string.name_path = vec!["String".to_owned()];
        let viable = sp_with_params(vec![param(ParamMode::In, string)]);

        let opaque_score = crate::score::score(&ast, &opaque);
        let viable_score = crate::score::score(&ast, &viable);
        assert_eq!(opaque_score.fuzzable_params, 0);
        assert_eq!(opaque_score.harness_viability, -1_000);
        assert!(viable_score.total > opaque_score.total);
    }

    #[test]
    fn has_range_constrained_scalar_returns_one_when_param_is_scalar_with_constraints() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            constrained_type_ref(TypeKind::Scalar(ScalarKind::Integer), "range 1 .. 10"),
        )]);

        assert_eq!(has_range_constrained_scalar(&ast, &sp), 1);
    }

    #[test]
    fn has_range_constrained_scalar_returns_zero_when_param_type_unknown() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            constrained_type_ref(TypeKind::Unknown, "range 1 .. 10"),
        )]);

        assert_eq!(has_range_constrained_scalar(&ast, &sp), 0);
    }

    #[test]
    fn has_range_constrained_scalar_returns_zero_for_unconstrained_scalar() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Scalar(ScalarKind::Integer)),
        )]);

        assert_eq!(has_range_constrained_scalar(&ast, &sp), 0);
    }

    #[test]
    fn untrusted_input_param_detects_string_and_stream_types() {
        let ast = StructuralAst::new();
        let mut string_ty = type_ref(TypeKind::Scalar(ScalarKind::Integer));
        string_ty.name_path = vec!["String".to_owned()];
        let sp = sp_with_params(vec![param(ParamMode::In, string_ty)]);
        assert_eq!(
            has_untrusted_input_param(&ast, &sp),
            1,
            "String input counts"
        );

        let mut int_ty = type_ref(TypeKind::Scalar(ScalarKind::Integer));
        int_ty.name_path = vec!["Integer".to_owned()];
        let sp2 = sp_with_params(vec![param(ParamMode::In, int_ty)]);
        assert_eq!(
            has_untrusted_input_param(&ast, &sp2),
            0,
            "Integer is not input"
        );

        // xmlada's `Input : in out Input_Sources.Input_Source'Class`.
        let mut src_ty = type_ref(TypeKind::Scalar(ScalarKind::Integer));
        src_ty.name_path = vec!["Input_Sources".to_owned(), "Input_Source".to_owned()];
        let sp3 = sp_with_params(vec![param(ParamMode::InOut, src_ty)]);
        assert_eq!(
            has_untrusted_input_param(&ast, &sp3),
            1,
            "stream source counts"
        );
    }

    #[test]
    fn parser_and_serializer_subprogram_names_are_classified() {
        let ast = StructuralAst::new();
        let parser = subprogram(1, "Load_String", SubprogramOwner::LibraryLevel, None);
        assert_eq!(has_parser_subprogram_name(&ast, &parser), 1);
        assert_eq!(has_serializer_subprogram_name(&ast, &parser), 0);

        let writer = subprogram(2, "Write", SubprogramOwner::LibraryLevel, None);
        assert_eq!(has_serializer_subprogram_name(&ast, &writer), 1);
        assert_eq!(has_parser_subprogram_name(&ast, &writer), 0);

        // A value manipulator is neither a parser nor a serializer.
        let neutral = subprogram(3, "Merge", SubprogramOwner::LibraryLevel, None);
        assert_eq!(has_parser_subprogram_name(&ast, &neutral), 0);
        assert_eq!(has_serializer_subprogram_name(&ast, &neutral), 0);

        let download = subprogram(4, "Download_File", SubprogramOwner::LibraryLevel, None);
        assert_eq!(has_parser_subprogram_name(&ast, &download), 0);
        let rewrite = subprogram(5, "Rewrite_Header", SubprogramOwner::LibraryLevel, None);
        assert_eq!(has_serializer_subprogram_name(&ast, &rewrite), 0);
    }

    #[test]
    fn has_array_index_or_slice_returns_one_for_array_param() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Array {
                idx_types: vec![TypeId(1)],
                elem_type: TypeId(2),
                bounds: "1 .. 10".to_owned(),
                elem_name: "Integer".to_owned(),
            }),
        )]);

        assert_eq!(has_array_index_or_slice(&ast, &sp), 1);
    }

    #[test]
    fn has_array_index_or_slice_returns_zero_for_scalar_param() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Scalar(ScalarKind::Integer)),
        )]);

        assert_eq!(has_array_index_or_slice(&ast, &sp), 0);
    }

    #[test]
    fn has_discriminant_or_variant_returns_one_for_discriminated_param() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Discriminated {
                base: TypeId(1),
                discriminants: Fields(vec!["Kind".to_owned()]),
            }),
        )]);

        assert_eq!(has_discriminant_or_variant(&ast, &sp), 1);
    }

    #[test]
    fn has_discriminant_or_variant_returns_zero_for_record_param() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Record(Fields(vec!["Value".to_owned()]))),
        )]);

        assert_eq!(has_discriminant_or_variant(&ast, &sp), 0);
    }

    #[test]
    fn has_access_param_returns_one_for_access_mode_param() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::AccessMode,
            type_ref(TypeKind::Scalar(ScalarKind::Integer)),
        )]);

        assert_eq!(has_access_param(&ast, &sp), 1);
    }

    #[test]
    fn has_access_param_returns_one_for_access_type_param() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Access { target: TypeId(9) }),
        )]);

        assert_eq!(has_access_param(&ast, &sp), 1);
    }

    #[test]
    fn has_access_param_returns_zero_for_in_scalar_param() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Scalar(ScalarKind::Integer)),
        )]);

        assert_eq!(has_access_param(&ast, &sp), 0);
    }

    #[test]
    fn has_tagged_dispatch_returns_one_for_param_of_tagged_type() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Tagged {
                base: TypeId(0),
                is_abstract: false,
            }),
        )]);

        assert_eq!(has_tagged_dispatch(&ast, &sp), 1);
    }

    #[test]
    fn has_tagged_dispatch_returns_zero_for_no_tagged_params() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(vec![param(
            ParamMode::In,
            type_ref(TypeKind::Scalar(ScalarKind::Integer)),
        )]);

        assert_eq!(has_tagged_dispatch(&ast, &sp), 0);
    }

    #[test]
    fn uses_protected_or_task_returns_zero_until_ast_supports_body_content() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(Vec::new());

        assert_eq!(uses_protected_or_task(&ast, &sp), 0);
    }

    #[test]
    fn uses_unchecked_conversion_returns_zero_until_body_content_analysis_exists() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(Vec::new());

        assert_eq!(uses_unchecked_conversion(&ast, &sp), 0);
    }

    #[test]
    fn is_corba_servant_op_returns_zero_until_corba_analysis_exists() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(Vec::new());

        assert_eq!(is_corba_servant_op(&ast, &sp), 0);
    }

    #[test]
    fn is_idl_op_impl_returns_zero_until_idl_analysis_exists() {
        let ast = StructuralAst::new();
        let sp = sp_with_params(Vec::new());

        assert_eq!(is_idl_op_impl(&ast, &sp), 0);
    }

    #[test]
    fn trivial_getter_starting_with_get_returns_one() {
        let ast = StructuralAst::new();
        let mut sp = subprogram(
            1,
            "Get_Value",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 50)),
        );
        sp.kind = SubprogramKind::Function;

        assert_eq!(is_trivial_getter_setter(&ast, &sp), 1);
    }

    #[test]
    fn non_trivial_function_returns_zero() {
        let ast = StructuralAst::new();
        let mut sp = subprogram(
            1,
            "Compute",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 50)),
        );
        sp.kind = SubprogramKind::Function;

        assert_eq!(is_trivial_getter_setter(&ast, &sp), 0);
    }

    #[test]
    fn getter_with_handler_in_body_returns_zero() {
        let mut sp = subprogram(
            1,
            "Get_Value",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 70)),
        );
        sp.kind = SubprogramKind::Function;
        let ast = StructuralAst {
            handlers: vec![handler(
                1,
                HandlerOwner::Subprogram(sp.id),
                "others",
                span(30, 40),
            )],
            ..StructuralAst::new()
        };

        assert_eq!(is_trivial_getter_setter(&ast, &sp), 0);
    }

    #[test]
    fn unconstructible_limited_private_returns_one_for_limited_private_return_type() {
        let ast = StructuralAst::new();
        let mut sp = subprogram(
            1,
            "Make_Private",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 80)),
        );
        sp.kind = SubprogramKind::Function;
        sp.return_type = Some(constrained_type_ref(TypeKind::Private, "limited private"));

        assert_eq!(unconstructible_limited_private(&ast, &sp), 1);
    }

    #[test]
    fn returns_zero_for_regular_private_return_type() {
        let ast = StructuralAst::new();
        let mut sp = subprogram(
            1,
            "Make_Private",
            SubprogramOwner::LibraryLevel,
            Some(span(10, 80)),
        );
        sp.kind = SubprogramKind::Function;
        sp.return_type = Some(constrained_type_ref(TypeKind::Private, "private"));

        assert_eq!(unconstructible_limited_private(&ast, &sp), 0);
    }
}
