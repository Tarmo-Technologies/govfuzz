// SPDX-License-Identifier: Apache-2.0

pub use ada_parser::ast::{StructuralAst, Subprogram, SubprogramId};

pub mod c_rank;
pub mod go_rank;
pub mod heuristics;
pub mod java_rank;
pub mod perl_rank;
pub mod python_rank;
pub mod rank;
pub mod rust_rank;
pub mod score;

pub use c_rank::{
    classify_input_reachability, cpp_target_name, rank_c_targets, rank_cpp_targets,
    CScoreBreakdown, CTarget, InputReachability,
};
pub use go_rank::{rank_go_targets, GoScoreBreakdown, GoTarget};
pub use java_rank::{
    java_target_has_byte_channel, rank_java_targets, JavaScoreBreakdown, JavaTarget,
};
pub use perl_rank::{rank_perl_targets, PerlScoreBreakdown, PerlTarget};
pub use python_rank::{rank_python_targets, PythonScoreBreakdown, PythonTarget};
pub use rank::rank_targets;
pub use rust_rank::{rank_rust_targets, RustScoreBreakdown, RustTarget};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Target {
    pub subprogram_id: SubprogramId,
    pub name: String,
    pub score: i32,
    pub breakdown: ScoreBreakdown,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Serialize)]
pub struct ScoreBreakdown {
    pub is_public: i32,
    pub swallowed_when_others_in_pkg: i32,
    pub explicit_raises_in_or_below: i32,
    pub handlers_in_or_below: i32,
    /// Bonus when a subprogram takes an untrusted-input parameter — a `String`,
    /// `Stream_Element_Array`, byte array, or stream type. This is the Ada analog
    /// of the C ranker's byte-buffer bonus: a `Load_String(Content : String)`
    /// parse entry is the real attack surface, but without it that entry scored
    /// the same as a 1-arg getter and ranked below multi-arg value setters.
    pub untrusted_input_param: i32,
    /// Bonus when the subprogram NAME marks it a parse/read/load entry point
    /// (`Parse`, `Read`, `Load`, `Decode`, `Lex`, `Scan`, `Deserialize`,
    /// `Import`). Distinguishes the parser from same-shape data manipulators.
    pub parser_subprogram_name: i32,
    /// Penalty when the subprogram NAME marks it an output/serializer
    /// (`Write`, `Print`, `Dump`, `Serialize`, `To_String`): it emits the
    /// program's own data, so it is not the attack surface — the Ada analog of
    /// the C `OutputSerializer`. Keeps a DOM `Write` from out-ranking `Parse`.
    pub serializer_subprogram_name: i32,
    pub fuzzable_params: i32,
    /// Conservative generation-viability penalty. A signature containing a
    /// parameter whose structural type cannot be decoded remains discoverable,
    /// but must not displace a proven byte/scalar/aggregate endpoint under a cap.
    pub harness_viability: i32,
    pub range_constrained_scalar: i32,
    pub array_index_or_slice: i32,
    pub discriminant_or_variant: i32,
    pub unchecked_conversion: i32,
    pub access_param: i32,
    pub tagged_dispatch: i32,
    pub corba_servant_op: i32,
    pub idl_op_impl: i32,
    pub protected_or_task: i32,
    pub trivial_getter_setter: i32,
    pub unconstructible_limited_private: i32,
    pub total: i32,
}

pub fn crate_name() -> &'static str {
    "target_rank"
}

#[cfg(test)]
mod tests {
    use super::{heuristics, rank, score};
    use ada_parser::ast::{
        Span, StructuralAst, Subprogram, SubprogramId, SubprogramKind, SubprogramOwner, Visibility,
    };

    fn sp_with_visibility(visibility: Visibility) -> Subprogram {
        sp(1, "Target", visibility)
    }

    fn sp(id: u32, name: &str, visibility: Visibility) -> Subprogram {
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
            body_span: None,
            decl_span: Span::new(0, 10, 1, 1),
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility,
            is_generic: false,
        }
    }

    #[test]
    fn is_public_returns_one_for_public_subprogram() {
        let ast = StructuralAst::new();
        let sp = sp_with_visibility(Visibility::Public);

        assert_eq!(heuristics::is_public(&ast, &sp), 1);
    }

    #[test]
    fn is_public_returns_one_for_library_level_subprogram() {
        let ast = StructuralAst::new();
        let sp = sp_with_visibility(Visibility::LibraryLevel);

        assert_eq!(heuristics::is_public(&ast, &sp), 1);
    }

    #[test]
    fn is_public_returns_zero_for_local_subprogram() {
        let ast = StructuralAst::new();
        let sp = sp_with_visibility(Visibility::Local);

        assert_eq!(heuristics::is_public(&ast, &sp), 0);
    }

    #[test]
    fn score_for_pure_public_returns_20() {
        let ast = StructuralAst::new();
        let sp = sp_with_visibility(Visibility::Public);

        let breakdown = score::score(&ast, &sp);

        assert_eq!(breakdown.is_public, 20);
        assert_eq!(breakdown.total, 20);
    }

    #[test]
    fn score_breakdown_total_equals_field_sum() {
        let ast = StructuralAst::new();
        let sp = sp_with_visibility(Visibility::Public);

        let breakdown = score::score(&ast, &sp);
        let field_sum = breakdown.is_public
            + breakdown.swallowed_when_others_in_pkg
            + breakdown.explicit_raises_in_or_below
            + breakdown.handlers_in_or_below
            + breakdown.fuzzable_params
            + breakdown.harness_viability
            + breakdown.range_constrained_scalar
            + breakdown.array_index_or_slice
            + breakdown.discriminant_or_variant
            + breakdown.unchecked_conversion
            + breakdown.access_param
            + breakdown.tagged_dispatch
            + breakdown.corba_servant_op
            + breakdown.idl_op_impl
            + breakdown.protected_or_task
            + breakdown.trivial_getter_setter
            + breakdown.unconstructible_limited_private;

        assert_eq!(breakdown.total, field_sum);
    }

    #[test]
    fn score_for_local_only_subprogram_is_zero() {
        let ast = StructuralAst::new();
        let sp = sp_with_visibility(Visibility::Local);

        let breakdown = score::score(&ast, &sp);

        assert_eq!(breakdown.total, 0);
    }

    #[test]
    fn rank_targets_returns_descending_by_score() {
        let ast = StructuralAst {
            subprograms: vec![
                sp(1, "Low", Visibility::Local),
                sp(2, "High", Visibility::Public),
            ],
            ..StructuralAst::new()
        };

        let targets = rank::rank_targets(&ast);

        assert_eq!(targets[0].name, "High");
        assert_eq!(targets[1].name, "Low");
    }

    #[test]
    fn rank_targets_breaks_ties_by_name() {
        let ast = StructuralAst {
            subprograms: vec![
                sp(1, "Zulu", Visibility::Public),
                sp(2, "Alpha", Visibility::Public),
            ],
            ..StructuralAst::new()
        };

        let targets = rank::rank_targets(&ast);

        assert_eq!(targets[0].name, "Alpha");
        assert_eq!(targets[1].name, "Zulu");
    }

    #[test]
    fn rank_targets_empty_for_empty_ast() {
        let ast = StructuralAst::new();

        assert!(rank::rank_targets(&ast).is_empty());
    }
}
