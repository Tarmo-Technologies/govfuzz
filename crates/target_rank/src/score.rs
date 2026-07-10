// SPDX-License-Identifier: Apache-2.0

use crate::{heuristics, ScoreBreakdown};
use ada_parser::ast::{StructuralAst, Subprogram};

pub fn score(ast: &StructuralAst, sp: &Subprogram) -> ScoreBreakdown {
    let mut breakdown = ScoreBreakdown::default();
    breakdown.is_public = 20 * heuristics::is_public(ast, sp);
    breakdown.swallowed_when_others_in_pkg =
        15 * heuristics::has_swallowed_when_others_in_pkg(ast, sp);
    breakdown.explicit_raises_in_or_below =
        10 * heuristics::count_explicit_raises_in_or_below(ast, sp);
    breakdown.handlers_in_or_below = 8 * heuristics::count_handlers_in_or_below(ast, sp);
    breakdown.untrusted_input_param = 15 * heuristics::has_untrusted_input_param(ast, sp);
    breakdown.parser_subprogram_name = 15 * heuristics::has_parser_subprogram_name(ast, sp);
    breakdown.serializer_subprogram_name =
        -20 * heuristics::has_serializer_subprogram_name(ast, sp);
    breakdown.fuzzable_params = 5 * heuristics::count_fuzzable_params(ast, sp);
    breakdown.range_constrained_scalar = 5 * heuristics::has_range_constrained_scalar(ast, sp);
    breakdown.array_index_or_slice = 4 * heuristics::has_array_index_or_slice(ast, sp);
    breakdown.discriminant_or_variant = 4 * heuristics::has_discriminant_or_variant(ast, sp);
    breakdown.unchecked_conversion = 4 * heuristics::uses_unchecked_conversion(ast, sp);
    breakdown.access_param = 4 * heuristics::has_access_param(ast, sp);
    breakdown.tagged_dispatch = 3 * heuristics::has_tagged_dispatch(ast, sp);
    breakdown.corba_servant_op = 3 * heuristics::is_corba_servant_op(ast, sp);
    breakdown.idl_op_impl = 3 * heuristics::is_idl_op_impl(ast, sp);
    breakdown.protected_or_task = 2 * heuristics::uses_protected_or_task(ast, sp);
    breakdown.trivial_getter_setter = -3 * heuristics::is_trivial_getter_setter(ast, sp);
    breakdown.unconstructible_limited_private =
        -10 * heuristics::unconstructible_limited_private(ast, sp);
    breakdown.total = breakdown.is_public
        + breakdown.swallowed_when_others_in_pkg
        + breakdown.explicit_raises_in_or_below
        + breakdown.handlers_in_or_below
        + breakdown.untrusted_input_param
        + breakdown.parser_subprogram_name
        + breakdown.serializer_subprogram_name
        + breakdown.fuzzable_params
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
    breakdown
}
