// SPDX-License-Identifier: Apache-2.0

use crate::{score, Target};
use ada_parser::ast::StructuralAst;

pub fn rank_targets(ast: &StructuralAst) -> Vec<Target> {
    let mut targets = ast
        .subprograms
        .iter()
        .map(|subprogram| {
            let breakdown = score::score(ast, subprogram);
            Target {
                subprogram_id: subprogram.id,
                name: subprogram.name.clone(),
                score: breakdown.total,
                breakdown,
            }
        })
        .collect::<Vec<_>>();
    targets.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.name.cmp(&right.name))
    });
    targets
}
