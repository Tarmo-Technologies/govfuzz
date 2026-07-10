// SPDX-License-Identifier: Apache-2.0

pub mod aspect;
pub mod constant;
pub mod cursor;
pub mod handler;
pub mod pragma;
pub mod raise_site;
pub mod representation;
pub mod scope;
pub mod statements;
pub mod subprogram;
pub mod type_decl;
pub mod use_clause;

pub use aspect::parse_trailing_aspects;
pub use constant::extract_constants;
pub use cursor::TokenCursor;
pub use handler::extract_handlers;
pub use pragma::extract_unit_pragmas;
pub use raise_site::extract_raises;
pub use representation::{extract_representation_clauses, RepClause};
pub use scope::{build_scope_tree, Scope, ScopeKind, ScopeTree};
pub use statements::extract_statements;
pub use subprogram::{extract_packages, extract_subprograms};
pub use type_decl::extract_types;
pub use use_clause::extract_use_clauses;
