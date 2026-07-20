// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    AdaStandard, Aspects, Constraints, Expr, Package, PackageId, ParamMode, Parameter, Subprogram,
    SubprogramId, SubprogramKind, SubprogramOwner, TypeId, TypeKind, TypeOwner, TypeRef,
    Visibility,
};
use crate::extract::{Scope, ScopeKind, ScopeTree};
use crate::lexer::{Token, TokenKind};
use std::collections::HashMap;

pub fn extract_packages(scope_tree: &ScopeTree, _source: &str, _tokens: &[Token]) -> Vec<Package> {
    build_package_index(scope_tree).packages
}

pub fn extract_subprograms(
    scope_tree: &ScopeTree,
    source: &str,
    tokens: &[Token],
    dialect: AdaStandard,
) -> Vec<Subprogram> {
    let package_index = build_package_index(scope_tree);
    let mut subprograms = Vec::new();
    let mut type_id = 0u32;

    for (scope_index, scope) in scope_tree.scopes.iter().enumerate() {
        if !matches!(
            scope.kind,
            ScopeKind::SubprogramSpec | ScopeKind::SubprogramBody
        ) {
            continue;
        }

        let Some(start_index) = scope_start_index(tokens, scope) else {
            continue;
        };
        let owner = nearest_package_owner(scope_tree, &package_index.scope_ids, scope.parent)
            .map(SubprogramOwner::Package)
            .unwrap_or(SubprogramOwner::LibraryLevel);
        let params = parse_parameters(source, tokens, start_index, &mut type_id);
        let return_type = parse_return_type(tokens, start_index, &mut type_id);
        let id = SubprogramId(subprograms.len() as u32);

        subprograms.push(Subprogram {
            id,
            owner,
            name: scope.name.clone(),
            kind: subprogram_kind(tokens, start_index),
            params,
            return_type,
            is_abstract: scope_is_abstract(tokens, start_index),
            is_dispatching: false,
            is_overriding: dialect >= AdaStandard::Ada2005
                && start_index
                    .checked_sub(1)
                    .and_then(|previous| tokens.get(previous))
                    .is_some_and(|token| token.effective_kind == TokenKind::KwOverriding),
            body_span: scope.body_span,
            decl_span: scope.decl_span,
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility: visibility_for_scope(scope_tree, tokens, scope_index),
            is_generic: scope.is_generic,
        });
    }

    subprograms
}

struct PackageIndex {
    packages: Vec<Package>,
    scope_ids: Vec<Option<PackageId>>,
}

fn build_package_index(scope_tree: &ScopeTree) -> PackageIndex {
    let mut packages: Vec<Package> = Vec::new();
    let mut scope_ids = vec![None; scope_tree.scopes.len()];
    let mut by_name: HashMap<String, PackageId> = HashMap::new();

    for (scope_index, scope) in scope_tree.scopes.iter().enumerate() {
        if !matches!(scope.kind, ScopeKind::PackageSpec | ScopeKind::PackageBody) {
            continue;
        }

        if let Some(existing) = by_name.get(&scope.name).copied() {
            scope_ids[scope_index] = Some(existing);
            if let Some(package) = packages.get_mut(existing.0 as usize) {
                package.is_generic |= scope.is_generic;
            }
            continue;
        }

        let id = PackageId(packages.len() as u32);
        let parent = package_parent(scope_tree, &scope_ids, &by_name, scope);
        packages.push(Package {
            id,
            name: scope.name.clone(),
            parent,
            is_generic: scope.is_generic,
            formals: Vec::new(),
            decls: Vec::new(),
            is_private: scope_in_parent_private_part(scope_tree, scope),
        });
        by_name.insert(scope.name.clone(), id);
        scope_ids[scope_index] = Some(id);
    }

    PackageIndex {
        packages,
        scope_ids,
    }
}

/// Whether this package scope is declared inside its enclosing package's
/// `private` part — making it a private nested package whose entities are not
/// externally visible.
fn scope_in_parent_private_part(scope_tree: &ScopeTree, scope: &Scope) -> bool {
    let Some(parent_index) = scope.parent else {
        return false;
    };
    let Some(parent) = scope_tree.scopes.get(parent_index) else {
        return false;
    };
    let Some(private_span) = &parent.private_declarative_span else {
        return false;
    };
    scope.decl_span.start_byte >= private_span.start_byte
        && scope.decl_span.start_byte < private_span.end_byte
}

fn package_parent(
    scope_tree: &ScopeTree,
    scope_ids: &[Option<PackageId>],
    by_name: &HashMap<String, PackageId>,
    scope: &Scope,
) -> Option<PackageId> {
    if let Some(parent) = nearest_package_owner(scope_tree, scope_ids, scope.parent) {
        return Some(parent);
    }

    scope
        .name
        .rfind('.')
        .and_then(|dot| by_name.get(&scope.name[..dot]).copied())
}

fn nearest_package_owner(
    scope_tree: &ScopeTree,
    scope_ids: &[Option<PackageId>],
    mut parent: Option<usize>,
) -> Option<PackageId> {
    while let Some(scope_index) = parent {
        if let Some(package_id) = scope_ids.get(scope_index).and_then(|id| *id) {
            return Some(package_id);
        }
        parent = scope_tree
            .scopes
            .get(scope_index)
            .and_then(|scope| scope.parent);
    }

    None
}

fn scope_start_index(tokens: &[Token], scope: &Scope) -> Option<usize> {
    tokens
        .iter()
        .position(|token| token.text_span.start == scope.decl_span.start_byte)
}

fn subprogram_kind(tokens: &[Token], start_index: usize) -> SubprogramKind {
    match tokens.get(start_index).map(|token| &token.effective_kind) {
        Some(TokenKind::KwFunction) => SubprogramKind::Function,
        Some(TokenKind::KwEntry) => SubprogramKind::Entry,
        _ => SubprogramKind::Procedure,
    }
}

fn parse_parameters(
    source: &str,
    tokens: &[Token],
    start_index: usize,
    type_id: &mut u32,
) -> Vec<Parameter> {
    let Some((_, after_name)) = parse_dotted_name(tokens, start_index.saturating_add(1)) else {
        return Vec::new();
    };
    if !kind_at(tokens, after_name, &TokenKind::LParen) {
        return Vec::new();
    }

    let Some(close_index) = find_matching_rparen(tokens, after_name) else {
        return Vec::new();
    };
    let mut params = Vec::new();
    let mut index = after_name.saturating_add(1);

    while index < close_index {
        skip_param_separators(tokens, &mut index);
        if index >= close_index {
            break;
        }

        let (names, after_names) = parse_param_names(tokens, index, close_index);
        if names.is_empty() || !kind_at(tokens, after_names, &TokenKind::Colon) {
            index = index.saturating_add(1);
            continue;
        }

        index = after_names.saturating_add(1);
        let (mode, is_aliased, is_not_null_access) = parse_param_mode(tokens, &mut index);
        let type_start = index;
        let type_end = find_param_type_end(tokens, index, close_index);
        let type_name = type_name_from_tokens(tokens, type_start, type_end);
        // For an anonymous access-to-subprogram formal, the words inside the
        // callback profile are not a dotted type name. Preserve the full profile
        // structurally so harness generation can synthesize a conforming callback
        // or pass null. Without this, `access function (Recipient : Address)
        // return Boolean` becomes the bogus type `Recipient.Address.Boolean`.
        let anonymous_subprogram_profile = (matches!(mode, ParamMode::AccessMode)
            && matches!(
                tokens.get(type_start).map(|token| &token.effective_kind),
                Some(TokenKind::KwFunction | TokenKind::KwProcedure)
            ))
        .then(|| {
            source_text(source, tokens, type_start, type_end)
                .unwrap_or_default()
                .trim()
                .to_owned()
        });
        index = type_end;

        let default = if kind_at(tokens, index, &TokenKind::Assign) {
            let default_start = index.saturating_add(1);
            let default_end = find_param_default_end(tokens, default_start, close_index);
            index = default_end;
            source_text(source, tokens, default_start, default_end).map(Expr)
        } else {
            None
        };

        for name in names {
            let mut type_ref = if let Some(profile) = &anonymous_subprogram_profile {
                TypeRef {
                    id: TypeId(*type_id),
                    name_path: Vec::new(),
                    visibility: Visibility::LibraryLevel,
                    owner: TypeOwner::LibraryLevel,
                    kind: TypeKind::Access { target: TypeId(0) },
                    constraints: Constraints(profile.clone()),
                    aspects: Aspects(Vec::new()),
                }
            } else {
                unknown_type_ref(*type_id, type_name.clone())
            };
            if is_aliased {
                // An `aliased` formal requires the harness local to be `aliased`
                // too. Carry it as a marker on the formal's type_ref aspects (read
                // back before type resolution, which replaces the type_ref).
                type_ref.aspects.0.push("aliased".to_owned());
            }
            if is_not_null_access {
                type_ref.aspects.0.push("not_null_access".to_owned());
            }
            params.push(Parameter {
                name,
                mode: mode.clone(),
                type_ref,
                default: default.clone(),
            });
            *type_id = (*type_id).saturating_add(1);
        }
    }

    params
}

fn parse_param_names(
    tokens: &[Token],
    mut index: usize,
    close_index: usize,
) -> (Vec<String>, usize) {
    let mut names = Vec::new();

    while index < close_index {
        let Some(name) = identifier_text(tokens.get(index)) else {
            break;
        };
        names.push(name);
        index = index.saturating_add(1);

        if !kind_at(tokens, index, &TokenKind::Comma) {
            break;
        }

        let next_name = index.saturating_add(1);
        if !token_range_contains_colon_before_separator(tokens, next_name, close_index) {
            break;
        }
        index = next_name;
    }

    (names, index)
}

fn token_range_contains_colon_before_separator(
    tokens: &[Token],
    mut index: usize,
    close_index: usize,
) -> bool {
    while index < close_index {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::Colon) => return true,
            Some(TokenKind::Semicolon | TokenKind::Assign | TokenKind::RParen) => return false,
            Some(_) => index = index.saturating_add(1),
            None => return false,
        }
    }

    false
}

fn skip_param_separators(tokens: &[Token], index: &mut usize) {
    while matches!(
        tokens.get(*index).map(|token| &token.effective_kind),
        Some(TokenKind::Semicolon | TokenKind::Comma)
    ) {
        *index = (*index).saturating_add(1);
    }
}

/// Parse the optional mode prefix of a formal parameter, returning the mode and
/// whether the formal is `aliased` (`procedure P (X : aliased T)`).
fn parse_param_mode(tokens: &[Token], index: &mut usize) -> (ParamMode, bool, bool) {
    let is_aliased = consume_kind(tokens, index, &TokenKind::KwAliased);

    if consume_kind(tokens, index, &TokenKind::KwNot) {
        consume_kind(tokens, index, &TokenKind::KwNull);
        if consume_kind(tokens, index, &TokenKind::KwAccess) {
            return (ParamMode::AccessMode, is_aliased, true);
        }
    }

    let mode = if consume_kind(tokens, index, &TokenKind::KwIn) {
        if consume_kind(tokens, index, &TokenKind::KwOut) {
            ParamMode::InOut
        } else {
            ParamMode::In
        }
    } else if consume_kind(tokens, index, &TokenKind::KwOut) {
        ParamMode::Out
    } else if consume_kind(tokens, index, &TokenKind::KwAccess) {
        ParamMode::AccessMode
    } else {
        ParamMode::In
    };
    (mode, is_aliased, false)
}

fn find_param_type_end(tokens: &[Token], mut index: usize, close_index: usize) -> usize {
    let mut paren_depth = 0u32;

    while index < close_index {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
            Some(TokenKind::Assign | TokenKind::Semicolon | TokenKind::Comma)
                if paren_depth == 0 =>
            {
                return index;
            }
            Some(_) => {}
            None => return index,
        }
        index = index.saturating_add(1);
    }

    index
}

fn find_param_default_end(tokens: &[Token], mut index: usize, close_index: usize) -> usize {
    let mut paren_depth = 0u32;

    while index < close_index {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
            Some(TokenKind::Semicolon | TokenKind::Comma) if paren_depth == 0 => return index,
            Some(_) => {}
            None => return index,
        }
        index = index.saturating_add(1);
    }

    index
}

fn parse_return_type(tokens: &[Token], start_index: usize, type_id: &mut u32) -> Option<TypeRef> {
    if !kind_at(tokens, start_index, &TokenKind::KwFunction) {
        return None;
    }

    let return_index = find_keyword_after_header(tokens, start_index, &TokenKind::KwReturn)?;
    let type_start = return_index.saturating_add(1);
    let type_end = find_return_type_end(tokens, type_start);
    let type_ref = unknown_type_ref(
        *type_id,
        type_name_from_tokens(tokens, type_start, type_end),
    );
    *type_id = (*type_id).saturating_add(1);

    Some(type_ref)
}

fn find_keyword_after_header(
    tokens: &[Token],
    mut index: usize,
    kind: &TokenKind,
) -> Option<usize> {
    let mut paren_depth = 0u32;

    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
            Some(TokenKind::Semicolon | TokenKind::KwIs) if paren_depth == 0 => return None,
            Some(current) if current == kind && paren_depth == 0 => return Some(index),
            Some(_) => {}
            None => return None,
        }
        index = index.saturating_add(1);
    }

    None
}

fn find_return_type_end(tokens: &[Token], mut index: usize) -> usize {
    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            // `renames` ends the return type too: a renaming declaration
            // (`function F (...) return PKZip_Format renames Format_from_Code;`)
            // otherwise folds the renamed-to name into the type
            // ("Pkzip_Format.Format_From_Code").
            Some(
                TokenKind::KwIs | TokenKind::Semicolon | TokenKind::KwWith | TokenKind::KwRenames,
            ) => return index,
            Some(TokenKind::Eof) | None => return index,
            Some(_) => index = index.saturating_add(1),
        }
    }

    index
}

fn unknown_type_ref(id: u32, name: Vec<String>) -> TypeRef {
    TypeRef {
        id: TypeId(id),
        name_path: name,
        visibility: Visibility::LibraryLevel,
        owner: TypeOwner::LibraryLevel,
        kind: TypeKind::Unknown,
        constraints: Constraints(String::new()),
        aspects: Aspects(Vec::new()),
    }
}

fn type_name_from_tokens(tokens: &[Token], start: usize, end: usize) -> Vec<String> {
    let mut path = Vec::new();
    let mut current = String::new();
    let mut index = start;

    while index < end {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::Identifier(name)) => {
                if !current.is_empty() && !current.ends_with('.') && !current.ends_with('\'') {
                    path.push(current);
                    current = String::new();
                }
                current.push_str(name);
            }
            Some(TokenKind::Dot) => {
                if !current.is_empty() {
                    current.push('.');
                }
            }
            Some(TokenKind::Tick) => {
                if !current.is_empty() {
                    current.push('\'');
                }
            }
            Some(TokenKind::KwAccess | TokenKind::KwNot | TokenKind::KwAliased) => {}
            Some(_) => {
                if !current.is_empty() {
                    path.push(current);
                    current = String::new();
                }
            }
            None => break,
        }
        index = index.saturating_add(1);
    }

    if !current.is_empty() {
        path.push(current);
    }

    path
}

fn scope_is_abstract(tokens: &[Token], start_index: usize) -> bool {
    let mut index = start_index;
    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::KwAbstract) => return true,
            Some(TokenKind::Semicolon | TokenKind::KwBegin) => return false,
            Some(TokenKind::KwIs) if !kind_at(tokens, index + 1, &TokenKind::KwAbstract) => {
                return false;
            }
            Some(_) => index = index.saturating_add(1),
            None => return false,
        }
    }

    false
}

fn visibility_for_scope(
    scope_tree: &ScopeTree,
    tokens: &[Token],
    scope_index: usize,
) -> Visibility {
    let Some(scope) = scope_tree.scopes.get(scope_index) else {
        return Visibility::Local;
    };
    let Some(parent_index) = scope.parent else {
        return Visibility::LibraryLevel;
    };
    let Some(parent) = scope_tree.scopes.get(parent_index) else {
        return Visibility::Local;
    };

    match parent.kind {
        ScopeKind::PackageSpec => {
            if is_after_private(tokens, parent, scope) {
                Visibility::Private
            } else {
                Visibility::Public
            }
        }
        ScopeKind::SubprogramBody | ScopeKind::PackageBody | ScopeKind::SubprogramSpec => {
            Visibility::Local
        }
    }
}

fn is_after_private(_tokens: &[Token], parent: &Scope, scope: &Scope) -> bool {
    parent
        .private_declarative_span
        .as_ref()
        .is_some_and(|priv_span| {
            scope.decl_span.start_byte >= priv_span.start_byte
                && scope.decl_span.start_byte < priv_span.end_byte
        })
}

fn parse_dotted_name(tokens: &[Token], mut index: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    parts.push(identifier_text(tokens.get(index))?);
    index = index.saturating_add(1);

    while kind_at(tokens, index, &TokenKind::Dot) {
        index = index.saturating_add(1);
        parts.push(identifier_text(tokens.get(index))?);
        index = index.saturating_add(1);
    }

    Some((parts.join("."), index))
}

fn identifier_text(token: Option<&Token>) -> Option<String> {
    match token.map(|token| &token.effective_kind) {
        Some(TokenKind::Identifier(name)) => Some(name.clone()),
        _ => None,
    }
}

fn find_matching_rparen(tokens: &[Token], open_index: usize) -> Option<usize> {
    let mut paren_depth = 0u32;
    let mut index = open_index;

    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => {
                paren_depth = paren_depth.saturating_sub(1);
                if paren_depth == 0 {
                    return Some(index);
                }
            }
            Some(TokenKind::Eof) | None => return None,
            Some(_) => {}
        }
        index = index.saturating_add(1);
    }

    None
}

fn consume_kind(tokens: &[Token], index: &mut usize, kind: &TokenKind) -> bool {
    if !kind_at(tokens, *index, kind) {
        return false;
    }

    *index = (*index).saturating_add(1);
    true
}

fn kind_at(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == *kind)
}

fn source_text(source: &str, tokens: &[Token], start: usize, end: usize) -> Option<String> {
    if start >= end {
        return None;
    }

    let start_byte = tokens.get(start)?.text_span.start as usize;
    let end_byte = tokens.get(end.saturating_sub(1))?.text_span.end as usize;
    source
        .get(start_byte..end_byte)
        .map(|text| text.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::{extract_packages, extract_subprograms};
    use crate::ast::{
        AdaStandard, PackageId, ParamMode, SubprogramKind, SubprogramOwner, TypeKind, Visibility,
    };
    use crate::extract::build_scope_tree;
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str, dialect: AdaStandard) -> Vec<Token> {
        lex(source, dialect)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    fn tree_and_tokens(source: &str) -> (crate::extract::ScopeTree, Vec<Token>) {
        let tokens = tokens(source, AdaStandard::Ada2022);
        let tree = build_scope_tree(&tokens);
        (tree, tokens)
    }

    #[test]
    fn lib_package_emits_single_package() {
        let source = "package P is end P;";
        let (tree, tokens) = tree_and_tokens(source);

        let packages = extract_packages(&tree, source, &tokens);

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].id, PackageId(0));
        assert_eq!(packages[0].name, "p");
        assert_eq!(packages[0].parent, None);
    }

    #[test]
    fn child_package_resolves_parent_id() {
        let source = "package Parent is end Parent; package Parent.Child is end Parent.Child;";
        let (tree, tokens) = tree_and_tokens(source);

        let packages = extract_packages(&tree, source, &tokens);

        assert_eq!(packages.len(), 2);
        assert_eq!(packages[1].name, "parent.child");
        assert_eq!(packages[1].parent, Some(PackageId(0)));
    }

    #[test]
    fn separate_package_body_owns_operations_under_full_parent_path() {
        let source = "separate (Crypto.Types.Big_Numbers) \
                      package body Utils is \
                         function To_Big_Unsigned (S : String) return Integer is (0); \
                      end Utils;";
        let (tree, tokens) = tree_and_tokens(source);
        let packages = extract_packages(&tree, source, &tokens);
        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "crypto.types.big_numbers.utils");
        assert_eq!(subprograms.len(), 1);
        assert_eq!(subprograms[0].owner, SubprogramOwner::Package(PackageId(0)));
    }

    #[test]
    fn generic_formals_dont_yet_populate_but_is_generic_is_set() {
        let source = "generic type T is private; package P is end P;";
        let (tree, tokens) = tree_and_tokens(source);

        let packages = extract_packages(&tree, source, &tokens);

        assert!(packages[0].is_generic);
        assert!(packages[0].formals.is_empty());
        assert!(packages[0].decls.is_empty());
    }

    #[test]
    fn generic_subprogram_sets_is_generic() {
        // A generic subprogram (declared after a `generic` formal part) cannot
        // be called until instantiated, so the flag must distinguish it from an
        // ordinary subprogram in the same (non-generic) package.
        let source = "package P is generic with procedure Act; procedure Traverse (N : Integer); \
             procedure Plain (N : Integer); end P;";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);
        let traverse = subprograms
            .iter()
            .find(|s| s.name == "traverse")
            .expect("traverse");
        let plain = subprograms
            .iter()
            .find(|s| s.name == "plain")
            .expect("plain");

        assert!(
            traverse.is_generic,
            "generic subprogram must set is_generic"
        );
        assert!(!plain.is_generic, "ordinary subprogram must not be generic");
    }

    #[test]
    fn package_body_does_not_duplicate_spec() {
        let source = "package P is end P; package body P is end P;";
        let (tree, tokens) = tree_and_tokens(source);

        let packages = extract_packages(&tree, source, &tokens);

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "p");
    }

    #[test]
    fn nested_packages_have_correct_parent_chain() {
        let source =
            "package Outer is package Inner is package Leaf is end Leaf; end Inner; end Outer;";
        let (tree, tokens) = tree_and_tokens(source);

        let packages = extract_packages(&tree, source, &tokens);

        assert_eq!(packages.len(), 3);
        assert_eq!(packages[1].parent, Some(PackageId(0)));
        assert_eq!(packages[2].parent, Some(PackageId(1)));
    }

    #[test]
    fn procedure_no_params_zero_parameter_list() {
        let source = "procedure Run;";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(subprograms.len(), 1);
        assert_eq!(subprograms[0].name, "run");
        assert_eq!(subprograms[0].kind, SubprogramKind::Procedure);
        assert!(subprograms[0].params.is_empty());
        assert_eq!(subprograms[0].visibility, Visibility::LibraryLevel);
    }

    #[test]
    fn library_level_subprogram_uses_library_level_owner() {
        let source = "procedure Main is begin null; end Main;";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(subprograms.len(), 1);
        assert_eq!(subprograms[0].name, "main");
        assert_eq!(subprograms[0].owner, SubprogramOwner::LibraryLevel);
        assert_eq!(subprograms[0].visibility, Visibility::LibraryLevel);
    }

    #[test]
    fn package_subprogram_uses_matching_package_owner() {
        let source = "package P is procedure Foo; end P;";
        let (tree, tokens) = tree_and_tokens(source);

        let packages = extract_packages(&tree, source, &tokens);
        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(packages.len(), 1);
        assert_eq!(subprograms.len(), 1);
        assert_eq!(subprograms[0].name, "foo");
        assert_eq!(
            subprograms[0].owner,
            SubprogramOwner::Package(packages[0].id)
        );
        assert_eq!(subprograms[0].visibility, Visibility::Public);
    }

    #[test]
    fn package_instantiation_does_not_own_following_subprogram() {
        let source = "package body P is package Local is new Factory (Integer); function F return Integer is begin return 1; end F; end P;";
        let (tree, tokens) = tree_and_tokens(source);

        let packages = extract_packages(&tree, source, &tokens);
        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "p");
        assert_eq!(subprograms.len(), 1);
        assert_eq!(subprograms[0].name, "f");
        assert_eq!(
            subprograms[0].owner,
            SubprogramOwner::Package(packages[0].id)
        );
    }

    #[test]
    fn procedure_with_in_out_param_records_inout_mode() {
        let source = "procedure Run (X : in out Integer);";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(subprograms[0].params[0].name, "x");
        assert_eq!(subprograms[0].params[0].mode, ParamMode::InOut);
        assert_eq!(subprograms[0].params[0].type_ref.name_path, vec!["integer"]);
    }

    #[test]
    fn aliased_formal_records_aliased_aspect() {
        let source = "procedure Run (Line : aliased String);";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        let p = &subprograms[0].params[0];
        assert_eq!(p.name, "line");
        assert_eq!(p.mode, ParamMode::In);
        assert!(
            p.type_ref.aspects.0.iter().any(|a| a == "aliased"),
            "aliased formal must carry the aliased aspect, got {:?}",
            p.type_ref.aspects
        );
    }

    #[test]
    fn non_aliased_formal_has_no_aliased_aspect() {
        let source = "procedure Run (Line : String);";
        let (tree, tokens) = tree_and_tokens(source);
        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);
        assert!(!subprograms[0].params[0]
            .type_ref
            .aspects
            .0
            .iter()
            .any(|a| a == "aliased"));
    }

    #[test]
    fn function_with_return_type_records_unknown_typeref_with_name() {
        let source = "function Count return Natural;";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);
        let return_type = subprograms[0].return_type.as_ref().unwrap();

        assert_eq!(subprograms[0].kind, SubprogramKind::Function);
        assert_eq!(return_type.name_path, vec!["natural"]);
        assert_eq!(return_type.kind, TypeKind::Unknown);
    }

    #[test]
    fn renaming_function_return_type_excludes_renamed_to_name() {
        // zip-ada `function Method_from_Code (x : Unsigned_16) return
        // PKZip_Format renames Format_from_Code;` — the return type is
        // `PKZip_Format`, not `Pkzip_Format.Format_From_Code`.
        let source =
            "function Method_from_Code (x : Integer) return PKZip_Format renames Format_from_Code;";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);
        let return_type = subprograms[0].return_type.as_ref().unwrap();
        assert_eq!(return_type.name_path, vec!["pkzip_format"]);
    }

    #[test]
    fn procedure_with_default_value_captures_expr_text() {
        let source = "procedure Run (X : Integer := 1 + 2);";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(
            subprograms[0].params[0]
                .default
                .as_ref()
                .map(|expr| expr.0.as_str()),
            Some("1 + 2")
        );
    }

    #[test]
    fn abstract_subprogram_sets_is_abstract() {
        let source = "procedure Run is abstract;";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert!(subprograms[0].is_abstract);
    }

    #[test]
    fn overriding_subprogram_at_2005_sets_is_overriding() {
        let source = "overriding procedure Run;";
        let tokens = tokens(source, AdaStandard::Ada2005);
        let tree = build_scope_tree(&tokens);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2005);

        assert!(subprograms[0].is_overriding);
    }

    #[test]
    fn nested_subprogram_visibility_is_local() {
        let source = "procedure Outer is procedure Inner; begin null; end Outer;";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);
        let inner = subprograms
            .iter()
            .find(|subprogram| subprogram.name == "inner")
            .unwrap();

        assert_eq!(inner.visibility, Visibility::Local);
    }

    #[test]
    fn entry_kind_recognised() {
        let source = "package P is protected T is entry Lock; end T; end P;";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(subprograms[0].kind, SubprogramKind::Entry);
        assert_eq!(subprograms[0].name, "lock");
    }

    #[test]
    fn access_param_records_access_mode() {
        let source = "procedure Run (X : not null access Integer);";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);

        assert_eq!(subprograms[0].params[0].mode, ParamMode::AccessMode);
        assert_eq!(subprograms[0].params[0].type_ref.name_path, vec!["integer"]);
        assert!(subprograms[0].params[0]
            .type_ref
            .aspects
            .0
            .contains(&"not_null_access".to_owned()));
    }

    #[test]
    fn anonymous_access_function_preserves_callback_profile() {
        let source =
            "procedure Run (Filter : access function (Item : Address) return Boolean := null);";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);
        let param = &subprograms[0].params[0];

        assert_eq!(param.mode, ParamMode::AccessMode);
        assert!(param.type_ref.name_path.is_empty());
        assert!(matches!(param.type_ref.kind, TypeKind::Access { .. }));
        assert_eq!(
            param.type_ref.constraints.0,
            "function (Item : Address) return Boolean"
        );
        assert_eq!(
            param.default.as_ref().map(|expr| expr.0.as_str()),
            Some("null")
        );
    }

    #[test]
    fn qualified_and_classwide_type_marks_remain_single_paths() {
        let source = "procedure Run (Moment : Ada.Calendar.Time; Parser : Argument_Parser'Class);";
        let (tree, tokens) = tree_and_tokens(source);

        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);
        let params = &subprograms[0].params;
        assert_eq!(params[0].type_ref.name_path, vec!["ada.calendar.time"]);
        assert_eq!(params[1].type_ref.name_path, vec!["argument_parser'class"]);
    }
}
