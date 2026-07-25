// SPDX-License-Identifier: Apache-2.0

//! An index of the CLIENT project's own Ada declarations, used to classify what
//! an actual in a generic instantiation *is*.
//!
//! When [`crate::auto::ada_generic_stub`] synthesizes a stub for an external
//! generic, the kind of each generic formal has to match the actual exactly: a
//! type actual needs a formal type, a subprogram actual needs a formal
//! subprogram, and a value needs a formal object. Ada gives no syntactic clue —
//! `Arg_Type => SPAT.Subject_Name` and `Convert => SPAT.To_Name` look identical.
//! The client's own source, however, declares both, so indexing it answers the
//! question directly.
//!
//! The index is deliberately built from the same source texts the stub model is
//! seeded from (the instrumented Ada closure), so it needs no access to the
//! project AST and stays a pure function of that text.

use std::collections::{BTreeMap, BTreeSet};

/// A subprogram's profile as declared in the client source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SubProfile {
    pub(crate) is_function: bool,
    /// `(parameter name, type spelling)` in declaration order.
    pub(crate) params: Vec<(String, String)>,
    pub(crate) ret: Option<String>,
}

/// What an instantiation actual denotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActualKind {
    /// A literal, with the Ada type it belongs to (`String`, `Integer`, ...).
    Literal(&'static str),
    /// A (sub)type mark.
    Type,
    /// A subprogram. Ada resolves an actual against a formal subprogram by
    /// PROFILE, so an overload set is carried in full and the caller picks the
    /// member that fits the instantiation.
    Subprogram(Vec<SubProfile>),
    /// An object or constant, with its declared type spelling.
    Object(String),
    /// Not classifiable from the client source (e.g. an entity of another
    /// missing library, or a computed expression).
    Unknown,
}

/// Ada predefined types that are directly visible without a `with`, so an actual
/// naming one is a type even though the client never declares it.
const PREDEFINED_TYPES: &[&str] = &[
    "boolean",
    "character",
    "duration",
    "float",
    "integer",
    "long_float",
    "long_integer",
    "long_long_float",
    "long_long_integer",
    "natural",
    "positive",
    "short_float",
    "short_integer",
    "string",
    "wide_character",
    "wide_string",
    "wide_wide_character",
    "wide_wide_string",
];

#[derive(Debug, Clone, Default)]
pub(crate) struct ClientSymbols {
    /// Lowercased type names: both the simple name and `Unit.Name`.
    types: BTreeSet<String>,
    /// Lowercased subprogram names (simple and qualified) -> overload set, in
    /// declaration order.
    subprograms: BTreeMap<String, Vec<SubProfile>>,
    /// Lowercased object/constant names (simple and qualified) -> type spelling.
    objects: BTreeMap<String, String>,
    /// Lowercased names of the units these sources declare, so a qualified actual
    /// can be told apart from one belonging to a foreign (missing) library.
    units: BTreeSet<String>,
}

impl ClientSymbols {
    /// Index every declaration in `sources`.
    pub(crate) fn from_sources(sources: &[String]) -> Self {
        let mut index = Self::default();
        for source in sources {
            index.add_source(source);
        }
        index
    }

    fn add_source(&mut self, source: &str) {
        let Some(tree) = ada_parser::parse_with_tree_sitter(source) else {
            return;
        };
        let bytes = source.as_bytes();
        let unit = enclosing_unit_name(source);
        if let Some(unit) = &unit {
            self.units.insert(unit.to_ascii_lowercase());
        }
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            match node.kind() {
                kind if kind.ends_with("type_declaration") => {
                    if let Some(name) = first_identifier(node, bytes) {
                        self.insert_type(&unit, &name);
                    }
                }
                "subprogram_declaration"
                | "expression_function_declaration"
                | "subprogram_body"
                | "abstract_subprogram_declaration" => {
                    if let Some((name, profile)) = subprogram_profile(node, bytes) {
                        self.insert_subprogram(&unit, &name, profile);
                    }
                }
                "object_declaration" => {
                    for (name, ty) in object_declarations(node, bytes) {
                        self.insert_object(&unit, &name, &ty);
                    }
                }
                // `Null_Name : Subject_Name renames Some.Other;` is just as much an
                // object as a plain declaration, and real code uses it to re-export a
                // library constant under a local name.
                "object_renaming_declaration" => {
                    if let (Some(name), Some(ty)) = (
                        first_identifier(node, bytes),
                        node.child_by_field_name("subtype_mark")
                            .and_then(|m| m.utf8_text(bytes).ok())
                            .map(|t| t.trim().to_owned()),
                    ) {
                        self.insert_object(&unit, &name, &ty);
                    }
                }
                _ => {}
            }
            // Push children in REVERSE so the stack pops them in source order: the
            // index records an overload set in declaration order, which decides the
            // fallback choice when no overload matches an instantiation.
            let mut cursor = node.walk();
            let children: Vec<tree_sitter::Node> = node.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }

    fn insert_type(&mut self, unit: &Option<String>, name: &str) {
        for key in keys(unit, name) {
            self.types.insert(key);
        }
    }

    fn insert_subprogram(&mut self, unit: &Option<String>, name: &str, profile: SubProfile) {
        for key in keys(unit, name) {
            let overloads = self.subprograms.entry(key).or_default();
            // A spec declaration and its body repeat the same profile; keep one.
            if !overloads.contains(&profile) {
                overloads.push(profile.clone());
            }
        }
    }

    fn insert_object(&mut self, unit: &Option<String>, name: &str, ty: &str) {
        for key in keys(unit, name) {
            self.objects.entry(key).or_insert_with(|| ty.to_owned());
        }
    }

    /// Classify an instantiation actual's source text.
    pub(crate) fn classify(&self, actual: &str) -> ActualKind {
        let text = actual.trim();
        if let Some(literal) = literal_type(text) {
            return ActualKind::Literal(literal);
        }
        if !is_name(text) {
            return ActualKind::Unknown;
        }
        let lower = text.to_ascii_lowercase();
        let leaf = lower.rsplit('.').next().unwrap_or(&lower).to_owned();
        // Matching on the LEAF name lets a client refer to its own entity through a
        // partial prefix, but it must not reach across libraries: without this guard
        // `GNATCOLL.Opt_Parse.Convert` — an entity of the MISSING library — would
        // match a client function that merely happens to be called `Convert`, and the
        // generic would be given that unrelated profile.
        let leaf_ok = self.leaf_lookup_allowed(&lower);
        let by_leaf = |map_has: bool| map_has && leaf_ok;
        // `Standard.Integer` and a bare `Integer` are both the predefined type.
        if PREDEFINED_TYPES.contains(&leaf.as_str()) && !self.declares_non_type(&lower, &leaf) {
            return ActualKind::Type;
        }
        if self.types.contains(&lower) || by_leaf(self.types.contains(&leaf)) {
            return ActualKind::Type;
        }
        if let Some(overloads) = self
            .subprograms
            .get(&lower)
            .or_else(|| leaf_ok.then(|| self.subprograms.get(&leaf)).flatten())
        {
            return ActualKind::Subprogram(overloads.clone());
        }
        if let Some(ty) = self
            .objects
            .get(&lower)
            .or_else(|| leaf_ok.then(|| self.objects.get(&leaf)).flatten())
        {
            return ActualKind::Object(ty.clone());
        }
        ActualKind::Unknown
    }

    /// Whether a name may be resolved by its LEAF: always for an unqualified name,
    /// and for a qualified one only when its qualifier is a unit these sources
    /// declare (so the entity really is the client's).
    fn leaf_lookup_allowed(&self, lower_name: &str) -> bool {
        match lower_name.rsplit_once('.') {
            None => true,
            Some((qualifier, _)) => self
                .units
                .iter()
                .any(|unit| unit == qualifier || unit.ends_with(&format!(".{qualifier}"))),
        }
    }

    /// True when the client declares this name as something other than a type,
    /// so a predefined-type name that has been shadowed is not misread (e.g. a
    /// client constant called `Duration`).
    fn declares_non_type(&self, lower: &str, leaf: &str) -> bool {
        (self.subprograms.contains_key(lower)
            || self.subprograms.contains_key(leaf)
            || self.objects.contains_key(lower)
            || self.objects.contains_key(leaf))
            && !(self.types.contains(lower) || self.types.contains(leaf))
    }
}

/// Every name declared in `source` that denotes an OBJECT, mapped to its type mark:
/// subprogram parameters, object declarations, and object renamings.
///
/// Unlike [`ClientSymbols`] this is per-source and unqualified — it answers "what is
/// the type of `Object` in `Object.Get (...)`", which is how a prefix-notation call
/// reveals that the stubbed type it is called on must be TAGGED.
pub(crate) fn local_object_types(source: &str) -> BTreeMap<String, String> {
    let Some(tree) = ada_parser::parse_with_tree_sitter(source) else {
        return BTreeMap::new();
    };
    let bytes = source.as_bytes();
    let mut out = BTreeMap::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "parameter_specification" | "object_declaration" => {
                for (name, ty) in object_declarations(node, bytes) {
                    out.entry(name.to_ascii_lowercase()).or_insert(ty);
                }
            }
            "object_renaming_declaration" => {
                if let (Some(name), Some(ty)) = (
                    first_identifier(node, bytes),
                    node.child_by_field_name("subtype_mark")
                        .and_then(|m| m.utf8_text(bytes).ok())
                        .map(|t| t.trim().to_owned()),
                ) {
                    out.entry(name.to_ascii_lowercase()).or_insert(ty);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

/// Index keys for a declaration: the simple name plus `Unit.Name` when the
/// enclosing unit is known (a client refers to it either way).
fn keys(unit: &Option<String>, name: &str) -> Vec<String> {
    let simple = name.to_ascii_lowercase();
    match unit {
        Some(unit) => vec![
            simple.clone(),
            format!("{}.{}", unit.to_ascii_lowercase(), simple),
        ],
        None => vec![simple],
    }
}

/// The Ada type a literal belongs to, or `None` when the text is not a literal.
fn literal_type(text: &str) -> Option<&'static str> {
    if text.starts_with('"') {
        return Some("String");
    }
    // A character literal is exactly `'x'`; `'` also starts an attribute or a
    // qualified expression, so require the closing quote.
    let chars: Vec<char> = text.chars().collect();
    if chars.len() == 3 && chars[0] == '\'' && chars[2] == '\'' {
        return Some("Character");
    }
    if text.eq_ignore_ascii_case("true") || text.eq_ignore_ascii_case("false") {
        return Some("Boolean");
    }
    let numeric = text.replace('_', "");
    if numeric.is_empty() {
        return None;
    }
    if numeric.chars().all(|c| c.is_ascii_digit()) {
        return Some("Integer");
    }
    // A real literal always has a decimal point in Ada (`1.0`, `0.5e-3`).
    if numeric.contains('.') && numeric.parse::<f64>().is_ok() {
        return Some("Float");
    }
    None
}

/// True when `text` is a simple or dotted Ada name (no operators or calls).
fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && text.starts_with(|c: char| c.is_ascii_alphabetic())
}

/// The unit name a source declares (`package body SPAT.Strings` -> `SPAT.Strings`),
/// with the source's own casing. Shared by the generic-instantiation scanner (to
/// qualify an instance name) and the stub model (to match a build error's file back
/// to the unit that produced it).
pub(crate) fn enclosing_unit_name(source: &str) -> Option<String> {
    for raw in source.lines() {
        let line = match raw.find("--") {
            Some(i) => &raw[..i],
            None => raw,
        }
        .trim();
        let lower = line.to_ascii_lowercase();
        // Skip context clauses and anything else ahead of the unit declaration.
        let Some(rest) = lower
            .strip_prefix("package body ")
            .or_else(|| lower.strip_prefix("package "))
            .or_else(|| lower.strip_prefix("private package "))
        else {
            continue;
        };
        let start = line.len() - rest.len();
        let name: String = line[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

/// The first direct-child `identifier` of a node (a declaration's defining name).
fn first_identifier(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            return child.utf8_text(bytes).ok().map(|t| t.trim().to_owned());
        }
    }
    None
}

/// The name and profile of a subprogram declaration / body / expression function.
fn subprogram_profile(node: tree_sitter::Node, bytes: &[u8]) -> Option<(String, SubProfile)> {
    let mut cursor = node.walk();
    let spec = node.children(&mut cursor).find(|c| {
        matches!(
            c.kind(),
            "function_specification" | "procedure_specification"
        )
    })?;
    let is_function = spec.kind() == "function_specification";
    let name = first_identifier(spec, bytes)?;
    let mut params = Vec::new();
    let mut ret = None;
    let mut spec_cursor = spec.walk();
    for child in spec.children(&mut spec_cursor) {
        match child.kind() {
            "formal_part" => params = formal_part_params(child, bytes),
            "result_profile" => ret = type_mark_of(child, bytes),
            _ => {}
        }
    }
    Some((
        name,
        SubProfile {
            is_function,
            params,
            ret,
        },
    ))
}

/// `(name, type)` for each parameter in a `formal_part`, expanding a shared
/// declaration (`A, B : String`) into one entry per name.
fn formal_part_params(part: tree_sitter::Node, bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cursor = part.walk();
    for spec in part.children(&mut cursor) {
        if spec.kind() != "parameter_specification" {
            continue;
        }
        let Some(ty) = type_mark_of(spec, bytes) else {
            continue;
        };
        // Every identifier before the `:` is a parameter name; the type mark is
        // whatever follows, so stop collecting names at the colon.
        let mut names = Vec::new();
        let mut spec_cursor = spec.walk();
        for child in spec.children(&mut spec_cursor) {
            match child.kind() {
                ":" => break,
                "identifier" => {
                    if let Ok(text) = child.utf8_text(bytes) {
                        names.push(text.trim().to_owned());
                    }
                }
                _ => {}
            }
        }
        for name in names {
            out.push((name, ty.clone()));
        }
    }
    out
}

/// The type mark of a parameter specification or result profile: the last
/// `identifier`/`selected_component` child, i.e. the one after the `:`/`return`.
fn type_mark_of(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let mut seen_separator = node.kind() == "result_profile";
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            ":" | "return" => seen_separator = true,
            "identifier" | "selected_component" if seen_separator => {
                return child.utf8_text(bytes).ok().map(|t| t.trim().to_owned());
            }
            // `subtype_indication` wraps a constrained mark (`String (1 .. 4)`).
            "subtype_indication" if seen_separator => {
                return type_mark_of_indication(child, bytes);
            }
            _ => {}
        }
    }
    None
}

fn type_mark_of_indication(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if matches!(child.kind(), "identifier" | "selected_component") {
            return child.utf8_text(bytes).ok().map(|t| t.trim().to_owned());
        }
    }
    None
}

/// `(name, type)` for each object an `object_declaration` introduces.
fn object_declarations(node: tree_sitter::Node, bytes: &[u8]) -> Vec<(String, String)> {
    let Some(ty) = type_mark_of(node, bytes) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            ":" => break,
            "identifier" => {
                if let Ok(text) = child.utf8_text(bytes) {
                    names.push(text.trim().to_owned());
                }
            }
            _ => {}
        }
    }
    names.into_iter().map(|n| (n, ty.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spat shape: one spec declaring a type, a constant of it, a converting
    /// function, and an object — the four things an instantiation actual can be.
    fn spat_source() -> String {
        "package SPAT is\n\
         type Subject_Name is new String;\n\
         Null_Name : constant Subject_Name := \"\";\n\
         Parser : Integer := 0;\n\
         function To_Name (Source : in String) return Subject_Name;\n\
         end SPAT;\n"
            .to_owned()
    }

    #[test]
    fn classifies_a_type_actual() {
        let index = ClientSymbols::from_sources(&[spat_source()]);
        assert_eq!(index.classify("SPAT.Subject_Name"), ActualKind::Type);
        // The simple name resolves too: a client inside SPAT writes it unqualified.
        assert_eq!(index.classify("Subject_Name"), ActualKind::Type);
    }

    #[test]
    fn classifies_a_subprogram_actual_with_its_profile() {
        let index = ClientSymbols::from_sources(&[spat_source()]);
        let ActualKind::Subprogram(overloads) = index.classify("SPAT.To_Name") else {
            panic!(
                "expected a subprogram: {:?}",
                index.classify("SPAT.To_Name")
            );
        };
        assert_eq!(overloads.len(), 1, "{overloads:?}");
        let profile = &overloads[0];
        assert!(profile.is_function);
        assert_eq!(
            profile.params,
            vec![("Source".to_owned(), "String".to_owned())]
        );
        assert_eq!(profile.ret.as_deref(), Some("Subject_Name"));
    }

    #[test]
    fn keeps_every_overload_of_a_name() {
        // spat declares four `Convert` functions differing ONLY in return type. The
        // caller has to see all of them to pick the one an instantiation means.
        let src = "package P is\n\
                   function Convert (Value : in String) return Detail_Level;\n\
                   function Convert (Value : in String) return Duration;\n\
                   function Convert (Value : in String) return Report_Mode;\n\
                   end P;\n";
        let index = ClientSymbols::from_sources(&[src.to_owned()]);
        let ActualKind::Subprogram(overloads) = index.classify("Convert") else {
            panic!("expected a subprogram");
        };
        let returns: Vec<&str> = overloads.iter().filter_map(|p| p.ret.as_deref()).collect();
        assert_eq!(returns, vec!["Detail_Level", "Duration", "Report_Mode"]);
    }

    #[test]
    fn a_spec_declaration_and_its_body_are_not_counted_as_two_overloads() {
        let spec = "package P is\n function F (X : String) return Integer;\n end P;\n";
        let body = "package body P is\n\
                    function F (X : String) return Integer is\n\
                    begin\n return 0;\n end F;\n\
                    end P;\n";
        let index = ClientSymbols::from_sources(&[spec.to_owned(), body.to_owned()]);
        let ActualKind::Subprogram(overloads) = index.classify("P.F") else {
            panic!("expected a subprogram");
        };
        assert_eq!(overloads.len(), 1, "{overloads:?}");
    }

    #[test]
    fn indexes_an_object_renaming_as_an_object() {
        // spat re-exports a library constant this way:
        //   Null_Name : Subject_Name renames Ada.Strings.Unbounded.Null_Unbounded_String;
        let src = "package SPAT is\n\
                   subtype Subject_Name is Ada.Strings.Unbounded.Unbounded_String;\n\
                   Null_Name : Subject_Name renames \
                   Ada.Strings.Unbounded.Null_Unbounded_String;\n\
                   end SPAT;\n";
        let index = ClientSymbols::from_sources(&[src.to_owned()]);
        assert_eq!(
            index.classify("SPAT.Null_Name"),
            ActualKind::Object("Subject_Name".to_owned()),
            "a renaming declares an object just as much as `:=` does"
        );
    }

    #[test]
    fn classifies_an_object_actual_with_its_declared_type() {
        let index = ClientSymbols::from_sources(&[spat_source()]);
        assert_eq!(
            index.classify("SPAT.Null_Name"),
            ActualKind::Object("Subject_Name".to_owned())
        );
        assert_eq!(
            index.classify("Parser"),
            ActualKind::Object("Integer".to_owned())
        );
    }

    #[test]
    fn classifies_literals_by_their_ada_type() {
        let index = ClientSymbols::default();
        assert_eq!(index.classify("\"-P\""), ActualKind::Literal("String"));
        assert_eq!(index.classify("3"), ActualKind::Literal("Integer"));
        assert_eq!(index.classify("1_000"), ActualKind::Literal("Integer"));
        assert_eq!(index.classify("0.0"), ActualKind::Literal("Float"));
        assert_eq!(index.classify("True"), ActualKind::Literal("Boolean"));
        assert_eq!(index.classify("'x'"), ActualKind::Literal("Character"));
    }

    #[test]
    fn predefined_type_names_are_types_without_a_declaration() {
        let index = ClientSymbols::default();
        assert_eq!(index.classify("Duration"), ActualKind::Type);
        assert_eq!(index.classify("Standard.Integer"), ActualKind::Type);
    }

    #[test]
    fn an_unknown_name_is_not_guessed() {
        let index = ClientSymbols::from_sources(&[spat_source()]);
        // An entity of another missing library: nothing in the client declares it.
        assert_eq!(
            index.classify("GNATCOLL.Opt_Parse.Convert"),
            ActualKind::Unknown
        );
        // A computed expression is not a name.
        assert_eq!(index.classify("X + 1"), ActualKind::Unknown);
    }

    #[test]
    fn indexes_a_body_and_a_multi_name_parameter() {
        let src = "package body Util is\n\
                   procedure Emit (Item, Extra : Subject_Name; Count : Positive := 1) is\n\
                   begin\n null;\n end Emit;\n\
                   end Util;\n";
        let index = ClientSymbols::from_sources(&[src.to_owned()]);
        let ActualKind::Subprogram(overloads) = index.classify("Util.Emit") else {
            panic!("expected a subprogram");
        };
        let profile = &overloads[0];
        assert!(!profile.is_function);
        assert_eq!(
            profile.params,
            vec![
                ("Item".to_owned(), "Subject_Name".to_owned()),
                ("Extra".to_owned(), "Subject_Name".to_owned()),
                ("Count".to_owned(), "Positive".to_owned()),
            ]
        );
        assert_eq!(profile.ret, None);
    }

    #[test]
    fn a_subtype_declaration_is_a_type() {
        let src = "package P is\n subtype Alias is Integer;\n end P;\n";
        let index = ClientSymbols::from_sources(&[src.to_owned()]);
        assert_eq!(index.classify("P.Alias"), ActualKind::Type);
    }
}
