// SPDX-License-Identifier: Apache-2.0

//! Scanning and formal-parameter inference for instantiations of an external
//! Ada generic that is missing offline.
//!
//! [`crate::auto::ada_external_stub`] reconstructs the used subset of a missing
//! library, but a *generic* unit cannot be stubbed like a plain package: Ada
//! checks the instantiation's actual list against the generic's formal part, and
//! the kind of every formal has to match. `Arg_Type => SPAT.Subject_Name` needs a
//! formal type, `Convert => SPAT.To_Name` needs a formal subprogram, and
//! `Short => "-P"` needs a formal object — all three look identical in the source.
//!
//! Two facts make the inference tractable:
//!
//!  1. A named association *gives* the formal's name (`Arg_Type => …` means the
//!     generic declares a formal called `Arg_Type`), which is how real GNATColl
//!     clients are written.
//!  2. The client's own source declares its types, subprograms, and objects, so
//!     [`crate::auto::ada_client_symbols`] can say which of them an actual names.
//!
//! What is left over — an actual naming an entity of *another* missing library, or
//! a computed expression — becomes a formal object of a placeholder type and is
//! pinned down by the same GNAT `expected`/`found` oracle the rest of the model
//! uses.

use std::collections::BTreeSet;

use crate::auto::ada_client_symbols::{enclosing_unit_name, ActualKind, ClientSymbols, SubProfile};

/// One generic instantiation in the client source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Instantiation {
    /// The instance name qualified with its enclosing unit when known
    /// (`SPAT.Command_Line.Project`), else as written (`Project`).
    pub(crate) instance: String,
    /// The instance name exactly as written (`Project`).
    pub(crate) simple_name: String,
    /// The stubbed package that must declare the generic (`GNATCOLL.Opt_Parse`).
    pub(crate) owner: String,
    /// The generic's simple name (`Parse_Option`).
    pub(crate) generic: String,
    /// `false` for `function`/`procedure … is new …`.
    pub(crate) is_package: bool,
    /// Actuals in call order: `(formal name if named, actual source text)`.
    pub(crate) actuals: Vec<(Option<String>, String)>,
}

impl Instantiation {
    /// Lowercased model key for the generic within its owner package.
    pub(crate) fn generic_key(&self) -> String {
        self.generic.to_ascii_lowercase()
    }
}

/// Find every `generic_instantiation` in `source` whose generic belongs to one of
/// `packages` (the missing external libraries being stubbed).
///
/// The owner is the dotted prefix of the generic's name that names a stubbed
/// package, and the generic is rendered *nested inside that package's spec* —
/// never as a child unit, because the client only `with`s the package and a child
/// unit would need its own `with`. A generic nested deeper than one level is
/// skipped rather than guessed at; body stub-out remains the backstop for those.
pub(crate) fn scan_instantiations(source: &str, packages: &BTreeSet<String>) -> Vec<Instantiation> {
    let Some(tree) = ada_parser::parse_with_tree_sitter(source) else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let unit = enclosing_unit_name(source);
    let mut out = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "generic_instantiation" {
            if let Some(found) = parse_instantiation(node, bytes, packages, unit.as_deref()) {
                out.push(found);
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn parse_instantiation(
    node: tree_sitter::Node,
    bytes: &[u8],
    packages: &BTreeSet<String>,
    unit: Option<&str>,
) -> Option<Instantiation> {
    let is_package = node_has_keyword(node, "package");
    let instance_node = node.child_by_field_name("name")?;
    let simple_name = instance_node.utf8_text(bytes).ok()?.trim().to_owned();
    if simple_name.is_empty() {
        return None;
    }
    // The generic's name and its actual list arrive together as a `function_call`
    // (or a bare name when the generic takes no actuals).
    let generic_node = node.child_by_field_name("generic_name")?;
    let (name_node, actuals) = split_generic_name(generic_node, bytes);
    let generic_name = name_node?;
    let (owner, generic) = split_owner(&generic_name, packages)?;
    let instance = match unit {
        Some(unit) => format!("{unit}.{simple_name}"),
        None => simple_name.clone(),
    };
    Some(Instantiation {
        instance,
        simple_name,
        owner,
        generic,
        is_package,
        actuals,
    })
}

/// Split a `generic_name` node into the dotted generic name and its actuals.
fn split_generic_name(
    node: tree_sitter::Node,
    bytes: &[u8],
) -> (Option<String>, Vec<(Option<String>, String)>) {
    if node.kind() != "function_call" {
        let name = node.utf8_text(bytes).ok().map(|t| t.trim().to_owned());
        return (name.filter(|n| is_dotted_name(n)), Vec::new());
    }
    let mut name = None;
    let mut actuals = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "selected_component" | "identifier" | "name" if name.is_none() => {
                name = child
                    .utf8_text(bytes)
                    .ok()
                    .map(|t| t.trim().to_owned())
                    .filter(|n| is_dotted_name(n));
            }
            "actual_parameter_part" => actuals = generic_actuals(child, bytes),
            _ => {}
        }
    }
    (name, actuals)
}

/// `(formal name if named, actual text)` per top-level actual.
fn generic_actuals(part: tree_sitter::Node, bytes: &[u8]) -> Vec<(Option<String>, String)> {
    let mut out = Vec::new();
    let mut cursor = part.walk();
    for assoc in part.children(&mut cursor) {
        if assoc.kind() != "parameter_association" {
            continue;
        }
        let mut name = None;
        let mut value = None;
        let mut seen_arrow = false;
        let mut assoc_cursor = assoc.walk();
        for child in assoc.children(&mut assoc_cursor) {
            match child.kind() {
                "component_choice_list" if !seen_arrow => {
                    name = child
                        .utf8_text(bytes)
                        .ok()
                        .map(|t| t.trim().to_owned())
                        .filter(|n| is_simple_name(n));
                }
                "=>" => seen_arrow = true,
                _ => {
                    if value.is_none() && (seen_arrow || name.is_none()) {
                        value = child.utf8_text(bytes).ok().map(|t| t.trim().to_owned());
                    }
                }
            }
        }
        // A `<>` (box) actual takes the generic's own default; nothing to infer,
        // but it still occupies a formal position.
        let value = value.unwrap_or_else(|| "<>".to_owned());
        out.push((name, value));
    }
    out
}

/// Split `GNATCOLL.Opt_Parse.Parse_Option` into the stubbed owner package and the
/// generic's simple name.
///
/// The owner is matched case-insensitively (Ada is case-insensitive, and a missing
/// unit's name often reaches us folded from a file name) but returned with the
/// SOURCE's casing, so every part of the model keys the package the same way a
/// usage scan of the same source does.
fn split_owner(generic_name: &str, packages: &BTreeSet<String>) -> Option<(String, String)> {
    let (prefix, leaf) = generic_name.rsplit_once('.')?;
    if !packages.iter().any(|p| p.eq_ignore_ascii_case(prefix)) {
        return None;
    }
    (!leaf.is_empty()).then(|| (prefix.to_owned(), leaf.to_owned()))
}

fn node_has_keyword(node: tree_sitter::Node, keyword: &str) -> bool {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(|c| c.kind() == keyword);
    found
}

fn is_simple_name(text: &str) -> bool {
    !text.is_empty()
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && text.starts_with(|c: char| c.is_ascii_alphabetic())
}

fn is_dotted_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && text.starts_with(|c: char| c.is_ascii_alphabetic())
}

/// What the generic's formal at one position must be, inferred from one actual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FormalShape {
    /// A formal object of a known type (`Short : String`).
    Object(String),
    /// A formal object whose type is not yet known; the caller allocates a
    /// placeholder and lets the GNAT oracle resolve it.
    OpaqueObject,
    /// A formal type (`type Arg_Type is private`).
    Type,
    /// A formal subprogram, mirroring the actual's profile.
    Subprogram(SubProfile),
}

/// Infer what the formal behind `actual` has to be.
///
/// `type_actuals` holds the lowercased type actuals of the SAME instantiation. It
/// only matters for an overloaded subprogram actual: Ada resolves that against the
/// formal's profile, so the overload whose result is one of this instantiation's
/// type actuals is the one meant. spat, for example, declares four `Convert`
/// functions differing ONLY in return type, one per option it parses — picking the
/// first would give every instantiation the same wrong profile.
pub(crate) fn infer_formal_shape(
    actual: &str,
    symbols: &ClientSymbols,
    type_actuals: &BTreeSet<String>,
) -> FormalShape {
    match symbols.classify(actual) {
        ActualKind::Literal(ty) => FormalShape::Object(ty.to_owned()),
        ActualKind::Type => FormalShape::Type,
        ActualKind::Subprogram(overloads) => {
            let chosen = overloads
                .iter()
                .find(|profile| {
                    profile.ret.as_deref().is_some_and(|ret| {
                        let leaf = ret.rsplit('.').next().unwrap_or(ret).to_ascii_lowercase();
                        type_actuals.contains(&leaf)
                    })
                })
                .or_else(|| overloads.first());
            match chosen {
                Some(profile) => FormalShape::Subprogram(profile.clone()),
                None => FormalShape::OpaqueObject,
            }
        }
        ActualKind::Object(ty) => FormalShape::Object(ty),
        ActualKind::Unknown => FormalShape::OpaqueObject,
    }
}

/// The formal name to declare at `index`: the named association when the call
/// site gave one, a synthetic name otherwise.
pub(crate) fn formal_name(named: Option<&String>, index: usize) -> String {
    named
        .cloned()
        .unwrap_or_else(|| format!("Gf_Formal_{}", index + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkgset(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// The root unit declaring the option type, its null value, and its converter,
    /// as spat's `spat.ads` does.
    const SPAT_ROOT: &str = "package SPAT is\n\
         type Subject_Name is new String;\n\
         Null_Name : constant Subject_Name := \"\";\n\
         function To_Name (Source : in String) return Subject_Name;\n\
         end SPAT;\n";

    /// The canonical GNATColl shape, following spat's `spat-command_line.ads`.
    const SPAT_CLIENT: &str = "with GNATCOLL.Opt_Parse;\n\
         package SPAT.Command_Line is\n\
         Parser : GNATCOLL.Opt_Parse.Argument_Parser :=\n\
           GNATCOLL.Opt_Parse.Create_Argument_Parser (Help => \"h\");\n\
         package Project is new GNATCOLL.Opt_Parse.Parse_Option\n\
           (Parser      => Parser,\n\
            Short       => \"-P\",\n\
            Arg_Type    => SPAT.Subject_Name,\n\
            Default_Val => SPAT.Null_Name,\n\
            Convert     => SPAT.To_Name);\n\
         end SPAT.Command_Line;\n";

    #[test]
    fn finds_a_package_instantiation_with_its_owner_and_actuals() {
        let found = scan_instantiations(SPAT_CLIENT, &pkgset(&["GNATCOLL.Opt_Parse"]));
        assert_eq!(found.len(), 1, "{found:?}");
        let inst = &found[0];
        assert_eq!(inst.owner, "GNATCOLL.Opt_Parse");
        assert_eq!(inst.generic, "Parse_Option");
        assert!(inst.is_package);
        // Qualified with the enclosing unit, so a use through
        // `SPAT.Command_Line.Project.Get` resolves to this instance.
        assert_eq!(inst.instance, "SPAT.Command_Line.Project");
        assert_eq!(inst.simple_name, "Project");
        let names: Vec<Option<&str>> = inst.actuals.iter().map(|(n, _)| n.as_deref()).collect();
        assert_eq!(
            names,
            vec![
                Some("Parser"),
                Some("Short"),
                Some("Arg_Type"),
                Some("Default_Val"),
                Some("Convert"),
            ]
        );
        assert_eq!(inst.actuals[2].1, "SPAT.Subject_Name");
    }

    #[test]
    fn infers_one_formal_kind_per_actual() {
        let symbols = ClientSymbols::from_sources(&[SPAT_ROOT.to_owned(), SPAT_CLIENT.to_owned()]);
        let inst = &scan_instantiations(SPAT_CLIENT, &pkgset(&["GNATCOLL.Opt_Parse"]))[0];
        let shapes: Vec<FormalShape> = inst
            .actuals
            .iter()
            .map(|(_, actual)| infer_formal_shape(actual, &symbols, &BTreeSet::new()))
            .collect();
        // Parser is a client object of an external (stubbed) type.
        assert_eq!(
            shapes[0],
            FormalShape::Object("GNATCOLL.Opt_Parse.Argument_Parser".to_owned())
        );
        assert_eq!(shapes[1], FormalShape::Object("String".to_owned()));
        assert_eq!(shapes[2], FormalShape::Type);
        assert_eq!(shapes[3], FormalShape::Object("Subject_Name".to_owned()));
        let FormalShape::Subprogram(profile) = &shapes[4] else {
            panic!("Convert must be a formal subprogram: {:?}", shapes[4]);
        };
        assert!(profile.is_function);
        assert_eq!(profile.ret.as_deref(), Some("Subject_Name"));
    }

    #[test]
    fn finds_a_generic_subprogram_instantiation() {
        let src = "with SI_Units.Metric;\n\
                   package body Client is\n\
                   function Img is new SI_Units.Metric.Fixed_Image (Item => Duration, Aft => 3);\n\
                   end Client;\n";
        let found = scan_instantiations(src, &pkgset(&["SI_Units.Metric"]));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(!found[0].is_package);
        assert_eq!(found[0].generic, "Fixed_Image");
        assert_eq!(found[0].instance, "Client.Img");
    }

    #[test]
    fn an_instantiation_of_a_present_library_is_ignored() {
        // `Ada.Containers.Vectors` is in the runtime: nothing to stub.
        let src = "with Ada.Containers.Vectors;\n\
                   package P is\n\
                   package V is new Ada.Containers.Vectors (Positive, Integer);\n\
                   end P;\n";
        assert!(scan_instantiations(src, &pkgset(&["GNATCOLL.Opt_Parse"])).is_empty());
    }

    #[test]
    fn a_generic_nested_deeper_than_one_level_is_skipped() {
        // `Extension` is not a stubbed package (spat vendors it), so the owner
        // lookup must fail rather than invent a nesting.
        let src = "package P is\n\
                   package D is new GNATCOLL.Opt_Parse.Extension.Parse_Option_With_Default\n\
                     (Short => \"-d\");\n\
                   end P;\n";
        assert!(scan_instantiations(src, &pkgset(&["GNATCOLL.Opt_Parse"])).is_empty());
    }

    #[test]
    fn a_positional_actual_gets_a_synthetic_formal_name() {
        let src = "package P is\n\
                   package V is new Vendorlib.Holder (Integer, 4);\n\
                   end P;\n";
        let found = scan_instantiations(src, &pkgset(&["Vendorlib"]));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].actuals[0], (None, "Integer".to_owned()));
        assert_eq!(
            formal_name(found[0].actuals[0].0.as_ref(), 0),
            "Gf_Formal_1"
        );
        assert_eq!(
            formal_name(found[0].actuals[1].0.as_ref(), 1),
            "Gf_Formal_2"
        );
    }

    #[test]
    fn an_actual_of_another_missing_library_is_left_unclassified() {
        // Ranking across instantiations lives in the model (it needs the generic's
        // formal types); here the contract is only that an actual the client source
        // does not declare is reported as unclassified rather than guessed.
        let symbols = ClientSymbols::from_sources(&[SPAT_ROOT.to_owned(), SPAT_CLIENT.to_owned()]);
        assert_eq!(
            infer_formal_shape("GNATCOLL.Opt_Parse.Convert", &symbols, &BTreeSet::new()),
            FormalShape::OpaqueObject
        );
    }
}
