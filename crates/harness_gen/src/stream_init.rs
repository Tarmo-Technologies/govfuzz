// SPDX-License-Identifier: Apache-2.0
//
//! Initialise abstract class-wide "stateful object" parameters (e.g. an Ada
//! stream type) that the direct-call decoder cannot construct from scratch.
//!
//! Many legacy Ada APIs take a `Some_Root_Type'Class` parameter — an abstract,
//! limited, class-wide type. There is no constructor function returning it
//! (limited types are initialised in place), so the direct decoder gives up.
//! But the source set usually provides a *concrete* derivation plus a public
//! procedure that loads it from bytes (the canonical example being zip-ada's
//! `Zip_Streams.Memory_Zipstream` + `Zip_Streams.Set (S, Unbounded_String)`).
//! This module discovers that pair so the harness can declare the concrete
//! object, fill it from the fuzz input, and pass it where the class-wide
//! parameter is expected.

use ada_parser::ast::{ParamMode, StructuralAst, SubprogramKind, SubprogramOwner, Visibility};

/// How to construct and initialise a concrete object for an abstract
/// class-wide parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamInit {
    /// Qualified concrete type to declare, e.g. `Zip_Streams.Memory_Zipstream`.
    pub concrete_type: String,
    /// Qualified initialiser procedure, e.g. `Zip_Streams.Set`.
    pub init_proc: String,
    /// Decode expression for the initialiser's byte argument.
    pub arg_decoder: String,
    /// Units the harness must `with` to compile the initialisation.
    pub extra_withs: Vec<String>,
}

/// If `name_path` is a class-wide reference (`Foo'Class`, which the parser
/// records as a path ending in a `class` component), return the simple name of
/// the root tagged type (`foo`).
pub fn class_wide_root(name_path: &[String]) -> Option<String> {
    let last = name_path.last()?;
    if !last.trim_matches('.').eq_ignore_ascii_case("class") {
        return None;
    }
    // Everything before the trailing `class` component, joined and re-split, is
    // the root type's dotted name; take its simple (last) segment.
    let joined = name_path[..name_path.len() - 1].join(".");
    joined
        .split('.')
        .map(str::trim)
        .rfind(|segment| !segment.is_empty())
        .map(str::to_owned)
}

/// Find a concrete type derived from `root_simple` plus a public procedure that
/// initialises it from a byte-decodable argument.
pub fn discover_stream_init(ast: &StructuralAst, root_simple: &str) -> Option<StreamInit> {
    // Candidate concrete types: any type whose derivation constraints name the
    // root tagged type (e.g. `is new Root_Zipstream_Type with private`).
    for ty in &ast.types {
        if !ty
            .constraints
            .0
            .to_ascii_lowercase()
            .contains(&root_simple.to_ascii_lowercase())
        {
            continue;
        }
        let concrete_simple = match ty.name_path.last() {
            Some(name) => name.clone(),
            None => continue,
        };
        // Skip the root itself.
        if concrete_simple.eq_ignore_ascii_case(root_simple) {
            continue;
        }

        if let Some(init) = find_byte_initializer(ast, &concrete_simple) {
            return Some(init);
        }
    }
    None
}

/// Find a public procedure `P (Obj : in out <concrete>; Arg : <byte type>)`
/// that loads the concrete object from an in-memory byte-like argument.
fn find_byte_initializer(ast: &StructuralAst, concrete_simple: &str) -> Option<StreamInit> {
    for sp in &ast.subprograms {
        if sp.kind != SubprogramKind::Procedure || sp.visibility != Visibility::Public {
            continue;
        }
        // Exactly two parameters: the concrete object (writable) plus the byte
        // source. We emit `Init (Obj, Arg)`, so a different arity would be a
        // wrong-arity call — only match initialisers we can call correctly.
        if sp.params.len() != 2 {
            continue;
        }
        let receiver = &sp.params[0];
        if !matches!(receiver.mode, ParamMode::InOut | ParamMode::Out) {
            continue;
        }
        if !simple_name(&receiver.type_ref.name_path).eq_ignore_ascii_case(concrete_simple) {
            continue;
        }
        // The second parameter must be a decodable in-memory byte source.
        let Some(arg) = byte_arg_decoder(&sp.params[1]) else {
            continue;
        };

        let owner = package_name(ast, &sp.owner);
        let mut extra_withs = arg.extra_withs;
        // The harness must `with` the package that declares the concrete type
        // and its initialiser.
        if !owner.is_empty() {
            let owner_with = ada_dotted(&owner);
            if !extra_withs.contains(&owner_with) {
                extra_withs.insert(0, owner_with);
            }
        }
        return Some(StreamInit {
            concrete_type: qualify(&owner, concrete_simple),
            init_proc: qualify(&owner, &sp.name),
            arg_decoder: arg.decoder,
            extra_withs,
        });
    }
    None
}

struct ByteArg {
    decoder: String,
    extra_withs: Vec<String>,
}

/// Decode expression for a parameter that carries in-memory bytes, if its type
/// is one the runtime can synthesise (Unbounded_String / String).
fn byte_arg_decoder(p: &ada_parser::ast::Parameter) -> Option<ByteArg> {
    let name = p.type_ref.name_path.join(".").to_ascii_lowercase();
    let simple = simple_name(&p.type_ref.name_path).to_ascii_lowercase();
    if name.ends_with("unbounded_string") || simple == "unbounded_string" {
        Some(ByteArg {
            decoder: "Ada.Strings.Unbounded.To_Unbounded_String (AdaFuzz.Decode.Ada_String (Cur, 0, 4096))".to_owned(),
            extra_withs: vec!["Ada.Strings.Unbounded".to_owned()],
        })
    } else if simple == "string" {
        Some(ByteArg {
            decoder: "AdaFuzz.Decode.Ada_String (Cur, 0, 4096)".to_owned(),
            extra_withs: Vec::new(),
        })
    } else {
        None
    }
}

fn simple_name(name_path: &[String]) -> String {
    name_path
        .last()
        .map(|s| s.trim_matches('.').to_owned())
        .unwrap_or_default()
}

fn package_name(ast: &StructuralAst, owner: &SubprogramOwner) -> String {
    match owner {
        SubprogramOwner::Package(id) => ast
            .packages
            .iter()
            .find(|p| p.id == *id)
            .map(|p| p.name.clone())
            .unwrap_or_default(),
        SubprogramOwner::LibraryLevel => String::new(),
    }
}

fn qualify(owner: &str, simple: &str) -> String {
    if owner.is_empty() {
        ada_case(simple)
    } else {
        format!("{}.{}", ada_dotted(owner), ada_case(simple))
    }
}

/// Title-case each `_`-separated word so the lowercased parser names render as
/// idiomatic Ada (`memory_zipstream` -> `Memory_Zipstream`). Ada is
/// case-insensitive, so this is purely cosmetic but keeps emitted code clean.
fn ada_case(name: &str) -> String {
    name.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("_")
}

fn ada_dotted(name: &str) -> String {
    name.split('.').map(ada_case).collect::<Vec<_>>().join(".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ada_parser::ast::{
        Aspects, Constraints, Package, PackageId, Parameter, Span, StructuralAst, Subprogram,
        SubprogramId, TypeId, TypeKind, TypeOwner, TypeRef, Visibility,
    };

    fn span() -> Span {
        Span::new(0, 10, 1, 1)
    }

    fn type_ref(name: &str, kind: TypeKind, constraints: &str) -> TypeRef {
        TypeRef {
            id: TypeId(1),
            name_path: name.split('.').map(str::to_owned).collect(),
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind,
            constraints: Constraints(constraints.to_owned()),
            aspects: Aspects(Vec::new()),
        }
    }

    fn param(name: &str, type_name: &str, mode: ParamMode) -> Parameter {
        Parameter {
            name: name.to_owned(),
            mode,
            type_ref: type_ref(type_name, TypeKind::Private, ""),
            default: None,
        }
    }

    #[test]
    fn class_wide_root_extracts_root_type_name() {
        // The parser records `Root_Zipstream_Type'Class` as ["root_zipstream_type.", "class"].
        assert_eq!(
            class_wide_root(&["root_zipstream_type.".to_owned(), "class".to_owned()]),
            Some("root_zipstream_type".to_owned())
        );
    }

    #[test]
    fn class_wide_root_is_none_for_plain_type() {
        assert_eq!(class_wide_root(&["integer".to_owned()]), None);
    }

    #[test]
    fn discovers_concrete_type_and_unbounded_string_initializer() {
        let mut ast = StructuralAst::new();
        ast.packages.push(Package {
            id: PackageId(0),
            name: "zip_streams".to_owned(),
            parent: None,
            is_generic: false,
            formals: Vec::new(),
            decls: Vec::new(),
            is_private: false,
        });
        // type Memory_Zipstream is new Root_Zipstream_Type with private;
        ast.types.push(type_ref(
            "zip_streams.memory_zipstream",
            TypeKind::Derived { base: TypeId(0) },
            "Root_Zipstream_Type with private",
        ));
        // procedure Set (Str : in out Memory_Zipstream; Unb : Unbounded_String);
        ast.subprograms.push(Subprogram {
            id: SubprogramId(1),
            owner: SubprogramOwner::Package(PackageId(0)),
            name: "set".to_owned(),
            kind: SubprogramKind::Procedure,
            params: vec![
                param("str", "memory_zipstream", ParamMode::InOut),
                param(
                    "unb",
                    "ada.strings.unbounded.unbounded_string",
                    ParamMode::In,
                ),
            ],
            return_type: None,
            is_abstract: false,
            is_dispatching: false,
            is_overriding: false,
            body_span: Some(span()),
            decl_span: span(),
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility: Visibility::Public,
            is_generic: false,
        });

        let init = discover_stream_init(&ast, "root_zipstream_type").expect("stream init");
        assert_eq!(init.concrete_type, "Zip_Streams.Memory_Zipstream");
        assert_eq!(init.init_proc, "Zip_Streams.Set");
        assert!(init.arg_decoder.contains("To_Unbounded_String"));
        // Must `with` both the concrete type's package and Unbounded_String.
        assert_eq!(
            init.extra_withs,
            vec!["Zip_Streams".to_owned(), "Ada.Strings.Unbounded".to_owned()]
        );
    }

    #[test]
    fn no_init_when_only_file_based_concrete_exists() {
        // A File_Zipstream with only an Open (File_Mode) procedure has no
        // in-memory byte initialiser, so it is not fuzzable from stdin bytes.
        let mut ast = StructuralAst::new();
        ast.packages.push(Package {
            id: PackageId(0),
            name: "zip_streams".to_owned(),
            parent: None,
            is_generic: false,
            formals: Vec::new(),
            decls: Vec::new(),
            is_private: false,
        });
        ast.types.push(type_ref(
            "zip_streams.file_zipstream",
            TypeKind::Derived { base: TypeId(0) },
            "Root_Zipstream_Type with private",
        ));
        ast.subprograms.push(Subprogram {
            id: SubprogramId(1),
            owner: SubprogramOwner::Package(PackageId(0)),
            name: "open".to_owned(),
            kind: SubprogramKind::Procedure,
            params: vec![
                param("str", "file_zipstream", ParamMode::InOut),
                param("mode", "file_mode", ParamMode::In),
            ],
            return_type: None,
            is_abstract: false,
            is_dispatching: false,
            is_overriding: false,
            body_span: Some(span()),
            decl_span: span(),
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility: Visibility::Public,
            is_generic: false,
        });

        assert_eq!(discover_stream_init(&ast, "root_zipstream_type"), None);
    }
}
