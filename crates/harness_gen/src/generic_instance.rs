// SPDX-License-Identifier: Apache-2.0
//
//! Instantiate a generic package so its subprograms become fuzzable.
//!
//! The legacy Ada codecs (`LZMA.Decoding`, `BZip2.Decoding`, `LZMA.Encoding`,
//! ...) are generic packages whose formal part is a small, stereotyped set of
//! callbacks plus a few scalar parameters:
//!
//! ```ada
//! generic
//!   with function  Read_Byte  return Byte;
//!   with procedure Write_Byte (b : Byte);
//!   check_crc : Boolean;
//! package BZip2.Decoding is
//!   procedure Decompress;
//! end BZip2.Decoding;
//! ```
//!
//! Instantiating `Read_Byte` with a function that returns *fuzz bytes* feeds the
//! fuzz input straight into the decompressor - the ideal way to fuzz a streaming
//! codec. This module parses the formal part from source and, when every formal
//! is one we can synthesise (a stub subprogram or a defaulted/scalar object),
//! produces the declarations the harness needs: the stub bodies and the
//! `package <Inst> is new <Generic> (...)` instantiation.

/// The name of the synthesised instance.
pub const INSTANCE_NAME: &str = "Govfuzz_Generic_Instance";

/// Describes the generic unit to instantiate.
pub struct GenericUnit {
    /// `package`, `procedure`, or `function` - the instantiation keyword.
    pub keyword: &'static str,
    /// The declaration text to locate in the source so the `generic` formal
    /// part before it can be extracted, e.g. `package bzip2.decoding` (a child
    /// package, dotted) or `procedure encode` (a generic subprogram, simple).
    pub decl_search: String,
    /// The qualified generic-unit name for `is new ...`, e.g. `BZip2.Decoding`
    /// or `LZMA.Encoding.Encode`.
    pub instance_of: String,
    /// A package to `use` so the formal types resolve unqualified in the stubs.
    pub use_parent: Option<String>,
}

/// Everything the harness needs to instantiate a generic unit and call into it.
#[derive(Debug, Clone, PartialEq)]
pub struct GenericInstance {
    /// Local declarations (stub subprogram bodies) placed before the
    /// instantiation.
    pub stub_decls: Vec<String>,
    /// The `package|procedure|function <INSTANCE_NAME> is new <Generic> (...);`
    /// line.
    pub instantiation: String,
    /// Units the harness must `with`/`use` so the formal types are visible.
    pub extra_withs: Vec<String>,
}

/// Try to synthesise a generic instantiation for `unit`, parsing the formal
/// part out of `source`. Returns `Err(reason)` naming the specific blocking
/// formal when the generic uses a formal we cannot synthesise (a formal package,
/// a private/array/access formal type, or a formal subprogram whose return type
/// we cannot produce) - the caller surfaces `reason` in the `blocked_by_generic`
/// skip so the user knows exactly what blocked it.
pub fn synthesize(source: &str, unit: &GenericUnit) -> Result<GenericInstance, String> {
    let formal_block = extract_formal_block(source, &unit.decl_search)
        .ok_or_else(|| "no generic formal part found".to_owned())?;
    let formals = split_formals(&formal_block);
    if formals.is_empty() {
        return Err("the generic formal part is empty".to_owned());
    }

    let mut stub_decls = Vec::new();
    let mut actuals: Vec<String> = Vec::new();
    let mut extra_withs = Vec::new();
    if let Some(parent) = &unit.use_parent {
        // `use` the parent so the formal types (e.g. `Byte`) resolve unqualified
        // in the stubs and the instantiation.
        extra_withs.push(parent.clone());
    }

    for formal in formals {
        let classified = classify_formal(&formal)
            .ok_or_else(|| format!("unparsable formal '{}'", formal_display(&formal)))?;
        match classified {
            Formal::Function {
                name,
                profile,
                return_type,
            } => {
                if profile.is_empty() && return_type.eq_ignore_ascii_case("boolean") {
                    // A nullary Boolean formal is a continue/`More_Bytes`-style
                    // loop predicate. The fuzz cursor wraps at end-of-input, so
                    // a fuzz-bool would keep saying "more" and the codec's read
                    // loop would never terminate (it would time out as an
                    // unrecoverable runtime). Bound it with a per-testcase
                    // budget so the loop ends.
                    stub_decls.push(format!("Stub_{name}_Budget : Natural := 4096;"));
                    stub_decls.push(format!("function Stub_{name} return Boolean is"));
                    stub_decls.push("begin".to_owned());
                    stub_decls.push(format!(
                        "   if Stub_{name}_Budget = 0 then return False; end if;"
                    ));
                    stub_decls.push(format!("   Stub_{name}_Budget := Stub_{name}_Budget - 1;"));
                    stub_decls.push("   return True;".to_owned());
                    stub_decls.push(format!("end Stub_{name};"));
                } else {
                    let body = function_stub_body(&return_type).ok_or_else(|| {
                        format!(
                            "formal subprogram '{name}' has an unbuildable return type '{return_type}'"
                        )
                    })?;
                    stub_decls.push(format!(
                        "function Stub_{name} {profile}return {return_type} is"
                    ));
                    stub_decls.push("begin".to_owned());
                    stub_decls.push(format!("   return {body};"));
                    stub_decls.push(format!("end Stub_{name};"));
                }
                actuals.push(format!("{name} => Stub_{name}"));
            }
            Formal::Procedure { name, profile } => {
                stub_decls.push(format!("procedure Stub_{name} {profile}is"));
                stub_decls.push("begin".to_owned());
                stub_decls.push("   null;".to_owned());
                stub_decls.push(format!("end Stub_{name};"));
                actuals.push(format!("{name} => Stub_{name}"));
            }
            Formal::DiscreteType { name, decl } => {
                stub_decls.push(decl);
                actuals.push(format!("{name} => Stub_{name}"));
            }
            Formal::ObjectWithDefault => {
                // Has a default; omit it from the actuals.
            }
            Formal::Object { name, value } => {
                actuals.push(format!("{name} => {value}"));
            }
            Formal::Unsupported => return Err(unsupported_formal_reason(&formal)),
        }
    }

    let actuals = if actuals.is_empty() {
        String::new()
    } else {
        format!(" ({})", actuals.join(", "))
    };
    let instantiation = format!(
        "{} {INSTANCE_NAME} is new {}{actuals};",
        unit.keyword, unit.instance_of
    );

    Ok(GenericInstance {
        stub_decls,
        instantiation,
        extra_withs,
    })
}

/// A short, single-line rendering of a formal for diagnostics.
fn formal_display(formal: &str) -> String {
    let one_line = normalize_ws(formal);
    one_line.trim_end_matches(';').trim().to_owned()
}

/// Describe WHY a formal classified as `Unsupported` cannot be synthesised, for
/// the `blocked_by_generic` skip message.
fn unsupported_formal_reason(formal: &str) -> String {
    let display = formal_display(formal);
    let lower = formal.trim().to_ascii_lowercase();
    if lower.starts_with("with package ") {
        format!("formal package '{display}' cannot be synthesised (multi-level formal-package instantiation is unsupported)")
    } else if lower.starts_with("type ") {
        format!("formal type '{display}' has no synthesizable concrete actual (private/array/access/derived formal types are unsupported)")
    } else if lower.starts_with("with function ") || lower.starts_with("with procedure ") {
        format!("formal subprogram '{display}' cannot be synthesised")
    } else {
        format!("formal object '{display}' has an unsupported type")
    }
}

/// Pull the text between `generic` and the unit declaration that follows it
/// (comments stripped). `decl_search` is the declaration to find, e.g.
/// `package bzip2.decoding` or `procedure encode`.
fn extract_formal_block(source: &str, decl_search: &str) -> Option<String> {
    let no_comments: String = source
        .lines()
        .map(|line| match line.find("--") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let lower = no_comments.to_ascii_lowercase();

    // Find the unit declaration, then the `generic` formal part that precedes
    // it.
    let pkg_pos = find_word_sequence(&lower, &decl_search.to_ascii_lowercase())?;
    // Find the nearest `generic` KEYWORD (word boundary) before the unit decl —
    // skipping substring hits like a formal's `Generic_Bus` (sdpcm).
    let mut search_end = pkg_pos;
    let generic_pos = loop {
        let pos = lower[..search_end].rfind("generic")?;
        if is_word_boundary(&lower, pos, "generic") {
            break pos;
        }
        search_end = pos;
    };
    Some(
        no_comments[generic_pos + "generic".len()..pkg_pos]
            .trim()
            .to_owned(),
    )
}

/// Split a formal block into individual formal declarations on top-level `;`
/// (semicolons inside parentheses belong to a parameter list).
fn split_formals(block: &str) -> Vec<String> {
    let mut formals = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in block.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth -= 1;
                current.push(ch);
            }
            ';' if depth == 0 => {
                let trimmed = normalize_ws(&current);
                if !trimmed.is_empty() {
                    formals.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let trimmed = normalize_ws(&current);
    if !trimmed.is_empty() {
        formals.push(trimmed);
    }
    formals
}

enum Formal {
    Function {
        name: String,
        profile: String,
        return_type: String,
    },
    Procedure {
        name: String,
        profile: String,
    },
    Object {
        name: String,
        value: String,
    },
    /// A formal discrete/numeric type (`type X is (<>)` / `range <>` / `mod <>` /
    /// `digits <>`) backed by a fabricated concrete `decl`.
    DiscreteType {
        name: String,
        decl: String,
    },
    ObjectWithDefault,
    Unsupported,
}

/// Whether every generic formal in `formals` can be given a concrete actual by
/// the harness generator. A formal *type* (`type State_Type is private`),
/// `with package`, or `is <>` formal subprogram has no value govfuzz can invent,
/// so a package with any such formal can never be auto-instantiated — its
/// subprograms will always `blocked_by_generic` skip. Discovery uses this to
/// deprioritise those targets behind buildable concrete ones. A package with
/// only object / callable formals (which the instance synthesizer handles) is
/// synthesizable. An empty formal list (non-generic, or generic with no formals)
/// is trivially synthesizable.
pub fn formals_are_synthesizable(formals: &[String]) -> bool {
    formals
        .iter()
        .all(|formal| !matches!(classify_formal(formal), None | Some(Formal::Unsupported)))
}

/// Whether the generic package named `package_name` (e.g. `Generic_Sponge`,
/// `Keccak.Generic_Hash`) declared in `source` can be auto-instantiated — its
/// formal block is parsed from the source (the structural AST doesn't retain
/// formals) and checked with [`formals_are_synthesizable`]. Returns `true` when
/// no formal block is found (not actually a generic at this name, or
/// unparseable) so discovery never demotes a target it can't prove generic.
pub fn generic_package_is_synthesizable(source: &str, package_name: &str) -> bool {
    let decl_search = format!("package {package_name}");
    match extract_formal_block(source, &decl_search) {
        Some(block) => formals_are_synthesizable(&split_formals(&block)),
        None => true,
    }
}

fn classify_formal(formal: &str) -> Option<Formal> {
    let lower = formal.to_ascii_lowercase();
    if lower.starts_with("type ") {
        // A formal discrete/numeric type (`type X is (<>)` / `range <>` /
        // `mod <>` / `digits <>`) can be instantiated with a fabricated concrete
        // type. Private/array/access/derived formals still have no synthesizable
        // actual and stay Unsupported.
        let rest = &formal["type ".len()..];
        let (name, after) = read_identifier(rest);
        let def = after.trim_start();
        let def = def
            .strip_prefix("is")
            .or_else(|| def.strip_prefix("IS"))
            .or_else(|| def.strip_prefix("Is"))
            .map(str::trim_start)
            .unwrap_or(def);
        let def_low = def.to_ascii_lowercase();
        let decl = if def_low.starts_with("(<>)") {
            Some(format!("type Stub_{name} is (Gf_E0, Gf_E1, Gf_E2);"))
        } else if def_low.starts_with("range <>") {
            Some(format!("type Stub_{name} is range 0 .. 255;"))
        } else if def_low.starts_with("mod <>") {
            Some(format!("type Stub_{name} is mod 256;"))
        } else if def_low.starts_with("digits <>") {
            Some(format!("type Stub_{name} is digits 6;"))
        } else {
            None
        };
        return Some(match decl {
            Some(decl) => Formal::DiscreteType { name, decl },
            None => Formal::Unsupported,
        });
    }
    if lower.starts_with("with function ") {
        let rest = &formal["with function ".len()..];
        let (name, after_name) = read_identifier(rest);
        // Optional parameter profile, then `return <type>`.
        let after_name_trim = after_name.trim_start();
        let (profile, after_profile) = if after_name_trim.starts_with('(') {
            let close = matching_paren(after_name_trim)?;
            (
                format!("{} ", &after_name_trim[..=close]),
                &after_name_trim[close + 1..],
            )
        } else {
            (String::new(), after_name_trim)
        };
        let lower_after = after_profile.trim_start().to_ascii_lowercase();
        let return_type = lower_after.strip_prefix("return ")?;
        return Some(Formal::Function {
            name,
            profile,
            return_type: normalize_ws(&after_profile.trim_start()["return ".len()..])
                .trim_end_matches(';')
                .trim()
                .to_owned(),
        })
        .filter(|_| !return_type.is_empty());
    }
    if lower.starts_with("with procedure ") {
        let rest = &formal["with procedure ".len()..];
        let (name, after_name) = read_identifier(rest);
        let after_name_trim = after_name.trim_start();
        let profile = if after_name_trim.starts_with('(') {
            let close = matching_paren(after_name_trim)?;
            format!("{} ", &after_name_trim[..=close])
        } else {
            String::new()
        };
        return Some(Formal::Procedure { name, profile });
    }
    if lower.starts_with("with ") {
        // `with package`, formal subprogram with `is <>`, etc.
        return Some(Formal::Unsupported);
    }
    // Formal object: `Name [, Name] : Type [:= Default]`.
    let (name_part, type_part) = formal.split_once(':')?;
    if name_part.contains(',') {
        // Multiple names in one declaration - keep it simple and bail.
        return Some(Formal::Unsupported);
    }
    let name = normalize_ws(name_part);
    if name.is_empty() {
        return Some(Formal::Unsupported);
    }
    if type_part.contains(":=") {
        return Some(Formal::ObjectWithDefault);
    }
    // A formal object may carry an explicit mode (`Columns : in Positive`,
    // `State : in out T`); strip it so the type name resolves.
    let type_name = normalize_ws(type_part);
    let type_name = type_name
        .strip_prefix("in out ")
        .or_else(|| type_name.strip_prefix("in "))
        .or_else(|| type_name.strip_prefix("out "))
        .unwrap_or(&type_name)
        .trim()
        .to_owned();
    let value = object_value(&type_name)?;
    Some(Formal::Object { name, value })
}

/// A decode/neutral value for a formal object's type. Only the simple cases a
/// generic codec actually uses; anything else makes the whole instance
/// unsupported.
fn object_value(type_name: &str) -> Option<String> {
    match type_name.to_ascii_lowercase().as_str() {
        "boolean" => Some("False".to_owned()),
        "integer" | "natural" | "positive" => Some(format!("{type_name}'First")),
        "float" | "long_float" => Some("0.0".to_owned()),
        _ => None,
    }
}

/// The expression a stub function returns for a given return type.
fn function_stub_body(return_type: &str) -> Option<String> {
    let simple = return_type
        .rsplit('.')
        .next()
        .unwrap_or(return_type)
        .to_ascii_lowercase();
    match simple.as_str() {
        "boolean" => Some("AdaFuzz.Decode.Bool (Cur)".to_owned()),
        // A byte-ish return: feed a fuzz byte, converted to the codec's type.
        "byte" | "unsigned_8" => Some(format!("{return_type} (AdaFuzz.Decode.U8 (Cur))")),
        "integer" | "natural" | "positive" => {
            Some(format!("{return_type} (AdaFuzz.Decode.U8 (Cur))"))
        }
        _ => None,
    }
}

fn read_identifier(input: &str) -> (String, &str) {
    let input = input.trim_start();
    let end = input
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(input.len());
    (input[..end].to_owned(), &input[end..])
}

fn matching_paren(input: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (idx, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn normalize_ws(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn find_word_sequence(haystack: &str, needle: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(needle) {
        let pos = from + rel;
        let before_ok = pos == 0
            || !haystack.as_bytes()[pos - 1].is_ascii_alphanumeric()
                && haystack.as_bytes()[pos - 1] != b'_';
        if before_ok {
            return Some(pos);
        }
        from = pos + 1;
    }
    None
}

fn is_word_boundary(haystack: &str, pos: usize, word: &str) -> bool {
    let after = pos + word.len();
    let before_ok = pos == 0
        || !haystack.as_bytes()[pos - 1].is_ascii_alphanumeric()
            && haystack.as_bytes()[pos - 1] != b'_';
    let after_ok = after >= haystack.len()
        || !haystack.as_bytes()[after].is_ascii_alphanumeric()
            && haystack.as_bytes()[after] != b'_';
    before_ok && after_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formals_synthesizable_rejects_formal_type_accepts_callables_and_objects() {
        // libkeccak's Generic_Sponge: a formal type can't be synthesized.
        assert!(!formals_are_synthesizable(&[
            "type State_Type is private".to_owned(),
            "with procedure Init_State (S : out State_Type)".to_owned(),
        ]));
        // `with package` / `is <>` are unsupported.
        assert!(!formals_are_synthesizable(&[
            "with package P is new Q (<>)".to_owned()
        ]));
        // Callable + object formals (LZMA.Decoding-style) ARE synthesizable.
        assert!(formals_are_synthesizable(&[
            "with function Read_Byte return Interfaces.Unsigned_8".to_owned(),
            "Buffer_Size : Positive := 4096".to_owned(),
        ]));
        // No formals (non-generic, or generic with none) is trivially OK.
        assert!(formals_are_synthesizable(&[]));
    }

    fn package_unit(dotted: &str, parent: &str) -> GenericUnit {
        GenericUnit {
            keyword: "package",
            decl_search: format!("package {dotted}"),
            instance_of: dotted.to_owned(),
            use_parent: Some(parent.to_owned()),
        }
    }

    const BZIP2_DECODING: &str = "\
generic
  --  Input function
  with function Read_Byte return Byte;
  --  Output procedure
  with procedure Write_Byte (b : Byte);
  check_crc : Boolean;
package BZip2.Decoding is
  procedure Decompress;
end BZip2.Decoding;
";

    #[test]
    fn synthesizes_bzip2_decoding_codec() {
        let inst = synthesize(BZIP2_DECODING, &package_unit("BZip2.Decoding", "BZip2"))
            .expect("synthesizable");
        let body = inst.stub_decls.join("\n");
        assert!(
            body.contains("function Stub_Read_Byte return Byte is")
                && body.contains("Byte (AdaFuzz.Decode.U8 (Cur))"),
            "Read_Byte must feed fuzz bytes: {body}"
        );
        assert!(
            body.contains("procedure Stub_Write_Byte (b : Byte) is") && body.contains("null;"),
            "Write_Byte must be a sink: {body}"
        );
        assert_eq!(
            inst.instantiation,
            "package Govfuzz_Generic_Instance is new BZip2.Decoding (Read_Byte => Stub_Read_Byte, Write_Byte => Stub_Write_Byte, check_crc => False);"
        );
        assert!(inst.extra_withs.contains(&"BZip2".to_owned()));
    }

    #[test]
    fn synthesizes_generic_subprogram_instantiation() {
        // The encoders are generic *subprograms*: `generic ... procedure Encode`.
        let src = "\
package LZMA.Encoding is
  generic
    with function  Read_Byte return Byte;
    with function  More_Bytes return Boolean;
    with procedure Write_Byte (b : Byte);
  procedure Encode (level : Integer := 1);
end LZMA.Encoding;
";
        let unit = GenericUnit {
            keyword: "procedure",
            decl_search: "procedure Encode".to_owned(),
            instance_of: "LZMA.Encoding.Encode".to_owned(),
            use_parent: Some("LZMA".to_owned()),
        };
        let inst = synthesize(src, &unit).expect("synthesizable");
        assert_eq!(
            inst.instantiation,
            "procedure Govfuzz_Generic_Instance is new LZMA.Encoding.Encode (Read_Byte => Stub_Read_Byte, More_Bytes => Stub_More_Bytes, Write_Byte => Stub_Write_Byte);"
        );
    }

    #[test]
    fn synthesizes_more_bytes_function() {
        let src = "\
generic
  with function  Read_Byte return Byte;
  with function  More_Bytes return Boolean;
  with procedure Write_Byte (b : Byte);
package LZMA.Encoding is
end LZMA.Encoding;
";
        let inst = synthesize(src, &package_unit("LZMA.Encoding", "LZMA")).expect("synthesizable");
        let body = inst.stub_decls.join("\n");
        assert!(
            body.contains("function Stub_More_Bytes return Boolean is")
                && body.contains("Stub_More_Bytes_Budget := Stub_More_Bytes_Budget - 1;"),
            "More_Bytes (a nullary Boolean predicate) must be budget-bounded so the read loop terminates: {body}"
        );
    }

    #[test]
    fn formal_object_with_explicit_mode_resolves_its_type() {
        // `Columns : in Positive` (mode-qualified formal object) must instantiate,
        // not `blocked_by_generic` on an "unparsable formal".
        let src = "\
generic
  Columns : in Positive;
  with procedure Write (S : String);
package Tables is
end Tables;
";
        let inst = synthesize(src, &package_unit("Tables", "App")).expect("synthesizable");
        assert!(
            inst.instantiation.contains("Columns => Positive'First"),
            "mode-qualified object formal resolved: {}",
            inst.instantiation
        );
    }

    #[test]
    fn defaulted_object_formals_are_omitted() {
        let src = "\
generic
  String_buffer_size : Integer := 2**12;
  with function Read_Byte return Byte;
package LZ77 is
end LZ77;
";
        let inst = synthesize(src, &package_unit("LZ77", "Zip")).expect("synthesizable");
        assert!(
            !inst.instantiation.contains("String_buffer_size"),
            "defaulted formal must be omitted: {}",
            inst.instantiation
        );
    }

    #[test]
    fn formal_private_type_makes_generic_unsupported() {
        // A formal *private* (or array/access) type still has no synthesizable
        // concrete actual — keep it a clean blocked_by_generic skip.
        let src = "\
generic
  type Element is private;
  with function Read_Byte return Byte;
package Data_Segmentation is
end Data_Segmentation;
";
        let err = synthesize(src, &package_unit("Data_Segmentation", "Zip"))
            .expect_err("a formal private type is not synthesizable");
        assert!(
            err.contains("formal type") && err.contains("Element"),
            "error should name the blocking formal type: {err}"
        );
    }

    #[test]
    fn synthesize_reports_specific_unsupported_formal() {
        // The skip message must name the actual blocker (formal package vs type).
        let pkg_formal = "\
generic
  with package Bus is new SDPCM.Generic_Bus (<>);
package Generic_Io is
end Generic_Io;
";
        let err = synthesize(pkg_formal, &package_unit("Generic_Io", "Sdpcm"))
            .expect_err("a formal package is unsupported");
        assert!(
            err.contains("formal package") && err.contains("Bus"),
            "error should name the formal package: {err}"
        );

        let fn_formal = "\
generic
  with function Make return Some_Private_T;
package Factory is
end Factory;
";
        let err = synthesize(fn_formal, &package_unit("Factory", "Lib"))
            .expect_err("a formal subprogram with an unbuildable return is unsupported");
        assert!(
            err.contains("unbuildable return type") && err.contains("Make"),
            "error should name the formal subprogram + return type: {err}"
        );
    }

    #[test]
    fn synthesizes_discrete_formal_type_instantiation() {
        // A formal discrete enum type `type Categories is (<>)` (ada_drivers
        // logging) is the most synthesizable generic formal: instantiate it with
        // a fabricated concrete enum.
        let src = "\
generic
  type Categories is (<>);
package Logging is
end Logging;
";
        let inst = synthesize(src, &package_unit("Logging", "Drivers"))
            .expect("a discrete formal type is synthesizable");
        assert!(
            inst.stub_decls
                .iter()
                .any(|d| d == "type Stub_Categories is (Gf_E0, Gf_E1, Gf_E2);"),
            "stub_decls: {:?}",
            inst.stub_decls
        );
        assert!(
            inst.instantiation.contains("Categories => Stub_Categories"),
            "instantiation: {}",
            inst.instantiation
        );
    }

    #[test]
    fn synthesizes_range_and_mod_formal_type_instantiation() {
        let src = "\
generic
  type Index is range <>;
  type Mask is mod <>;
package Buffers is
end Buffers;
";
        let inst = synthesize(src, &package_unit("Buffers", "Drivers"))
            .expect("range/mod formal types are synthesizable");
        assert!(inst
            .stub_decls
            .iter()
            .any(|d| d == "type Stub_Index is range 0 .. 255;"));
        assert!(inst
            .stub_decls
            .iter()
            .any(|d| d == "type Stub_Mask is mod 256;"));
        assert!(inst.instantiation.contains("Index => Stub_Index"));
        assert!(inst.instantiation.contains("Mask => Stub_Mask"));
    }
}
