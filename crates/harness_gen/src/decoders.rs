// SPDX-License-Identifier: Apache-2.0

use crate::registry::{ConstructorEntry, ConstructorRegistry};
use crate::HarnessGenError;
use ada_parser::ast::{ParamMode, Parameter, ScalarKind, StructuralAst, TypeId, TypeKind, TypeRef};

#[derive(Debug, Clone, PartialEq)]
pub struct DecoderEmission {
    pub call_expr: String,
    pub setup_lines: Vec<String>,
}

pub type DecoderCall = DecoderEmission;

pub fn select_initializer_for_param(
    ast: &StructuralAst,
    p: &Parameter,
    registry: &ConstructorRegistry,
) -> Result<DecoderEmission, HarnessGenError> {
    match p.mode {
        ParamMode::In | ParamMode::InOut | ParamMode::AccessMode => {
            select_decoder_for_param(ast, p, registry)
        }
        ParamMode::Out => select_neutral_for_param(ast, p, registry),
    }
}

pub fn select_decoder_for_param(
    ast: &StructuralAst,
    p: &Parameter,
    registry: &ConstructorRegistry,
) -> Result<DecoderEmission, HarnessGenError> {
    // Known stdlib discrete subtypes parse as opaque named types; decode them
    // within their fixed range instead of failing for "no constructor".
    if let Some((qualified, lo, hi)) = known_stdlib_scalar_subtype(&p.type_ref) {
        return Ok(DecoderEmission {
            call_expr: format!("{qualified} (AdaFuzz.Decode.Bounded_Range (Cur, {lo}, {hi}))"),
            setup_lines: Vec::new(),
        });
    }
    // `Ada.Streams.Stream_Element_Array` is the canonical Ada byte buffer; the
    // fuzz runtime returns exactly that type. Decode it directly rather than
    // demanding a constructor (ada-keystore's marshallers take it).
    if is_stream_element_array(&p.type_ref) {
        return Ok(DecoderEmission {
            call_expr: "AdaFuzz.Decode.Bytes (Cur, 0, 4096)".to_owned(),
            setup_lines: Vec::new(),
        });
    }
    // Predefined fixed-point `Duration` (ada-security's token expiry): convert a
    // bounded integer second-count, always in range, instead of "needs ctor".
    if is_standard_duration(&p.type_ref) {
        return Ok(DecoderEmission {
            call_expr: "Standard.Duration (AdaFuzz.Decode.Bounded_Range (Cur, -86_400, 86_400))"
                .to_owned(),
            setup_lines: Vec::new(),
        });
    }
    match &p.type_ref.kind {
        TypeKind::Scalar(ScalarKind::Integer) => Ok(DecoderEmission {
            call_expr: integer_scalar_decode(&ada_type_name(p)),
            setup_lines: Vec::new(),
        }),
        TypeKind::Scalar(ScalarKind::Boolean) => Ok(DecoderEmission {
            call_expr: "AdaFuzz.Decode.Bool (Cur)".to_owned(),
            setup_lines: Vec::new(),
        }),
        TypeKind::Scalar(ScalarKind::Float) => Ok(DecoderEmission {
            call_expr: format!("{} (AdaFuzz.Decode.F64 (Cur))", ada_type_name(p)),
            setup_lines: Vec::new(),
        }),
        // Modular (`type Byte is mod 256`): the Ada 2012 `'Mod` attribute maps any
        // integer onto the type's `0 .. Modulus-1` range — total, never out of range.
        TypeKind::Scalar(ScalarKind::Modular) => Ok(DecoderEmission {
            call_expr: format!("{}'Mod (AdaFuzz.Decode.U64 (Cur))", ada_type_name(p)),
            setup_lines: Vec::new(),
        }),
        // Character (and Wide_/custom character types): decode within the type's own
        // position range, exactly like an enumeration — total and in range.
        TypeKind::Scalar(ScalarKind::Character) => Ok(DecoderEmission {
            call_expr: character_decode(&ada_type_name(p)),
            setup_lines: Vec::new(),
        }),
        // Fixed-point / decimal-fixed (`type Angle is delta 0.01 range -3.14 .. 3.14`,
        // financial decimals): convert a bounded integer between the (truncated)
        // range bounds into the fixed type. Low-resolution but total and guaranteed
        // in range — mirrors the predefined-`Duration` handling above.
        TypeKind::Scalar(ScalarKind::Fixed) | TypeKind::Scalar(ScalarKind::Decimal) => {
            let ty = ada_type_name(p);
            Ok(DecoderEmission {
                call_expr: format!(
                    "{ty} (AdaFuzz.Decode.Bounded_Range (Cur, Integer ({ty}'First), Integer ({ty}'Last)))"
                ),
                setup_lines: Vec::new(),
            })
        }
        TypeKind::Enum(literals) => {
            if literals.is_empty() {
                return Err(HarnessGenError::UnsupportedParamType(
                    "empty enum".to_owned(),
                ));
            }

            // Decode within the type's own range via 'First/'Last rather than
            // the literal count. For a full enumeration this is identical, but
            // for a constrained subtype (e.g. `subtype Reduction_Method is
            // Compression_Method range Reduce_1 .. Reduce_4`) it stays inside
            // the subtype - the literal count would index the base type and
            // raise Constraint_Error on nearly every input.
            let ty = ada_type_name(p);
            Ok(DecoderEmission {
                call_expr: format!(
                    "{ty}'Val ({ty}'Pos ({ty}'First) + AdaFuzz.Decode.Bounded_Range (Cur, 0, {ty}'Pos ({ty}'Last) - {ty}'Pos ({ty}'First)))"
                ),
                setup_lines: Vec::new(),
            })
        }
        TypeKind::Array {
            elem_name, bounds, ..
        } => {
            let arr_type = ada_type_name(p);
            let param_name = ada_name(&p.name);
            let temp_name = format!("Tmp_{param_name}");
            let len_name = format!("Len_{param_name}");
            let decode_name = format!("Decode_{param_name}");
            let elem_expr = array_element_decoder(elem_name, &arr_type);

            // A constrained array type (`array (Index) of ...`, fixed bounds)
            // already has its index range; giving it `(1 .. Len)` is illegal
            // ("array type is already constrained"). Declare it bare and fill
            // its own 'Range. Only an unconstrained type (`array (Index range
            // <>) of ...`) takes - and requires - a decoded length.
            let unconstrained = bounds.is_empty() || bounds.contains("<>");
            // The decoded length is `Natural`, but the array's index type may be
            // a custom integer (SPARKNaCl `array (N32 range <>)`, N32 a subtype
            // of Interfaces.Integer_32) — `(1 .. Len)` then mismatches
            // ("expected Interfaces.Integer_32, found Standard.Integer"). For a
            // custom index, cast the bound through its `'Base` (no range check,
            // so a 0 length stays an empty `1 .. 0`), qualifying the index with
            // the array type's package since the harness only `with`s it
            // (`Sparknacl.N32'Base (Len)`). Standard indices (Positive/Natural/
            // Integer) are directly visible and the plain `Natural` bound works.
            let upper_bound = match array_index_type(bounds) {
                Some(idx) if !is_standard_index_type(&idx) => {
                    format!("{}'Base ({len_name})", qualify_index_type(&arr_type, &idx))
                }
                _ => len_name.clone(),
            };
            // Arrays can be multi-dimensional (a covariance matrix is
            // `array (R, C) of Float`). Fill every dimension with nested loops
            // over each `'Range (k)` and a full N-subscript assignment; a single
            // `Temp (I)` on a 2-D array fails to compile ("too few subscripts").
            let dims = array_dimensions(bounds);
            let fill = array_fill_loop_lines(&temp_name, dims, &elem_expr);
            let mut setup_lines = vec![format!("function {decode_name} return {arr_type} is")];
            if unconstrained {
                setup_lines.push(format!(
                    "   {len_name} : constant Natural := AdaFuzz.Decode.Bounded_Length (Cur, 0, 16);"
                ));
                // One decoded length applied to each dimension (a square N-D
                // array). Exact for the common 1-D case; a reasonable shape for
                // the rare unconstrained multi-D one.
                let index_bounds = vec![format!("1 .. {upper_bound}"); dims.max(1)].join(", ");
                setup_lines.push(format!("   {temp_name} : {arr_type} ({index_bounds});"));
            } else {
                setup_lines.push(format!("   {temp_name} : {arr_type};"));
            }
            setup_lines.push("begin".to_owned());
            setup_lines.extend(fill);
            setup_lines.push(format!("   return {temp_name};"));
            setup_lines.push(format!("end {decode_name};"));

            Ok(DecoderEmission {
                call_expr: decode_name.clone(),
                setup_lines,
            })
        }
        TypeKind::Record(fields) => {
            if record_is_empty(fields) {
                // An empty record (`type Tag is record null; end record;`, marker /
                // phantom / proof types) has nothing to decode — the empty aggregate
                // `T'(null record)` is always a valid value.
                return Ok(DecoderEmission {
                    call_expr: format!("{}'(null record)", ada_type_name(p)),
                    setup_lines: Vec::new(),
                });
            }

            let field_decoders = fields
                .0
                .iter()
                .flat_map(|field| record_field_components(field))
                .map(|(name, ty)| {
                    format!("{} => {}", ada_name(&name), decode_record_field(ast, &ty))
                })
                .collect::<Vec<_>>();

            Ok(DecoderEmission {
                call_expr: format!("{}'({})", ada_type_name(p), field_decoders.join(", ")),
                setup_lines: Vec::new(),
            })
        }
        TypeKind::Discriminated { discriminants, .. } => {
            let record_type = ada_type_name(p);
            let (disc_name, disc_ty) = discriminants
                .0
                .first()
                .map(|field| parse_record_field(field))
                .unwrap_or_else(|| ("D".to_owned(), "Integer".to_owned()));
            let disc_field = ada_name(&disc_name);
            let disc_expr = discriminant_decode(ast, &record_type, &disc_ty);

            Ok(DecoderEmission {
                call_expr: format!("{record_type}'({disc_field} => {disc_expr}, others => <>)"),
                setup_lines: Vec::new(),
            })
        }
        TypeKind::Tagged { .. } | TypeKind::Private => {
            let tagged_type = ada_type_name(p);
            let constructors: Vec<&ConstructorEntry> = registry
                .for_tagged_type(&tagged_type)
                .into_iter()
                .filter(|constructor| constructor_is_usable(constructor))
                .collect();
            if constructors.is_empty() {
                let kind_label = match &p.type_ref.kind {
                    TypeKind::Tagged { .. } => "tagged",
                    TypeKind::Private => "private",
                    _ => "named",
                };
                return Err(HarnessGenError::UnsupportedParamType(format!(
                    "{kind_label} type {tagged_type} has no constructor with synthesizable parameters"
                )));
            }

            let param_name = ada_name(&p.name);
            let decode_name = format!("Decode_{param_name}");
            // Return each constructor result directly rather than assigning into
            // a temporary first. Assignment (`:=`) is illegal for `limited`
            // types (e.g. `Util.Encoders.Encoder is tagged limited private`),
            // whereas a direct `return Constructor(...)` builds in place and is
            // legal for both limited and non-limited types.
            let mut setup_lines = vec![
                format!("function {decode_name} return {tagged_type} is"),
                "begin".to_owned(),
                format!(
                    "   case AdaFuzz.Decode.Choose_Tag (Cur, {}) is",
                    constructors.len()
                ),
            ];

            for (idx, constructor) in constructors.iter().enumerate() {
                setup_lines.push(format!(
                    "      when {} => return {};",
                    idx + 1,
                    constructor_call(constructor)
                ));
            }
            if let Some(first_constructor) = constructors.first() {
                setup_lines.push(format!(
                    "      when others => return {};",
                    constructor_call(first_constructor)
                ));
            }
            setup_lines.push("   end case;".to_owned());
            setup_lines.push(format!("end {decode_name};"));

            Ok(DecoderEmission {
                call_expr: decode_name,
                setup_lines,
            })
        }
        TypeKind::Access { .. } => {
            let acc_type = ada_type_name(p);
            let param_name = ada_name(&p.name);
            let temp_name = format!("Tmp_{param_name}");
            let slots_name = format!("Slots_{param_name}");
            let idx_name = format!("Idx_{param_name}");
            let decode_name = format!("Decode_{param_name}");

            Ok(DecoderEmission {
                call_expr: decode_name.clone(),
                setup_lines: vec![
                    format!("function {decode_name} return {acc_type} is"),
                    format!("   {slots_name} : array (1 .. 4) of {acc_type} := (others => null);"),
                    format!(
                        "   {idx_name} : constant Natural := AdaFuzz.Decode.Slot_Index (Cur, 4);"
                    ),
                    format!("   {temp_name} : {acc_type};"),
                    "begin".to_owned(),
                    format!("   if {idx_name} = 0 then"),
                    format!("      {temp_name} := null;"),
                    "   else".to_owned(),
                    format!("      {temp_name} := {slots_name} ({idx_name});"),
                    "   end if;".to_owned(),
                    format!("   return {temp_name};"),
                    format!("end {decode_name};"),
                ],
            })
        }
        // A derived type (`type My_Int is new Integer range 0 .. 100`) is a
        // transparent newtype: decode AS the ultimate base kind but in the derived
        // type's own name (so the value lands in the derived subtype and inherits its
        // range). Resolve through a chain of derivations, with cycle detection.
        TypeKind::Derived { base } => {
            let Some(base_kind) = resolve_derived_base_kind(ast, &p.type_ref, *base) else {
                return Err(HarnessGenError::UnsupportedParamType(type_name(
                    &p.type_ref,
                )));
            };
            let mut synth = p.clone();
            synth.type_ref.kind = base_kind;
            select_decoder_for_param(ast, &synth, registry)
        }
        _ if is_corba_object_ref(&p.type_ref) => Ok(object_ref_decoder(p)),
        _ if is_typed_ref(&p.type_ref) => Ok(typed_ref_decoder(p)),
        // Predefined `Character` family — not declared in the tree, so they reach
        // here as named types rather than `Scalar(Character)`.
        _ if last_type_name_is(&p.type_ref, "Character")
            || last_type_name_is(&p.type_ref, "Wide_Character")
            || last_type_name_is(&p.type_ref, "Wide_Wide_Character") =>
        {
            Ok(DecoderEmission {
                call_expr: character_decode(&ada_type_name(p)),
                setup_lines: Vec::new(),
            })
        }
        _ if last_type_name_is(&p.type_ref, "String") => Ok(DecoderEmission {
            call_expr: "AdaFuzz.Decode.Ada_String (Cur, 0, 1024)".to_owned(),
            setup_lines: Vec::new(),
        }),
        // `Unbounded_String` is the ubiquitous Ada string-input idiom. Decode it
        // from fuzz bytes (To_Unbounded_String of a fuzzed String) rather than
        // the empty `Null_Unbounded_String` neutral, so the parameter actually
        // fuzzes. The out-parameter/neutral path keeps the empty value.
        _ if last_type_name_is(&p.type_ref, "Unbounded_String") => Ok(DecoderEmission {
            call_expr: "Ada.Strings.Unbounded.To_Unbounded_String \
                        (AdaFuzz.Decode.Ada_String (Cur, 0, 1024))"
                .to_owned(),
            setup_lines: Vec::new(),
        }),
        // `X.Bounded_String` is the `Ada.Strings.Bounded.Generic_Bounded_Length`
        // instance idiom (e.g. `Sys.Bounded_750_Type.Bounded_String`). The AST
        // does not model the instantiation, so recognize it by the standard leaf
        // name and construct via the instance's `To_Bounded_String`, truncating
        // (`Ada.Strings.Right`) so an over-long fuzzed string can't raise
        // `Length_Error` and crash the harness. Needs a real instance prefix (the
        // `len() >= 2` guard) so `<prefix>.To_Bounded_String` is nameable; a bare
        // `Bounded_String` with no prefix falls through to the clean skip.
        _ if last_type_name_is(&p.type_ref, "Bounded_String")
            && type_path_parts(&p.type_ref).len() >= 2 =>
        {
            let full = ada_type_name(p);
            let prefix = full
                .rsplit_once('.')
                .map_or(full.as_str(), |(head, _)| head);
            Ok(DecoderEmission {
                call_expr: format!(
                    "{prefix}.To_Bounded_String \
                     (AdaFuzz.Decode.Ada_String (Cur, 0, 1024), Ada.Strings.Right)"
                ),
                setup_lines: Vec::new(),
            })
        }
        _ if last_type_name_is(&p.type_ref, "Integer")
            || last_type_name_is(&p.type_ref, "Natural")
            || last_type_name_is(&p.type_ref, "Positive") =>
        {
            // Standard `Natural`/`Positive` (not resolved to a Scalar kind because
            // they aren't declared in the tree) reach here: decode in-range so the
            // declarative-part conversion never range-fails and crashes the harness.
            Ok(DecoderEmission {
                call_expr: integer_scalar_decode(&ada_type_name(p)),
                setup_lines: Vec::new(),
            })
        }
        _ if is_integer_alias_name(&p.type_ref) => Ok(integer_alias_decoder(
            p,
            interfaces_integer_bound(&p.type_ref),
        )),
        _ if last_type_name_is(&p.type_ref, "Boolean") => Ok(DecoderEmission {
            call_expr: "AdaFuzz.Decode.Bool (Cur)".to_owned(),
            setup_lines: Vec::new(),
        }),
        _ if builtin_named_type_neutral(&p.type_ref).is_some() => Ok(DecoderEmission {
            call_expr: builtin_named_type_neutral(&p.type_ref).unwrap(),
            setup_lines: Vec::new(),
        }),
        // Catch-all for an out-of-tree / unresolved parameter type (e.g. a
        // Libadalang type a harness can't see). Emit a descriptive, properly-cased
        // reason like the Tagged/Private branches rather than a bare lowercased
        // echo of the name — the surrounding error reprints the cased name too, so
        // the bare echo just duplicated it with no added information (#45).
        _ => Err(HarnessGenError::UnsupportedParamType(format!(
            "named type {} is not declared in the parsed source set and has no \
             synthesizable constructor",
            ada_type_name(p)
        ))),
    }
}

fn builtin_named_type_neutral(type_ref: &TypeRef) -> Option<String> {
    let dotted = type_path_parts(type_ref).join(".").to_ascii_lowercase();
    match dotted.as_str() {
        "system.address" => Some("System.Null_Address".to_owned()),
        "system.storage_elements.storage_offset"
        | "system.storage_elements.storage_count"
        | "system.storage_elements.storage_element" => Some("0".to_owned()),
        "ada.calendar.time" => Some("Ada.Calendar.Clock".to_owned()),
        "ada.strings.unbounded.unbounded_string" => {
            Some("Ada.Strings.Unbounded.Null_Unbounded_String".to_owned())
        }
        _ => None,
    }
}

/// Known Ada standard-library scalar subtypes whose definitions live in the
/// runtime (not the parsed source set), so the parser sees them as opaque named
/// types rather than scalars — without this they would skip with "no
/// constructor with synthesizable parameters". Returns the qualified type name
/// and its inclusive `(low, high)` bounds; the bounded-range value is converted
/// to the subtype, which is legal for both the integer subtypes and the
/// fixed-point `Day_Duration` (0 .. 86400 seconds). Matched on the full dotted
/// path or the distinctive leaf name (for `use Ada.Calendar;` code).
fn known_stdlib_scalar_subtype(type_ref: &TypeRef) -> Option<(&'static str, i64, i64)> {
    let dotted = type_path_parts(type_ref).join(".").to_ascii_lowercase();
    let leaf = dotted.rsplit('.').next().unwrap_or(dotted.as_str());
    match (dotted.as_str(), leaf) {
        ("ada.calendar.year_number", _) | (_, "year_number") => {
            Some(("Ada.Calendar.Year_Number", 1901, 2399))
        }
        ("ada.calendar.month_number", _) | (_, "month_number") => {
            Some(("Ada.Calendar.Month_Number", 1, 12))
        }
        ("ada.calendar.day_number", _) | (_, "day_number") => {
            Some(("Ada.Calendar.Day_Number", 1, 31))
        }
        ("ada.calendar.day_duration", _) | (_, "day_duration") => {
            Some(("Ada.Calendar.Day_Duration", 0, 86_400))
        }
        _ => None,
    }
}

/// The library unit a known stdlib scalar subtype lives in. The harness must
/// `with` it to name the fully-qualified type in the decode/neutral expression.
/// `Ada.Streams.Stream_Element_Array` decoding also needs `Ada.Streams` (already
/// in the direct template, but added for the generic/servant paths).
pub fn known_stdlib_type_with(type_ref: &TypeRef) -> Option<&'static str> {
    if known_stdlib_scalar_subtype(type_ref).is_some() {
        return Some("Ada.Calendar");
    }
    if is_stream_element_array(type_ref) {
        return Some("Ada.Streams");
    }
    // A `Generic_Bounded_Length` instance's `Bounded_String` is decoded via
    // `<instance>.To_Bounded_String (.., Ada.Strings.Right)`; the `Right`
    // truncation literal lives in `Ada.Strings`. (The instance package itself is
    // withed by `param_type_unit_with`.)
    if last_type_name_is(type_ref, "Bounded_String") && type_path_parts(type_ref).len() >= 2 {
        return Some("Ada.Strings");
    }
    None
}

/// Like [`known_stdlib_type_with`] but keyed on a dotted type-NAME string — used
/// for a CONSTRUCTOR's parameter types (recorded as names, not `TypeRef`s). A
/// constructor decoded into a tagged/private param emits fully-qualified neutral
/// args for these (`Ada.Calendar.Year_Number'First`), so the harness must `with`
/// their unit. `Ada.Calendar` scalar subtypes -> "Ada.Calendar",
/// `Stream_Element_Array` -> "Ada.Streams".
pub fn known_stdlib_with_for_type_name(name: &str) -> Option<&'static str> {
    let leaf = name.rsplit('.').next().unwrap_or(name).to_ascii_lowercase();
    match leaf.as_str() {
        "year_number" | "month_number" | "day_number" | "day_duration" => Some("Ada.Calendar"),
        "stream_element_array" => Some("Ada.Streams"),
        _ => None,
    }
}

/// Whether `type_ref` is the predefined `Ada.Streams.Stream_Element_Array`
/// (matched on the dotted path or the distinctive leaf, for `use Ada.Streams;`).
fn is_stream_element_array(type_ref: &TypeRef) -> bool {
    let dotted = type_path_parts(type_ref).join(".").to_ascii_lowercase();
    dotted == "ada.streams.stream_element_array"
        || dotted.rsplit('.').next() == Some("stream_element_array")
}

/// Whether `type_ref` is the predefined fixed-point `Standard.Duration` (not the
/// distinct `Ada.Calendar.Day_Duration`, handled as a subtype above).
fn is_standard_duration(type_ref: &TypeRef) -> bool {
    let dotted = type_path_parts(type_ref).join(".").to_ascii_lowercase();
    dotted == "duration" || dotted == "standard.duration"
}

fn select_neutral_for_param(
    ast: &StructuralAst,
    p: &Parameter,
    registry: &ConstructorRegistry,
) -> Result<DecoderEmission, HarnessGenError> {
    if let Some((qualified, _lo, _hi)) = known_stdlib_scalar_subtype(&p.type_ref) {
        return Ok(DecoderEmission {
            call_expr: format!("{qualified}'First"),
            setup_lines: Vec::new(),
        });
    }
    if is_stream_element_array(&p.type_ref) {
        // Empty byte array — a valid neutral for an `out`/`in out` slot.
        return Ok(DecoderEmission {
            call_expr: "(1 .. 0 => 0)".to_owned(),
            setup_lines: Vec::new(),
        });
    }
    if is_standard_duration(&p.type_ref) {
        return Ok(DecoderEmission {
            call_expr: "0.0".to_owned(),
            setup_lines: Vec::new(),
        });
    }
    match &p.type_ref.kind {
        // Use `'First` rather than a `0`/`1` literal: it is always in range for
        // a constrained integer subtype (zip-ada `out File_Index :
        // ZS_Index_Type range 1 .. ...` — `ZS_Index_Type (0)` is a static
        // "value not in range" error). For an `out`/neutral placeholder the
        // exact value is irrelevant.
        TypeKind::Scalar(ScalarKind::Integer) => Ok(DecoderEmission {
            call_expr: format!("{}'First", ada_type_name(p)),
            setup_lines: Vec::new(),
        }),
        TypeKind::Scalar(ScalarKind::Boolean) => Ok(DecoderEmission {
            call_expr: "False".to_owned(),
            setup_lines: Vec::new(),
        }),
        TypeKind::Scalar(ScalarKind::Float) => Ok(scalar_neutral(p, "0.0")),
        // Modular / Character / Fixed / Decimal out-params: `'First` is always a
        // valid in-range neutral (0 for modular, NUL for Character, the low bound
        // for a fixed/decimal type).
        TypeKind::Scalar(
            ScalarKind::Modular | ScalarKind::Character | ScalarKind::Fixed | ScalarKind::Decimal,
        ) => Ok(DecoderEmission {
            call_expr: format!("{}'First", ada_type_name(p)),
            setup_lines: Vec::new(),
        }),
        TypeKind::Derived { base } => {
            let Some(base_kind) = resolve_derived_base_kind(ast, &p.type_ref, *base) else {
                return Err(HarnessGenError::UnsupportedParamType(type_name(
                    &p.type_ref,
                )));
            };
            let mut synth = p.clone();
            synth.type_ref.kind = base_kind;
            select_neutral_for_param(ast, &synth, registry)
        }
        TypeKind::Enum(literals) => {
            if literals.is_empty() {
                return Err(HarnessGenError::UnsupportedParamType(
                    "empty enum".to_owned(),
                ));
            }

            Ok(DecoderEmission {
                call_expr: format!("{}'Val (0)", ada_type_name(p)),
                setup_lines: Vec::new(),
            })
        }
        TypeKind::Array { .. } => Ok(array_neutral(p)),
        TypeKind::Record(fields) if record_is_empty(fields) => Ok(DecoderEmission {
            call_expr: format!("{}'(null record)", ada_type_name(p)),
            setup_lines: Vec::new(),
        }),
        TypeKind::Record(fields) => Ok(record_neutral(p, fields)),
        TypeKind::Discriminated { discriminants, .. } => {
            let disc_field = discriminants
                .0
                .first()
                .map(|field| ada_name(&parse_record_field(field).0))
                .unwrap_or_else(|| "D".to_owned());

            Ok(DecoderEmission {
                call_expr: format!(
                    "{}'({disc_field} => Integer (0), others => <>)",
                    ada_type_name(p)
                ),
                setup_lines: Vec::new(),
            })
        }
        TypeKind::Tagged { .. } | TypeKind::Private => {
            let tagged_type = ada_type_name(p);
            let usable: Vec<&ConstructorEntry> = registry
                .for_tagged_type(&tagged_type)
                .into_iter()
                .filter(|constructor| constructor_is_usable(constructor))
                .collect();
            let Some(first_constructor) = usable.first() else {
                let kind_label = match &p.type_ref.kind {
                    TypeKind::Tagged { .. } => "tagged",
                    TypeKind::Private => "private",
                    _ => "named",
                };
                return Err(HarnessGenError::UnsupportedParamType(format!(
                    "{kind_label} type {tagged_type} has no constructor with synthesizable parameters"
                )));
            };

            Ok(DecoderEmission {
                call_expr: constructor_call(first_constructor),
                setup_lines: Vec::new(),
            })
        }
        TypeKind::Access { .. } => Ok(DecoderEmission {
            call_expr: "null".to_owned(),
            setup_lines: Vec::new(),
        }),
        _ if is_corba_object_ref(&p.type_ref) => Ok(DecoderEmission {
            call_expr: "CORBA.Object.Nil".to_owned(),
            setup_lines: Vec::new(),
        }),
        _ if is_typed_ref(&p.type_ref) => Ok(DecoderEmission {
            call_expr: format!("{}'(null record)", ada_type_name(p)),
            setup_lines: Vec::new(),
        }),
        _ if last_type_name_is(&p.type_ref, "Character")
            || last_type_name_is(&p.type_ref, "Wide_Character")
            || last_type_name_is(&p.type_ref, "Wide_Wide_Character") =>
        {
            Ok(DecoderEmission {
                call_expr: format!("{}'First", ada_type_name(p)),
                setup_lines: Vec::new(),
            })
        }
        _ if last_type_name_is(&p.type_ref, "String") => Ok(DecoderEmission {
            call_expr: "\"\"".to_owned(),
            setup_lines: Vec::new(),
        }),
        _ if last_type_name_is(&p.type_ref, "Integer")
            || last_type_name_is(&p.type_ref, "Natural")
            || last_type_name_is(&p.type_ref, "Positive") =>
        {
            Ok(scalar_neutral(p, integer_neutral_literal(p)))
        }
        _ if is_integer_alias_name(&p.type_ref) => Ok(scalar_neutral(p, "0")),
        _ if last_type_name_is(&p.type_ref, "Boolean") => Ok(DecoderEmission {
            call_expr: "False".to_owned(),
            setup_lines: Vec::new(),
        }),
        _ if builtin_named_type_neutral(&p.type_ref).is_some() => Ok(DecoderEmission {
            call_expr: builtin_named_type_neutral(&p.type_ref).unwrap(),
            setup_lines: Vec::new(),
        }),
        // Out/neutral `X.Bounded_String` (a `Generic_Bounded_Length` instance):
        // the instance exposes `Null_Bounded_String` as its empty value. Mirrors
        // the initializer-side `To_Bounded_String` decode so a pure `out` bounded
        // param doesn't reopen the "no synthesizable constructor" skip.
        _ if last_type_name_is(&p.type_ref, "Bounded_String")
            && type_path_parts(&p.type_ref).len() >= 2 =>
        {
            let full = ada_type_name(p);
            let prefix = full
                .rsplit_once('.')
                .map_or(full.as_str(), |(head, _)| head);
            Ok(DecoderEmission {
                call_expr: format!("{prefix}.Null_Bounded_String"),
                setup_lines: Vec::new(),
            })
        }
        // Catch-all for an out-of-tree / unresolved parameter type (e.g. a
        // Libadalang type a harness can't see). Emit a descriptive, properly-cased
        // reason like the Tagged/Private branches rather than a bare lowercased
        // echo of the name — the surrounding error reprints the cased name too, so
        // the bare echo just duplicated it with no added information (#45).
        _ => Err(HarnessGenError::UnsupportedParamType(format!(
            "named type {} is not declared in the parsed source set and has no \
             synthesizable constructor",
            ada_type_name(p)
        ))),
    }
}

/// True when a record has no real components: an empty field list, or only the
/// `null` component of `record null; end record` (the parser surfaces the `null`
/// component-list as a phantom "null" field, and `null` is reserved so it can never
/// be a genuine field name).
fn record_is_empty(fields: &ada_parser::ast::Fields) -> bool {
    fields
        .0
        .iter()
        .flat_map(|f| record_field_components(f))
        .all(|(name, _)| name.eq_ignore_ascii_case("null"))
}

/// Decode a character-typed value within the type's own position range (total and
/// in range for `Character`, `Wide_Character`, `Wide_Wide_Character`, and declared
/// character types) — structurally identical to the enumeration decode.
fn character_decode(ty: &str) -> String {
    format!(
        "{ty}'Val ({ty}'Pos ({ty}'First) + AdaFuzz.Decode.Bounded_Range (Cur, 0, {ty}'Pos ({ty}'Last) - {ty}'Pos ({ty}'First)))"
    )
}

/// Resolve a `Derived` type's ultimate base [`TypeKind`] by walking the derivation
/// chain in the AST type table, with cycle detection. Returns `None` if the base is
/// unknown to the tree, self-referential, or the chain cycles/exceeds a sane depth.
fn resolve_derived_base_kind(
    ast: &StructuralAst,
    origin: &TypeRef,
    mut base: TypeId,
) -> Option<TypeKind> {
    let mut seen = vec![origin.id];
    for _ in 0..16 {
        let resolved = ast.types.iter().find(|t| t.id == base)?;
        if seen.contains(&resolved.id) {
            return None; // cyclic derivation
        }
        seen.push(resolved.id);
        match &resolved.kind {
            TypeKind::Derived { base: next } => base = *next,
            other => return Some(other.clone()),
        }
    }
    None
}

fn integer_alias_decoder(p: &Parameter, bound: Option<(i32, i32)>) -> DecoderEmission {
    let call_expr = if let Some((lo, hi)) = bound {
        format!(
            "{} (AdaFuzz.Decode.Bounded_Range (Cur, {lo}, {hi}))",
            ada_type_name(p)
        )
    } else {
        format!("{} (AdaFuzz.Decode.I32 (Cur))", ada_type_name(p))
    };
    DecoderEmission {
        call_expr,
        setup_lines: Vec::new(),
    }
}

fn interfaces_integer_bound(type_ref: &TypeRef) -> Option<(i32, i32)> {
    let name = type_ref
        .name_path
        .last()
        .map(|name| name.to_ascii_lowercase())?;
    match name.as_str() {
        "integer_8" | "signed_char" => Some((-128, 127)),
        "integer_16" | "short" | "c_short" => Some((-32768, 32767)),
        "integer_32" | "integer_64" | "int" | "c_int" | "long" | "long_long" => None,
        "unsigned_8" | "unsigned_char" => Some((0, 255)),
        "unsigned_16" | "unsigned_short" => Some((0, 65535)),
        "unsigned_32" | "unsigned_64" | "unsigned" | "unsigned_long" | "unsigned_long_long"
        | "size_t" | "c_size_t" => Some((0, i32::MAX)),
        _ => None,
    }
}

/// Whether the type's simple name is a known integer alias (Standard,
/// Interfaces, or Interfaces.C). Distinct from `interfaces_integer_bound`,
/// which yields a *tight* bound only for the widths that fit in `i32`: a wider
/// alias (`Integer_32`, `Integer_64`, `Long_Integer`, ...) is still a decodable
/// integer, just decoded over the full `I32` range rather than a tight bound.
fn is_integer_alias_name(type_ref: &TypeRef) -> bool {
    let Some(name) = type_ref
        .name_path
        .last()
        .map(|name| name.to_ascii_lowercase())
    else {
        return false;
    };
    matches!(
        name.as_str(),
        "integer_8"
            | "signed_char"
            | "integer_16"
            | "short"
            | "c_short"
            | "integer_32"
            | "integer_64"
            | "int"
            | "c_int"
            | "long"
            | "long_long"
            | "long_integer"
            | "short_integer"
            | "long_long_integer"
            | "unsigned_8"
            | "unsigned_char"
            | "unsigned_16"
            | "unsigned_short"
            | "unsigned_32"
            | "unsigned_64"
            | "unsigned"
            | "unsigned_long"
            | "unsigned_long_long"
            | "size_t"
            | "c_size_t"
    )
}

fn scalar_neutral(p: &Parameter, literal: &str) -> DecoderEmission {
    DecoderEmission {
        call_expr: format!("{} ({literal})", ada_type_name(p)),
        setup_lines: Vec::new(),
    }
}

fn integer_neutral_literal(p: &Parameter) -> &'static str {
    if last_type_name_is(&p.type_ref, "Positive") {
        "1"
    } else {
        "0"
    }
}

fn array_neutral(p: &Parameter) -> DecoderEmission {
    let arr_type = ada_type_name(p);
    let param_name = ada_name(&p.name);
    let temp_name = format!("Tmp_{param_name}");
    let decode_name = format!("Decode_{param_name}");

    DecoderEmission {
        call_expr: decode_name.clone(),
        setup_lines: vec![
            format!("function {decode_name} return {arr_type} is"),
            format!("   {temp_name} : {arr_type} (1 .. 16) := (others => 0);"),
            "begin".to_owned(),
            format!("   return {temp_name};"),
            format!("end {decode_name};"),
        ],
    }
}

fn record_neutral(p: &Parameter, fields: &ada_parser::ast::Fields) -> DecoderEmission {
    if fields.0.is_empty() {
        return DecoderEmission {
            call_expr: format!("{}'(null record)", ada_type_name(p)),
            setup_lines: Vec::new(),
        };
    }

    let field_values = fields
        .0
        .iter()
        .flat_map(|field| record_field_components(field))
        .map(|(name, ty)| format!("{} => {}", ada_name(&name), guess_neutral_for_type(&ty)))
        .collect::<Vec<_>>();

    DecoderEmission {
        call_expr: format!("{}'({})", ada_type_name(p), field_values.join(", ")),
        setup_lines: Vec::new(),
    }
}

fn object_ref_decoder(p: &Parameter) -> DecoderEmission {
    let ref_type = ada_type_name(p);
    let param_name = ada_name(&p.name);
    let decode_name = format!("Decode_{param_name}");

    DecoderEmission {
        call_expr: decode_name.clone(),
        setup_lines: vec![
            format!("function {decode_name} return {ref_type} is"),
            "begin".to_owned(),
            "   case AdaFuzz.Decode.Bounded_Range (Cur, 0, 1) is".to_owned(),
            "      when 0 => return CORBA.Object.Nil;".to_owned(),
            "      when others => return CORBA.Object.Fake (Integer (AdaFuzz.Decode.I32 (Cur)));"
                .to_owned(),
            "   end case;".to_owned(),
            format!("end {decode_name};"),
        ],
    }
}

fn typed_ref_decoder(p: &Parameter) -> DecoderEmission {
    let ref_type = ada_type_name(p);
    let param_name = ada_name(&p.name);
    let decode_name = format!("Decode_{param_name}");

    DecoderEmission {
        call_expr: decode_name.clone(),
        setup_lines: vec![
            format!("function {decode_name} return {ref_type} is"),
            "begin".to_owned(),
            format!("   return {ref_type}'(null record);"),
            format!("end {decode_name};"),
        ],
    }
}

fn constructor_call(constructor: &ConstructorEntry) -> String {
    let path = ada_dotted_name(&constructor.qualified_path);
    if constructor.param_count == 0 {
        return path;
    }

    // Omit trailing parameters that have a default expression: passing a
    // wrong-typed neutral (`0`) for them is both unnecessary and a hard type
    // error when the type isn't scalar (ada-toml's
    // `Location : Source_Location := No_Location` -> "found type universal
    // integer"). Positional omission is correct only for the trailing run of
    // defaulted formals, so emit args up to the last required (non-defaulted)
    // one. With no per-param default info recorded, fall back to all params.
    let emit_count = if constructor.param_has_default.len() == constructor.param_count as usize {
        constructor
            .param_has_default
            .iter()
            .rposition(|has_default| !has_default)
            .map(|last_required| last_required + 1)
            .unwrap_or(0)
    } else {
        constructor.param_count as usize
    };
    if emit_count == 0 {
        return path;
    }

    let args = (0..emit_count)
        .map(|index| {
            constructor
                .param_type_names
                .get(index)
                .filter(|name| !name.is_empty())
                .map(|name| guess_neutral_for_type(name))
                .unwrap_or_else(|| "0".to_owned())
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{path}({args})")
}

fn parse_record_field(field: &str) -> (String, String) {
    let mut parts = field.splitn(2, ':');
    let name = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("F")
        .to_owned();
    let ty = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Integer")
        .to_owned();

    (name, ty)
}

/// Expand a record field declaration into one `(name, type)` pair per declared
/// component. Ada allows `a, b : T;` to declare several components of the same
/// type in a single declaration; each needs its own aggregate association, so a
/// decoder that treats the whole `a, b` blob as one name emits an invalid
/// `a,\nb => value` (positional-after-named) aggregate.
fn record_field_components(field: &str) -> Vec<(String, String)> {
    let (names, ty) = parse_record_field(field);
    names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| (name.to_owned(), ty.clone()))
        .collect()
}

/// The index subtype name of an unconstrained array, parsed from its bounds
/// text (`"N32 range <>"` -> `"N32"`, `"Positive range <>"` -> `"Positive"`).
/// Returns None when there is no named index (`"<>"`) so the caller falls back
/// to the plain `Natural` bound.
/// Whether `name` is a directly-visible standard index type — these need no
/// qualification (and the plain `Natural` bound already works for them).
fn is_standard_index_type(name: &str) -> bool {
    matches!(
        name,
        "Positive" | "Natural" | "Integer" | "Long_Integer" | "Short_Integer" | "Long_Long_Integer"
    )
}

/// Qualify a package-local array index type with the array type's package so
/// it's visible in the harness (`Sparknacl.Byte_Seq` + `N32` ->
/// `Sparknacl.N32`). Already-qualified or package-less names are returned as-is.
fn qualify_index_type(arr_type: &str, index_type: &str) -> String {
    if index_type.contains('.') {
        return index_type.to_owned();
    }
    match arr_type.rsplit_once('.') {
        Some((package, _)) => format!("{package}.{index_type}"),
        None => index_type.to_owned(),
    }
}

fn array_index_type(bounds: &str) -> Option<String> {
    let head = bounds.split("range").next().unwrap_or("").trim();
    if head.is_empty() {
        return None;
    }
    let valid = head.split('.').all(|seg| {
        let s = seg.trim();
        !s.is_empty()
            && s.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    });
    valid.then(|| head.to_owned())
}

/// Number of index dimensions of an array type, read from its bounds/index
/// string (`"1 .. 3, 1 .. 3"` -> 2; `"Index range <>"` -> 1). Only top-level
/// commas count (a bound expression may itself contain parenthesised commas).
/// Minimum 1 (an empty/unknown constraint is treated as one-dimensional).
fn array_dimensions(bounds: &str) -> usize {
    if bounds.trim().is_empty() {
        return 1;
    }
    let mut depth = 0i32;
    let mut commas = 0usize;
    for ch in bounds.chars() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => commas += 1,
            _ => {}
        }
    }
    commas + 1
}

/// Nested fill loops for a `dims`-dimensional array local `temp`: one
/// `for Ik in temp'Range (k) loop` per dimension, then a single N-subscript
/// assignment `temp (I1, .., IN) := <elem>`. Indent matches the surrounding
/// decode function (3 spaces per level, body one level deeper).
fn array_fill_loop_lines(temp: &str, dims: usize, elem_expr: &str) -> Vec<String> {
    let dims = dims.max(1);
    if dims == 1 {
        // Preserve the simple one-dimensional form (`'Range`, single subscript).
        return vec![
            format!("   for I in {temp}'Range loop"),
            format!("      {temp} (I) := {elem_expr};"),
            "   end loop;".to_owned(),
        ];
    }
    // Multi-dimensional: one nested loop per dimension over its `'Range (k)`,
    // then a single N-subscript assignment.
    let mut lines = Vec::new();
    for k in 1..=dims {
        let indent = "   ".repeat(k);
        lines.push(format!("{indent}for I{k} in {temp}'Range ({k}) loop"));
    }
    let subs = (1..=dims)
        .map(|k| format!("I{k}"))
        .collect::<Vec<_>>()
        .join(", ");
    let indent = "   ".repeat(dims + 1);
    lines.push(format!("{indent}{temp} ({subs}) := {elem_expr};"));
    for k in (1..=dims).rev() {
        let indent = "   ".repeat(k);
        lines.push(format!("{indent}end loop;"));
    }
    lines
}

/// Decode expression for one array element of component type `elem_name`.
/// Byte/modular/integer subtypes (the common buffer case) take a fuzz byte via
/// `U8`, which is always in range for those types, so the decode loop itself
/// can never raise a spurious Constraint_Error that would escape the harness.
fn array_element_decoder(elem_name: &str, arr_type: &str) -> String {
    let base = elem_name.rsplit('.').next().unwrap_or(elem_name).trim();
    match base.to_ascii_lowercase().as_str() {
        // Unknown component: preserve the historical best-effort behaviour.
        "" => "Integer (AdaFuzz.Decode.I32 (Cur))".to_owned(),
        "boolean" => "AdaFuzz.Decode.Bool (Cur)".to_owned(),
        "character" => {
            "Character'Val (Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 255)))".to_owned()
        }
        "float" | "long_float" => "Float (AdaFuzz.Decode.F64 (Cur))".to_owned(),
        // Always-visible Standard integer types: a fuzz byte (0 .. 255) is in
        // range and non-negative, so the decode loop cannot raise.
        "integer" | "natural" => "Integer (AdaFuzz.Decode.U8 (Cur))".to_owned(),
        "positive" => "Positive (Natural (AdaFuzz.Decode.U8 (Cur)) + 1)".to_owned(),
        // A named component type: a package-local Unsigned_8 *subtype* (the common
        // byte-buffer case) OR a *derived* integer type (`Event is new Unsigned_8`).
        // A derived type rejects the raw `Unsigned_8` fuzz byte, so convert it to
        // the component type; the same conversion is a harmless no-op for a plain
        // subtype. Qualify the component with the array type's package (the only
        // package the harness `with`s) when it isn't already qualified.
        _ => format!(
            "{} (AdaFuzz.Decode.U8 (Cur))",
            qualify_component_type(arr_type, elem_name)
        ),
    }
}

/// Qualify an array's component type with the array type's package when the
/// component is named bare (`Event` -> `Sdpcm.Events.Event`), mirroring
/// [`qualify_index_type`] for the index type. An already-qualified component
/// name is returned unchanged.
fn qualify_component_type(arr_type: &str, elem_name: &str) -> String {
    if elem_name.contains('.') || is_predefined_scalar_name(elem_name) {
        return elem_name.to_owned();
    }
    match arr_type.rsplit_once('.') {
        Some((package, _)) => format!("{package}.{elem_name}"),
        None => elem_name.to_owned(),
    }
}

/// Decode a discriminant default within a small bounded range (a discriminant
/// commonly bounds an array length or selects a variant, so a large value risks a
/// Storage_Error or huge allocation). An in-tree enum discriminant decodes via
/// `'Val`; any other (possibly *derived* integer, e.g. `SDPCM_Channel is new
/// Unsigned_8`) is converted to its actual type — qualified with the record's
/// package — instead of the historical hardcoded `Integer`.
fn discriminant_decode(ast: &StructuralAst, record_type: &str, disc_ty: &str) -> String {
    let by_field = decode_record_field(ast, disc_ty);
    if by_field.contains("'Val") {
        return by_field;
    }
    let qualified = qualify_component_type(record_type, disc_ty);
    format!("{qualified} (AdaFuzz.Decode.Bounded_Range (Cur, 0, 4))")
}

/// Whether a type name is a directly-visible Standard predefined scalar that must
/// never be package-qualified (`Integer` -> not `Pkg.Integer`).
fn is_predefined_scalar_name(name: &str) -> bool {
    let leaf = name.rsplit('.').next().unwrap_or(name).trim();
    matches!(
        leaf.to_ascii_lowercase().as_str(),
        "integer"
            | "natural"
            | "positive"
            | "long_integer"
            | "short_integer"
            | "long_long_integer"
            | "short_short_integer"
            | "boolean"
            | "character"
            | "wide_character"
            | "wide_wide_character"
            | "float"
            | "long_float"
            | "long_long_float"
            | "short_float"
            | "duration"
            | "string"
    )
}

/// Decode an integer-typed value of the (sub)type spelled `name`.
///
/// `Natural (I32)` / `Positive (I32)` range-check-fail on a negative /
/// non-positive draw — and the param's initializer runs in the harness block's
/// *declarative* part, where Ada does NOT route the exception to the block's
/// `exception when others` handler, so the whole harness process crashes
/// (~half the inputs). Decode these within their range via `Bounded_Range`
/// instead, with an upper bound (`2**30`) that never overflows `Hi - Lo + 1`
/// (`Integer'Last` would). Plain `Integer` keeps the full-range `I32` decode.
fn integer_scalar_decode(name: &str) -> String {
    let leaf = name.rsplit('.').next().unwrap_or(name);
    match leaf.to_ascii_lowercase().as_str() {
        "natural" => "Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 2 ** 30))".to_owned(),
        "positive" => "Positive (AdaFuzz.Decode.Bounded_Range (Cur, 1, 2 ** 30))".to_owned(),
        _ => format!("{name} (AdaFuzz.Decode.I32 (Cur))"),
    }
}

/// Decode one record field. A standard type decodes by name
/// (`guess_decoder_for_type`); otherwise resolve the field type against the tree
/// — a fuzzable enumeration decodes via `'Val` over its literal count. Anything
/// else still default-initialises (`<>`).
///
/// The enum is named QUALIFIED so it is visible in the harness (which `with`s
/// but does not `use` the unit): a bare field type (`Color`) is qualified with
/// its owning package (`Rec.Color`) — the same package the harness already
/// `with`s for the record — while an already-qualified field type is kept as
/// written (its unit is `with`ed via the record's own source).
fn decode_record_field(ast: &StructuralAst, ty: &str) -> String {
    let by_name = guess_decoder_for_type(ty);
    if by_name != "<>" {
        return by_name;
    }
    let leaf = ty.trim().rsplit('.').next().unwrap_or(ty).trim();
    if leaf.is_empty() {
        return "<>".to_owned();
    }
    if let Some(declared) = ast.types.iter().find(|t| {
        t.name_path
            .last()
            .is_some_and(|n| n.eq_ignore_ascii_case(leaf))
    }) {
        if let TypeKind::Enum(variants) = &declared.kind {
            // A real in-tree enumeration: decode an index over its literals. The
            // synthetic "__external_discrete" marker has no known cardinality.
            let literal_count = variants.iter().filter(|v| !v.starts_with("__")).count();
            if literal_count >= 2 {
                let qualified = qualify_enum_field(ast, ty, leaf, declared);
                return format!(
                    "{qualified}'Val (Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, {})))",
                    literal_count - 1
                );
            }
        }
    }
    "<>".to_owned()
}

/// The harness-visible name for an enum field type. An already-qualified `ty`
/// (contains a dot) is kept as written; a bare name is qualified with its owning
/// package, which the harness `with`s for the enclosing record.
fn qualify_enum_field(ast: &StructuralAst, ty: &str, leaf: &str, declared: &TypeRef) -> String {
    if ty.contains('.') {
        return ty.trim().to_owned();
    }
    if let ada_parser::ast::TypeOwner::Package(pid) = declared.owner {
        if let Some(pkg) = ast.packages.iter().find(|p| p.id == pid) {
            return format!("{}.{}", ada_dotted_name(&pkg.name), leaf);
        }
    }
    ty.trim().to_owned()
}

fn guess_decoder_for_type(ty: &str) -> String {
    let base_ty = ty.split('(').next().unwrap_or(ty).trim();
    match base_ty.to_ascii_lowercase().as_str() {
        // Standard discrete/float types: always visible, and the I32/F64
        // decoders fit them without a range-check failure (Integer/Long_Integer/
        // Long_Long_Integer are >= 32-bit; the floats subsume Long_Float). We
        // deliberately do NOT cover narrow widths (Short_Integer, Integer_8) or
        // `Interfaces`/modular spellings here: an I32 cast to a narrow type
        // raises CONSTRAINT_ERROR for most inputs (a false-positive finding), and
        // a qualified `Interfaces.*` cast needs a `with` the record decoder does
        // not add. Those (and project-derived aliases like Data_Bytes_Count,
        // which keep their documented default via `<>`) need AST-aware field
        // typing + with-management — deferred.
        "integer" => "Integer (AdaFuzz.Decode.I32 (Cur))".to_owned(),
        // Bounded decode (see integer_scalar_decode): a record-field initializer
        // is likewise in the aggregate's declarative context.
        "natural" => integer_scalar_decode("Natural"),
        "positive" => integer_scalar_decode("Positive"),
        "long_integer" => "Long_Integer (AdaFuzz.Decode.I32 (Cur))".to_owned(),
        "long_long_integer" => "Long_Long_Integer (AdaFuzz.Decode.I32 (Cur))".to_owned(),
        "boolean" => "AdaFuzz.Decode.Bool (Cur)".to_owned(),
        "float" => "Float (AdaFuzz.Decode.F64 (Cur))".to_owned(),
        "long_float" => "Long_Float (AdaFuzz.Decode.F64 (Cur))".to_owned(),
        "long_long_float" => "Long_Long_Float (AdaFuzz.Decode.F64 (Cur))".to_owned(),
        "string" | "standard.string" => "AdaFuzz.Decode.Ada_String (Cur, 0, 64)".to_owned(),
        "unbounded_string" | "ada.strings.unbounded.unbounded_string" => {
            "Ada.Strings.Unbounded.To_Unbounded_String (AdaFuzz.Decode.Ada_String (Cur, 0, 64))"
                .to_owned()
        }
        "character" => {
            "Character'Val (Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 127)))".to_owned()
        }
        // Unknown field type (an access-to-subprogram callback, a nested
        // record, a private type ...). A literal `0` only compiles for an
        // integer field and otherwise fails with "expected type X". `<>`
        // default-initialises the field in the aggregate (null for access
        // types, the declared default for a field that has one), which is
        // always legal and is the right neutral for a field we cannot decode.
        _ => "<>".to_owned(),
    }
}

fn guess_neutral_for_type(ty: &str) -> String {
    let normalized = ty.trim();
    let last = normalized
        .split('.')
        .next_back()
        .unwrap_or(normalized)
        .to_ascii_lowercase();

    match last.as_str() {
        "boolean" => "False".to_owned(),
        "string" => "\"\"".to_owned(),
        "unbounded_string" => "Ada.Strings.Unbounded.Null_Unbounded_String".to_owned(),
        "float" | "long_float" => format!("{} (0.0)", ada_dotted_name(normalized)),
        "positive" => format!("{} (1)", ada_dotted_name(normalized)),
        "integer" | "natural" => format!("{} (0)", ada_dotted_name(normalized)),
        // Emit the canonical fully-qualified name rather than echoing the input
        // (a parser name_path can carry trailing dots, which `ada_dotted_name`
        // would render as `Ada..Calendar..Year_Number`).
        "year_number" => "Ada.Calendar.Year_Number'First".to_owned(),
        "month_number" => "Ada.Calendar.Month_Number'First".to_owned(),
        "day_number" => "Ada.Calendar.Day_Number'First".to_owned(),
        "day_duration" => "Ada.Calendar.Day_Duration'First".to_owned(),
        "ref" => format!("{}'(null record)", ada_dotted_name(normalized)),
        _ if looks_like_fixed_size_byte_alias(&last) => {
            format!("{}'(others => 0)", ada_dotted_name(normalized))
        }
        _ => "0".to_owned(),
    }
}

/// Whether `guess_neutral_for_type` produces a *type-correct* neutral for this
/// type (not the bare `0` fallback, which only compiles for an integer). Used
/// to skip constructors whose required parameters can't be synthesised — a
/// stream/tagged/range-constrained param (zip-ada `Get_Time (S : in
/// Root_Zipstream_Type)`) would otherwise emit `Get_Time (0)` ("no candidate
/// interpretations match the actuals").
fn type_has_known_neutral(ty: &str) -> bool {
    let last = ty
        .trim()
        .split('.')
        .next_back()
        .unwrap_or(ty)
        .to_ascii_lowercase();
    matches!(
        last.as_str(),
        "boolean"
            | "string"
            | "unbounded_string"
            | "float"
            | "long_float"
            | "positive"
            | "integer"
            | "natural"
            | "year_number"
            | "month_number"
            | "day_number"
            | "day_duration"
            | "ref"
    ) || looks_like_fixed_size_byte_alias(&last)
}

/// A constructor is usable for neutral synthesis only when every required
/// (non-defaulted) parameter has a known neutral. With no recorded parameter
/// types, keep the legacy behaviour (assume usable).
fn constructor_is_usable(constructor: &ConstructorEntry) -> bool {
    if constructor.param_type_names.len() != constructor.param_count as usize {
        return true;
    }
    let required = if constructor.param_has_default.len() == constructor.param_count as usize {
        constructor
            .param_has_default
            .iter()
            .rposition(|has_default| !has_default)
            .map(|last_required| last_required + 1)
            .unwrap_or(0)
    } else {
        constructor.param_count as usize
    };
    (0..required).all(|index| {
        constructor
            .param_type_names
            .get(index)
            .is_some_and(|name| type_has_known_neutral(name))
    })
}

fn looks_like_fixed_size_byte_alias(last_lower: &str) -> bool {
    let Some(rest) = last_lower
        .strip_prefix("bytes_")
        .or_else(|| last_lower.strip_prefix("byte_seq_"))
    else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

fn ada_dotted_name(name: &str) -> String {
    name.split('.').map(ada_name).collect::<Vec<_>>().join(".")
}

fn ada_type_name(p: &Parameter) -> String {
    if !p.type_ref.name_path.is_empty() {
        return type_path_parts(&p.type_ref)
            .into_iter()
            .map(ada_name)
            .collect::<Vec<_>>()
            .join(".");
    }

    match &p.type_ref.kind {
        TypeKind::Scalar(ScalarKind::Integer) => "Integer".to_owned(),
        TypeKind::Scalar(ScalarKind::Float) => "Long_Float".to_owned(),
        TypeKind::Scalar(ScalarKind::Boolean) => "Boolean".to_owned(),
        _ => type_name(&p.type_ref),
    }
}

fn ada_name(name: &str) -> String {
    if name.chars().any(|ch| ch.is_ascii_uppercase()) {
        return name.to_owned();
    }

    let mut rendered = String::with_capacity(name.len());
    let mut capitalize_next = true;
    for ch in name.chars() {
        if ch == '_' {
            rendered.push(ch);
            capitalize_next = true;
        } else if capitalize_next {
            rendered.push(ch.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            rendered.push(ch);
        }
    }
    rendered
}

fn last_type_name_is(type_ref: &TypeRef, expected: &str) -> bool {
    type_path_parts(type_ref)
        .last()
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

fn is_corba_object_ref(type_ref: &TypeRef) -> bool {
    let parts = type_path_parts(type_ref);
    parts.len() == 3
        && parts[0].eq_ignore_ascii_case("CORBA")
        && parts[1].eq_ignore_ascii_case("Object")
        && parts[2].eq_ignore_ascii_case("Ref")
}

fn is_typed_ref(type_ref: &TypeRef) -> bool {
    !is_corba_object_ref(type_ref) && last_type_name_is(type_ref, "Ref")
}

fn type_name(type_ref: &TypeRef) -> String {
    if type_ref.name_path.is_empty() {
        format!("{type_ref:?}")
    } else {
        type_path_parts(type_ref).join(".")
    }
}

fn type_path_parts(type_ref: &TypeRef) -> Vec<&str> {
    type_ref
        .name_path
        .iter()
        .flat_map(|part| part.split('.'))
        .filter(|part| !part.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{known_stdlib_type_with, known_stdlib_with_for_type_name};
    use super::{select_decoder_for_param, select_initializer_for_param, DecoderEmission};

    #[test]
    fn known_stdlib_with_for_type_name_maps_calendar_and_streams() {
        assert_eq!(
            known_stdlib_with_for_type_name("Ada.Calendar.Year_Number"),
            Some("Ada.Calendar")
        );
        assert_eq!(
            known_stdlib_with_for_type_name("day_duration"),
            Some("Ada.Calendar")
        );
        assert_eq!(
            known_stdlib_with_for_type_name("Ada.Streams.Stream_Element_Array"),
            Some("Ada.Streams")
        );
        assert_eq!(known_stdlib_with_for_type_name("Zip.Time"), None);
    }

    use crate::registry::{ConstructorEntry, ConstructorRegistry};
    use crate::HarnessGenError;
    use ada_parser::ast::{
        Aspects, Constraints, Fields, Package, PackageId, ParamMode, Parameter, ScalarKind,
        StructuralAst, TypeId, TypeKind, TypeOwner, TypeRef, Visibility,
    };

    fn param(type_name: &str, kind: TypeKind) -> Parameter {
        param_with_mode(type_name, kind, ParamMode::In)
    }

    fn param_with_mode(type_name: &str, kind: TypeKind, mode: ParamMode) -> Parameter {
        Parameter {
            name: "Value".to_owned(),
            mode,
            type_ref: TypeRef {
                id: TypeId(1),
                name_path: type_name.split('.').map(str::to_owned).collect(),
                visibility: Visibility::Public,
                owner: TypeOwner::LibraryLevel,
                kind,
                constraints: Constraints(String::new()),
                aspects: Aspects(Vec::new()),
            },
            default: None,
        }
    }

    fn type_ref_with_kind_and_name(kind: TypeKind, name_path: &[&str]) -> TypeRef {
        TypeRef {
            id: TypeId(1),
            name_path: name_path.iter().map(|name| (*name).to_owned()).collect(),
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind,
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        }
    }

    fn select(p: &Parameter) -> Result<DecoderEmission, HarnessGenError> {
        let registry = ConstructorRegistry::new();
        select_decoder_for_param(&StructuralAst::new(), p, &registry)
    }

    fn select_with_ast(
        ast: &StructuralAst,
        p: &Parameter,
    ) -> Result<DecoderEmission, HarnessGenError> {
        let registry = ConstructorRegistry::new();
        select_decoder_for_param(ast, p, &registry)
    }

    fn select_initializer(p: &Parameter) -> Result<DecoderEmission, HarnessGenError> {
        let registry = ConstructorRegistry::new();
        select_initializer_for_param(&StructuralAst::new(), p, &registry)
    }

    #[test]
    fn select_decoder_for_modular_param_uses_mod_attribute() {
        let d = select(&param("Byte", TypeKind::Scalar(ScalarKind::Modular))).unwrap();
        assert_eq!(d.call_expr, "Byte'Mod (AdaFuzz.Decode.U64 (Cur))");
    }

    #[test]
    fn select_decoder_for_character_decodes_in_range() {
        // Predefined Character arrives as a named Unknown type (not Scalar(Character)).
        let d = select(&param("Character", TypeKind::Unknown)).unwrap();
        assert!(
            d.call_expr
                .contains("Character'Val (Character'Pos (Character'First)"),
            "{}",
            d.call_expr
        );
        // A declared character type classified Scalar(Character) takes the same path.
        let d2 = select(&param("My_Char", TypeKind::Scalar(ScalarKind::Character))).unwrap();
        assert!(d2.call_expr.starts_with("My_Char'Val"), "{}", d2.call_expr);
    }

    #[test]
    fn select_decoder_for_fixed_and_decimal_convert_bounded_range() {
        for kind in [ScalarKind::Fixed, ScalarKind::Decimal] {
            let d = select(&param("Angle", TypeKind::Scalar(kind))).unwrap();
            assert_eq!(
                d.call_expr,
                "Angle (AdaFuzz.Decode.Bounded_Range (Cur, Integer (Angle'First), Integer (Angle'Last)))"
            );
        }
    }

    #[test]
    fn select_decoder_for_empty_record_emits_null_aggregate() {
        // Truly empty field list, and the `record null` phantom "null" component.
        let empty = select(&param("Tag", TypeKind::Record(Fields(Vec::new())))).unwrap();
        assert_eq!(empty.call_expr, "Tag'(null record)");
        let null_rec = select(&param(
            "Tag",
            TypeKind::Record(Fields(vec!["null".to_owned()])),
        ))
        .unwrap();
        assert_eq!(null_rec.call_expr, "Tag'(null record)");
    }

    #[test]
    fn select_decoder_for_derived_type_decodes_as_base() {
        // `type My_Int is new Integer` — resolve the base kind from the AST and
        // decode as the base, but in the derived type's own name.
        let mut ast = StructuralAst::new();
        ast.types.push(type_ref_with_kind_and_name(
            TypeKind::Scalar(ScalarKind::Integer),
            &["Integer"],
        ));
        // Give the base a distinct id the Derived points at.
        ast.types[0].id = TypeId(2);
        let p = param("My_Int", TypeKind::Derived { base: TypeId(2) });
        let d = select_with_ast(&ast, &p).unwrap();
        assert_eq!(d.call_expr, "My_Int (AdaFuzz.Decode.I32 (Cur))");

        // A derived type whose base the tree doesn't know is a clean skip.
        let orphan = param("Mystery", TypeKind::Derived { base: TypeId(99) });
        assert!(select_with_ast(&ast, &orphan).is_err());
    }

    #[test]
    fn select_decoder_for_integer_param() {
        let decoder = select(&param("Integer", TypeKind::Scalar(ScalarKind::Integer))).unwrap();

        assert_eq!(
            decoder,
            DecoderEmission {
                call_expr: "Integer (AdaFuzz.Decode.I32 (Cur))".to_owned(),
                setup_lines: Vec::new()
            }
        );
    }

    #[test]
    fn select_decoder_for_wide_integer_alias_falls_back_to_i32() {
        // Predefined wide integer aliases (Interfaces.Integer_64, Long_Integer)
        // arrive Unknown - there is no source declaration to resolve. They must
        // still decode as integers (full I32 range), not be skipped.
        for name in ["Integer_64", "Long_Integer"] {
            let decoder = select(&param(name, TypeKind::Unknown)).unwrap();
            assert_eq!(
                decoder.call_expr,
                format!("{name} (AdaFuzz.Decode.I32 (Cur))"),
                "wide integer alias {name} must decode, not skip"
            );
        }
    }

    #[test]
    fn out_boolean_initializer_uses_false_neutral() {
        // An `out Boolean` parameter (Unknown kind, predefined Standard.Boolean)
        // must get a neutral False, not be skipped as unconstructible.
        let initializer = select_initializer(&param_with_mode(
            "Boolean",
            TypeKind::Unknown,
            ParamMode::Out,
        ))
        .unwrap();
        assert_eq!(initializer.call_expr, "False");
        assert!(initializer.setup_lines.is_empty());
    }

    #[test]
    fn out_integer_initializer_uses_neutral_without_consuming_bytes() {
        let initializer = select_initializer(&param_with_mode(
            "Integer",
            TypeKind::Scalar(ScalarKind::Integer),
            ParamMode::Out,
        ))
        .unwrap();

        assert_eq!(initializer.call_expr, "Integer'First");
        assert!(initializer.setup_lines.is_empty());
    }

    #[test]
    fn inout_integer_initializer_keeps_decoded_input() {
        let initializer = select_initializer(&param_with_mode(
            "Integer",
            TypeKind::Scalar(ScalarKind::Integer),
            ParamMode::InOut,
        ))
        .unwrap();

        assert_eq!(initializer.call_expr, "Integer (AdaFuzz.Decode.I32 (Cur))");
        assert!(initializer.setup_lines.is_empty());
    }

    #[test]
    fn out_corba_object_ref_initializer_uses_nil() {
        let initializer = select_initializer(&param_with_mode(
            "CORBA.Object.Ref",
            TypeKind::Unknown,
            ParamMode::Out,
        ))
        .unwrap();

        assert_eq!(initializer.call_expr, "CORBA.Object.Nil");
        assert!(initializer.setup_lines.is_empty());
    }

    #[test]
    fn out_array_initializer_returns_unsupported_instead_of_guessing_element_neutral() {
        let initializer = select_initializer(&param_with_mode(
            "Bool_Array",
            TypeKind::Array {
                idx_types: vec![TypeId(2)],
                elem_type: TypeId(3),
                bounds: "Positive range <>".to_owned(),
                elem_name: String::new(),
            },
            ParamMode::Out,
        ))
        .unwrap();

        assert_eq!(initializer.call_expr, "Decode_Value");
        assert_eq!(
            initializer.setup_lines,
            vec![
                "function Decode_Value return Bool_Array is".to_owned(),
                "   Tmp_Value : Bool_Array (1 .. 16) := (others => 0);".to_owned(),
                "begin".to_owned(),
                "   return Tmp_Value;".to_owned(),
                "end Decode_Value;".to_owned(),
            ]
        );
    }

    #[test]
    fn scalar_decoder_emission_has_empty_setup_lines() {
        let registry = crate::registry::ConstructorRegistry::new();
        let decoder = select_decoder_for_param(
            &StructuralAst::new(),
            &param("Integer", TypeKind::Scalar(ScalarKind::Integer)),
            &registry,
        )
        .unwrap();

        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn known_stdlib_discrete_subtype_decodes_within_range() {
        let registry = crate::registry::ConstructorRegistry::new();
        // An `in` Ada.Calendar.Year_Number (opaque to the parser) is fuzz-decoded
        // within its 1901 .. 2399 range instead of skipping for "no constructor".
        let decoder = select_decoder_for_param(
            &StructuralAst::new(),
            &param("Ada.Calendar.Year_Number", TypeKind::Private),
            &registry,
        )
        .unwrap();
        assert_eq!(
            decoder.call_expr,
            "Ada.Calendar.Year_Number (AdaFuzz.Decode.Bounded_Range (Cur, 1901, 2399))"
        );
        assert!(decoder.setup_lines.is_empty());

        // An `out` Day_Number takes the neutral `'First`.
        let neutral = select_initializer_for_param(
            &StructuralAst::new(),
            &param_with_mode("Ada.Calendar.Day_Number", TypeKind::Private, ParamMode::Out),
            &registry,
        )
        .unwrap();
        assert_eq!(neutral.call_expr, "Ada.Calendar.Day_Number'First");

        // The distinctive leaf name resolves even when written `use`-visible.
        let leaf = select_decoder_for_param(
            &StructuralAst::new(),
            &param("Month_Number", TypeKind::Private),
            &registry,
        )
        .unwrap();
        assert_eq!(
            leaf.call_expr,
            "Ada.Calendar.Month_Number (AdaFuzz.Decode.Bounded_Range (Cur, 1, 12))"
        );

        // Day_Duration (fixed-point) converts the bounded range to the subtype.
        let dur = select_decoder_for_param(
            &StructuralAst::new(),
            &param("Ada.Calendar.Day_Duration", TypeKind::Private),
            &registry,
        )
        .unwrap();
        assert_eq!(
            dur.call_expr,
            "Ada.Calendar.Day_Duration (AdaFuzz.Decode.Bounded_Range (Cur, 0, 86400))"
        );

        // And the constructor-arg synthesis path recognises it.
        assert!(super::type_has_known_neutral("Ada.Calendar.Year_Number"));
        assert_eq!(
            super::guess_neutral_for_type("Ada.Calendar.Year_Number"),
            "Ada.Calendar.Year_Number'First"
        );
    }

    #[test]
    fn decodes_stream_element_array_and_duration_without_a_constructor() {
        let registry = ConstructorRegistry::new();
        // Ada.Streams.Stream_Element_Array -> the runtime's Bytes decoder.
        let sea = select_decoder_for_param(
            &StructuralAst::new(),
            &param("Ada.Streams.Stream_Element_Array", TypeKind::Private),
            &registry,
        )
        .unwrap();
        assert_eq!(sea.call_expr, "AdaFuzz.Decode.Bytes (Cur, 0, 4096)");
        // leaf name (use Ada.Streams;) resolves too.
        let sea_leaf = select_decoder_for_param(
            &StructuralAst::new(),
            &param("Stream_Element_Array", TypeKind::Private),
            &registry,
        )
        .unwrap();
        assert_eq!(sea_leaf.call_expr, "AdaFuzz.Decode.Bytes (Cur, 0, 4096)");

        // Predefined Duration -> bounded fixed-point conversion.
        let dur = select_decoder_for_param(
            &StructuralAst::new(),
            &param("Duration", TypeKind::Private),
            &registry,
        )
        .unwrap();
        assert_eq!(
            dur.call_expr,
            "Standard.Duration (AdaFuzz.Decode.Bounded_Range (Cur, -86_400, 86_400))"
        );

        // out-param neutrals.
        let sea_out = select_initializer_for_param(
            &StructuralAst::new(),
            &param_with_mode("Stream_Element_Array", TypeKind::Private, ParamMode::Out),
            &registry,
        )
        .unwrap();
        assert_eq!(sea_out.call_expr, "(1 .. 0 => 0)");
        let dur_out = select_initializer_for_param(
            &StructuralAst::new(),
            &param_with_mode("Duration", TypeKind::Private, ParamMode::Out),
            &registry,
        )
        .unwrap();
        assert_eq!(dur_out.call_expr, "0.0");
    }

    #[test]
    fn select_decoder_for_boolean_param() {
        let decoder = select(&param("Boolean", TypeKind::Scalar(ScalarKind::Boolean))).unwrap();

        assert_eq!(decoder.call_expr, "AdaFuzz.Decode.Bool (Cur)");
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn select_decoder_for_named_boolean_param_uses_bool_decoder() {
        let decoder = select(&param("Boolean", TypeKind::Unknown)).unwrap();

        assert_eq!(decoder.call_expr, "AdaFuzz.Decode.Bool (Cur)");
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn select_decoder_for_standard_boolean_param_uses_bool_decoder() {
        let decoder = select(&param("Standard.Boolean", TypeKind::Unknown)).unwrap();

        assert_eq!(decoder.call_expr, "AdaFuzz.Decode.Bool (Cur)");
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn select_decoder_for_float_param() {
        let decoder = select(&param("Float", TypeKind::Scalar(ScalarKind::Float))).unwrap();

        assert_eq!(decoder.call_expr, "Float (AdaFuzz.Decode.F64 (Cur))");
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn float_param_decoder_wraps_with_explicit_conversion() {
        let p = Parameter {
            name: "F".to_string(),
            mode: ParamMode::In,
            type_ref: type_ref_with_kind_and_name(TypeKind::Scalar(ScalarKind::Float), &["Float"]),
            default: None,
        };
        let decoder = select(&p).unwrap();
        assert_eq!(decoder.call_expr, "Float (AdaFuzz.Decode.F64 (Cur))");
    }

    #[test]
    fn long_float_param_decoder_wraps_with_long_float_conversion() {
        let p = Parameter {
            name: "L".to_string(),
            mode: ParamMode::In,
            type_ref: type_ref_with_kind_and_name(
                TypeKind::Scalar(ScalarKind::Float),
                &["Long_Float"],
            ),
            default: None,
        };
        let decoder = select(&p).unwrap();
        assert_eq!(decoder.call_expr, "Long_Float (AdaFuzz.Decode.F64 (Cur))");
    }

    #[test]
    fn user_defined_float_subtype_uses_user_type_in_conversion() {
        let p = Parameter {
            name: "Y".to_string(),
            mode: ParamMode::In,
            type_ref: type_ref_with_kind_and_name(
                TypeKind::Scalar(ScalarKind::Float),
                &["My_Pkg", "My_Float"],
            ),
            default: None,
        };
        let decoder = select(&p).unwrap();
        assert_eq!(
            decoder.call_expr,
            "My_Pkg.My_Float (AdaFuzz.Decode.F64 (Cur))"
        );
    }

    #[test]
    fn user_defined_integer_subtype_uses_user_type_in_conversion() {
        let p = Parameter {
            name: "X".to_string(),
            mode: ParamMode::In,
            type_ref: type_ref_with_kind_and_name(
                TypeKind::Scalar(ScalarKind::Integer),
                &["My_Int"],
            ),
            default: None,
        };
        let decoder = select(&p).unwrap();
        assert_eq!(decoder.call_expr, "My_Int (AdaFuzz.Decode.I32 (Cur))");
    }

    #[test]
    fn natural_param_uses_natural_in_conversion() {
        let p = Parameter {
            name: "N".to_string(),
            mode: ParamMode::In,
            type_ref: type_ref_with_kind_and_name(
                TypeKind::Scalar(ScalarKind::Integer),
                &["Natural"],
            ),
            default: None,
        };
        let decoder = select(&p).unwrap();
        // Bounded (non-negative) decode: a plain `Natural (I32)` would
        // range-check-fail on a negative draw and crash the harness in the
        // param's declarative part.
        assert_eq!(
            decoder.call_expr,
            "Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 2 ** 30))"
        );
    }

    #[test]
    fn natural_positive_by_name_fallback_decode_in_range() {
        // Standard Natural/Positive aren't declared in the tree, so they reach
        // the name-based fallback arm (kind != Scalar). It must also decode
        // in-range, not crash via `Natural (I32)`.
        for (name, expected) in [
            (
                "Natural",
                "Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 2 ** 30))",
            ),
            (
                "Positive",
                "Positive (AdaFuzz.Decode.Bounded_Range (Cur, 1, 2 ** 30))",
            ),
        ] {
            let p = Parameter {
                name: "N".to_string(),
                mode: ParamMode::In,
                type_ref: type_ref_with_kind_and_name(TypeKind::Unknown, &[name]),
                default: None,
            };
            assert_eq!(select(&p).unwrap().call_expr, expected);
        }
    }

    #[test]
    fn select_decoder_for_string_param() {
        let decoder = select(&param("String", TypeKind::Unknown)).unwrap();

        assert_eq!(
            decoder.call_expr,
            "AdaFuzz.Decode.Ada_String (Cur, 0, 1024)"
        );
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn select_decoder_for_standard_string_param() {
        let decoder = select(&param("Standard.String", TypeKind::Unknown)).unwrap();

        assert_eq!(
            decoder.call_expr,
            "AdaFuzz.Decode.Ada_String (Cur, 0, 1024)"
        );
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn select_decoder_for_unbounded_string_param_fuzzes_not_empty() {
        // An Unbounded_String input parameter must decode fuzz bytes, not the
        // empty Null_Unbounded_String neutral.
        let decoder = select(&param(
            "Ada.Strings.Unbounded.Unbounded_String",
            TypeKind::Unknown,
        ))
        .unwrap();

        assert_eq!(
            decoder.call_expr,
            "Ada.Strings.Unbounded.To_Unbounded_String \
             (AdaFuzz.Decode.Ada_String (Cur, 0, 1024))"
        );
        assert!(!decoder.call_expr.contains("Null_Unbounded_String"));
    }

    #[test]
    fn select_decoder_for_bounded_string_param_uses_to_bounded_string() {
        // A `Generic_Bounded_Length` instance's Bounded_String input decodes via
        // the instance's `To_Bounded_String`, truncating (Ada.Strings.Right) so an
        // over-long fuzzed string can't raise Length_Error.
        let ty = "Sys.Bounded_750_Type.Bounded_String";
        let decoder = select(&param(ty, TypeKind::Unknown)).unwrap();
        assert_eq!(
            decoder.call_expr,
            "Sys.Bounded_750_Type.To_Bounded_String \
             (AdaFuzz.Decode.Ada_String (Cur, 0, 1024), Ada.Strings.Right)"
        );
        assert!(decoder.setup_lines.is_empty());
        // The `Right` truncation literal needs `with Ada.Strings;`.
        assert_eq!(
            known_stdlib_type_with(&type_ref_with_kind_and_name(
                TypeKind::Unknown,
                &["Sys", "Bounded_750_Type", "Bounded_String"],
            )),
            Some("Ada.Strings")
        );
        // A bare `Bounded_String` with no instance prefix can't be constructed
        // (no nameable To_Bounded_String) — clean skip, not a mis-built harness.
        assert!(select(&param("Bounded_String", TypeKind::Unknown)).is_err());
    }

    #[test]
    fn select_neutral_for_bounded_string_out_param_uses_null_bounded_string() {
        let ty = "Sys.Bounded_750_Type.Bounded_String";
        let p = param_with_mode(ty, TypeKind::Unknown, ParamMode::Out);
        // `select_initializer_for_param` routes a pure `out` param to the neutral.
        let decoder =
            select_initializer_for_param(&StructuralAst::new(), &p, &ConstructorRegistry::new())
                .expect("out bounded string has a neutral");
        assert_eq!(
            decoder.call_expr,
            "Sys.Bounded_750_Type.Null_Bounded_String"
        );
    }

    #[test]
    fn select_decoder_for_standard_integer_param_uses_i32_decoder() {
        let decoder = select(&param("Standard.Integer", TypeKind::Unknown)).unwrap();

        assert_eq!(
            decoder.call_expr,
            "Standard.Integer (AdaFuzz.Decode.I32 (Cur))"
        );
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn select_decoder_for_unsigned_64_param_uses_bounded_nonnegative_value() {
        let decoder = select(&param("Unsigned_64", TypeKind::Unknown)).unwrap();

        assert_eq!(
            decoder.call_expr,
            "Unsigned_64 (AdaFuzz.Decode.Bounded_Range (Cur, 0, 2147483647))"
        );
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn select_decoder_for_unsigned_8_param_respects_type_range() {
        let decoder = select(&param("Interfaces.Unsigned_8", TypeKind::Unknown)).unwrap();

        assert_eq!(
            decoder.call_expr,
            "Interfaces.Unsigned_8 (AdaFuzz.Decode.Bounded_Range (Cur, 0, 255))"
        );
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn corba_object_ref_decoder_uses_nil_and_fake_factories() {
        let decoder = select(&param("CORBA.Object.Ref", TypeKind::Unknown)).unwrap();

        assert_eq!(decoder.call_expr, "Decode_Value");
        assert!(decoder
            .setup_lines
            .contains(&"function Decode_Value return CORBA.Object.Ref is".to_owned()));
        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| { line.contains("case AdaFuzz.Decode.Bounded_Range (Cur, 0, 1) is") }));
        assert!(decoder
            .setup_lines
            .contains(&"      when 0 => return CORBA.Object.Nil;".to_owned()));
        assert!(decoder.setup_lines.contains(
            &"      when others => return CORBA.Object.Fake (Integer (AdaFuzz.Decode.I32 (Cur)));"
                .to_owned()
        ));
    }

    #[test]
    fn typed_idl_ref_decoder_uses_neutral_typed_ref() {
        let decoder = select(&param("Demo.Calculator.Ref", TypeKind::Unknown)).unwrap();

        assert_eq!(decoder.call_expr, "Decode_Value");
        assert!(decoder
            .setup_lines
            .contains(&"function Decode_Value return Demo.Calculator.Ref is".to_owned()));
        assert!(decoder
            .setup_lines
            .contains(&"   return Demo.Calculator.Ref'(null record);".to_owned()));
    }

    #[test]
    fn select_decoder_for_natural_param_decodes_in_range() {
        let decoder = select(&param("Natural", TypeKind::Unknown)).unwrap();

        // In-range (non-negative) decode; a plain `Natural (I32)` crashes the
        // harness on a negative draw (declarative-part range check).
        assert_eq!(
            decoder.call_expr,
            "Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 2 ** 30))"
        );
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn select_decoder_for_positive_param_decodes_in_range() {
        let decoder = select(&param("Positive", TypeKind::Unknown)).unwrap();

        assert_eq!(
            decoder.call_expr,
            "Positive (AdaFuzz.Decode.Bounded_Range (Cur, 1, 2 ** 30))"
        );
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn enum_param_decoder_uses_val_attribute_with_bounded_range() {
        let decoder = select(&param(
            "Color",
            TypeKind::Enum(vec!["Red".to_owned(), "Blue".to_owned()]),
        ))
        .unwrap();

        assert_eq!(
            decoder.call_expr,
            "Color'Val (Color'Pos (Color'First) + AdaFuzz.Decode.Bounded_Range (Cur, 0, Color'Pos (Color'Last) - Color'Pos (Color'First)))"
        );
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn enum_param_bounds_decode_by_type_attributes_not_literal_count() {
        // The decode range comes from the type's own 'First/'Last so that a
        // constrained subtype stays inside its range; the literal count of the
        // (base) enumeration must not drive the bound.
        let decoder = select(&param(
            "Color",
            TypeKind::Enum(vec![
                "Red".to_owned(),
                "Green".to_owned(),
                "Blue".to_owned(),
            ]),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Color'Pos (Color'Last) - Color'Pos (Color'First)"));
    }

    #[test]
    fn empty_enum_returns_unsupported_error() {
        let error = select(&param("Empty_Color", TypeKind::Enum(Vec::new()))).unwrap_err();

        assert!(matches!(error, HarnessGenError::UnsupportedParamType(_)));
        assert!(error.to_string().contains("empty enum"));
    }

    #[test]
    fn array_param_decoder_emits_temp_var_setup_lines() {
        let decoder = select(&param(
            "Int_Array",
            TypeKind::Array {
                idx_types: vec![TypeId(2)],
                elem_type: TypeId(3),
                bounds: "Positive range <>".to_owned(),
                elem_name: String::new(),
            },
        ))
        .unwrap();

        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("Tmp_Value : Int_Array")));
        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("for I in Tmp_Value'Range loop")));
    }

    #[test]
    fn array_param_decoder_casts_bound_through_custom_index_base() {
        // SPARKNaCl `array (N32 range <>)`: the decoded `Natural` length must be
        // cast through the index type's `'Base`, else `(1 .. Len)` mismatches
        // ("expected Interfaces.Integer_32, found Standard.Integer").
        assert_eq!(
            super::array_index_type("N32 range <>").as_deref(),
            Some("N32")
        );
        assert_eq!(super::array_index_type("<>"), None);
        // A custom index is qualified with the array type's package so it's
        // visible in the harness; standard indices stay unqualified.
        assert_eq!(
            super::qualify_index_type("Sparknacl.Byte_Seq", "N32"),
            "Sparknacl.N32"
        );
        assert_eq!(super::qualify_index_type("Buf", "N32"), "N32");
        assert!(super::is_standard_index_type("Positive"));
        assert!(!super::is_standard_index_type("N32"));
        let decoder = select(&param(
            "Buf",
            TypeKind::Array {
                idx_types: vec![TypeId(2)],
                elem_type: TypeId(3),
                bounds: "N32 range <>".to_owned(),
                elem_name: "Byte".to_owned(),
            },
        ))
        .unwrap();
        assert!(
            decoder
                .setup_lines
                .iter()
                .any(|line| line.contains("Tmp_Value : Buf (1 .. N32'Base (Len_Value))")),
            "got: {:?}",
            decoder.setup_lines
        );
    }

    #[test]
    fn array_param_decoder_call_expr_references_local_function() {
        let decoder = select(&param(
            "Int_Array",
            TypeKind::Array {
                idx_types: vec![TypeId(2)],
                elem_type: TypeId(3),
                bounds: "Positive range <>".to_owned(),
                elem_name: String::new(),
            },
        ))
        .unwrap();

        assert_eq!(decoder.call_expr, "Decode_Value");
    }

    #[test]
    fn array_param_decoder_wraps_setup_in_local_function() {
        let decoder = select(&param(
            "Int_Array",
            TypeKind::Array {
                idx_types: vec![TypeId(2)],
                elem_type: TypeId(3),
                bounds: "Positive range <>".to_owned(),
                elem_name: String::new(),
            },
        ))
        .unwrap();

        assert_eq!(decoder.call_expr, "Decode_Value");
        assert!(decoder
            .setup_lines
            .contains(&"function Decode_Value return Int_Array is".to_owned()));
    }

    #[test]
    fn array_param_decoder_uses_bounded_length_for_size() {
        let decoder = select(&param(
            "Int_Array",
            TypeKind::Array {
                idx_types: vec![TypeId(2)],
                elem_type: TypeId(3),
                bounds: "Positive range <>".to_owned(),
                elem_name: String::new(),
            },
        ))
        .unwrap();

        assert!(decoder.setup_lines.iter().any(|line| line.contains(
            "Len_Value : constant Natural := AdaFuzz.Decode.Bounded_Length (Cur, 0, 16);"
        )));
    }

    #[test]
    fn constrained_array_param_declares_bare_without_added_bounds() {
        // `type Option_Set is array (Option) of Boolean` is constrained: the
        // decode temp must be declared bare and filled over its own 'Range.
        // Adding `(1 .. Len)` is illegal ("array type is already constrained").
        let decoder = select(&param(
            "Option_Set",
            TypeKind::Array {
                idx_types: vec![TypeId(2)],
                elem_type: TypeId(3),
                bounds: "Option".to_owned(),
                elem_name: "boolean".to_owned(),
            },
        ))
        .unwrap();

        assert!(
            decoder
                .setup_lines
                .iter()
                .any(|line| line.contains("Tmp_Value : Option_Set;")),
            "constrained array must be declared bare: {:?}",
            decoder.setup_lines
        );
        assert!(
            !decoder
                .setup_lines
                .iter()
                .any(|line| line.contains("(1 ..")),
            "constrained array must not add bounds: {:?}",
            decoder.setup_lines
        );
        assert!(
            decoder
                .setup_lines
                .iter()
                .any(|line| line.contains("for I in Tmp_Value'Range loop")),
            "constrained array must iterate its own range: {:?}",
            decoder.setup_lines
        );
    }

    #[test]
    fn array_param_temp_var_name_includes_param_name() {
        let decoder = select(&Parameter {
            name: "Items".to_owned(),
            mode: ParamMode::In,
            type_ref: type_ref_with_kind_and_name(
                TypeKind::Array {
                    idx_types: vec![TypeId(2)],
                    elem_type: TypeId(3),
                    bounds: "Positive range <>".to_owned(),
                    elem_name: String::new(),
                },
                &["Int_Array"],
            ),
            default: None,
        })
        .unwrap();

        assert_eq!(decoder.call_expr, "Decode_Items");
        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("Len_Items")));
    }

    #[test]
    fn record_param_decoder_emits_named_aggregate() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec![
                "Count : Integer".to_owned(),
                "Enabled : Boolean".to_owned(),
            ])),
        ))
        .unwrap();

        assert_eq!(
            decoder.call_expr,
            "Root_Record'(Count => Integer (AdaFuzz.Decode.I32 (Cur)), Enabled => AdaFuzz.Decode.Bool (Cur))"
        );
        assert!(decoder.setup_lines.is_empty());
    }

    #[test]
    fn record_param_with_multi_name_field_expands_each_component() {
        // `compressed_size, uncompressed_size : Unsigned_64;` declares two
        // components in one field declaration. Each must become its own named
        // association, not a single mangled `A,\nB => ...` that produces a
        // positional-after-named aggregate (which fails to compile).
        let decoder = select(&param(
            "Desc",
            TypeKind::Record(Fields(vec![
                "Crc_32 : Unsigned_32".to_owned(),
                "compressed_size, uncompressed_size : Unsigned_64".to_owned(),
            ])),
        ))
        .unwrap();

        assert!(
            decoder.call_expr.contains("Compressed_Size =>"),
            "missing Compressed_Size component: {}",
            decoder.call_expr
        );
        assert!(
            decoder.call_expr.contains("Uncompressed_Size =>"),
            "missing Uncompressed_Size component: {}",
            decoder.call_expr
        );
        assert!(
            !decoder.call_expr.contains(",\n"),
            "field names leaked a comma into one association: {}",
            decoder.call_expr
        );
    }

    #[test]
    fn array_param_with_named_byte_component_decodes_via_u8() {
        // `Byte_Buffer is array (Integer range <>) of aliased Byte`: the
        // element loop must feed a fuzz byte (U8), not the historical
        // `Integer (I32 ..)` which fails to compile against a Byte component.
        let decoder = select(&param(
            "Buffer",
            TypeKind::Array {
                idx_types: Vec::new(),
                elem_type: TypeId(0),
                bounds: "Integer range <>".to_owned(),
                elem_name: "byte".to_owned(),
            },
        ))
        .unwrap();

        // The fuzz byte is converted to the component type (`byte (U8)`); the
        // conversion is a no-op for a plain Unsigned_8 subtype and required for a
        // derived one. Either way it feeds a real byte, not the historical I32.
        assert!(
            decoder
                .setup_lines
                .iter()
                .any(|line| line.contains("(I) := byte (AdaFuzz.Decode.U8 (Cur));")),
            "byte component should decode via a U8 conversion: {:?}",
            decoder.setup_lines
        );
        assert!(
            !decoder
                .setup_lines
                .iter()
                .any(|line| line.contains("Integer (AdaFuzz.Decode.I32")),
            "byte component must not be decoded as Integer: {:?}",
            decoder.setup_lines
        );
    }

    #[test]
    fn array_dimensions_counts_top_level_index_commas() {
        assert_eq!(super::array_dimensions("1 .. 3"), 1);
        assert_eq!(super::array_dimensions("Positive range <>"), 1);
        assert_eq!(super::array_dimensions("1 .. 3, 1 .. 3"), 2);
        assert_eq!(
            super::array_dimensions("R range <>, C range <>, D range <>"),
            3
        );
        // A comma inside a bound expression's parens is NOT a dimension separator.
        assert_eq!(super::array_dimensions("1 .. Foo (A, B)"), 1);
        assert_eq!(super::array_dimensions(""), 1);
    }

    #[test]
    fn multi_dim_array_param_fills_every_dimension_with_nested_loops() {
        // A 2-D matrix (`array (R, C) of Float`) must be filled with nested loops
        // over each `'Range (k)` and a full 2-subscript assignment — a single
        // `Tmp (I)` fails to compile ("too few subscripts in array reference").
        let decoder = select(&param(
            "Covariance_Matrix_Type",
            TypeKind::Array {
                idx_types: vec![TypeId(2), TypeId(2)],
                elem_type: TypeId(3),
                bounds: "1 .. 3, 1 .. 3".to_owned(),
                elem_name: "Float".to_owned(),
            },
        ))
        .unwrap();
        let body = decoder.setup_lines.join("\n");
        assert!(
            body.contains("for I1 in Tmp_Value'Range (1) loop")
                && body.contains("for I2 in Tmp_Value'Range (2) loop"),
            "must iterate each dimension: {body}"
        );
        assert!(
            body.contains("Tmp_Value (I1, I2) :="),
            "must assign with a full 2-subscript reference: {body}"
        );
        assert!(
            !body.contains("Tmp_Value (I) :="),
            "must not emit a single-subscript assignment for a 2-D array: {body}"
        );
    }

    #[test]
    fn array_of_derived_scalar_converts_element_to_component_type() {
        // `Event_Array is array (...) of Event` where `Event is new Unsigned_8`:
        // a derived-integer element type requires an explicit conversion of the
        // fuzz byte to the component type. The element type is qualified with the
        // array type's package since the harness only `with`s that package.
        let decoder = select(&param(
            "Sdpcm.Events.Event_Array",
            TypeKind::Array {
                idx_types: Vec::new(),
                elem_type: TypeId(0),
                bounds: "Positive range <>".to_owned(),
                elem_name: "Event".to_owned(),
            },
        ))
        .unwrap();
        assert!(
            decoder
                .setup_lines
                .iter()
                .any(|line| line.contains("(I) := Sdpcm.Events.Event (AdaFuzz.Decode.U8 (Cur));")),
            "derived-scalar element must be converted to its component type: {:?}",
            decoder.setup_lines
        );
    }

    #[test]
    fn record_param_with_integer_field_decodes_via_i32() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Count : Integer".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Count => Integer (AdaFuzz.Decode.I32 (Cur))"));
    }

    #[test]
    fn record_param_with_wide_standard_numeric_fields_decode_not_default() {
        // Standard wide numerics now decode instead of falling back to `<>`.
        let decoder = select(&param(
            "Cfg",
            TypeKind::Record(Fields(vec![
                "Big : Long_Integer".to_owned(),
                "Huge : Long_Long_Integer".to_owned(),
                "Ratio : Long_Long_Float".to_owned(),
            ])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Big => Long_Integer (AdaFuzz.Decode.I32 (Cur))"));
        assert!(decoder
            .call_expr
            .contains("Huge => Long_Long_Integer (AdaFuzz.Decode.I32 (Cur))"));
        assert!(decoder
            .call_expr
            .contains("Ratio => Long_Long_Float (AdaFuzz.Decode.F64 (Cur))"));
    }

    #[test]
    fn record_param_with_narrow_or_qualified_numeric_field_stays_default() {
        // Narrow widths (range-check raise) and qualified/derived spellings
        // (extra `with` / no name match) keep the safe `<>` default.
        let decoder = select(&param(
            "Cfg",
            TypeKind::Record(Fields(vec![
                "Small : Short_Integer".to_owned(),
                "Count : Data_Bytes_Count".to_owned(),
            ])),
        ))
        .unwrap();

        assert!(decoder.call_expr.contains("Small => <>"));
        assert!(decoder.call_expr.contains("Count => <>"));
    }

    #[test]
    fn record_param_with_string_field_decodes_via_ada_string() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Name : String".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Name => AdaFuzz.Decode.Ada_String (Cur, 0, 64)"));
    }

    #[test]
    fn record_param_with_unbounded_string_field_fuzzes() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec![
                "Note : Ada.Strings.Unbounded.Unbounded_String".to_owned(),
            ])),
        ))
        .unwrap();
        assert!(decoder.call_expr.contains(
            "Note => Ada.Strings.Unbounded.To_Unbounded_String (AdaFuzz.Decode.Ada_String (Cur, 0, 64))"
        ));
    }

    #[test]
    fn record_param_with_enum_field_decodes_via_val_over_literal_count() {
        // An enum-typed field is AST-resolved and decoded via 'Val over its
        // literal count (here 3 literals -> Bounded_Range (0, 2)), qualified with
        // its owning package (the harness `with`s but does not `use` the unit);
        // without the AST it would default-initialise (`<>`).
        let mut ast = StructuralAst::new();
        ast.packages.push(Package {
            id: PackageId(1),
            name: "rec".to_owned(),
            parent: None,
            is_generic: false,
            is_private: false,
            formals: Vec::new(),
            decls: Vec::new(),
        });
        ast.types.push(TypeRef {
            id: TypeId(9),
            name_path: vec!["Color".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(1)),
            kind: TypeKind::Enum(vec![
                "Red".to_owned(),
                "Green".to_owned(),
                "Blue".to_owned(),
            ]),
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        });
        let decoder = select_with_ast(
            &ast,
            &param(
                "Root_Record",
                TypeKind::Record(Fields(vec![
                    "Shade : Color".to_owned(),
                    "N : Integer".to_owned(),
                ])),
            ),
        )
        .unwrap();
        assert!(
            decoder.call_expr.contains(
                "Shade => Rec.Color'Val (Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 2)))"
            ),
            "enum field must fuzz over its literals (qualified), got: {}",
            decoder.call_expr
        );
        assert!(decoder
            .call_expr
            .contains("N => Integer (AdaFuzz.Decode.I32 (Cur))"));
    }

    #[test]
    fn record_param_with_unresolved_field_stays_default() {
        // A field whose type is neither a standard type nor resolvable in the
        // tree still default-initialises (`<>`) — never a bare 0.
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Opaque : Some_Private_Type".to_owned()])),
        ))
        .unwrap();
        assert!(decoder.call_expr.contains("Opaque => <>"));
    }

    #[test]
    fn record_param_with_natural_field_decodes_in_range() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Count : Natural".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Count => Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 2 ** 30))"));
    }

    #[test]
    fn record_param_with_positive_field_decodes_in_range() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Count : Positive".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Count => Positive (AdaFuzz.Decode.Bounded_Range (Cur, 1, 2 ** 30))"));
    }

    #[test]
    fn record_param_with_boolean_field_decodes_via_bool() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Enabled : Boolean".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Enabled => AdaFuzz.Decode.Bool (Cur)"));
    }

    #[test]
    fn record_param_with_float_field_decodes_via_f64() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Ratio : Float".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Ratio => Float (AdaFuzz.Decode.F64 (Cur))"));
    }

    #[test]
    fn record_param_with_long_float_field_decodes_via_f64() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Ratio : Long_Float".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Ratio => Long_Float (AdaFuzz.Decode.F64 (Cur))"));
    }

    #[test]
    fn record_param_with_character_field_decodes_bounded_ascii() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Ch : Character".to_owned()])),
        ))
        .unwrap();

        assert!(decoder.call_expr.contains(
            "Ch => Character'Val (Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 127)))"
        ));
    }

    #[test]
    fn record_param_with_constrained_string_field_uses_string_decoder() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Name : String (1 .. 8)".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Name => AdaFuzz.Decode.Ada_String (Cur, 0, 64)"));
    }

    #[test]
    fn record_param_with_standard_string_field_uses_string_decoder() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Name : Standard.String".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Name => AdaFuzz.Decode.Ada_String (Cur, 0, 64)"));
    }

    #[test]
    fn record_param_field_without_type_defaults_to_integer_decoder() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Count".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Count => Integer (AdaFuzz.Decode.I32 (Cur))"));
    }

    #[test]
    fn record_param_empty_field_name_defaults_to_f() {
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec![": Integer".to_owned()])),
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("F => Integer (AdaFuzz.Decode.I32 (Cur))"));
    }

    #[test]
    fn record_param_with_unknown_field_type_defaults_in_aggregate() {
        // An undecodable field (here an access/private `Fancy_Type`) must
        // default-initialise via `<>` - a literal `0` only compiles for an
        // integer field and otherwise fails with "expected type".
        let decoder = select(&param(
            "Root_Record",
            TypeKind::Record(Fields(vec!["Mystery : Fancy_Type".to_owned()])),
        ))
        .unwrap();

        assert!(
            decoder.call_expr.contains("Mystery => <>"),
            "unknown field must default via <>: {}",
            decoder.call_expr
        );
    }

    #[test]
    fn record_param_aggregate_uses_qualified_record_type() {
        let decoder = select(&param(
            "Pkg.Root_Record",
            TypeKind::Record(Fields(vec!["Count : Integer".to_owned()])),
        ))
        .unwrap();

        assert!(decoder.call_expr.starts_with("Pkg.Root_Record'("));
    }

    #[test]
    fn discriminated_record_decoder_decodes_discriminant_first() {
        let decoder = select(&param(
            "Variant_Record",
            TypeKind::Discriminated {
                base: TypeId(9),
                discriminants: Fields(vec!["Kind : Integer".to_owned()]),
            },
        ))
        .unwrap();

        assert!(decoder
            .call_expr
            .contains("Kind => Integer (AdaFuzz.Decode.Bounded_Range (Cur, 0, 4)), others => <>"));
    }

    #[test]
    fn discriminated_record_with_derived_integer_discriminant_converts_to_its_type() {
        // sdpcm's `Packet (Channel : SDPCM_Channel := ...)` where
        // `SDPCM_Channel is new Interfaces.Unsigned_8`: the discriminant default
        // must be converted to the discriminant's actual type (qualified with the
        // record's package), not the hardcoded `Integer`.
        let decoder = select(&param(
            "Sdpcm.Packets.Packet",
            TypeKind::Discriminated {
                base: TypeId(9),
                discriminants: Fields(vec!["Channel : SDPCM_Channel".to_owned()]),
            },
        ))
        .unwrap();
        assert!(
            decoder.call_expr.contains(
                "Channel => Sdpcm.Packets.SDPCM_Channel (AdaFuzz.Decode.Bounded_Range (Cur, 0, 4))"
            ),
            "derived discriminant must be converted to its type: {}",
            decoder.call_expr
        );
        assert!(
            !decoder.call_expr.contains("Integer (AdaFuzz"),
            "must not hardcode Integer for a derived discriminant: {}",
            decoder.call_expr
        );
    }

    #[test]
    fn discriminated_record_uses_others_box_for_remaining_fields() {
        let decoder = select(&param(
            "Variant_Record",
            TypeKind::Discriminated {
                base: TypeId(9),
                discriminants: Fields(vec!["Kind : Integer".to_owned()]),
            },
        ))
        .unwrap();

        assert!(decoder.call_expr.ends_with(", others => <>)"));
    }

    #[test]
    fn discriminated_record_qualified_type_in_aggregate() {
        let decoder = select(&param(
            "Pkg.Variant_Record",
            TypeKind::Discriminated {
                base: TypeId(9),
                discriminants: Fields(vec!["Kind : Integer".to_owned()]),
            },
        ))
        .unwrap();

        assert!(decoder.call_expr.starts_with("Pkg.Variant_Record'("));
    }

    #[test]
    fn select_decoder_for_empty_record_param_emits_null_aggregate() {
        // An empty record is now synthesizable as `T'(null record)` (it used to
        // return UnsupportedParamType) — see the dedicated empty-record test.
        let d = select(&param("Root_Record", TypeKind::Record(Fields(Vec::new())))).unwrap();
        assert_eq!(d.call_expr, "Root_Record'(null record)");
    }

    #[test]
    fn access_param_decoder_declares_slot_table() {
        let decoder = select(&param(
            "Root_Access",
            TypeKind::Access { target: TypeId(7) },
        ))
        .unwrap();

        assert!(decoder.setup_lines.iter().any(|line| line
            .contains("Slots_Value : array (1 .. 4) of Root_Access := (others => null);")));
    }

    #[test]
    fn access_param_decoder_uses_slot_index() {
        let decoder = select(&param(
            "Root_Access",
            TypeKind::Access { target: TypeId(7) },
        ))
        .unwrap();

        assert!(decoder.setup_lines.iter().any(|line| line
            .contains("Idx_Value : constant Natural := AdaFuzz.Decode.Slot_Index (Cur, 4);")));
    }

    #[test]
    fn access_param_decoder_handles_index_zero_as_null() {
        let decoder = select(&param(
            "Root_Access",
            TypeKind::Access { target: TypeId(7) },
        ))
        .unwrap();

        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("if Idx_Value = 0 then")));
        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("Tmp_Value := null;")));
    }

    #[test]
    fn access_param_slot_table_size_is_four_for_m8() {
        let decoder = select(&param(
            "Root_Access",
            TypeKind::Access { target: TypeId(7) },
        ))
        .unwrap();

        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("1 .. 4")));
        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("Slot_Index (Cur, 4)")));
    }

    #[test]
    fn access_param_temp_var_name_includes_param_name() {
        let decoder = select(&Parameter {
            name: "Node".to_owned(),
            mode: ParamMode::In,
            type_ref: type_ref_with_kind_and_name(
                TypeKind::Access { target: TypeId(7) },
                &["Root_Access"],
            ),
            default: None,
        })
        .unwrap();

        assert_eq!(decoder.call_expr, "Decode_Node");
        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("Tmp_Node : Root_Access;")));
    }

    #[test]
    fn access_param_decoder_wraps_setup_in_local_function() {
        let decoder = select(&Parameter {
            name: "Node".to_owned(),
            mode: ParamMode::In,
            type_ref: type_ref_with_kind_and_name(
                TypeKind::Access { target: TypeId(7) },
                &["Root_Access"],
            ),
            default: None,
        })
        .unwrap();

        assert_eq!(decoder.call_expr, "Decode_Node");
        assert!(decoder
            .setup_lines
            .contains(&"function Decode_Node return Root_Access is".to_owned()));
    }

    #[test]
    fn select_decoder_for_access_param_returns_temp_expression() {
        let decoder = select(&param(
            "Root_Access",
            TypeKind::Access { target: TypeId(2) },
        ))
        .unwrap();

        assert_eq!(decoder.call_expr, "Decode_Value");
    }

    fn constructor(
        tagged_type_name: &str,
        qualified_path: &str,
        param_count: u32,
    ) -> ConstructorEntry {
        ConstructorEntry {
            tagged_type_name: tagged_type_name.to_owned(),
            constructor_name: qualified_path
                .rsplit('.')
                .next()
                .unwrap_or(qualified_path)
                .to_owned(),
            qualified_path: qualified_path.to_owned(),
            param_count,
            param_type_names: Vec::new(),
            param_has_default: Vec::new(),
        }
    }

    #[test]
    fn tagged_param_decoder_dispatches_via_choose_tag() {
        let registry = ConstructorRegistry {
            entries: vec![constructor("Root_Type", "Pkg.Make_Root", 0)],
        };
        let decoder = select_decoder_for_param(
            &StructuralAst::new(),
            &param(
                "Root_Type",
                TypeKind::Tagged {
                    base: TypeId(1),
                    is_abstract: false,
                },
            ),
            &registry,
        )
        .unwrap();

        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("case AdaFuzz.Decode.Choose_Tag (Cur, 1) is")));
    }

    #[test]
    fn private_param_uses_public_constant_as_neutral() {
        // zip-ada `Convert (Date : in Time) return Ada.Calendar.Time`: `Time` is
        // private with no synthesisable constructor function (its only function
        // `Get_Time` needs a stream). The public constant `default_time`, which
        // `discover_constructors` registers as a nullary constructor, is the
        // neutral — the decoder returns `Zip_Streams.default_time` directly.
        let registry = ConstructorRegistry {
            entries: vec![constructor("Time", "Zip_Streams.default_time", 0)],
        };
        let decoder = select_decoder_for_param(
            &StructuralAst::new(),
            &param("Zip_Streams.Time", TypeKind::Private),
            &registry,
        )
        .unwrap();

        // Ada is case-insensitive; govfuzz title-cases the emitted identifier.
        assert!(
            decoder.setup_lines.iter().any(|line| line
                .to_ascii_lowercase()
                .contains("return zip_streams.default_time;")),
            "setup: {:?}",
            decoder.setup_lines
        );
    }

    #[test]
    fn constructor_is_usable_rejects_non_synthesizable_required_params() {
        // zip-ada `Get_Time (S : in Root_Zipstream_Type) return Time`: the
        // stream param has no neutral, so the constructor is unusable (emitting
        // `Get_Time (0)` fails "no candidate interpretations match").
        let stream_ctor = ConstructorEntry {
            tagged_type_name: "Zip_Streams.Time".to_owned(),
            constructor_name: "Get_Time".to_owned(),
            qualified_path: "Zip_Streams.Get_Time".to_owned(),
            param_count: 1,
            param_type_names: vec!["Root_Zipstream_Type".to_owned()],
            param_has_default: vec![false],
        };
        assert!(!super::constructor_is_usable(&stream_ctor));
        // A scalar/string constructor is usable.
        let scalar_ctor = ConstructorEntry {
            tagged_type_name: "Pkg.T".to_owned(),
            constructor_name: "Make".to_owned(),
            qualified_path: "Pkg.Make".to_owned(),
            param_count: 2,
            param_type_names: vec!["Boolean".to_owned(), "Integer".to_owned()],
            param_has_default: vec![false, false],
        };
        assert!(super::constructor_is_usable(&scalar_ctor));
        // A constructor taking an Unbounded_String is now usable (neutral =
        // Null_Unbounded_String), e.g. ada-toml's Create_String overload.
        let unbounded_ctor = ConstructorEntry {
            tagged_type_name: "Toml.TOML_Value".to_owned(),
            constructor_name: "Create_String".to_owned(),
            qualified_path: "Toml.Create_String".to_owned(),
            param_count: 1,
            param_type_names: vec!["Ada.Strings.Unbounded.Unbounded_String".to_owned()],
            param_has_default: vec![false],
        };
        assert!(super::constructor_is_usable(&unbounded_ctor));
        assert_eq!(
            super::guess_neutral_for_type("Ada.Strings.Unbounded.Unbounded_String"),
            "Ada.Strings.Unbounded.Null_Unbounded_String"
        );
        // No recorded param types -> assume usable (legacy behaviour).
        let unknown_ctor = ConstructorEntry {
            tagged_type_name: "Pkg.T".to_owned(),
            constructor_name: "Make".to_owned(),
            qualified_path: "Pkg.Make".to_owned(),
            param_count: 1,
            param_type_names: Vec::new(),
            param_has_default: Vec::new(),
        };
        assert!(super::constructor_is_usable(&unknown_ctor));
    }

    #[test]
    fn constructor_call_omits_trailing_defaulted_parameters() {
        // ada-toml shape: `Create_Boolean (Value : Boolean; Location :
        // Source_Location := No_Location)`. The decoder must pass only the
        // required Value and rely on the default for the record-typed Location
        // — passing `0` for it raises "found type universal integer".
        let entry = ConstructorEntry {
            tagged_type_name: "Toml.TOML_Value".to_owned(),
            constructor_name: "Create_Boolean".to_owned(),
            qualified_path: "Toml.Create_Boolean".to_owned(),
            param_count: 2,
            param_type_names: vec!["Boolean".to_owned(), "Source_Location".to_owned()],
            param_has_default: vec![false, true],
        };
        let call = super::constructor_call(&entry);
        assert_eq!(call, "Toml.Create_Boolean(False)", "got: {call:?}");

        // An all-defaulted constructor (`Create_Table (Location := ...)`) takes
        // no positional args at all.
        let all_default = ConstructorEntry {
            tagged_type_name: "Toml.TOML_Value".to_owned(),
            constructor_name: "Create_Table".to_owned(),
            qualified_path: "Toml.Create_Table".to_owned(),
            param_count: 1,
            param_type_names: vec!["Source_Location".to_owned()],
            param_has_default: vec![true],
        };
        assert_eq!(super::constructor_call(&all_default), "Toml.Create_Table");
    }

    #[test]
    fn tagged_param_decoder_wraps_dispatch_in_local_function() {
        let registry = ConstructorRegistry {
            entries: vec![constructor("Root_Type", "Pkg.Make_Root", 0)],
        };
        let decoder = select_decoder_for_param(
            &StructuralAst::new(),
            &param(
                "Root_Type",
                TypeKind::Tagged {
                    base: TypeId(1),
                    is_abstract: false,
                },
            ),
            &registry,
        )
        .unwrap();

        assert_eq!(decoder.call_expr, "Decode_Value");
        assert!(decoder
            .setup_lines
            .contains(&"function Decode_Value return Root_Type is".to_owned()));
    }

    #[test]
    fn tagged_param_decoder_emits_case_arm_per_constructor() {
        let registry = ConstructorRegistry {
            entries: vec![
                constructor("Root_Type", "Pkg.Make_Root", 0),
                constructor("Root_Type", "Pkg.Make_Other", 0),
            ],
        };
        let decoder = select_decoder_for_param(
            &StructuralAst::new(),
            &param(
                "Root_Type",
                TypeKind::Tagged {
                    base: TypeId(1),
                    is_abstract: false,
                },
            ),
            &registry,
        )
        .unwrap();

        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("when 1 => return Pkg.Make_Root;")));
        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("when 2 => return Pkg.Make_Other;")));
    }

    #[test]
    fn tagged_param_decoder_calls_constructor_with_qualified_path() {
        let registry = ConstructorRegistry {
            entries: vec![constructor("Root_Type", "Factories.Make_Root", 0)],
        };
        let decoder = select_decoder_for_param(
            &StructuralAst::new(),
            &param(
                "Root_Type",
                TypeKind::Tagged {
                    base: TypeId(1),
                    is_abstract: false,
                },
            ),
            &registry,
        )
        .unwrap();

        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("when 1 => return Factories.Make_Root;")));
    }

    #[test]
    fn tagged_param_decoder_passes_neutral_args_to_constructor() {
        let registry = ConstructorRegistry {
            entries: vec![constructor("Root_Type", "Factories.Make_Root", 2)],
        };
        let decoder = select_decoder_for_param(
            &StructuralAst::new(),
            &param(
                "Root_Type",
                TypeKind::Tagged {
                    base: TypeId(1),
                    is_abstract: false,
                },
            ),
            &registry,
        )
        .unwrap();

        assert!(decoder
            .setup_lines
            .iter()
            .any(|line| line.contains("when 1 => return Factories.Make_Root(0, 0);")));
    }

    #[test]
    fn tagged_param_decoder_returns_unsupported_when_no_constructors() {
        let registry = ConstructorRegistry::new();
        let error = select_decoder_for_param(
            &StructuralAst::new(),
            &param(
                "Root_Type",
                TypeKind::Tagged {
                    base: TypeId(1),
                    is_abstract: false,
                },
            ),
            &registry,
        )
        .unwrap_err();

        assert!(matches!(error, HarnessGenError::UnsupportedParamType(_)));
        assert!(error
            .to_string()
            .contains("tagged type Root_Type has no constructor with synthesizable parameters"));
    }
}
