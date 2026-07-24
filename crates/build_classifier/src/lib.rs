// SPDX-License-Identifier: Apache-2.0

//! Classify gcc/clang/ld/gprbuild error output into structured
//! BuildErrorKind variants so the auto attempt loop can decide which
//! repair to synthesise.

use serde::{Deserialize, Serialize};

pub mod cargo;
pub mod gcc_clang;
pub mod gnat;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BuildErrorKind {
    MissingHeader {
        path: String,
    },
    MissingType {
        name: String,
    },
    /// A type that IS declared (a forward `class X;`/`struct X;`) but never
    /// *defined* in the compiled sources — the pimpl idiom (`class Foo { class
    /// FooImpl *impl; };` where `FooImpl`'s body lives in a .cpp the harness
    /// doesn't compile). clang says "incomplete type 'X'"/"variable has
    /// incomplete type"/"... with incomplete return type", NOT "unknown type
    /// name". It must NOT be `void *`-typedef-repaired (that redefines the
    /// forward declaration) — it signals an external/private definition the
    /// offline harness can never complete, so the target degrades to report-only.
    IncompleteType {
        name: String,
    },
    /// An ALL-CAPS identifier used but never defined — almost always a
    /// build-config preprocessor macro the project's build system injects
    /// (generated `config.h`, `-D` flags), e.g. libyaml's `YAML_VERSION_STRING`.
    /// `as_value` is true when used in value position (define to `0`); false
    /// when used in type/specifier position — an inline/export/api qualifier
    /// like jansson's `JSON_INLINE` — which must define to *nothing*.
    MissingMacro {
        name: String,
        as_value: bool,
    },
    UndefinedSymbol {
        name: String,
    },
    /// A C frontend rejected a call because no declaration was visible. This is
    /// distinct from a linker undefined reference: adding a standalone weak
    /// definition cannot make the calling translation unit compile. The source
    /// location lets repair inspect missing function-like/declaration macros.
    UndeclaredFunction {
        name: String,
        file: String,
        line: u32,
    },
    MissingSharedLib {
        name: String,
    },
    MissingAdaWith {
        unit: String,
    },
    MissingAdaSymbol {
        unit: String,
        symbol: String,
    },
    MissingAdaPackageBody {
        unit: String,
    },
    /// An Ada body source the assembler/compiler can't translate on this host —
    /// most often target-specific inline machine code (bb-runtimes' ARM `mcr
    /// p15` / AArch64 `mrs` intrinsics built on x86). Repaired by overriding the
    /// body with a synthesised stub so a *dependent* target still builds and
    /// fuzzes — govfuzz's "fuzz code that doesn't cleanly build" thesis.
    UncompilableAdaBody {
        source: String,
    },
    MissingGprImport {
        path: String,
    },
    /// A C/C++ translation unit where a macro/IDL-codegen line expands to a
    /// body-less function declarator clang rejects with "expected function body
    /// after function declarator". The function name is absent from the error
    /// text (clang points its caret at the macro invocation), so only the
    /// source `file:line` is captured; the repair rewrites that line in place
    /// (append `{}`) since the malformed declaration is in an in-tree TU, not a
    /// link-time stub.
    MalformedFunctionDecl {
        file: String,
        line: u32,
    },
    Other {
        tail: String,
    },
}

/// Classify a captured stderr against both toolchain regex packs.
/// Returns one event per distinct error in source order. `Other` is
/// emitted only when no known pattern matched any line - so a
/// successful classifier still surfaces the unknown tail for the
/// report.
pub fn classify(stderr: &str) -> Vec<BuildErrorKind> {
    let mut hits = Vec::new();
    gcc_clang::classify_into(stderr, &mut hits);
    gnat::classify_into(stderr, &mut hits);
    // gprbuild frequently repeats the same underlying GNAT diagnostic while
    // compiling a dependency and again while summarizing the failed main. Counts
    // and repair rounds must represent distinct causes, not repeated lines.
    let mut distinct = Vec::new();
    for hit in hits.drain(..) {
        if !distinct.contains(&hit) {
            distinct.push(hit);
        }
    }
    hits = distinct;
    if hits.is_empty() {
        // Prefer the lines that actually name an error. A multi-unit gprbuild
        // run prints a long compile listing ("[Ada] foo.adb ...") and ends with
        // "compilation phase failed"; the real diagnostic is mid-stream, so the
        // last few lines are a useless listing. Surface the error lines when
        // present, falling back to the trailing lines only when none are found.
        let error_lines: Vec<&str> = stderr
            .lines()
            .filter(|line| {
                let l = line.to_ascii_lowercase();
                l.contains("error:")
                    // rustc codes are `error[E0425]:` — `error:` is not a substring,
                    // so without this the codegen diagnostic was dropped and the tail
                    // fell back to a lossy summary that read as a missing dep (#40).
                    || l.contains("error[")
                    || l.contains("fatal error")
                    || l.contains("undefined reference")
            })
            .collect();
        let tail: String = if error_lines.is_empty() {
            stderr
                .lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            error_lines
                .into_iter()
                .take(8)
                .collect::<Vec<_>>()
                .join("\n")
        };
        hits.push(BuildErrorKind::Other { tail });
    }
    hits
}

/// True when a diagnostic is a govfuzz HARNESS / CODEGEN build error — a
/// malformed generated harness or a parser recovery artifact — rather than a
/// genuine missing external dependency. The report must NOT frame these to the
/// user as "bring this dependency / acquire ..." (yaml-cpp's "no member named …
/// did you mean", ada-url's recovery-artifact bare `type`, a clang `use of
/// undeclared identifier` on a generated symbol): the fix is in govfuzz's
/// codegen / the project's own build config, not an upstream package.
///
/// Conservative: only fires on the `MissingType { name }` recovery-artifact
/// shape and on `Other` tails that carry an unmistakable codegen/identifier
/// marker. Recognized missing-header / missing-symbol / missing-lib / Ada
/// diagnostics are untouched and still route to the dependency manifest.
pub fn is_codegen_error(kind: &BuildErrorKind) -> bool {
    match kind {
        BuildErrorKind::MissingType { name } => is_recovery_artifact(name),
        BuildErrorKind::Other { tail } => tail_is_codegen(tail),
        _ => false,
    }
}

/// A clang/gcc parser RECOVERY ARTIFACT rather than a real type the tree is
/// missing: the bare placeholder token (`type`) the frontend substitutes while
/// recovering from a malformed declaration. Stubbing it as a `void *` C type (or
/// reporting it as a missing dependency) is noise.
pub fn is_recovery_artifact(name: &str) -> bool {
    matches!(name.trim(), "type" | "expression" | "<recovery-expr>")
}

/// Whether an `Other` diagnostic tail names a codegen / identifier error: a
/// member/type lookup failure, a typo-suggestion, or an undeclared identifier
/// the project's build config / govfuzz codegen would have provided — none of
/// which is a "bring this dependency" situation.
fn tail_is_codegen(tail: &str) -> bool {
    let lower = tail.to_ascii_lowercase();
    lower.contains("no member named")
        || lower.contains("no type named")
        || lower.contains("did you mean")
        || lower.contains("use of undeclared identifier")
        // Compiler-driver FLAG / OPTION errors are a govfuzz build-recipe problem
        // (e.g. a recovered `-std=c2x` applied to a C++ TU: "invalid argument
        // '-std=c2x' not allowed with 'C++'"), never an external dependency to
        // acquire (#41).
        || lower.contains("not allowed with")
        || lower.contains("unknown argument")
        || lower.contains("unsupported option")
        || lower.contains("unknown option")
        || lower.contains("unrecognized command-line option")
        || lower.contains("unrecognized command line option")
        // Rust harness-codegen failures: the generated call path doesn't resolve
        // (E0425) or the method/item doesn't exist (E0599). These are govfuzz
        // codegen bugs surfaced through the lossy Rust build summary, not missing
        // external deps (#40).
        || lower.contains("error[e0425]")
        || lower.contains("error[e0599]")
        || lower.contains("cannot find function")
        || lower.contains("cannot find value")
        || lower.contains("no method named")
        || lower.contains("no function or associated item named")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_member_named_is_a_codegen_error_not_a_missing_dep() {
        // yaml-cpp: a member/typo lookup failure is a codegen/version mismatch,
        // never an external dependency to acquire.
        let other = BuildErrorKind::Other {
            tail: "node.cpp:9:7: error: no member named 'as' in 'YAML::Node'; did you mean 'at'?"
                .to_owned(),
        };
        assert!(is_codegen_error(&other));

        // A genuine missing-header Other-shaped tail is NOT a codegen error.
        let dep = BuildErrorKind::Other {
            tail: "internal compiler error: out of memory".to_owned(),
        };
        assert!(!is_codegen_error(&dep));
    }

    #[test]
    fn rust_codegen_e0425_e0599_are_not_missing_deps() {
        // #40: a Rust harness-codegen failure round-trips through this classifier as
        // a lossy summary string. The error[E0425]/[E0599] diagnostic must route to
        // codegen, not the dependency manifest.
        for tail in [
            "cargo build failed: error[E0425]: cannot find function `decode_to_vec` in this scope",
            "cargo build failed: error[E0599]: no method named `parse_str` found for struct `Doc`",
            "in-crate cargo build failed: cannot find value `STANDARD` in this scope",
        ] {
            let kinds = classify(tail);
            assert!(
                kinds.iter().any(is_codegen_error),
                "rust codegen tail must be a codegen error, not a dep: {tail:?} -> {kinds:?}"
            );
        }
        // A genuine missing crate is still a dependency (must NOT be swept up).
        let dep = BuildErrorKind::Other {
            tail: "error[E0463]: can't find crate for `serde`".to_owned(),
        };
        assert!(!is_codegen_error(&dep));
    }

    #[test]
    fn compiler_flag_diagnostics_are_codegen_not_missing_deps() {
        // #41: cmark's recovered `-std=c2x` applied to a C++ TU is a build-recipe
        // problem, not an external dependency to acquire.
        for tail in [
            "clang: error: invalid argument '-std=c2x' not allowed with 'C++'",
            "clang: error: unknown argument: '-fmodules-ts'",
            "cc1plus: error: unrecognized command-line option '-Wfoo'",
        ] {
            let other = BuildErrorKind::Other {
                tail: tail.to_owned(),
            };
            assert!(
                is_codegen_error(&other),
                "flag/option diagnostic must be codegen: {tail:?}"
            );
        }
    }

    #[test]
    fn use_of_undeclared_identifier_tail_is_codegen() {
        let other = BuildErrorKind::Other {
            tail: "h.c:4:5: error: use of undeclared identifier 'helper_fn'".to_owned(),
        };
        assert!(is_codegen_error(&other));
    }

    #[test]
    fn recovery_artifact_type_is_codegen_not_a_ctype_dep() {
        // ada-url: clang recovering from a malformed declaration emits a bare
        // `type` placeholder — never a real missing C type.
        assert!(is_codegen_error(&BuildErrorKind::MissingType {
            name: "type".to_owned()
        }));
        // A real missing type stays a dependency.
        assert!(!is_codegen_error(&BuildErrorKind::MissingType {
            name: "widget_t".to_owned()
        }));
        // And missing headers/symbols/libs are never codegen errors.
        assert!(!is_codegen_error(&BuildErrorKind::MissingHeader {
            path: "foo.h".to_owned()
        }));
        assert!(!is_codegen_error(&BuildErrorKind::MissingSharedLib {
            name: "hiredis".to_owned()
        }));
    }

    #[test]
    fn classifies_expected_function_body_as_malformed_function_decl() {
        // A macro that expands to a body-less declarator: clang's caret points
        // at the macro invocation, so the function name is absent — only the
        // source file:line is recoverable.
        let stderr = "t.c:2:9: error: expected function body after function declarator\n    \
                      2 | PROTO(y)\n      |         ^\n";
        let kinds = classify(stderr);
        assert_eq!(
            kinds,
            vec![BuildErrorKind::MalformedFunctionDecl {
                file: "t.c".to_owned(),
                line: 2,
            }]
        );
        // A normal semantic error is unaffected (no false positive).
        let other = classify("t.c:9:6: error: unknown type name 'Frobnicator'\n");
        assert!(other
            .iter()
            .all(|k| !matches!(k, BuildErrorKind::MalformedFunctionDecl { .. })));
    }

    #[test]
    fn classifies_missing_parameter_wrapper_macro() {
        let stderr = "api.c:97:57: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]\n\
            \x20  97 |         yaml_char_t **b_start, yaml_char_t **b_pointer, SHIM(yaml_char_t **b_end))\n\
            \x20     |                                                   ^\n";
        let kinds = classify(stderr);
        assert_eq!(
            kinds,
            vec![BuildErrorKind::MissingMacro {
                name: "SHIM".to_owned(),
                as_value: false,
            }]
        );
    }

    #[test]
    fn other_surfaces_error_line_not_compile_listing() {
        // A multi-unit gprbuild run: the real error is mid-stream, followed by
        // a long listing and the generic failure summary. The Other tail must
        // surface the error, not the trailing listing.
        let stderr = "Compile\n   [Ada] main.adb\n\
            main.adb:9:06: error: unrecognised gnat diagnostic about pkg\n\
            \x20  [Ada] adafuzz-probe.adb\n   [Ada] adafuzz-decode.adb\n\
            \x20  [Ada] toml.adb\ngprbuild: *** compilation phase failed\n";
        let kinds = classify(stderr);
        match kinds.as_slice() {
            [BuildErrorKind::Other { tail }] => assert!(
                tail.contains("unrecognised gnat diagnostic"),
                "Other tail must surface the error line, got: {tail:?}"
            ),
            other => panic!("expected a single Other, got {other:?}"),
        }
    }

    #[test]
    fn missing_header_clang_form() {
        let stderr = "main.c:3:10: fatal error: 'internal/log.h' file not found\n    #include \"internal/log.h\"\n         ^~~~~~~~~~~~~~~~\n1 error generated.\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingHeader { path } if path == "internal/log.h"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_parent_header_clang_suggestion_form() {
        let stderr = "internal/stack.h:18:10: error: '../allocators.h' file not found, did you mean 'allocators.h'?\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                BuildErrorKind::MissingHeader { path } if path == "../allocators.h"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn explicit_no_config_error_is_a_missing_generated_header() {
        let stderr = "archive_platform.h:50:2: error: Oops: No config.h and no pre-built configuration in archive_platform.h.\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                BuildErrorKind::MissingHeader { path } if path == "config.h"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn undefined_symbol_ld_form() {
        let stderr = "/usr/bin/ld: /tmp/foo.o: in function `main':\n/tmp/foo.c:9: undefined reference to `decoder_create'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::UndefinedSymbol { name } if name == "decoder_create"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_macro_all_caps_undeclared_identifier() {
        let stderr = "api.c:11:12: error: use of undeclared identifier 'YAML_VERSION_STRING'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingMacro { name, as_value: true } if name == "YAML_VERSION_STRING"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn all_caps_unknown_type_is_a_specifier_macro_not_a_type() {
        // jansson's `static JSON_INLINE json_t *json_incref(...)` — JSON_INLINE
        // is an inline/qualifier macro in type position, not a real type.
        let stderr = "jansson.h:120:8: error: unknown type name 'JSON_INLINE'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingMacro { name, as_value: false } if name == "JSON_INLINE"
            )),
            "ALL-CAPS unknown type should be a specifier macro: {kinds:?}"
        );
        // A real lower/mixed-case unknown type stays a MissingType.
        let kinds = classify("x.c:1:1: error: unknown type name 'widget_t'\n");
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::MissingType { name } if name == "widget_t")),
            "got {kinds:?}"
        );
    }

    #[test]
    fn leading_underscore_all_caps_is_a_specifier_macro() {
        // PX4 / NuttX / HAL visibility + linkage macros: `__EXPORT int param_get(
        // ...)`, `__BEGIN_DECLS`. The leading underscore must not demote them to a
        // (void*) MissingType, which corrupts every declaration; define-empty.
        for name in ["__EXPORT", "__BEGIN_DECLS", "__WEAK"] {
            let stderr = format!("p.h:1:1: error: unknown type name '{name}'\n");
            let kinds = classify(&stderr);
            assert!(
                kinds.iter().any(|k| matches!(
                    k,
                    BuildErrorKind::MissingMacro { name: n, as_value: false } if n == name
                )),
                "{name} should be a specifier macro: {kinds:?}"
            );
        }
        // A leading-underscore but mixed-case name is not a macro (`_MyType`).
        let kinds = classify("x.c:1:1: error: unknown type name '_MyType'\n");
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::MissingType { name } if name == "_MyType")),
            "got {kinds:?}"
        );
    }

    #[test]
    fn all_caps_typedef_in_type_position_is_a_type_not_a_macro() {
        // #96: legacy C libraries use ALL_CAPS TYPEDEF names. Expat's `SCANNER` is a
        // typedef in a project header; "unknown type name 'SCANNER'" must produce a
        // type/header repair, NOT a define-empty macro (which corrupts the decl).
        // Covers Clang + GCC phrasings (identical text), C and C++.
        for stderr in [
            "xmlparse.c:120:5: error: unknown type name 'SCANNER'\n",
            "expat.cpp:9:1: error: unknown type name 'BUFFER'\n",
            "s.c:1:1: error: unknown type name 'HASHTABLE'\n",
        ] {
            let kinds = classify(stderr);
            assert!(
                kinds
                    .iter()
                    .any(|k| matches!(k, BuildErrorKind::MissingType { .. })),
                "uppercase typedef in type position must be MissingType: {stderr:?} -> {kinds:?}"
            );
            assert!(
                !kinds
                    .iter()
                    .any(|k| matches!(k, BuildErrorKind::MissingMacro { .. })),
                "must NOT be a macro: {stderr:?} -> {kinds:?}"
            );
        }
        // Declaration DECORATOR macros stay macros (a decl-spec word or leading _).
        for name in ["JSON_INLINE", "WINAPI", "MYLIB_EXPORT", "__EXPORT"] {
            let kinds = classify(&format!("h.h:1:1: error: unknown type name '{name}'\n"));
            assert!(
                kinds.iter().any(|k| matches!(
                    k,
                    BuildErrorKind::MissingMacro { name: n, .. } if n == name
                )),
                "decorator {name} must stay a macro: {kinds:?}"
            );
        }
    }

    #[test]
    fn type_position_classification_is_stable_across_rounds() {
        // #96 oscillation guard: the SAME diagnostic always yields the SAME kind, so
        // a successful type-header repair cannot be undone by a later round
        // reclassifying the same symbol as a macro.
        let stderr = "p.c:1:1: error: unknown type name 'SCANNER'\n";
        let first = classify(stderr);
        let second = classify(stderr);
        assert_eq!(format!("{first:?}"), format!("{second:?}"));
        assert!(first
            .iter()
            .any(|k| matches!(k, BuildErrorKind::MissingType { name } if name == "SCANNER")));
    }

    #[test]
    fn lowercase_undeclared_identifier_is_not_a_macro() {
        // A real undeclared symbol must not be faked as a macro #define.
        let stderr = "x.c:4:5: error: use of undeclared identifier 'helper_fn'\n";
        let kinds = classify(stderr);
        assert!(
            !kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::MissingMacro { .. })),
            "got {kinds:?}"
        );
    }

    #[test]
    fn mixed_case_project_constants_and_aliases_are_repairable() {
        for name in ["True", "UChar", "cJSON_IsReference"] {
            let kinds = classify(&format!(
                "x.c:4:5: error: use of undeclared identifier '{name}'\n"
            ));
            assert!(
                matches!(
                    kinds.as_slice(),
                    [BuildErrorKind::MissingMacro { name: found, as_value: true }]
                        if found == name
                ),
                "{name}: {kinds:?}"
            );
        }
    }

    #[test]
    fn undeclared_identifier_in_cpp_call_context_is_repairable() {
        let stderr = "coding.h:42:10: error: use of undeclared identifier 'DecodeFixed32'\n\
                      return DecodeFixed32(data);\n\
                             ^\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                BuildErrorKind::MissingMacro { name, as_value: true }
                    if name == "DecodeFixed32"
            )),
            "got {kinds:?}"
        );

        let variable = classify(
            "coding.h:42:10: error: use of undeclared identifier 'decode_state'\n\
             return decode_state;\n\
                    ^\n",
        );
        assert!(matches!(
            variable.as_slice(),
            [BuildErrorKind::Other { .. }]
        ));
    }

    #[test]
    fn known_posix_cpp_undeclared_identifier_is_repairable_symbol() {
        let kinds = classify("TProtocol.h:658:50: error: use of undeclared identifier 'htons'\n");
        assert!(kinds.iter().any(|kind| matches!(
            kind,
            BuildErrorKind::UndefinedSymbol { name } if name == "htons"
        )));

        // A lowercase variable is deliberately not promoted to a function.
        let kinds = classify("x.cpp:4:5: error: use of undeclared identifier 'state'\n");
        assert!(matches!(kinds.as_slice(), [BuildErrorKind::Other { .. }]));
    }

    #[test]
    fn undeclared_std_qualifier_preserves_the_qualified_standard_type() {
        let stderr = "x.cpp:4:7: error: use of undeclared identifier 'std'\n\
                      using std::string;\n\
                            ^\n";
        let kinds = classify(stderr);
        assert!(kinds.iter().any(|kind| matches!(
            kind,
            BuildErrorKind::MissingType { name } if name == "std::string"
        )));
    }

    #[test]
    fn known_wide_string_function_is_not_classified_as_a_macro() {
        let kinds = classify("archive.c:10:9: error: use of undeclared identifier 'wcslen'\n");
        assert!(matches!(
            kinds.as_slice(),
            [BuildErrorKind::UndefinedSymbol { name }] if name == "wcslen"
        ));
    }

    #[test]
    fn undeclared_c_boolean_literal_is_repairable_via_stdbool() {
        let kinds = classify("data.c:9:4: error: use of undeclared identifier 'false'\n");
        assert!(matches!(
            kinds.as_slice(),
            [BuildErrorKind::UndefinedSymbol { name }] if name == "false"
        ));
    }

    #[test]
    fn call_to_undeclared_clang_frontend_form() {
        // clang's compile-time error when a function is referenced
        // without a prior declaration. Prior to this regex the auto
        // pipeline saw it as `Other` and never planned a call-site repair.
        let stderr = "harness.c:77:11: error: call to undeclared function 'vendor_helper'; \
                      ISO C99 and later do not support implicit function declarations \
                      [-Wimplicit-function-declaration]\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::UndeclaredFunction { name, file, line }
                    if name == "vendor_helper" && file == "harness.c" && *line == 77
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn call_to_undeclared_library_function_is_repairable() {
        let kinds = classify(
            "mpc.c:105:20: error: call to undeclared library function 'malloc' with type 'void *(unsigned long)'\n",
        );
        assert!(matches!(
            kinds.as_slice(),
            [BuildErrorKind::UndeclaredFunction { name, file, line }]
                if name == "malloc" && file == "mpc.c" && *line == 105
        ));
    }

    #[test]
    fn math_symbol_reclassifies_as_missing_libm() {
        let stderr = "/usr/bin/ld: /tmp/foo.o: in function `f':\n\
                      /tmp/foo.c:9: undefined reference to `sqrt'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "m"
            )),
            "sqrt should reclassify to MissingSharedLib(m), got {kinds:?}"
        );
        assert!(
            !kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::UndefinedSymbol { name } if name == "sqrt"
            )),
            "sqrt should NOT also be reported as UndefinedSymbol"
        );
    }

    #[test]
    fn pthread_symbol_reclassifies_as_missing_pthread() {
        let stderr = "ld: undefined reference to `pthread_mutex_lock'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "pthread"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn dl_symbol_reclassifies_as_missing_libdl() {
        let stderr = "ld: undefined reference to `dlopen'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "dl"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn rt_symbol_reclassifies_as_missing_librt() {
        let stderr = "ld: undefined reference to `clock_gettime'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "rt"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn unknown_symbol_stays_undefined_symbol() {
        // Project-local symbols don't match the system-lib table and
        // should still flow through the existing UndefinedSymbol →
        // StubDeclared / StubBlind path.
        let stderr = "ld: undefined reference to `vendor_decode'\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::UndefinedSymbol { name } if name == "vendor_decode"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_shared_lib_ld_form() {
        let stderr = "/usr/bin/ld: cannot find -lhiredis: No such file or directory\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingSharedLib { name } if name == "hiredis"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_type_clang_form() {
        let stderr = "main.c:5:1: error: unknown type name 'Widget'\nWidget x;\n^\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingType { name } if name == "Widget"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn target_specific_inline_asm_is_an_uncompilable_body() {
        // bb-runtimes ARM/AArch64 machine intrinsics built on an x86 host.
        for stderr in [
            "/w/i-arm_v7ar.adb:273: Error: no such instruction: `mcr p15,'\n",
            "/w/i-aarch64.adb:9: Error: junk `el1' after expression\n",
            "i-aarch64.adb:9:4: error: missing \"return\" statement in function body\n",
        ] {
            let kinds = classify(stderr);
            assert!(
                kinds.iter().any(|k| matches!(
                    k,
                    BuildErrorKind::UncompilableAdaBody { source } if source.ends_with(".adb")
                )),
                "asm error should be an uncompilable Ada body: {kinds:?}"
            );
        }
        // A normal Ada semantic error is NOT an uncompilable body.
        let kinds = classify("x.adb:1:1: error: \"Foo\" is undefined\n");
        assert!(
            !kinds
                .iter()
                .any(|k| matches!(k, BuildErrorKind::UncompilableAdaBody { .. })),
            "got {kinds:?}"
        );
    }

    #[test]
    fn other_for_unknown_tail() {
        let stderr = "internal compiler error: oh no\nflux capacitor exploded\n";
        let kinds = classify(stderr);
        assert!(matches!(kinds[0], BuildErrorKind::Other { .. }));
    }

    #[test]
    fn incomplete_type_is_distinct_from_unknown_type() {
        // A forward-declared-but-undefined type (pimpl) is IncompleteType, NOT
        // MissingType — so it is never `void *`-repaired (that redefines the
        // forward decl) and instead degrades the target to report-only.
        for line in [
            "main.cpp:81:47: error: calling 'parse' with incomplete return type 'EncryptionParametersImpl'",
            "main.cpp:5:24: error: variable has incomplete type 'FooImpl'",
            "main.cpp:9:5: error: field has incomplete type 'class BarImpl'",
        ] {
            let kinds = classify(line);
            assert!(
                matches!(&kinds[0], BuildErrorKind::IncompleteType { .. }),
                "expected IncompleteType for {line:?}, got {kinds:?}"
            );
        }
        // The captured name strips a leading class/struct keyword.
        let kinds = classify("main.cpp:9:5: error: field has incomplete type 'class BarImpl'");
        assert!(
            matches!(&kinds[0], BuildErrorKind::IncompleteType { name } if name == "BarImpl"),
            "got {kinds:?}"
        );
        // A genuinely unknown type stays MissingType (gets the void* repair).
        let unknown = classify("x.c:1:1: error: unknown type name 'CString'");
        assert!(
            matches!(&unknown[0], BuildErrorKind::MissingType { name } if name == "CString"),
            "got {unknown:?}"
        );
    }

    #[test]
    fn missing_with_ada() {
        let stderr = "src/app.adb:3:06: file \"foo.ads\" not found\ngprbuild: \"src/app.adb\" compilation failed\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaWith { unit } if unit == "foo"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_ada_symbol() {
        let stderr = "src/app.adb:42:10: \"Parse_Error\" is undefined (more references follow)\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaSymbol { symbol, .. } if symbol == "Parse_Error"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_ada_symbol_not_declared_in_package() {
        let stderr = "src/app.adb:42:10: \"Score\" not declared in \"Aux_Pkg\"\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaSymbol { unit, symbol }
                    if unit == "Aux_Pkg" && symbol == "Score"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn repeated_gnat_diagnostics_are_counted_once() {
        let stderr = "x.adb:1:2: error: \"To_String\" not declared in \"Legacy\"\n\
                      x.adb:1:2: error: \"To_String\" not declared in \"Legacy\"\n";
        let errors = classify(stderr);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(matches!(
            &errors[0],
            BuildErrorKind::MissingAdaSymbol { unit, symbol }
                if unit == "Legacy" && symbol == "To_String"
        ));
    }

    #[test]
    fn missing_ada_package_body() {
        let stderr = "missing body for unit \"Demo.Parser\"\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaPackageBody { unit } if unit == "Demo.Parser"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_body_cannot_generate_code_form() {
        // gprbuild's way of saying "you have a spec but no body".
        let stderr = "Compile\n   [Ada]          aux_pkg.ads\n\
                      cannot generate code for file aux_pkg.ads (package spec)\n\
                      gprbuild: *** compilation phase failed\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingAdaPackageBody { unit } if unit == "aux_pkg"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_gpr_import_imported_project_form() {
        // gprbuild's "imported project file" flavour, which is what
        // we see in practice when an `<x>.gpr` `with`s a missing
        // `<y>.gpr`.
        let stderr = "govfuzz_build.gpr:3:06: imported project file \"missing.gpr\" not found\n\
                      gprbuild: \"govfuzz_build.gpr\" processing failed\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingGprImport { path } if path == "missing.gpr"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn missing_gpr_import() {
        let stderr = "demo.gpr:5:09: cannot find \"gnatcoll.gpr\"\ngprbuild: project file \"demo.gpr\" loading failed\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                BuildErrorKind::MissingGprImport { path } if path == "gnatcoll.gpr"
            )),
            "got {kinds:?}"
        );
    }
}
