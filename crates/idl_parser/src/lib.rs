// SPDX-License-Identifier: Apache-2.0

pub mod ada_emit;
pub mod ast;
pub mod error;
pub mod lexer;
mod literal;
mod parser;
pub mod preprocessor;
pub mod ros_interface;

pub use ada_emit::{emit_ada_packages, write_generated_ada_units, AdaEmitOutput, GeneratedAdaUnit};
pub use ast::*;
pub use error::{IdlParseError, Span};
pub use preprocessor::{
    preprocess_c_like, preprocess_c_like_with_line_map, preprocess_idl, preprocess_idl_file,
    preprocess_idl_file_recovering_with_include_dirs, preprocess_idl_file_recovering_with_options,
    preprocess_idl_file_with_defines, preprocess_idl_file_with_include_dirs,
    preprocess_idl_with_defines, LineMap,
};
pub use ros_interface::{parse_ros_action, parse_ros_interface_file, parse_ros_msg, parse_ros_srv};

pub fn parse_idl(source: &str) -> Result<IdlFile, IdlParseError> {
    let preprocessed = preprocessor::preprocess_idl(source)?;
    parser::parse_source(&preprocessed)
}

pub fn parse_idl_file(path: &std::path::Path) -> Result<IdlFile, IdlParseError> {
    let preprocessed = preprocessor::preprocess_idl_file(path)?;
    parser::parse_source(&preprocessed)
}

pub fn parse_idl_file_with_defines(
    path: &std::path::Path,
    defines: &[(String, String)],
) -> Result<IdlFile, IdlParseError> {
    let preprocessed = preprocessor::preprocess_idl_file_with_defines(path, defines)?;
    parser::parse_source(&preprocessed)
}

pub fn parse_idl_file_with_include_dirs(
    path: &std::path::Path,
    include_dirs: &[std::path::PathBuf],
) -> Result<IdlFile, IdlParseError> {
    let preprocessed = preprocessor::preprocess_idl_file_with_include_dirs(path, include_dirs)?;
    parser::parse_source(&preprocessed)
}

pub fn parse_idl_file_recovering_with_include_dirs(
    path: &std::path::Path,
    include_dirs: &[std::path::PathBuf],
) -> Result<IdlFile, IdlParseError> {
    let preprocessed =
        preprocessor::preprocess_idl_file_recovering_with_include_dirs(path, include_dirs)?;
    parser::parse_source(&preprocessed)
}

pub fn parse_idl_file_recovering_with_options(
    path: &std::path::Path,
    defines: &[(String, String)],
    include_dirs: &[std::path::PathBuf],
) -> Result<IdlFile, IdlParseError> {
    let preprocessed =
        preprocessor::preprocess_idl_file_recovering_with_options(path, defines, include_dirs)?;
    parser::parse_source(&preprocessed)
}

pub fn extract_idl_dictionary_tokens(source: &str) -> Result<Vec<String>, IdlParseError> {
    let ast = parse_idl(source)?;
    Ok(extract_idl_dictionary_tokens_from_ast(&ast))
}

pub fn extract_idl_dictionary_tokens_from_ast(ast: &IdlFile) -> Vec<String> {
    let mut tokens = Vec::new();
    collect_idl_dictionary_tokens(&ast.declarations, &mut tokens);
    tokens
}

fn collect_idl_dictionary_tokens(declarations: &[Declaration], tokens: &mut Vec<String>) {
    for declaration in declarations {
        match declaration {
            Declaration::Module(module) => {
                push_idl_dictionary_token(tokens, module.name.clone());
                collect_idl_dictionary_tokens(&module.declarations, tokens);
            }
            Declaration::Interface(interface) => {
                push_idl_dictionary_token(tokens, interface.name.clone());
                for member in &interface.members {
                    match member {
                        InterfaceMember::Operation(operation) => {
                            push_idl_dictionary_token(tokens, operation.name.clone());
                        }
                        InterfaceMember::Attribute(attribute) => {
                            push_idl_dictionary_token(tokens, attribute.name.clone());
                        }
                    }
                }
            }
            Declaration::Struct(struct_decl) => {
                push_idl_dictionary_token(tokens, struct_decl.name.clone());
                for field in &struct_decl.fields {
                    push_idl_dictionary_token(tokens, field.name.clone());
                }
            }
            Declaration::Enum(enum_decl) => {
                push_idl_dictionary_token(tokens, enum_decl.name.clone());
                for variant in &enum_decl.variants {
                    push_idl_dictionary_token(tokens, variant.clone());
                }
            }
            Declaration::Exception(exception) => {
                push_idl_dictionary_token(tokens, exception.name.clone());
                for field in &exception.fields {
                    push_idl_dictionary_token(tokens, field.name.clone());
                }
            }
            Declaration::Typedef(typedef) => {
                push_idl_dictionary_token(tokens, typedef.name.clone())
            }
            Declaration::Const(const_decl) => {
                push_idl_dictionary_token(tokens, const_decl.name.clone());
                push_idl_const_value(tokens, &const_decl.value);
            }
            Declaration::Union(union_decl) => {
                push_idl_dictionary_token(tokens, union_decl.name.clone());
                for arm in &union_decl.arms {
                    push_idl_dictionary_token(tokens, arm.field.name.clone());
                    for label in &arm.labels {
                        if let UnionLabel::Case(value) = label {
                            push_idl_const_value(tokens, value);
                        }
                    }
                }
            }
            Declaration::ValueType(value_type) => {
                push_idl_dictionary_token(tokens, value_type.name.clone());
            }
            Declaration::EventType(event_type) => {
                push_idl_dictionary_token(tokens, event_type.name.clone());
            }
            Declaration::Pragma(_) => {}
        }
    }
}

fn push_idl_const_value(tokens: &mut Vec<String>, value: &ConstValue) {
    match value {
        ConstValue::Integer(value) => push_idl_dictionary_token(tokens, value.to_string()),
        ConstValue::Float(value) => push_idl_dictionary_token(tokens, value.clone()),
        ConstValue::String(value) => {
            push_idl_dictionary_token(tokens, idl_string_literal_value(value));
        }
        ConstValue::Boolean(value) => push_idl_dictionary_token(tokens, value.to_string()),
        ConstValue::ScopedName(name) => {
            if !name.parts.is_empty() {
                push_idl_dictionary_token(tokens, name.parts.join("::"));
                if let Some(last) = name.parts.last() {
                    push_idl_dictionary_token(tokens, last.clone());
                }
            }
        }
    }
}

fn idl_string_literal_value(raw: &str) -> String {
    let raw = raw.strip_prefix('L').unwrap_or(raw);
    raw.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw)
        .to_owned()
}

fn push_idl_dictionary_token(tokens: &mut Vec<String>, token: String) {
    let token = token.trim().to_owned();
    if token.is_empty() || token.len() > 256 || tokens.contains(&token) {
        return;
    }
    tokens.push(token);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_idl_file_returns_empty_ast() {
        let ast = parse_idl("").expect("empty IDL parses");
        assert!(ast.declarations.is_empty());
        assert!(ast.warnings.is_empty());
    }

    #[test]
    fn parse_idl_runs_cpp_lite_defines_before_parsing() {
        let ast = parse_idl("#define LIMIT 8\nconst long Limit = LIMIT;\n").expect("IDL parses");
        let Declaration::Const(const_decl) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(const_decl.value, ConstValue::Integer(8));
    }

    #[test]
    fn extracts_dictionary_tokens_from_idl_constants_enums_and_union_labels() {
        let tokens = extract_idl_dictionary_tokens(
            r#"
            module Demo {
              enum Mode { MODE_FAST, MODE_SAFE };
              const string Ready = "READY";
              const unsigned long Magic = 0x42;
              union Choice switch (long) {
                case -1: string error;
                case MODE_FAST: string fast;
                default: long ok;
              };
            };
            "#,
        )
        .expect("IDL parses");

        assert!(tokens.contains(&"MODE_FAST".to_owned()));
        assert!(tokens.contains(&"MODE_SAFE".to_owned()));
        assert!(tokens.contains(&"READY".to_owned()));
        assert!(tokens.contains(&"66".to_owned()));
        assert!(tokens.contains(&"-1".to_owned()));
    }

    #[test]
    fn parse_idl_runs_cpp_lite_conditionals_before_parsing() {
        let ast = parse_idl(
            "#define ENABLED\n#ifdef ENABLED\ninterface Active {};\n#else\ninterface Inactive {};\n#endif\n",
        )
        .expect("IDL parses");
        assert_eq!(ast.declarations.len(), 1);
        let Declaration::Interface(interface) = &ast.declarations[0] else {
            panic!("interface expected")
        };
        assert_eq!(interface.name, "Active");
    }

    #[test]
    fn parse_unsupported_preprocessor_directive_reports_follow_up_error() {
        let error = parse_idl("#if VENDOR_FLAG(1)\ninterface I {};\n#endif\n")
            .expect_err("CPP expression is rejected");
        assert!(error.to_string().contains("unexpected trailing tokens"));
    }

    #[test]
    fn parse_idl_records_unknown_pragmas_as_warnings() {
        let ast = parse_idl("# pragma vendor fast-path enabled\ninterface Root {};\n")
            .expect("IDL parses");

        assert_eq!(ast.pragmas.len(), 1);
        assert!(ast.warnings.iter().any(
            |warning| warning.contains("unknown IDL pragma '#pragma vendor fast-path enabled'")
        ));
    }

    #[test]
    fn parse_idl_surfaces_govfuzz_warning_pragma_as_clean_message() {
        // govfuzz's own recovery breadcrumb must NOT be re-flagged as an unknown
        // pragma; its message is surfaced verbatim (the confusing double-diagnostic
        // the Ada/CORBA dogfood produced).
        let ast = parse_idl(
            "#pragma govfuzz_warning \"include 'common.idl' not found\"\ninterface Root {};\n",
        )
        .expect("IDL parses");
        assert!(
            ast.warnings
                .iter()
                .any(|w| w == "include 'common.idl' not found"),
            "clean message expected, got {:?}",
            ast.warnings
        );
        assert!(
            !ast.warnings
                .iter()
                .any(|w| w.contains("unknown IDL pragma")),
            "govfuzz_warning must not be labelled unknown: {:?}",
            ast.warnings
        );
    }

    #[test]
    fn parse_idl_skips_ros_numeric_annotation_literals() {
        parse_idl(
            "module Demo {
                struct Sample {
                    @default(value=.1)
                    float leading_dot;
                    @default(value=8.7d)
                    float fixed_with_fraction;
                    @default(value=7d)
                    float fixed_without_fraction;
                };
            };",
        )
        .expect("IDL parses");
    }

    #[test]
    fn parse_ros_msg_translates_fields_constants_arrays_and_sequences() {
        let ast = parse_ros_msg(
            "demo_msgs",
            "msg",
            "Sample",
            "int32 LIMIT=8\nstring<=32 label\nuint8[4] key\nint32[] values\nstd_msgs/Header header\n",
        )
        .expect("ROS msg parses");

        let Declaration::Module(package) = &ast.declarations[0] else {
            panic!("package module expected");
        };
        assert_eq!(package.name, "demo_msgs");
        let Declaration::Module(kind) = &package.declarations[0] else {
            panic!("kind module expected");
        };
        assert_eq!(kind.name, "msg");
        assert!(matches!(kind.declarations[0], Declaration::Const(_)));
        let Declaration::Struct(struct_decl) = &kind.declarations[1] else {
            panic!("message struct expected");
        };
        assert_eq!(struct_decl.name, "Sample");
        assert!(matches!(
            struct_decl.fields[1].ty,
            TypeRef::Array { ref dimensions, .. } if dimensions == &[4]
        ));
        assert!(matches!(
            struct_decl.fields[2].ty,
            TypeRef::Sequence { bound: None, .. }
        ));
        assert_eq!(
            struct_decl.fields[3].ty,
            TypeRef::Named(ScopedName {
                absolute: false,
                parts: vec!["std_msgs".to_owned(), "msg".to_owned(), "Header".to_owned()],
            })
        );

        let ast =
            parse_ros_msg("demo_msgs", "msg", "Nested", "Sample sample\n").expect("ROS msg parses");
        let Declaration::Module(package) = &ast.declarations[0] else {
            panic!("package module expected");
        };
        let Declaration::Module(kind) = &package.declarations[0] else {
            panic!("kind module expected");
        };
        let Declaration::Struct(struct_decl) = &kind.declarations[0] else {
            panic!("message struct expected");
        };
        assert_eq!(
            struct_decl.fields[0].ty,
            TypeRef::Named(ScopedName {
                absolute: false,
                parts: vec![
                    "demo_msgs".to_owned(),
                    "msg".to_owned(),
                    "Sample".to_owned()
                ],
            })
        );
    }

    #[test]
    fn parse_ros_srv_and_action_split_sections_into_structs() {
        let srv = parse_ros_srv("demo_msgs", "Query", "string name\n---\nbool ok\n")
            .expect("ROS srv parses");
        let action = parse_ros_action(
            "demo_msgs",
            "Move",
            "int32 order\n---\nbool done\n---\nfloat32 progress\n",
        )
        .expect("ROS action parses");

        let Declaration::Module(package) = &srv.declarations[0] else {
            panic!("package module expected");
        };
        let Declaration::Module(kind) = &package.declarations[0] else {
            panic!("srv module expected");
        };
        let names = kind
            .declarations
            .iter()
            .map(|decl| match decl {
                Declaration::Struct(struct_decl) => struct_decl.name.as_str(),
                _ => panic!("struct expected"),
            })
            .collect::<Vec<_>>();
        assert_eq!(names, ["Query_Request", "Query_Response"]);

        let Declaration::Module(package) = &action.declarations[0] else {
            panic!("package module expected");
        };
        let Declaration::Module(kind) = &package.declarations[0] else {
            panic!("action module expected");
        };
        let names = kind
            .declarations
            .iter()
            .map(|decl| match decl {
                Declaration::Struct(struct_decl) => struct_decl.name.as_str(),
                _ => panic!("struct expected"),
            })
            .collect::<Vec<_>>();
        assert_eq!(names, ["Move_Goal", "Move_Result", "Move_Feedback"]);
    }

    #[test]
    fn parse_ros_srv_accepts_empty_request_section() {
        let srv = parse_ros_srv(
            "demo_msgs",
            "Trigger",
            "---\nbool success\nstring message\n",
        )
        .expect("ROS srv parses");

        let Declaration::Module(package) = &srv.declarations[0] else {
            panic!("package module expected");
        };
        let Declaration::Module(kind) = &package.declarations[0] else {
            panic!("srv module expected");
        };
        let Declaration::Struct(request) = &kind.declarations[0] else {
            panic!("request struct expected");
        };
        let Declaration::Struct(response) = &kind.declarations[1] else {
            panic!("response struct expected");
        };
        assert!(request.fields.is_empty());
        assert_eq!(response.fields.len(), 2);
    }

    #[test]
    fn parse_ros_msg_ignores_field_annotations() {
        let ast = parse_ros_msg(
            "demo_msgs",
            "msg",
            "Annotated",
            "@optional\nfloat32 standalone\n@optional float32 inline_value\n@optional float32 INLINE_CONST=32.0\n",
        )
        .expect("ROS msg parses");

        let Declaration::Module(package) = &ast.declarations[0] else {
            panic!("package module expected");
        };
        let Declaration::Module(kind) = &package.declarations[0] else {
            panic!("kind module expected");
        };
        assert!(matches!(kind.declarations[0], Declaration::Const(_)));
        let Declaration::Struct(struct_decl) = &kind.declarations[1] else {
            panic!("message struct expected");
        };
        assert_eq!(struct_decl.fields[0].name, "standalone");
        assert_eq!(struct_decl.fields[1].name, "inline_value");
    }

    #[test]
    fn parse_idl_file_parses_declarations_from_includes() {
        let root =
            std::env::temp_dir().join(format!("govfuzz-idl-parse-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        std::fs::write(root.join("common.idl"), "interface Common {};\n").expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(&root_file, "#include \"common.idl\"\ninterface Root {};\n")
            .expect("write root");

        let ast = parse_idl_file(&root_file).expect("IDL file parses");

        assert_eq!(ast.declarations.len(), 2);
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn parse_idl_file_searches_configured_include_dirs() {
        let root = std::env::temp_dir().join(format!(
            "govfuzz-idl-parse-file-include-dir-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let include_dir = root.join("shared");
        std::fs::create_dir_all(&include_dir).expect("create include dir");
        std::fs::write(include_dir.join("common.idl"), "interface Common {};\n")
            .expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(&root_file, "#include \"common.idl\"\ninterface Root {};\n")
            .expect("write root");

        let ast =
            parse_idl_file_with_include_dirs(&root_file, &[include_dir]).expect("IDL file parses");

        assert_eq!(ast.declarations.len(), 2);
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn parse_idl_file_parses_include_inside_active_ifdef() {
        let root =
            std::env::temp_dir().join(format!("govfuzz-idl-active-include-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        std::fs::write(root.join("common.idl"), "interface Common {};\n").expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(
            &root_file,
            "#define ENABLED\n#ifdef ENABLED\n#include \"common.idl\"\n#endif\ninterface Root {};\n",
        )
        .expect("write root");

        let ast = parse_idl_file(&root_file).expect("IDL file parses");

        assert_eq!(ast.declarations.len(), 2);
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }
}
