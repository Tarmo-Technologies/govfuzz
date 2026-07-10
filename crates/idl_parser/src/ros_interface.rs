// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    Const, ConstValue, Declaration, Field, IdlFile, Module, PrimitiveType, ScopedName, Struct,
    TypeRef,
};
use crate::error::{IdlParseError, Span};
use std::path::Path;

pub fn parse_ros_msg(
    package: &str,
    kind: &str,
    name: &str,
    source: &str,
) -> Result<IdlFile, IdlParseError> {
    let context = RosTypeContext { package, kind };
    let (constants, fields) = parse_ros_members(source, context)?;
    Ok(wrap_declarations(
        package,
        kind,
        constants
            .into_iter()
            .map(Declaration::Const)
            .chain([Declaration::Struct(Struct {
                name: name.to_owned(),
                fields,
            })])
            .collect(),
    ))
}

pub fn parse_ros_srv(package: &str, name: &str, source: &str) -> Result<IdlFile, IdlParseError> {
    let sections = split_sections(source);
    if sections.len() != 2 {
        return Err(error(
            "ROS srv files must contain exactly one '---' separator",
        ));
    }
    let context = RosTypeContext {
        package,
        kind: "srv",
    };
    let (_, request_fields) = parse_ros_members(&sections[0], context)?;
    let (_, response_fields) = parse_ros_members(&sections[1], context)?;
    Ok(wrap_declarations(
        package,
        "srv",
        vec![
            Declaration::Struct(Struct {
                name: format!("{name}_Request"),
                fields: request_fields,
            }),
            Declaration::Struct(Struct {
                name: format!("{name}_Response"),
                fields: response_fields,
            }),
        ],
    ))
}

pub fn parse_ros_action(package: &str, name: &str, source: &str) -> Result<IdlFile, IdlParseError> {
    let sections = split_sections(source);
    if sections.len() != 3 {
        return Err(error(
            "ROS action files must contain exactly two '---' separators",
        ));
    }
    let context = RosTypeContext {
        package,
        kind: "action",
    };
    let (_, goal_fields) = parse_ros_members(&sections[0], context)?;
    let (_, result_fields) = parse_ros_members(&sections[1], context)?;
    let (_, feedback_fields) = parse_ros_members(&sections[2], context)?;
    Ok(wrap_declarations(
        package,
        "action",
        vec![
            Declaration::Struct(Struct {
                name: format!("{name}_Goal"),
                fields: goal_fields,
            }),
            Declaration::Struct(Struct {
                name: format!("{name}_Result"),
                fields: result_fields,
            }),
            Declaration::Struct(Struct {
                name: format!("{name}_Feedback"),
                fields: feedback_fields,
            }),
        ],
    ))
}

pub fn parse_ros_interface_file(path: &Path) -> Result<IdlFile, IdlParseError> {
    let source = std::fs::read_to_string(path).map_err(|error| {
        self::error(format!("read ROS interface '{}': {error}", path.display()))
    })?;
    let metadata = RosInterfaceMetadata::from_path(path)?;
    match metadata.kind.as_str() {
        "msg" => parse_ros_msg(&metadata.package, "msg", &metadata.name, &source),
        "srv" => parse_ros_srv(&metadata.package, &metadata.name, &source),
        "action" => parse_ros_action(&metadata.package, &metadata.name, &source),
        _ => Err(error(format!(
            "unsupported ROS interface extension for '{}'",
            path.display()
        ))),
    }
}

struct RosInterfaceMetadata {
    package: String,
    kind: String,
    name: String,
}

impl RosInterfaceMetadata {
    fn from_path(path: &Path) -> Result<Self, IdlParseError> {
        let name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                error(format!(
                    "ROS interface '{}' has no file stem",
                    path.display()
                ))
            })?
            .to_owned();
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .ok_or_else(|| {
                error(format!(
                    "ROS interface '{}' has no extension",
                    path.display()
                ))
            })?
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "msg" | "srv" | "action") {
            return Err(error(format!(
                "unsupported ROS interface extension '.{extension}'"
            )));
        }

        let kind_dir = path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .filter(|name| matches!(*name, "msg" | "srv" | "action"));
        let package = kind_dir
            .and_then(|_| {
                path.parent()
                    .and_then(|parent| parent.parent())
                    .and_then(|parent| parent.file_name())
                    .and_then(|name| name.to_str())
            })
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{name}_msgs"));
        let kind = kind_dir.map(str::to_owned).unwrap_or(extension);

        Ok(Self {
            package,
            kind,
            name,
        })
    }
}

fn wrap_declarations(package: &str, kind: &str, declarations: Vec<Declaration>) -> IdlFile {
    IdlFile {
        declarations: vec![Declaration::Module(Module {
            name: package.to_owned(),
            declarations: vec![Declaration::Module(Module {
                name: kind.to_owned(),
                declarations,
            })],
        })],
        pragmas: Vec::new(),
        warnings: Vec::new(),
    }
}

#[derive(Clone, Copy)]
struct RosTypeContext<'a> {
    package: &'a str,
    kind: &'a str,
}

fn parse_ros_members(
    source: &str,
    context: RosTypeContext<'_>,
) -> Result<(Vec<Const>, Vec<Field>), IdlParseError> {
    let mut constants = Vec::new();
    let mut fields = Vec::new();
    for (index, raw_line) in source.lines().enumerate() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "---" {
            continue;
        }
        let Some(line) = strip_leading_annotations(line) else {
            continue;
        };
        if let Some(index) = constant_assignment_index(line) {
            let (left, value) = line.split_at(index);
            let value = &value[1..];
            let mut parts = left.split_whitespace();
            let ty = parts
                .next()
                .ok_or_else(|| line_error(index, "expected ROS constant type"))?;
            let name = parts
                .next()
                .ok_or_else(|| line_error(index, "expected ROS constant name"))?;
            constants.push(Const {
                name: normalize_identifier(name),
                ty: parse_ros_type(ty, context)?,
                value: parse_const_value(value.trim()),
            });
            continue;
        }

        let mut parts = line.split_whitespace();
        let ty = parts
            .next()
            .ok_or_else(|| line_error(index, "expected ROS field type"))?;
        let name = parts
            .next()
            .ok_or_else(|| line_error(index, "expected ROS field name"))?;
        fields.push(Field {
            name: normalize_identifier(name),
            ty: parse_ros_type(ty, context)?,
        });
    }
    Ok((constants, fields))
}

fn strip_leading_annotations(mut line: &str) -> Option<&str> {
    loop {
        line = line.trim_start();
        let Some(rest) = line.strip_prefix('@') else {
            return Some(line);
        };
        let name_len = rest
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')
            .map(|(index, ch)| index + ch.len_utf8())
            .last()
            .unwrap_or(0);
        if name_len == 0 {
            return Some(line);
        }
        line = &rest[name_len..];
        line = line.trim_start();
        if let Some(rest) = line.strip_prefix('(') {
            line = skip_balanced_annotation_arguments(rest);
        }
        if line.trim().is_empty() {
            return None;
        }
    }
}

fn skip_balanced_annotation_arguments(line: &str) -> &str {
    let mut depth = 1_u32;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' if !escaped => in_string = !in_string,
            '(' if !in_string => depth += 1,
            ')' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return &line[index + ch.len_utf8()..];
                }
            }
            '\\' if in_string => {
                escaped = !escaped;
                continue;
            }
            _ => {}
        }
        escaped = false;
    }
    ""
}

fn parse_ros_type(token: &str, context: RosTypeContext<'_>) -> Result<TypeRef, IdlParseError> {
    let (base, suffix) = split_array_suffix(token)?;
    let mut ty = parse_ros_base_type(base, context)?;
    if let Some(suffix) = suffix {
        ty = match suffix {
            "" => TypeRef::Sequence {
                element: Box::new(ty),
                bound: None,
            },
            bound if bound.starts_with("<=") => TypeRef::Sequence {
                element: Box::new(ty),
                bound: Some(parse_u64(&bound[2..])?),
            },
            dimension => TypeRef::Array {
                element: Box::new(ty),
                dimensions: vec![parse_u64(dimension)?],
            },
        };
    }
    Ok(ty)
}

fn parse_ros_base_type(token: &str, context: RosTypeContext<'_>) -> Result<TypeRef, IdlParseError> {
    if let Some(bound) = token.strip_prefix("string<=") {
        return Ok(TypeRef::String {
            wide: false,
            bound: Some(parse_u64(bound)?),
        });
    }
    if let Some(bound) = token.strip_prefix("wstring<=") {
        return Ok(TypeRef::String {
            wide: true,
            bound: Some(parse_u64(bound)?),
        });
    }
    let ty = match token {
        "bool" => TypeRef::Primitive(PrimitiveType::Boolean),
        "byte" | "char" | "uint8" => TypeRef::Primitive(PrimitiveType::Octet),
        "int8" | "int16" => TypeRef::Primitive(PrimitiveType::Short),
        "uint16" => TypeRef::Primitive(PrimitiveType::UShort),
        "int32" => TypeRef::Primitive(PrimitiveType::Long),
        "uint32" => TypeRef::Primitive(PrimitiveType::ULong),
        "int64" => TypeRef::Primitive(PrimitiveType::LongLong),
        "uint64" => TypeRef::Primitive(PrimitiveType::ULongLong),
        "float32" => TypeRef::Primitive(PrimitiveType::Float),
        "float64" => TypeRef::Primitive(PrimitiveType::Double),
        "string" => TypeRef::String {
            wide: false,
            bound: None,
        },
        "wstring" => TypeRef::String {
            wide: true,
            bound: None,
        },
        named => TypeRef::Named(parse_ros_named_type(named, context)?),
    };
    Ok(ty)
}

fn parse_ros_named_type(
    token: &str,
    context: RosTypeContext<'_>,
) -> Result<ScopedName, IdlParseError> {
    if let Some((package, name)) = token.split_once('/') {
        if package.is_empty() || name.is_empty() || name.contains('/') {
            return Err(error(format!("invalid ROS type name '{token}'")));
        }
        return Ok(ScopedName {
            absolute: false,
            parts: vec![package.to_owned(), "msg".to_owned(), name.to_owned()],
        });
    }
    Ok(ScopedName {
        absolute: false,
        parts: vec![
            context.package.to_owned(),
            context.kind.to_owned(),
            token.to_owned(),
        ],
    })
}

fn split_array_suffix(token: &str) -> Result<(&str, Option<&str>), IdlParseError> {
    let Some(start) = token.rfind('[') else {
        return Ok((token, None));
    };
    if !token.ends_with(']') {
        return Err(error(format!("invalid ROS array suffix in '{token}'")));
    }
    Ok((&token[..start], Some(&token[start + 1..token.len() - 1])))
}

fn constant_assignment_index(line: &str) -> Option<usize> {
    line.char_indices()
        .find(|(index, ch)| *ch == '=' && !line[..*index].ends_with('<'))
        .map(|(index, _)| index)
}

fn parse_const_value(value: &str) -> ConstValue {
    if value.eq_ignore_ascii_case("true") {
        ConstValue::Boolean(true)
    } else if value.eq_ignore_ascii_case("false") {
        ConstValue::Boolean(false)
    } else if let Ok(value) = value.parse::<i64>() {
        ConstValue::Integer(value)
    } else if value.parse::<f64>().is_ok() {
        ConstValue::Float(value.to_owned())
    } else {
        ConstValue::String(quoted_string(value))
    }
}

fn quoted_string(value: &str) -> String {
    let value = value.trim_matches('"').replace('"', "\\\"");
    format!("\"{value}\"")
}

fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' if !escaped => in_string = !in_string,
            '#' if !in_string => return &line[..index],
            '\\' if in_string => escaped = !escaped,
            _ => escaped = false,
        }
    }
    line
}

fn split_sections(source: &str) -> Vec<String> {
    let mut sections = vec![String::new()];
    for line in source.lines() {
        if strip_comment(line).trim() == "---" {
            sections.push(String::new());
            continue;
        }
        if !sections.last().is_some_and(|section| section.is_empty()) {
            sections.last_mut().expect("section exists").push('\n');
        }
        sections.last_mut().expect("section exists").push_str(line);
    }
    sections
}

fn normalize_identifier(name: &str) -> String {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return "Id".to_owned();
    };
    let mut normalized = String::new();
    normalized.push(if first.is_ascii_alphabetic() || first == '_' {
        first
    } else {
        '_'
    });
    normalized.extend(chars.map(|ch| {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            ch
        } else {
            '_'
        }
    }));
    normalized
}

fn parse_u64(value: &str) -> Result<u64, IdlParseError> {
    value
        .parse::<u64>()
        .map_err(|_| error(format!("expected ROS array bound, found '{value}'")))
}

fn line_error(line: usize, message: impl Into<String>) -> IdlParseError {
    IdlParseError::new(
        message,
        Span {
            line: line + 1,
            ..Span::start()
        },
    )
}

fn error(message: impl Into<String>) -> IdlParseError {
    IdlParseError::new(message, Span::start())
}
