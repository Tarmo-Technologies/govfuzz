// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::StubGenError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Diagnostic {
    pub file: PathBuf,
    pub line: u32,
    pub col: u32,
    pub severity: Severity,
    pub message: String,
    pub continuation: Vec<String>,
    pub kind: DiagnosticKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Note,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    MissingFile {
        path: String,
    },
    MissingUnit {
        name: String,
    },
    UndefinedIdentifier {
        name: String,
    },
    NotVisible {
        name: String,
    },
    /// "<member>" not declared in "<unit>" -- qualified missing member diagnostic.
    NotDeclaredIn {
        member: String,
        unit: String,
    },
    TypeMismatch {
        context: String,
    },
    Unknown,
}

pub fn parse_text(stderr: &str) -> Vec<Diagnostic> {
    let main_re = match regex::Regex::new(
        r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s*(?:(?P<sev>error|warning|note|info):\s*)?(?P<msg>.*)$",
    ) {
        Ok(regex) => regex,
        Err(_) => return Vec::new(),
    };
    let cont_re = match regex::Regex::new(r"^\s{4,}(?P<msg>.*)$") {
        Ok(regex) => regex,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for line in stderr.lines() {
        if let Some(captures) = main_re.captures(line) {
            let msg = captures
                .name("msg")
                .map(|matched| matched.as_str())
                .unwrap_or_default();
            out.push(Diagnostic {
                file: PathBuf::from(
                    captures
                        .name("file")
                        .map(|matched| matched.as_str())
                        .unwrap_or_default(),
                ),
                line: captures
                    .name("line")
                    .and_then(|matched| matched.as_str().parse::<u32>().ok())
                    .unwrap_or(0),
                col: captures
                    .name("col")
                    .and_then(|matched| matched.as_str().parse::<u32>().ok())
                    .unwrap_or(0),
                severity: captures
                    .name("sev")
                    .map(|matched| parse_severity(matched.as_str()))
                    .unwrap_or(Severity::Error),
                message: msg.to_owned(),
                continuation: Vec::new(),
                kind: classify_message(msg),
            });
        } else if let Some(captures) = cont_re.captures(line) {
            if let Some(last) = out.last_mut() {
                last.continuation.push(
                    captures
                        .name("msg")
                        .map(|matched| matched.as_str().to_owned())
                        .unwrap_or_default(),
                );
            }
        }
    }
    out
}

pub fn parse_json(stderr: &str) -> Result<Vec<Diagnostic>, StubGenError> {
    let mut out = Vec::new();
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        let raw: JsonDiagnostic = serde_json::from_str(trimmed)?;
        out.push(Diagnostic {
            file: PathBuf::from(raw.file),
            line: raw.line,
            col: raw.column,
            severity: raw
                .severity
                .as_deref()
                .map(parse_severity)
                .unwrap_or(Severity::Error),
            kind: classify_message(&raw.message),
            message: raw.message,
            continuation: Vec::new(),
        });
    }
    Ok(out)
}

#[derive(Debug, serde::Deserialize)]
struct JsonDiagnostic {
    file: String,
    line: u32,
    #[serde(alias = "col")]
    column: u32,
    severity: Option<String>,
    message: String,
}

fn parse_severity(value: &str) -> Severity {
    match value {
        "warning" => Severity::Warning,
        "note" => Severity::Note,
        "info" => Severity::Info,
        _ => Severity::Error,
    }
}

fn classify_message(message: &str) -> DiagnosticKind {
    if let Some(path) = first_capture(r#"file "([^"]+)" not found"#, message) {
        return DiagnosticKind::MissingFile { path };
    }
    if let Some(name) = first_capture(r#"unit "([^"]+)" needed"#, message) {
        return DiagnosticKind::MissingUnit { name };
    }
    if let Some((member, unit)) = not_declared_in_captures(message) {
        return DiagnosticKind::NotDeclaredIn { member, unit };
    }
    if let Some(name) = first_capture(r#"^"([^"]+)" is undefined"#, message) {
        return DiagnosticKind::UndefinedIdentifier { name };
    }
    if let Some(name) = first_capture(r#"^"([^"]+)" is not visible"#, message) {
        return DiagnosticKind::NotVisible { name };
    }
    if message.contains("invalid expected type") {
        return DiagnosticKind::TypeMismatch {
            context: message.to_owned(),
        };
    }
    DiagnosticKind::Unknown
}

fn not_declared_in_captures(message: &str) -> Option<(String, String)> {
    let regex = regex::Regex::new(
        r#""(?P<member_d>[^"]+)"\s+not\s+declared\s+in\s+(?:package\s+)?"(?P<unit_d>[^"]+)"|'(?P<member_s>[^']+)'\s+not\s+declared\s+in\s+(?:package\s+)?'(?P<unit_s>[^']+)'"#,
    )
    .ok()?;
    let captures = regex.captures(message)?;
    let member = captures
        .name("member_d")
        .or_else(|| captures.name("member_s"))?
        .as_str()
        .to_owned();
    let unit = captures
        .name("unit_d")
        .or_else(|| captures.name("unit_s"))?
        .as_str()
        .to_owned();
    Some((member, unit))
}

fn first_capture(pattern: &str, message: &str) -> Option<String> {
    let regex = regex::Regex::new(pattern).ok()?;
    regex
        .captures(message)
        .and_then(|captures| captures.get(1))
        .map(|matched| matched.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{parse_json, parse_text, DiagnosticKind, Severity};

    const GNAT_11_TEXT: &str = include_str!("../tests/fixtures/gnat_11_text.stderr");
    const GNAT_14_TEXT: &str = include_str!("../tests/fixtures/gnat_14_text.stderr");
    const GNAT_14_JSON: &str = include_str!("../tests/fixtures/gnat_14_json.stderr");

    #[test]
    fn parse_text_extracts_file_line_col_message() {
        let diagnostics = parse_text("foo.adb:12:34: file \"external_lib.ads\" not found\n");

        assert_eq!(diagnostics[0].file, PathBuf::from("foo.adb"));
        assert_eq!(diagnostics[0].line, 12);
        assert_eq!(diagnostics[0].col, 34);
        assert_eq!(
            diagnostics[0].message,
            "file \"external_lib.ads\" not found"
        );
    }

    #[test]
    fn parse_text_handles_missing_severity_defaults_to_error() {
        let diagnostics = parse_text("foo.adb:12:34: file \"external_lib.ads\" not found\n");

        assert_eq!(diagnostics[0].severity, Severity::Error);
    }

    #[test]
    fn parse_text_handles_warning_severity() {
        let diagnostics =
            parse_text("foo.adb:12:34: warning: unit \"External_Lib\" needed for elaboration\n");

        assert_eq!(diagnostics[0].severity, Severity::Warning);
    }

    #[test]
    fn parse_text_attaches_continuation_lines_to_previous_diagnostic() {
        let diagnostics = parse_text("foo.adb:22:9: continuation starts\n    more detail\n");

        assert_eq!(diagnostics[0].continuation, vec!["more detail"]);
    }

    #[test]
    fn parse_text_classifies_missing_file_diagnostic() {
        let diagnostics = parse_text(GNAT_11_TEXT);

        assert_eq!(
            diagnostics[0].kind,
            DiagnosticKind::MissingFile {
                path: "external_lib.ads".to_owned()
            }
        );
    }

    #[test]
    fn parse_text_classifies_missing_unit_diagnostic() {
        let diagnostics = parse_text(GNAT_11_TEXT);

        assert_eq!(
            diagnostics[1].kind,
            DiagnosticKind::MissingUnit {
                name: "External_Lib".to_owned()
            }
        );
    }

    #[test]
    fn parse_text_classifies_undefined_identifier() {
        let diagnostics = parse_text(GNAT_11_TEXT);

        assert_eq!(
            diagnostics[2].kind,
            DiagnosticKind::UndefinedIdentifier {
                name: "Bar".to_owned()
            }
        );
    }

    #[test]
    fn parse_text_classifies_qualified_not_declared_in() {
        let stderr = r#"foo.adb:5:7: "Process" not declared in "External_Lib""#;
        let diagnostics = parse_text(stderr);

        assert_eq!(diagnostics.len(), 1);
        assert!(matches!(
            &diagnostics[0].kind,
            DiagnosticKind::NotDeclaredIn { member, unit }
                if member == "Process" && unit == "External_Lib"
        ));
    }

    #[test]
    fn parse_text_classifies_not_declared_in_package_qualifier() {
        let stderr = r#"foo.adb:5:7: "Process" not declared in package "External_Lib""#;
        let diagnostics = parse_text(stderr);

        assert!(matches!(
            &diagnostics[0].kind,
            DiagnosticKind::NotDeclaredIn { member, unit }
                if member == "Process" && unit == "External_Lib"
        ));
    }

    #[test]
    fn parse_text_classifies_not_visible() {
        let diagnostics = parse_text(GNAT_11_TEXT);

        assert_eq!(
            diagnostics[4].kind,
            DiagnosticKind::NotVisible {
                name: "Foo".to_owned()
            }
        );
    }

    #[test]
    fn parse_text_classifies_type_mismatch() {
        let diagnostics = parse_text(GNAT_11_TEXT);

        assert_eq!(
            diagnostics[3].kind,
            DiagnosticKind::TypeMismatch {
                context: "invalid expected type for \"Y\"".to_owned()
            }
        );
    }

    #[test]
    fn parse_text_classifies_unknown_for_unmatched_message() {
        let diagnostics = parse_text("foo.adb:1:2: impossible constraint warning\n");

        assert_eq!(diagnostics[0].kind, DiagnosticKind::Unknown);
    }

    #[test]
    fn parse_text_handles_multiple_diagnostics_in_sequence() {
        let diagnostics = parse_text(GNAT_14_TEXT);

        assert_eq!(diagnostics.len(), 3);
        assert_eq!(diagnostics[0].line, 7);
        assert_eq!(diagnostics[1].line, 9);
        assert_eq!(diagnostics[2].line, 11);
    }

    #[test]
    fn parse_text_handles_empty_stderr() {
        assert!(parse_text("").is_empty());
    }

    #[test]
    fn parse_json_decodes_single_diagnostic_line() {
        let diagnostics = parse_json(
            r#"{"file":"foo.adb","line":12,"column":34,"severity":"error","message":"file \"external_lib.ads\" not found"}"#,
        )
        .unwrap();

        assert_eq!(diagnostics[0].file, PathBuf::from("foo.adb"));
        assert_eq!(diagnostics[0].line, 12);
        assert_eq!(diagnostics[0].col, 34);
        assert_eq!(diagnostics[0].severity, Severity::Error);
    }

    #[test]
    fn parse_json_handles_multiple_lines() {
        let diagnostics = parse_json(GNAT_14_JSON).unwrap();

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].line, 12);
        assert_eq!(diagnostics[1].line, 15);
    }

    #[test]
    fn parse_json_skips_non_json_lines() {
        let diagnostics = parse_json("GNAT 14 banner\nnot-json\n").unwrap();

        assert!(diagnostics.is_empty());
    }

    #[test]
    fn parse_json_returns_empty_for_empty_input() {
        assert!(parse_json("").unwrap().is_empty());
    }

    #[test]
    fn parse_json_classifies_qualified_not_declared_in() {
        let diagnostics = parse_json(
            r#"{"file":"foo.adb","line":5,"column":7,"severity":"error","message":"\"Process\" not declared in \"External_Lib\""}"#,
        )
        .unwrap();

        assert_eq!(diagnostics.len(), 1);
        assert!(matches!(
            &diagnostics[0].kind,
            DiagnosticKind::NotDeclaredIn { .. }
        ));
    }

    #[test]
    fn parse_json_classifies_message_kind_via_shared_classifier() {
        let diagnostics = parse_json(GNAT_14_JSON).unwrap();

        assert_eq!(
            diagnostics[0].kind,
            DiagnosticKind::MissingFile {
                path: "external_lib.ads".to_owned()
            }
        );
        assert_eq!(
            diagnostics[1].kind,
            DiagnosticKind::UndefinedIdentifier {
                name: "Process".to_owned()
            }
        );
    }
}
