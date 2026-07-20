// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;

use crate::{Diagnostic, DiagnosticKind};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct StubNeed {
    pub unit_name: String,
    pub kind: StubNeedKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StubNeedKind {
    PackageSpec { decls: Vec<String> },
    PackageBody { ops: Vec<StubOp> },
    Identifier { unit: String, symbol: String },
    Visibility { unit: String, symbol: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct StubOp {
    pub name: String,
    pub kind: StubOpKind,
    pub return_type: Option<String>,
    #[serde(default)]
    pub params: Vec<StubParam>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct StubParam {
    pub name: String,
    pub mode: Option<String>,
    pub type_name: String,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StubOpKind {
    Procedure,
    Function,
}

pub fn derive_stub_needs(diags: &[Diagnostic]) -> Vec<StubNeed> {
    let mut package_decls: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut package_bodies: BTreeMap<String, Vec<StubOp>> = BTreeMap::new();
    let mut source_units: BTreeMap<std::path::PathBuf, Vec<String>> = BTreeMap::new();

    for diag in diags {
        let unit_name = match &diag.kind {
            DiagnosticKind::MissingFile { path } => {
                if let Some((unit_name, extension)) = unit_name_and_extension_from_file(path) {
                    if extension.eq_ignore_ascii_case("adb") {
                        package_bodies.entry(unit_name.clone()).or_default();
                    } else {
                        package_decls.entry(unit_name.clone()).or_default();
                    }
                    Some(unit_name)
                } else {
                    None
                }
            }
            DiagnosticKind::MissingUnit { name } => {
                package_decls.entry(name.clone()).or_default();
                Some(name.clone())
            }
            _ => None,
        };

        if let Some(unit_name) = unit_name {
            let units = source_units.entry(diag.file.clone()).or_default();
            if !units.contains(&unit_name) {
                units.push(unit_name);
            }
        }
    }

    let mut additional_needs = Vec::new();
    for diag in diags {
        match &diag.kind {
            DiagnosticKind::UndefinedIdentifier { name } => {
                if let Some(unit_name) = unique_source_unit(&source_units, &diag.file) {
                    add_decl(package_decls.entry(unit_name).or_default(), name);
                } else {
                    let unit = fallback_unit_from_source(&diag.file);
                    push_unique(
                        &mut additional_needs,
                        StubNeed {
                            unit_name: unit.clone(),
                            kind: StubNeedKind::Identifier {
                                unit,
                                symbol: name.clone(),
                            },
                        },
                    );
                }
            }
            DiagnosticKind::NotDeclaredIn { member, unit } => {
                add_decl(package_decls.entry(unit.clone()).or_default(), member);
                add_procedure_op(package_bodies.entry(unit.clone()).or_default(), member);
            }
            DiagnosticKind::NotVisible { name } => {
                let unit = fallback_unit_from_source(&diag.file);
                push_unique(
                    &mut additional_needs,
                    StubNeed {
                        unit_name: unit.clone(),
                        kind: StubNeedKind::Visibility {
                            unit,
                            symbol: name.clone(),
                        },
                    },
                );
            }
            DiagnosticKind::MissingFile { .. }
            | DiagnosticKind::MissingUnit { .. }
            | DiagnosticKind::TypeMismatch { .. }
            | DiagnosticKind::Unknown => {}
        }
    }

    let mut needs = package_decls
        .into_iter()
        .map(|(unit_name, decls)| StubNeed {
            unit_name,
            kind: StubNeedKind::PackageSpec { decls },
        })
        .collect::<Vec<_>>();
    needs.extend(package_bodies.into_iter().map(|(unit_name, ops)| StubNeed {
        unit_name,
        kind: StubNeedKind::PackageBody { ops },
    }));
    needs.extend(additional_needs);
    needs
}

fn unit_name_and_extension_from_file(path: &str) -> Option<(String, String)> {
    let path = Path::new(path);
    let file_stem = path.file_stem()?.to_string_lossy();
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().into_owned())
        .unwrap_or_default();
    Some((capitalize_ada_name(&file_stem.replace('-', ".")), extension))
}

fn fallback_unit_from_source(path: &Path) -> String {
    path.file_stem()
        .map(|stem| capitalize_ada_name(&stem.to_string_lossy()))
        .unwrap_or_else(|| "Govfuzz_Stub".to_owned())
}

fn capitalize_ada_name(name: &str) -> String {
    name.split('.')
        .map(|segment| {
            segment
                .split('_')
                .map(capitalize_segment)
                .collect::<Vec<_>>()
                .join("_")
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn capitalize_segment(segment: &str) -> String {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out = first.to_ascii_uppercase().to_string();
    out.push_str(&chars.as_str().to_ascii_lowercase());
    out
}

fn unique_source_unit(
    source_units: &BTreeMap<std::path::PathBuf, Vec<String>>,
    file: &Path,
) -> Option<String> {
    let units = source_units.get(file)?;
    if units.len() == 1 {
        units.first().cloned()
    } else {
        None
    }
}

fn add_decl(decls: &mut Vec<String>, symbol: &str) {
    let symbol = symbol.to_owned();
    if !decls.contains(&symbol) {
        decls.push(symbol);
    }
}

fn add_procedure_op(ops: &mut Vec<StubOp>, name: &str) {
    let op = StubOp {
        name: name.to_owned(),
        kind: StubOpKind::Procedure,
        return_type: None,
        params: Vec::new(),
    };
    if !ops.contains(&op) {
        ops.push(op);
    }
}

fn push_unique(needs: &mut Vec<StubNeed>, need: StubNeed) {
    if !needs.contains(&need) {
        needs.push(need);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{derive_stub_needs, Diagnostic, DiagnosticKind, Severity, StubNeed, StubNeedKind};

    #[test]
    fn derive_needs_for_missing_file_yields_package_spec() {
        let needs = derive_stub_needs(&[diag(DiagnosticKind::MissingFile {
            path: "external_lib.ads".to_owned(),
        })]);

        assert_eq!(
            needs,
            vec![StubNeed {
                unit_name: "External_Lib".to_owned(),
                kind: StubNeedKind::PackageSpec { decls: Vec::new() },
            }]
        );
    }

    #[test]
    fn derive_needs_for_missing_body_file_yields_package_body() {
        let needs = derive_stub_needs(&[diag(DiagnosticKind::MissingFile {
            path: "external_lib.adb".to_owned(),
        })]);

        assert_eq!(
            needs,
            vec![StubNeed {
                unit_name: "External_Lib".to_owned(),
                kind: StubNeedKind::PackageBody { ops: Vec::new() },
            }]
        );
    }

    #[test]
    fn derive_needs_capitalizes_unit_name_from_filename() {
        let needs = derive_stub_needs(&[diag(DiagnosticKind::MissingFile {
            path: "legacy_io_bridge.ads".to_owned(),
        })]);

        assert_eq!(needs[0].unit_name, "Legacy_Io_Bridge");
    }

    #[test]
    fn derive_needs_strips_ads_suffix() {
        let needs = derive_stub_needs(&[diag(DiagnosticKind::MissingFile {
            path: "external_lib.ads".to_owned(),
        })]);

        assert_eq!(needs[0].unit_name, "External_Lib");
    }

    #[test]
    fn derive_needs_dedupes_multiple_missing_file_diagnostics_for_same_unit() {
        let needs = derive_stub_needs(&[
            diag(DiagnosticKind::MissingFile {
                path: "external_lib.ads".to_owned(),
            }),
            diag(DiagnosticKind::MissingUnit {
                name: "External_Lib".to_owned(),
            }),
        ]);

        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0].unit_name, "External_Lib");
    }

    #[test]
    fn derive_needs_attaches_undefined_identifier_to_enclosing_stubbed_unit() {
        let needs = derive_stub_needs(&[
            diag(DiagnosticKind::MissingFile {
                path: "external_lib.ads".to_owned(),
            }),
            diag(DiagnosticKind::UndefinedIdentifier {
                name: "Process".to_owned(),
            }),
        ]);

        assert_eq!(
            needs,
            vec![StubNeed {
                unit_name: "External_Lib".to_owned(),
                kind: StubNeedKind::PackageSpec {
                    decls: vec!["Process".to_owned()]
                },
            }]
        );
    }

    #[test]
    fn not_declared_in_appends_member_to_existing_package_spec_decls() {
        let diags = vec![
            diag(DiagnosticKind::MissingFile {
                path: "external_lib.ads".to_owned(),
            }),
            diag(DiagnosticKind::NotDeclaredIn {
                member: "Process".to_owned(),
                unit: "External_Lib".to_owned(),
            }),
        ];

        let needs = derive_stub_needs(&diags);
        let spec = needs
            .iter()
            .find(|need| {
                need.unit_name == "External_Lib"
                    && matches!(need.kind, StubNeedKind::PackageSpec { .. })
            })
            .unwrap();

        if let StubNeedKind::PackageSpec { decls } = &spec.kind {
            assert!(decls.contains(&"Process".to_owned()));
        } else {
            panic!("not a PackageSpec");
        }
    }

    #[test]
    fn not_declared_in_creates_package_spec_when_no_existing_need() {
        let diags = vec![diag(DiagnosticKind::NotDeclaredIn {
            member: "Process".to_owned(),
            unit: "External_Lib".to_owned(),
        })];

        let needs = derive_stub_needs(&diags);
        let spec = needs
            .iter()
            .find(|need| {
                need.unit_name == "External_Lib"
                    && matches!(need.kind, StubNeedKind::PackageSpec { .. })
            })
            .expect("missing PackageSpec");

        if let StubNeedKind::PackageSpec { decls } = &spec.kind {
            assert_eq!(decls, &vec!["Process".to_owned()]);
        }
    }

    #[test]
    fn not_declared_in_also_emits_package_body_op() {
        let diags = vec![diag(DiagnosticKind::NotDeclaredIn {
            member: "Process".to_owned(),
            unit: "External_Lib".to_owned(),
        })];

        let needs = derive_stub_needs(&diags);
        let body = needs.iter().find(|need| {
            need.unit_name == "External_Lib"
                && matches!(need.kind, StubNeedKind::PackageBody { .. })
        });

        assert!(
            body.is_some(),
            "expected PackageBody need for External_Lib so the body declares Process; got needs: {needs:?}"
        );
    }

    #[test]
    fn derive_needs_emits_visibility_for_not_visible_diagnostic() {
        let needs = derive_stub_needs(&[diag(DiagnosticKind::NotVisible {
            name: "Hidden".to_owned(),
        })]);

        assert_eq!(
            needs,
            vec![StubNeed {
                unit_name: "Foo".to_owned(),
                kind: StubNeedKind::Visibility {
                    unit: "Foo".to_owned(),
                    symbol: "Hidden".to_owned(),
                },
            }]
        );
    }

    #[test]
    fn derive_needs_skips_unknown_diagnostic_kinds() {
        let needs = derive_stub_needs(&[
            diag(DiagnosticKind::Unknown),
            diag(DiagnosticKind::TypeMismatch {
                context: "invalid expected type for \"Y\"".to_owned(),
            }),
        ]);

        assert!(needs.is_empty());
    }

    #[test]
    fn derive_needs_returns_empty_for_no_diagnostics() {
        assert!(derive_stub_needs(&[]).is_empty());
    }

    fn diag(kind: DiagnosticKind) -> Diagnostic {
        Diagnostic {
            file: PathBuf::from("foo.adb"),
            line: 1,
            col: 1,
            severity: Severity::Error,
            message: String::new(),
            continuation: Vec::new(),
            kind,
        }
    }
}
