// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

macro_rules! id_newtype {
    ($name:ident) => {
        #[repr(transparent)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub u32);
    };
}

id_newtype!(UnitId);
id_newtype!(PackageId);
id_newtype!(SubprogramId);
id_newtype!(HandlerId);
id_newtype!(RaiseSiteId);
id_newtype!(TypeId);
id_newtype!(DepId);
id_newtype!(BuildArtifactId);
id_newtype!(CorbaArtifactId);
id_newtype!(StatementId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaStandard {
    /// M22: original Ada 83 (MIL-STD-1815A). Declared FIRST so it is the smallest
    /// `Ord` value — the lexer's `dialect >= AdaStandardNN` keyword guards then
    /// treat every post-83 reserved word (interface/overriding/synchronized/
    /// some/parallel/protected...) as an identifier, which is the correct
    /// "reduced keyword set" for Ada 83 source.
    Ada83,
    Ada95,
    Ada2005,
    Ada2012,
    Ada2022,
}

impl fmt::Display for AdaStandard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ada83 => "ada_83",
            Self::Ada95 => "ada_95",
            Self::Ada2005 => "ada_2005",
            Self::Ada2012 => "ada_2012",
            Self::Ada2022 => "ada_2022",
        })
    }
}

impl FromStr for AdaStandard {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase().replace(['_', '-'], "");

        match normalized.as_str() {
            "83" | "ada83" => Ok(Self::Ada83),
            "95" | "ada95" => Ok(Self::Ada95),
            "05" | "2005" | "ada05" | "ada2005" => Ok(Self::Ada2005),
            "12" | "2012" | "ada12" | "ada2012" => Ok(Self::Ada2012),
            "22" | "2022" | "ada22" | "ada2022" => Ok(Self::Ada2022),
            _ => Err(format!("unsupported Ada standard '{value}'")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start_byte: u32,
    pub end_byte: u32,
    pub start_line: u32,
    pub start_col: u32,
}

impl Span {
    pub fn new(start_byte: u32, end_byte: u32, line: u32, col: u32) -> Self {
        Self {
            start_byte,
            end_byte,
            start_line: line,
            start_col: col,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitKind {
    Spec,
    Body,
    Subunit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Private,
    LibraryLevel,
    Local,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubprogramKind {
    Procedure,
    Function,
    Entry,
    Operation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamMode {
    In,
    Out,
    InOut,
    AccessMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RaiseKind {
    Explicit,
    Reraise,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerOwner {
    Subprogram(SubprogramId),
    PackageBody(PackageId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementOwner {
    Subprogram(SubprogramId),
    PackageBody(PackageId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubprogramOwner {
    LibraryLevel,
    Package(PackageId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeOwner {
    LibraryLevel,
    Package(PackageId),
    Subprogram(SubprogramId),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepKind {
    Real,
    Stubbed,
    Fake,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorbaKind {
    Idl,
    GeneratedAda,
    ServantImpl,
    Helper,
    Skel,
    Stub,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UseKind {
    Use,
    UseType,
    UseAllType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UseClause {
    pub kind: UseKind,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pragma {
    pub name: String,
    pub args: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Unit {
    pub id: UnitId,
    pub path: PathBuf,
    pub kind: UnitKind,
    pub ada_standard: AdaStandard,
    pub withs: Vec<UnitRef>,
    pub uses: Vec<UseClause>,
    pub packages: Vec<PackageId>,
    pub pragmas: Vec<Pragma>,
}

impl Default for Unit {
    fn default() -> Self {
        Self {
            id: UnitId(0),
            path: PathBuf::new(),
            kind: UnitKind::Spec,
            ada_standard: AdaStandard::Ada2012,
            withs: Vec::new(),
            uses: Vec::new(),
            packages: Vec::new(),
            pragmas: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRef {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub id: PackageId,
    pub name: String,
    pub parent: Option<PackageId>,
    pub is_generic: bool,
    pub formals: Vec<String>,
    pub decls: Vec<String>,
    /// True when this is a nested package declared in its parent's `private`
    /// part (zip-ada `BZip2.CRC`). Its entities are not externally callable, so
    /// a direct-call harness cannot reach them — discovery skips such targets.
    #[serde(default)]
    pub is_private: bool,
}

/// A named constant object declaration (`Name : constant Type [:= ...];`).
///
/// The harness generator treats a public constant of a user-named type as a
/// parameterless "constructor": for a private type with no synthesisable
/// constructor function, such a constant (zip-ada `default_time : constant
/// Time;`, or the `Null_Unbounded_String`/`No_Element`/`Empty_Map` idiom) is the
/// only externally usable way to obtain a value of the type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstantDecl {
    /// The declared constant's simple name (`default_time`).
    pub name: String,
    /// The type mark as written (dotted path preserved, e.g. `Time` or
    /// `Zip_Streams.Time`). Empty when no named type mark was present
    /// (named-number constants like `Pi : constant := 3.14159;`).
    pub type_name: String,
    /// The owning package/subprogram, used to qualify the constant in emitted
    /// code (`Zip_Streams.default_time`).
    pub owner: TypeOwner,
    /// `Public` when declared in a package spec's visible part; `Private` when in
    /// the private part. Only public constants can back a harness neutral.
    pub visibility: Visibility,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subprogram {
    pub id: SubprogramId,
    pub owner: SubprogramOwner,
    pub name: String,
    pub kind: SubprogramKind,
    pub params: Vec<Parameter>,
    pub return_type: Option<TypeRef>,
    pub is_abstract: bool,
    pub is_dispatching: bool,
    pub is_overriding: bool,
    pub body_span: Option<Span>,
    pub decl_span: Span,
    pub handlers: Vec<HandlerId>,
    pub raises: Vec<RaiseSiteId>,
    pub visibility: Visibility,
    /// True when this is a generic subprogram (declared after a `generic`
    /// formal part). A generic subprogram cannot be called until instantiated,
    /// so it is not a viable direct-call target.
    pub is_generic: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub mode: ParamMode,
    pub type_ref: TypeRef,
    pub default: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypeRef {
    pub id: TypeId,
    pub name_path: Vec<String>,
    pub visibility: Visibility,
    pub owner: TypeOwner,
    pub kind: TypeKind,
    pub constraints: Constraints,
    pub aspects: Aspects,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Scalar(ScalarKind),
    Enum(Vec<String>),
    Array {
        idx_types: Vec<TypeId>,
        elem_type: TypeId,
        bounds: String,
        /// Source name of the component type (e.g. `Byte`, `Integer`), captured
        /// so harness generation can decode array elements with the right type
        /// instead of guessing. Empty when the parser could not recover it.
        #[serde(default)]
        elem_name: String,
    },
    Record(Fields),
    Discriminated {
        base: TypeId,
        discriminants: Fields,
    },
    Tagged {
        base: TypeId,
        is_abstract: bool,
    },
    Derived {
        base: TypeId,
    },
    Interface {
        parents: Vec<String>,
        kind: InterfaceKind,
    },
    Access {
        target: TypeId,
    },
    Private,
    Generic(FormalKind),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarKind {
    Integer,
    Modular,
    Float,
    Fixed,
    Decimal,
    Character,
    Boolean,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Plain,
    Limited,
    Synchronized,
    Task,
    Protected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormalKind {
    Type,
    Subprogram,
    Object,
    Package,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Constraints(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Aspects(pub Vec<String>);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fields(pub Vec<String>);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Expr(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExceptionHandler {
    pub id: HandlerId,
    pub owner: HandlerOwner,
    pub choices: Vec<Choice>,
    pub binds: Option<String>,
    pub span: Span,
    pub body_span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Choice(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RaiseSite {
    pub id: RaiseSiteId,
    pub kind: RaiseKind,
    pub exception: Option<String>,
    pub message: Option<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatementSpan {
    pub id: StatementId,
    pub owner: StatementOwner,
    pub file_byte_offset: u32,
    pub end_byte_offset: u32,
    pub line: u32,
    pub col: u32,
    pub depth: u8,
    pub index_in_block: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dependency {
    pub id: DepId,
    pub kind: DepKind,
    pub real_path: Option<PathBuf>,
    pub generated_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuildArtifact {
    pub id: BuildArtifactId,
    pub source_unit: UnitId,
    pub instrumented_path: PathBuf,
    pub object_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorbaArtifact {
    pub id: CorbaArtifactId,
    pub idl_path: Option<PathBuf>,
    pub package_name: String,
    pub op_list: Vec<String>,
    pub kind: CorbaKind,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StructuralAst {
    pub units: Vec<Unit>,
    pub packages: Vec<Package>,
    pub subprograms: Vec<Subprogram>,
    pub types: Vec<TypeRef>,
    #[serde(default)]
    pub constants: Vec<ConstantDecl>,
    pub handlers: Vec<ExceptionHandler>,
    pub raises: Vec<RaiseSite>,
    pub statements: Vec<StatementSpan>,
    pub deps: Vec<Dependency>,
    pub build_artifacts: Vec<BuildArtifact>,
    pub corba_artifacts: Vec<CorbaArtifact>,
}

impl StructuralAst {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subprogram(&self, id: SubprogramId) -> Option<&Subprogram> {
        self.subprograms
            .iter()
            .find(|subprogram| subprogram.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::str::FromStr;

    #[test]
    fn ada_standard_from_str_accepts_all_supported_variants_including_ada83() {
        // M22: Ada 83 is now a supported (best-effort, report-only) dialect.
        assert_eq!(AdaStandard::from_str("83"), Ok(AdaStandard::Ada83));
        assert_eq!(AdaStandard::from_str("Ada83"), Ok(AdaStandard::Ada83));
        assert_eq!(AdaStandard::from_str("ada_83"), Ok(AdaStandard::Ada83));
        assert_eq!(AdaStandard::from_str("95"), Ok(AdaStandard::Ada95));
        assert_eq!(AdaStandard::from_str("ada_95"), Ok(AdaStandard::Ada95));
        assert_eq!(AdaStandard::from_str("Ada95"), Ok(AdaStandard::Ada95));
        assert_eq!(AdaStandard::from_str("2005"), Ok(AdaStandard::Ada2005));
        assert_eq!(AdaStandard::from_str("ada_2005"), Ok(AdaStandard::Ada2005));
        assert_eq!(AdaStandard::from_str("Ada05"), Ok(AdaStandard::Ada2005));
        assert_eq!(AdaStandard::from_str("2012"), Ok(AdaStandard::Ada2012));
        assert_eq!(AdaStandard::from_str("ada_12"), Ok(AdaStandard::Ada2012));
        assert_eq!(AdaStandard::from_str("2022"), Ok(AdaStandard::Ada2022));
        assert_eq!(AdaStandard::from_str("ada_2022"), Ok(AdaStandard::Ada2022));
        assert!(AdaStandard::from_str("not-a-standard").is_err());
    }

    #[test]
    fn ada_standard_display_uses_stable_snake_case_names() {
        assert_eq!(AdaStandard::Ada95.to_string(), "ada_95");
        assert_eq!(AdaStandard::Ada2005.to_string(), "ada_2005");
        assert_eq!(AdaStandard::Ada2012.to_string(), "ada_2012");
        assert_eq!(AdaStandard::Ada2022.to_string(), "ada_2022");
    }

    #[test]
    fn ada_standard_orders_by_chronology() {
        // Ada83 must be the smallest so the lexer's `dialect >= AdaNN` keyword
        // guards leave post-83 reserved words as identifiers in Ada 83 source.
        assert!(AdaStandard::Ada83 < AdaStandard::Ada95);
        assert!(AdaStandard::Ada95 < AdaStandard::Ada2005);
        assert!(AdaStandard::Ada2005 < AdaStandard::Ada2012);
        assert!(AdaStandard::Ada2012 < AdaStandard::Ada2022);
    }

    #[test]
    fn span_new_records_byte_range_and_start_position() {
        assert_eq!(
            Span::new(3, 9, 2, 4),
            Span {
                start_byte: 3,
                end_byte: 9,
                start_line: 2,
                start_col: 4
            }
        );
    }

    #[test]
    fn id_newtypes_are_copy_hashable_and_serde_as_bare_u32() {
        fn assert_copy_eq_hash<T: Copy + Eq + std::hash::Hash>() {}

        assert_copy_eq_hash::<UnitId>();
        assert_copy_eq_hash::<PackageId>();
        assert_copy_eq_hash::<SubprogramId>();
        assert_copy_eq_hash::<HandlerId>();
        assert_copy_eq_hash::<RaiseSiteId>();
        assert_copy_eq_hash::<TypeId>();
        assert_copy_eq_hash::<DepId>();
        assert_copy_eq_hash::<BuildArtifactId>();
        assert_copy_eq_hash::<CorbaArtifactId>();
        assert_copy_eq_hash::<StatementId>();

        let mut ids = HashSet::new();
        ids.insert(UnitId(7));
        assert!(ids.contains(&UnitId(7)));
        assert_eq!(serde_json::to_string(&UnitId(7)).unwrap(), "7");
        assert_eq!(serde_json::from_str::<UnitId>("7").unwrap(), UnitId(7));
    }

    #[test]
    fn structural_ast_default_and_new_are_empty() {
        assert_eq!(StructuralAst::default(), StructuralAst::new());
        assert!(StructuralAst::new().units.is_empty());
        assert!(StructuralAst::new().packages.is_empty());
        assert!(StructuralAst::new().subprograms.is_empty());
        assert!(StructuralAst::new().types.is_empty());
        assert!(StructuralAst::new().handlers.is_empty());
        assert!(StructuralAst::new().raises.is_empty());
        assert!(StructuralAst::new().statements.is_empty());
        assert!(StructuralAst::new().deps.is_empty());
        assert!(StructuralAst::new().build_artifacts.is_empty());
        assert!(StructuralAst::new().corba_artifacts.is_empty());
    }

    #[test]
    fn use_clause_serde_round_trips_plain_use() {
        let clause = UseClause {
            kind: UseKind::Use,
            names: vec!["Ada.Text_IO".to_owned(), "Ada.Calendar".to_owned()],
        };

        let json = serde_json::to_string(&clause).unwrap();
        let decoded: UseClause = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, clause);
        assert!(json.contains("\"use\""));
    }

    #[test]
    fn use_clause_serde_round_trips_use_type() {
        let clause = UseClause {
            kind: UseKind::UseType,
            names: vec!["Interfaces.Unsigned_32".to_owned()],
        };

        let json = serde_json::to_string(&clause).unwrap();
        let decoded: UseClause = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, clause);
        assert!(json.contains("\"use_type\""));
    }

    #[test]
    fn use_clause_serde_round_trips_use_all_type() {
        let clause = UseClause {
            kind: UseKind::UseAllType,
            names: vec!["Root.T'Class".to_owned()],
        };

        let json = serde_json::to_string(&clause).unwrap();
        let decoded: UseClause = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, clause);
        assert!(json.contains("\"use_all_type\""));
    }

    #[test]
    fn handler_owner_serde_round_trips_both_variants() {
        fn assert_eq_hash<T: Eq + std::hash::Hash>() {}
        assert_eq_hash::<HandlerOwner>();

        let owners = [
            HandlerOwner::Subprogram(SubprogramId(7)),
            HandlerOwner::PackageBody(PackageId(3)),
        ];

        for owner in owners {
            let json = serde_json::to_string(&owner).unwrap();
            let decoded: HandlerOwner = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, owner);
        }
    }

    #[test]
    fn statement_owner_serde_round_trip_subprogram() {
        let owner = StatementOwner::Subprogram(SubprogramId(7));

        let json = serde_json::to_string(&owner).unwrap();
        let decoded: StatementOwner = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, owner);
        assert!(json.contains("subprogram"));
    }

    #[test]
    fn statement_owner_serde_round_trip_package_body() {
        let owner = StatementOwner::PackageBody(PackageId(3));

        let json = serde_json::to_string(&owner).unwrap();
        let decoded: StatementOwner = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, owner);
        assert!(json.contains("package_body"));
    }

    #[test]
    fn statement_owner_uniqueness() {
        fn assert_eq_hash<T: Eq + std::hash::Hash>() {}
        assert_eq_hash::<StatementOwner>();

        let mut owners = HashSet::new();
        owners.insert(StatementOwner::Subprogram(SubprogramId(1)));
        owners.insert(StatementOwner::Subprogram(SubprogramId(2)));
        owners.insert(StatementOwner::PackageBody(PackageId(1)));

        assert_eq!(owners.len(), 3);
        assert!(!owners.contains(&StatementOwner::PackageBody(PackageId(2))));
    }

    #[test]
    fn subprogram_owner_serde_round_trips_both_variants() {
        fn assert_eq_hash<T: Eq + std::hash::Hash>() {}
        assert_eq_hash::<SubprogramOwner>();

        let owners = [
            SubprogramOwner::LibraryLevel,
            SubprogramOwner::Package(PackageId(3)),
        ];

        for owner in owners {
            let json = serde_json::to_string(&owner).unwrap();
            let decoded: SubprogramOwner = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, owner);
        }
    }

    #[test]
    fn unit_default_has_no_use_clauses() {
        assert!(Unit::default().uses.is_empty());
    }

    #[test]
    fn pragma_serde_round_trip() {
        let pragma = Pragma {
            name: "Restrictions".to_owned(),
            args: "No_Allocators".to_owned(),
        };

        let json = serde_json::to_string(&pragma).unwrap();
        let decoded: Pragma = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, pragma);
    }

    #[test]
    fn unit_default_has_empty_pragmas() {
        assert!(Unit::default().pragmas.is_empty());
    }

    #[test]
    fn unit_with_pragmas_serde_preserves_them() {
        let unit = Unit {
            pragmas: vec![Pragma {
                name: "Pure".to_owned(),
                args: String::new(),
            }],
            ..Unit::default()
        };

        let json = serde_json::to_string(&unit).unwrap();
        let decoded: Unit = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.pragmas, unit.pragmas);
    }

    #[test]
    fn structural_ast_serde_round_trip_preserves_populated_model() {
        let span = Span::new(10, 20, 3, 5);
        let type_ref = TypeRef {
            id: TypeId(3),
            name_path: vec!["Integer".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(1)),
            kind: TypeKind::Scalar(ScalarKind::Integer),
            constraints: Constraints("range 1 .. 10".to_owned()),
            aspects: Aspects(vec!["Inline".to_owned()]),
        };

        let ast = StructuralAst {
            units: vec![Unit {
                id: UnitId(0),
                path: PathBuf::from("src/foo.ads"),
                kind: UnitKind::Spec,
                ada_standard: AdaStandard::Ada2012,
                withs: vec![UnitRef {
                    name: "Ada.Text_IO".to_owned(),
                }],
                uses: vec![UseClause {
                    kind: UseKind::Use,
                    names: vec!["Ada.Text_IO".to_owned()],
                }],
                packages: vec![PackageId(1)],
                pragmas: vec![Pragma {
                    name: "Pure".to_owned(),
                    args: String::new(),
                }],
            }],
            packages: vec![Package {
                id: PackageId(1),
                name: "Foo".to_owned(),
                parent: None,
                is_generic: true,
                formals: vec!["type T is private".to_owned()],
                decls: vec!["X : Integer".to_owned()],
                is_private: false,
            }],
            subprograms: vec![Subprogram {
                id: SubprogramId(2),
                owner: SubprogramOwner::Package(PackageId(1)),
                name: "Bar".to_owned(),
                kind: SubprogramKind::Procedure,
                params: vec![Parameter {
                    name: "X".to_owned(),
                    mode: ParamMode::InOut,
                    type_ref: type_ref.clone(),
                    default: Some(Expr("1".to_owned())),
                }],
                return_type: None,
                is_abstract: false,
                is_dispatching: true,
                is_overriding: false,
                body_span: Some(span),
                decl_span: span,
                handlers: vec![HandlerId(4)],
                raises: vec![RaiseSiteId(5)],
                visibility: Visibility::Public,
                is_generic: false,
            }],
            types: vec![type_ref],
            constants: Vec::new(),
            handlers: vec![ExceptionHandler {
                id: HandlerId(4),
                owner: HandlerOwner::Subprogram(SubprogramId(2)),
                choices: vec![Choice("Constraint_Error".to_owned())],
                binds: Some("E".to_owned()),
                span,
                body_span: span,
            }],
            raises: vec![RaiseSite {
                id: RaiseSiteId(5),
                kind: RaiseKind::Explicit,
                exception: Some("Constraint_Error".to_owned()),
                message: Some(Expr("\"bad\"".to_owned())),
                span,
            }],
            statements: vec![StatementSpan {
                id: StatementId(6),
                owner: StatementOwner::Subprogram(SubprogramId(2)),
                file_byte_offset: 10,
                end_byte_offset: 20,
                line: 3,
                col: 5,
                depth: 1,
                index_in_block: 0,
            }],
            deps: vec![Dependency {
                id: DepId(7),
                kind: DepKind::Real,
                real_path: Some(PathBuf::from("src/foo.ads")),
                generated_path: None,
            }],
            build_artifacts: vec![BuildArtifact {
                id: BuildArtifactId(8),
                source_unit: UnitId(0),
                instrumented_path: PathBuf::from("gen/foo.adb"),
                object_path: PathBuf::from("obj/foo.o"),
            }],
            corba_artifacts: vec![CorbaArtifact {
                id: CorbaArtifactId(9),
                idl_path: Some(PathBuf::from("idl/foo.idl")),
                package_name: "Foo.Corba".to_owned(),
                op_list: vec!["Run".to_owned()],
                kind: CorbaKind::ServantImpl,
            }],
        };

        let json = serde_json::to_string(&ast).unwrap();
        let decoded: StructuralAst = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, ast);
    }

    #[test]
    fn structural_ast_finds_subprogram_by_id() {
        let wanted = Subprogram {
            id: SubprogramId(44),
            owner: SubprogramOwner::LibraryLevel,
            name: "Run".to_owned(),
            kind: SubprogramKind::Procedure,
            params: Vec::new(),
            return_type: None,
            is_abstract: false,
            is_dispatching: false,
            is_overriding: false,
            body_span: None,
            decl_span: Span::new(0, 3, 1, 1),
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility: Visibility::LibraryLevel,
            is_generic: false,
        };
        let mut ast = StructuralAst::new();
        ast.subprograms.push(wanted);

        assert_eq!(
            ast.subprogram(SubprogramId(44)).map(|item| &item.name),
            Some(&"Run".to_owned())
        );
        assert_eq!(ast.subprogram(SubprogramId(45)), None);
    }
}
