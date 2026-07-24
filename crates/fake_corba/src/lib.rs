// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceText {
    pub path: PathBuf,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionReport {
    pub signals: Vec<DetectionSignal>,
    pub user_exceptions: Vec<UserException>,
    pub uses_any: bool,
    pub uses_typecode_package: bool,
    pub any_operations: BTreeSet<AnyOperation>,
    pub typecode_operations: BTreeSet<TypeCodeOperation>,
}

impl DetectionReport {
    pub fn is_corba_like(&self) -> bool {
        !self.signals.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DetectionSignal {
    pub kind: DetectionKind,
    pub path: PathBuf,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectionKind {
    CorbaNamePattern,
    PortableServerReference,
    GeneratedNamePattern,
    AnyReference,
    QualifiedException,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnyOperation {
    Clear,
    Equal,
    GetType,
    SetType,
}

impl AnyOperation {
    fn from_identifier(identifier: &str) -> Option<Self> {
        match identifier.to_ascii_lowercase().as_str() {
            "clear" => Some(Self::Clear),
            "equal" => Some(Self::Equal),
            "get_type" => Some(Self::GetType),
            "set_type" => Some(Self::SetType),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TypeCodeOperation {
    ContentType,
    Equal,
    Equivalent,
    Id,
    Kind,
    Length,
    MemberCount,
    MemberName,
    MemberType,
    Name,
}

impl TypeCodeOperation {
    fn from_identifier(identifier: &str) -> Option<Self> {
        match identifier.to_ascii_lowercase().as_str() {
            "content_type" => Some(Self::ContentType),
            "equal" => Some(Self::Equal),
            "equivalent" => Some(Self::Equivalent),
            "id" => Some(Self::Id),
            "kind" => Some(Self::Kind),
            "length" => Some(Self::Length),
            "member_count" => Some(Self::MemberCount),
            "member_name" => Some(Self::MemberName),
            "member_type" => Some(Self::MemberType),
            "name" => Some(Self::Name),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UserException {
    pub package: String,
    pub exception: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeCorbaPlan {
    pub include_any: bool,
    pub include_typecode: bool,
    pub any_operations: BTreeSet<AnyOperation>,
    pub typecode_operations: BTreeSet<TypeCodeOperation>,
    pub user_exceptions: Vec<UserException>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFile {
    pub relative_path: PathBuf,
    pub contents: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeCorbaOutput {
    pub report: DetectionReport,
    pub plan: FakeCorbaPlan,
    pub written_files: Vec<PathBuf>,
}

pub fn detect_source_tree(source_dir: &Path) -> io::Result<DetectionReport> {
    let mut paths = Vec::new();
    collect_ada_sources(source_dir, &mut paths)?;
    paths.sort();

    let mut sources = Vec::new();
    for path in paths {
        let text = fs::read_to_string(&path)?;
        sources.push(SourceText { path, text });
    }

    Ok(detect_source_texts(sources))
}

pub fn detect_source_texts<I>(sources: I) -> DetectionReport
where
    I: IntoIterator<Item = SourceText>,
{
    let mut signal_set = BTreeSet::new();
    let mut user_exceptions = BTreeSet::new();
    let mut uses_any = false;
    let mut uses_typecode_package = false;
    let mut any_operations = BTreeSet::new();
    let mut typecode_operations = BTreeSet::new();

    for source in sources {
        let text_lower = source.text.to_ascii_lowercase();
        let path_text = source.path.to_string_lossy().to_string();
        let path_lower = path_text.to_ascii_lowercase();
        let tokens = lex_ident_tokens(&source.text);

        if text_lower.contains("corba") || path_lower.contains("corba") {
            signal_set.insert(DetectionSignal {
                kind: DetectionKind::CorbaNamePattern,
                path: source.path.clone(),
                detail: "CORBA name pattern".to_owned(),
            });
        }

        if text_lower.contains("portableserver") {
            signal_set.insert(DetectionSignal {
                kind: DetectionKind::PortableServerReference,
                path: source.path.clone(),
                detail: "PortableServer reference".to_owned(),
            });
        }

        if contains_generated_name_pattern(&text_lower)
            || contains_generated_name_pattern(&path_lower)
        {
            signal_set.insert(DetectionSignal {
                kind: DetectionKind::GeneratedNamePattern,
                path: source.path.clone(),
                detail: "generated CORBA naming pattern".to_owned(),
            });
        }

        if text_lower.contains("corba.any")
            || text_lower.contains("typecode")
            || text_lower
                .split(|ch: char| !is_ident_char(ch))
                .any(|token| token == "any")
        {
            uses_any = true;
            signal_set.insert(DetectionSignal {
                kind: DetectionKind::AnyReference,
                path: source.path.clone(),
                detail: "Any or TypeCode reference".to_owned(),
            });
        }

        if has_scoped_package_ref(&tokens, &["corba", "typecode"]) {
            uses_typecode_package = true;
        }

        collect_lazy_any_typecode_refs(&tokens, &mut any_operations, &mut typecode_operations);

        for exception in infer_user_exceptions(&source.text) {
            signal_set.insert(DetectionSignal {
                kind: DetectionKind::QualifiedException,
                path: source.path.clone(),
                detail: format!("{}.{}", exception.package, exception.exception),
            });
            user_exceptions.insert(exception);
        }
    }

    DetectionReport {
        signals: signal_set.into_iter().collect(),
        user_exceptions: user_exceptions.into_iter().collect(),
        uses_any,
        uses_typecode_package,
        any_operations,
        typecode_operations,
    }
}

pub fn plan_from_report(report: &DetectionReport) -> FakeCorbaPlan {
    FakeCorbaPlan {
        include_any: report.uses_any
            || !report.any_operations.is_empty()
            || !report.typecode_operations.is_empty(),
        include_typecode: report.uses_typecode_package || !report.typecode_operations.is_empty(),
        any_operations: report.any_operations.clone(),
        typecode_operations: report.typecode_operations.clone(),
        user_exceptions: report.user_exceptions.clone(),
    }
}

pub fn render_plan(plan: &FakeCorbaPlan) -> Vec<GeneratedFile> {
    let mut files = vec![
        generated_file("corba.ads", render_corba_ads(&plan.typecode_operations)),
        generated_file("corba-object.ads", render_corba_object_ads()),
        generated_file("corba-object.adb", render_corba_object_adb()),
        generated_file("portableserver.ads", render_portableserver_ads()),
    ];

    if plan.include_any || !plan.any_operations.is_empty() || !plan.typecode_operations.is_empty() {
        files.push(generated_file(
            "corba-any.ads",
            render_corba_any_ads(&plan.any_operations),
        ));
        if !plan.any_operations.is_empty() {
            files.push(generated_file(
                "corba-any.adb",
                render_corba_any_adb(&plan.any_operations),
            ));
        }
    }

    if plan.include_typecode || !plan.typecode_operations.is_empty() {
        files.push(generated_file(
            "corba-typecode.ads",
            render_corba_typecode_ads(&plan.typecode_operations),
        ));
    }
    if !plan.typecode_operations.is_empty() {
        files.push(generated_file(
            "corba-typecode.adb",
            render_corba_typecode_adb(&plan.typecode_operations),
        ));
    }

    for exception in &plan.user_exceptions {
        files.push(generated_file(
            package_spec_filename(&exception.package),
            render_exception_package(exception),
        ));
    }

    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    files
}

pub fn render_corba_any_file() -> GeneratedFile {
    generated_file(
        "corba-any.ads",
        render_corba_any_ads(&BTreeSet::<AnyOperation>::new()),
    )
}

pub fn write_generated_files(
    output_dir: &Path,
    files: &[GeneratedFile],
) -> io::Result<Vec<PathBuf>> {
    let mut written = Vec::with_capacity(files.len());
    for file in files {
        let path = output_dir.join(&file.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &file.contents)?;
        written.push(path);
    }
    Ok(written)
}

pub fn generate_fake_corba(source_dir: &Path, output_dir: &Path) -> io::Result<FakeCorbaOutput> {
    generate_fake_corba_with(source_dir, output_dir, false)
}

/// Like [`generate_fake_corba`], but `skip_user_exceptions` drops the
/// heuristically-inferred `Pkg.Exception` application-library packages from the
/// plan. Under `--force`, those missing external packages are owned by the Ada
/// external-stub model (which reconstructs their full used API, not just a lone
/// exception), so emitting a competing flat stub here would duplicate the unit.
pub fn generate_fake_corba_with(
    source_dir: &Path,
    output_dir: &Path,
    skip_user_exceptions: bool,
) -> io::Result<FakeCorbaOutput> {
    let report = detect_source_tree(source_dir)?;
    let mut plan = plan_from_report(&report);
    if skip_user_exceptions {
        plan.user_exceptions.clear();
    }
    let files = render_plan(&plan);
    let written_files = write_generated_files(output_dir, &files)?;

    Ok(FakeCorbaOutput {
        report,
        plan,
        written_files,
    })
}

fn collect_ada_sources(dir: &Path, paths: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_ada_sources(&path, paths)?;
        } else if is_ada_source(&path) {
            paths.push(path);
        }
    }
    Ok(())
}

fn is_ada_source(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("adb") || extension.eq_ignore_ascii_case("ads")
        })
}

fn contains_generated_name_pattern(value: &str) -> bool {
    ["poa", "skeleton", "impl", "idl", "helper", "stub"]
        .iter()
        .any(|needle| value.contains(needle))
}

fn infer_user_exceptions(text: &str) -> Vec<UserException> {
    let tokens = lex_ident_tokens(text);
    let mut exceptions = BTreeSet::new();
    for index in 0..tokens.len().saturating_sub(3) {
        let keyword = tokens[index].to_ascii_lowercase();
        if keyword != "raise" && keyword != "when" {
            continue;
        }
        let package = &tokens[index + 1];
        if tokens[index + 2] != "." || skip_exception_package(package) {
            continue;
        }
        let exception = &tokens[index + 3];
        if is_identifier(package) && is_identifier(exception) {
            exceptions.insert(UserException {
                package: package.clone(),
                exception: exception.clone(),
            });
        }
    }
    exceptions.into_iter().collect()
}

fn lex_ident_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if is_ident_char(ch) {
            current.push(ch);
        } else {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            if ch == '.' {
                tokens.push(".".to_owned());
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn collect_lazy_any_typecode_refs(
    tokens: &[String],
    any_operations: &mut BTreeSet<AnyOperation>,
    typecode_operations: &mut BTreeSet<TypeCodeOperation>,
) {
    for index in 0..tokens.len().saturating_sub(4) {
        if token_eq(&tokens[index], "corba")
            && tokens[index + 1] == "."
            && token_eq(&tokens[index + 2], "any")
            && tokens[index + 3] == "."
        {
            if let Some(operation) = AnyOperation::from_identifier(&tokens[index + 4]) {
                any_operations.insert(operation);
            }
        }

        if token_eq(&tokens[index], "corba")
            && tokens[index + 1] == "."
            && token_eq(&tokens[index + 2], "typecode")
            && tokens[index + 3] == "."
        {
            if let Some(operation) = TypeCodeOperation::from_identifier(&tokens[index + 4]) {
                typecode_operations.insert(operation);
            }
        }
    }

    let any_ops_in_scope = has_use_clause(tokens, &["corba", "any"]);
    let typecode_ops_in_scope = has_use_clause(tokens, &["corba", "typecode"]);
    if !any_ops_in_scope && !typecode_ops_in_scope {
        return;
    }

    for token in tokens {
        if any_ops_in_scope {
            if let Some(operation) = AnyOperation::from_identifier(token) {
                any_operations.insert(operation);
            }
        }
        if typecode_ops_in_scope {
            if let Some(operation) = TypeCodeOperation::from_identifier(token) {
                typecode_operations.insert(operation);
            }
        }
    }
}

fn has_scoped_package_ref(tokens: &[String], path: &[&str]) -> bool {
    let needed_len = path.len() + path.len().saturating_sub(1);
    for index in 0..tokens.len().saturating_sub(needed_len - 1) {
        let mut cursor = index;
        let mut matched = true;
        for (part_index, part) in path.iter().enumerate() {
            if !tokens
                .get(cursor)
                .is_some_and(|token| token_eq(token, part))
            {
                matched = false;
                break;
            }
            cursor += 1;
            if part_index + 1 < path.len() {
                if tokens.get(cursor).is_none_or(|token| token != ".") {
                    matched = false;
                    break;
                }
                cursor += 1;
            }
        }

        if matched {
            return true;
        }
    }
    false
}

fn has_use_clause(tokens: &[String], path: &[&str]) -> bool {
    let needed_len = 1 + path.len() + path.len().saturating_sub(1);
    for index in 0..tokens.len().saturating_sub(needed_len - 1) {
        if !token_eq(&tokens[index], "use") {
            continue;
        }

        let mut cursor = index + 1;
        let mut matched = true;
        for (part_index, part) in path.iter().enumerate() {
            if !tokens
                .get(cursor)
                .is_some_and(|token| token_eq(token, part))
            {
                matched = false;
                break;
            }
            cursor += 1;
            if part_index + 1 < path.len() {
                if tokens.get(cursor).is_none_or(|token| token != ".") {
                    matched = false;
                    break;
                }
                cursor += 1;
            }
        }

        if matched {
            return true;
        }
    }
    false
}

fn token_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn skip_exception_package(package: &str) -> bool {
    matches!(
        package.to_ascii_lowercase().as_str(),
        "ada" | "standard" | "corba" | "portableserver" | "system" | "interfaces" | "gnat"
    )
}

fn generated_file(path: impl Into<PathBuf>, contents: String) -> GeneratedFile {
    GeneratedFile {
        relative_path: path.into(),
        contents,
    }
}

fn package_spec_filename(package: &str) -> String {
    format!("{}.ads", package.replace('.', "-").to_ascii_lowercase())
}

fn render_corba_ads(typecode_operations: &BTreeSet<TypeCodeOperation>) -> String {
    let mut contents = "--  SPDX-License-Identifier: Apache-2.0\n\
\n\
package CORBA is\n\
   pragma Pure;\n\
\n\
   type Long is new Integer;\n\
   type Unsigned_Long is mod 2 ** 32;\n\
   type Short is range -2 ** 15 .. 2 ** 15 - 1;\n\
   type Unsigned_Short is mod 2 ** 16;\n\
   subtype Boolean is Standard.Boolean;\n\
   subtype Float is Standard.Float;\n\
   subtype Double is Standard.Long_Float;\n\
   subtype String is Standard.String;\n\
   type Octet is mod 2 ** 8;\n\
   type Octet_Array is array (Positive range <>) of Octet;\n"
        .to_owned();
    if !typecode_operations.is_empty() {
        contents.push_str(
            "\n\
   subtype TCKind is Integer;\n\
   Tk_Null : constant TCKind := 0;\n\
   Tk_Void : constant TCKind := 1;\n\
   Tk_Short : constant TCKind := 2;\n\
   Tk_Long : constant TCKind := 3;\n\
   Tk_Ushort : constant TCKind := 4;\n\
   Tk_Ulong : constant TCKind := 5;\n\
   Tk_Float : constant TCKind := 6;\n\
   Tk_Double : constant TCKind := 7;\n\
   Tk_Boolean : constant TCKind := 8;\n\
   Tk_Char : constant TCKind := 9;\n\
   Tk_Octet : constant TCKind := 10;\n\
   Tk_Any : constant TCKind := 11;\n\
   Tk_TypeCode : constant TCKind := 12;\n\
   Tk_Principal : constant TCKind := 13;\n\
   Tk_Objref : constant TCKind := 14;\n\
   Tk_Struct : constant TCKind := 15;\n\
   Tk_Union : constant TCKind := 16;\n\
   Tk_Enum : constant TCKind := 17;\n\
   Tk_String : constant TCKind := 18;\n\
   Tk_Sequence : constant TCKind := 19;\n\
   Tk_Array : constant TCKind := 20;\n\
   Tk_Alias : constant TCKind := 21;\n\
   Tk_Except : constant TCKind := 22;\n\
   Tk_Longlong : constant TCKind := 23;\n\
   Tk_Ulonglong : constant TCKind := 24;\n\
   Tk_Longdouble : constant TCKind := 25;\n\
   Tk_Wchar : constant TCKind := 26;\n\
   Tk_Wstring : constant TCKind := 27;\n\
   Tk_Fixed : constant TCKind := 28;\n\
   Tk_Value : constant TCKind := 29;\n\
   Tk_Value_Box : constant TCKind := 30;\n\
   Tk_Native : constant TCKind := 31;\n\
   Tk_Abstract_Interface : constant TCKind := 32;\n",
        );
    }
    contents.push_str("end CORBA;\n");
    contents
}

fn render_corba_object_ads() -> String {
    "--  SPDX-License-Identifier: Apache-2.0\n\
\n\
package CORBA.Object is\n\
   pragma Preelaborate;\n\
\n\
   type Ref is tagged record\n\
      Nil_Value : Standard.Boolean := True;\n\
      Tag_Value : Integer := 0;\n\
   end record;\n\
   function Nil return Ref;\n\
   function Fake (Tag : Integer) return Ref;\n\
   function Is_Nil (R : Ref) return Standard.Boolean;\n\
end CORBA.Object;\n"
        .to_owned()
}

fn render_corba_object_adb() -> String {
    "--  SPDX-License-Identifier: Apache-2.0\n\
\n\
package body CORBA.Object is\n\
   function Nil return Ref is\n\
   begin\n\
      return Ref'(Nil_Value => True, Tag_Value => 0);\n\
   end Nil;\n\
\n\
   function Fake (Tag : Integer) return Ref is\n\
   begin\n\
      return Ref'(Nil_Value => False, Tag_Value => Tag);\n\
   end Fake;\n\
\n\
   function Is_Nil (R : Ref) return Standard.Boolean is\n\
   begin\n\
      return R.Nil_Value;\n\
   end Is_Nil;\n\
end CORBA.Object;\n"
        .to_owned()
}

fn render_corba_any_ads(operations: &BTreeSet<AnyOperation>) -> String {
    let mut contents = "--  SPDX-License-Identifier: Apache-2.0\n\
\n\
package CORBA.Any is\n\
   pragma Preelaborate;\n\
\n\
   type Value is tagged null record;\n\
   type TypeCode is null record;\n"
        .to_owned();
    if !operations.is_empty() {
        contents.push('\n');
        for operation in operations {
            contents.push_str(render_any_operation_spec(*operation));
        }
    }
    contents.push_str("end CORBA.Any;\n");
    contents
}

fn render_corba_any_adb(operations: &BTreeSet<AnyOperation>) -> String {
    let mut contents = "--  SPDX-License-Identifier: Apache-2.0\n\
\n\
package body CORBA.Any is\n"
        .to_owned();
    for operation in operations {
        contents.push_str(render_any_operation_body(*operation));
    }
    contents.push_str("end CORBA.Any;\n");
    contents
}

fn render_any_operation_spec(operation: AnyOperation) -> &'static str {
    match operation {
        AnyOperation::Clear => "   procedure Clear (Target : in out Value);\n",
        AnyOperation::Equal => {
            "   function Equal (Left : Value; Right : Value) return Standard.Boolean;\n"
        }
        AnyOperation::GetType => "   function Get_Type (Item : Value) return TypeCode;\n",
        AnyOperation::SetType => {
            "   procedure Set_Type (Target : in out Value; Code : TypeCode);\n"
        }
    }
}

fn render_any_operation_body(operation: AnyOperation) -> &'static str {
    match operation {
        AnyOperation::Clear => {
            "\n\
   procedure Clear (Target : in out Value) is\n\
      pragma Unreferenced (Target);\n\
   begin\n\
      null;\n\
   end Clear;\n"
        }
        AnyOperation::Equal => {
            "\n\
   function Equal (Left : Value; Right : Value) return Standard.Boolean is\n\
      pragma Unreferenced (Left);\n\
      pragma Unreferenced (Right);\n\
   begin\n\
      return False;\n\
   end Equal;\n"
        }
        AnyOperation::GetType => {
            "\n\
   function Get_Type (Item : Value) return TypeCode is\n\
      pragma Unreferenced (Item);\n\
   begin\n\
      return TypeCode'(null record);\n\
   end Get_Type;\n"
        }
        AnyOperation::SetType => {
            "\n\
   procedure Set_Type (Target : in out Value; Code : TypeCode) is\n\
      pragma Unreferenced (Target);\n\
      pragma Unreferenced (Code);\n\
   begin\n\
      null;\n\
   end Set_Type;\n"
        }
    }
}

fn render_corba_typecode_ads(operations: &BTreeSet<TypeCodeOperation>) -> String {
    let mut contents = "--  SPDX-License-Identifier: Apache-2.0\n\
\n\
with CORBA.Any;\n\
\n\
package CORBA.TypeCode is\n\
   pragma Preelaborate;\n\
\n\
   subtype Object is CORBA.Any.TypeCode;\n"
        .to_owned();
    if !operations.is_empty() {
        contents.push('\n');
        for operation in operations {
            contents.push_str(render_typecode_operation_spec(*operation));
        }
    }
    contents.push_str("end CORBA.TypeCode;\n");
    contents
}

fn render_corba_typecode_adb(operations: &BTreeSet<TypeCodeOperation>) -> String {
    let mut contents = "--  SPDX-License-Identifier: Apache-2.0\n\
\n\
package body CORBA.TypeCode is\n"
        .to_owned();
    for operation in operations {
        contents.push_str(render_typecode_operation_body(*operation));
    }
    contents.push_str("end CORBA.TypeCode;\n");
    contents
}

fn render_typecode_operation_spec(operation: TypeCodeOperation) -> &'static str {
    match operation {
        TypeCodeOperation::ContentType => {
            "   function Content_Type (Item : Object) return Object;\n"
        }
        TypeCodeOperation::Equal => {
            "   function Equal (Left : Object; Right : Object) return Standard.Boolean;\n"
        }
        TypeCodeOperation::Equivalent => {
            "   function Equivalent (Left : Object; Right : Object) return Standard.Boolean;\n"
        }
        TypeCodeOperation::Id => "   function Id (Item : Object) return Standard.String;\n",
        TypeCodeOperation::Kind => "   function Kind (Item : Object) return CORBA.TCKind;\n",
        TypeCodeOperation::Length => "   function Length (Item : Object) return Natural;\n",
        TypeCodeOperation::MemberCount => {
            "   function Member_Count (Item : Object) return Natural;\n"
        }
        TypeCodeOperation::MemberName => {
            "   function Member_Name (Item : Object; Index : Natural) return Standard.String;\n"
        }
        TypeCodeOperation::MemberType => {
            "   function Member_Type (Item : Object; Index : Natural) return Object;\n"
        }
        TypeCodeOperation::Name => "   function Name (Item : Object) return Standard.String;\n",
    }
}

fn render_typecode_operation_body(operation: TypeCodeOperation) -> &'static str {
    match operation {
        TypeCodeOperation::ContentType => {
            "\n\
   function Content_Type (Item : Object) return Object is\n\
      pragma Unreferenced (Item);\n\
   begin\n\
      return Object'(null record);\n\
   end Content_Type;\n"
        }
        TypeCodeOperation::Equal => {
            "\n\
   function Equal (Left : Object; Right : Object) return Standard.Boolean is\n\
      pragma Unreferenced (Left);\n\
      pragma Unreferenced (Right);\n\
   begin\n\
      return False;\n\
   end Equal;\n"
        }
        TypeCodeOperation::Equivalent => {
            "\n\
   function Equivalent (Left : Object; Right : Object) return Standard.Boolean is\n\
      pragma Unreferenced (Left);\n\
      pragma Unreferenced (Right);\n\
   begin\n\
      return False;\n\
   end Equivalent;\n"
        }
        TypeCodeOperation::Id => {
            "\n\
   function Id (Item : Object) return Standard.String is\n\
      pragma Unreferenced (Item);\n\
   begin\n\
      return \"\";\n\
   end Id;\n"
        }
        TypeCodeOperation::Kind => {
            "\n\
   function Kind (Item : Object) return CORBA.TCKind is\n\
      pragma Unreferenced (Item);\n\
   begin\n\
      return CORBA.Tk_Null;\n\
   end Kind;\n"
        }
        TypeCodeOperation::Length => {
            "\n\
   function Length (Item : Object) return Natural is\n\
      pragma Unreferenced (Item);\n\
   begin\n\
      return 0;\n\
   end Length;\n"
        }
        TypeCodeOperation::MemberCount => {
            "\n\
   function Member_Count (Item : Object) return Natural is\n\
      pragma Unreferenced (Item);\n\
   begin\n\
      return 0;\n\
   end Member_Count;\n"
        }
        TypeCodeOperation::MemberName => {
            "\n\
   function Member_Name (Item : Object; Index : Natural) return Standard.String is\n\
      pragma Unreferenced (Item);\n\
      pragma Unreferenced (Index);\n\
   begin\n\
      return \"\";\n\
   end Member_Name;\n"
        }
        TypeCodeOperation::MemberType => {
            "\n\
   function Member_Type (Item : Object; Index : Natural) return Object is\n\
      pragma Unreferenced (Item);\n\
      pragma Unreferenced (Index);\n\
   begin\n\
      return Object'(null record);\n\
   end Member_Type;\n"
        }
        TypeCodeOperation::Name => {
            "\n\
   function Name (Item : Object) return Standard.String is\n\
      pragma Unreferenced (Item);\n\
   begin\n\
      return \"\";\n\
   end Name;\n"
        }
    }
}

fn render_portableserver_ads() -> String {
    "--  SPDX-License-Identifier: Apache-2.0\n\
\n\
package PortableServer is\n\
   pragma Preelaborate;\n\
\n\
   type Servant_Base is abstract tagged null record;\n\
   type Servant is access all Servant_Base'Class;\n\
end PortableServer;\n"
        .to_owned()
}

fn render_exception_package(exception: &UserException) -> String {
    format!(
        "--  SPDX-License-Identifier: Apache-2.0\n\
\n\
package {} is\n\
   {} : exception;\n\
end {};\n",
        exception.package, exception.exception, exception.package
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn detect_sources_reports_portableserver_and_impl_signals() {
        let report = detect_source_texts([SourceText {
            path: "bar_impl.adb".into(),
            text: "with PortableServer;\npackage body Bar_Impl is\n   type T is new PortableServer.Servant_Base with null record;\nend Bar_Impl;\n".into(),
        }]);

        assert!(report.is_corba_like());
        assert!(report
            .signals
            .iter()
            .any(|signal| signal.kind == DetectionKind::PortableServerReference));
        assert!(report
            .signals
            .iter()
            .any(|signal| signal.kind == DetectionKind::GeneratedNamePattern));
    }

    #[test]
    fn detect_sources_infers_qualified_user_exception() {
        let report = detect_source_texts([SourceText {
            path: "bar_impl.adb".into(),
            text: "package body Bar_Impl is\nbegin\n   raise Foo.BadInput;\nexception\n   when Foo.BadInput => null;\nend Bar_Impl;\n".into(),
        }]);

        assert_eq!(
            report.user_exceptions,
            vec![UserException {
                package: "Foo".into(),
                exception: "BadInput".into()
            }]
        );
    }

    #[test]
    fn render_plan_emits_base_files_and_exception_package() {
        let plan = FakeCorbaPlan {
            include_any: false,
            include_typecode: false,
            any_operations: BTreeSet::new(),
            typecode_operations: BTreeSet::new(),
            user_exceptions: vec![UserException {
                package: "Foo".into(),
                exception: "BadInput".into(),
            }],
        };

        let files = render_plan(&plan);
        let paths = files
            .iter()
            .map(|file| file.relative_path.as_path())
            .collect::<Vec<_>>();

        assert!(paths.contains(&std::path::Path::new("corba.ads")));
        assert!(paths.contains(&std::path::Path::new("corba-object.ads")));
        assert!(paths.contains(&std::path::Path::new("corba-object.adb")));
        assert!(paths.contains(&std::path::Path::new("portableserver.ads")));
        assert!(paths.contains(&std::path::Path::new("foo.ads")));
        assert!(files.iter().all(|file| file
            .contents
            .contains("SPDX-License-Identifier: Apache-2.0")));
    }

    #[test]
    fn detect_sources_collects_lazy_any_typecode_operations() {
        let report = detect_source_texts([SourceText {
            path: "any_client.adb".into(),
            text: "with CORBA.Any;\nwith CORBA.TypeCode;\npackage body Any_Client is\n   procedure Touch (A : in out CORBA.Any.Value) is\n      TC : CORBA.TypeCode.Object := CORBA.Any.Get_Type (A);\n   begin\n      if CORBA.TypeCode.Kind (TC) = CORBA.Tk_Null then\n         CORBA.Any.Clear (A);\n      end if;\n   end Touch;\nend Any_Client;\n".into(),
        }]);

        assert_eq!(
            report.any_operations,
            BTreeSet::from([AnyOperation::Clear, AnyOperation::GetType])
        );
        assert_eq!(
            report.typecode_operations,
            BTreeSet::from([TypeCodeOperation::Kind])
        );
    }

    #[test]
    fn detect_sources_collects_use_visible_lazy_operations() {
        let report = detect_source_texts([SourceText {
            path: "any_client.adb".into(),
            text: "with CORBA.Any; use CORBA.Any;\nwith CORBA.TypeCode; use CORBA.TypeCode;\npackage body Any_Client is\n   procedure Touch (A : in out Value; TC : Object) is\n   begin\n      Set_Type (A, TC);\n      if Equivalent (TC, TC) then\n         Clear (A);\n      end if;\n   end Touch;\nend Any_Client;\n".into(),
        }]);

        assert_eq!(
            report.any_operations,
            BTreeSet::from([AnyOperation::Clear, AnyOperation::SetType])
        );
        assert_eq!(
            report.typecode_operations,
            BTreeSet::from([TypeCodeOperation::Equivalent])
        );
    }

    #[test]
    fn render_plan_keeps_minimal_any_surface_without_lazy_operations() {
        let plan = FakeCorbaPlan {
            include_any: true,
            include_typecode: false,
            any_operations: BTreeSet::new(),
            typecode_operations: BTreeSet::new(),
            user_exceptions: Vec::new(),
        };

        let files = render_plan(&plan);
        let paths = files
            .iter()
            .map(|file| file.relative_path.as_path())
            .collect::<Vec<_>>();
        let corba_ads = file_contents(&files, "corba.ads");

        assert!(paths.contains(&Path::new("corba-any.ads")));
        assert!(!paths.contains(&Path::new("corba-any.adb")));
        assert!(!paths.contains(&Path::new("corba-typecode.ads")));
        assert!(!corba_ads.contains("TCKind"));
    }

    #[test]
    fn render_plan_emits_typecode_spec_for_type_references_without_operations() {
        let report = detect_source_texts([SourceText {
            path: "any_client.adb".into(),
            text: "with CORBA.Any;\nwith CORBA.TypeCode;\npackage body Any_Client is\n   procedure Touch (A : in out CORBA.Any.Value) is\n      TC : CORBA.TypeCode.Object := CORBA.Any.Get_Type (A);\n   begin\n      CORBA.Any.Set_Type (A, TC);\n   end Touch;\nend Any_Client;\n".into(),
        }]);

        let files = render_plan(&plan_from_report(&report));
        let paths = files
            .iter()
            .map(|file| file.relative_path.as_path())
            .collect::<Vec<_>>();

        assert_eq!(
            report.any_operations,
            BTreeSet::from([AnyOperation::GetType, AnyOperation::SetType])
        );
        assert!(report.uses_typecode_package);
        assert!(report.typecode_operations.is_empty());
        assert!(paths.contains(&Path::new("corba-typecode.ads")));
        assert!(!paths.contains(&Path::new("corba-typecode.adb")));
    }

    #[test]
    fn render_plan_emits_only_requested_any_typecode_operations() {
        let plan = FakeCorbaPlan {
            include_any: true,
            include_typecode: true,
            any_operations: BTreeSet::from([AnyOperation::GetType]),
            typecode_operations: BTreeSet::from([TypeCodeOperation::Kind]),
            user_exceptions: Vec::new(),
        };

        let files = render_plan(&plan);
        let any_ads = file_contents(&files, "corba-any.ads");
        let any_adb = file_contents(&files, "corba-any.adb");
        let typecode_ads = file_contents(&files, "corba-typecode.ads");
        let corba_ads = file_contents(&files, "corba.ads");

        assert!(any_ads.contains("function Get_Type"));
        assert!(any_adb.contains("function Get_Type"));
        assert!(!any_ads.contains("procedure Clear"));
        assert!(typecode_ads.contains("function Kind"));
        assert!(!typecode_ads.contains("function Member_Count"));
        assert!(corba_ads.contains("subtype TCKind is Integer;"));
    }

    #[test]
    fn render_corba_object_exposes_nil_and_fake_factories() {
        let ads = render_corba_object_ads();
        let adb = render_corba_object_adb();

        assert!(ads.contains("Nil_Value : Standard.Boolean := True;"));
        assert!(ads.contains("Tag_Value : Integer := 0;"));
        assert!(ads.contains("function Nil return Ref;"));
        assert!(ads.contains("function Fake (Tag : Integer) return Ref;"));
        assert!(adb.contains("return Ref'(Nil_Value => True, Tag_Value => 0);"));
        assert!(adb.contains("return Ref'(Nil_Value => False, Tag_Value => Tag);"));
        assert!(adb.contains("return R.Nil_Value;"));
    }

    #[test]
    fn generated_ada_files_parse() {
        let plan = FakeCorbaPlan {
            include_any: true,
            include_typecode: false,
            any_operations: BTreeSet::new(),
            typecode_operations: BTreeSet::new(),
            user_exceptions: vec![UserException {
                package: "Foo".into(),
                exception: "BadInput".into(),
            }],
        };

        for file in render_plan(&plan) {
            ada_parser::reconcile::build_structural_ast(&file.contents, None, &file.relative_path)
                .unwrap_or_else(|error| panic!("{} parses: {error}", file.relative_path.display()));
        }
    }

    #[test]
    fn generate_fake_corba_writes_expected_files() {
        let temp = temp_dir("write");
        let source_dir = temp.join("src_instrumented");
        fs::create_dir_all(&source_dir).expect("source dir is created");
        fs::write(
            source_dir.join("bar_impl.adb"),
            "with PortableServer;\npackage body Bar_Impl is\nbegin\n   raise Foo.BadInput;\nexception\n   when Foo.BadInput => null;\nend Bar_Impl;\n",
        )
        .expect("source is written");
        let out_dir = temp.join("fake_corba");

        let output = generate_fake_corba(&source_dir, &out_dir).expect("fake CORBA is generated");

        assert!(output.report.is_corba_like());
        assert!(out_dir.join("corba.ads").is_file());
        assert!(out_dir.join("foo.ads").is_file());
    }

    fn file_contents<'a>(files: &'a [GeneratedFile], relative_path: &str) -> &'a str {
        files
            .iter()
            .find(|file| file.relative_path == Path::new(relative_path))
            .unwrap_or_else(|| panic!("{relative_path} is emitted"))
            .contents
            .as_str()
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-fake-corba-{name}-{nonce}"));
        fs::create_dir_all(&dir).expect("temporary directory is created");
        dir
    }
}
