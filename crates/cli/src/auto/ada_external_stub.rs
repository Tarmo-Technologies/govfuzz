// SPDX-License-Identifier: Apache-2.0

//! Force-fuzz external Ada library stubbing.
//!
//! When `--force` is used on a project whose dependency libraries are missing
//! offline, [`crate::auto::repair::Repair::StubGprImport`] synthesizes an empty
//! stub project so the build LOADS, but the code still `with`s and CALLS packages
//! from those libraries. This module reconstructs a *compilable* stub of the used
//! subset of each such package so the target's own body compiles and the target
//! reaches `built_and_fuzzed`.
//!
//! It cannot know the real library's API, so it:
//!  1. **Seeds** from the client SOURCE (tree-sitter): every `Pkg.Entity` use is
//!     classified as a function call (arity N), a procedure call, a type, or a
//!     bare value, so the stub has the right *shape*.
//!  2. Emits each unknown parameter/return type as a **distinct placeholder type**
//!     (`Gf_Ext_Stub_N`), so the compiler names the exact slot on a mismatch.
//!  3. **Refines** from GNAT's error oracle: an `expected type "X" / found type
//!     "Y"` pair where one side is a placeholder reveals the real type of that
//!     slot (the compiler does the type inference). Iterating drives the stub to a
//!     profile the real code compiles against.
//!
//! Findings from such a build are reduced-fidelity (the library behaves as a
//! neutral stub); the caller stamps them low-confidence and records the stubbed
//! libraries in the missing-dependency manifest.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Prefix for synthesized placeholder types. Chosen to never collide with a real
/// Ada identifier a project would use.
const PLACEHOLDER_PREFIX: &str = "Gf_Ext_Stub_";

/// One parameter or return type: either resolved to a real Ada type spelling, or
/// an unresolved placeholder the compiler will pin down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Slot {
    Resolved(String),
    Placeholder(String),
}

impl Slot {
    fn spelling(&self) -> &str {
        match self {
            Slot::Resolved(t) | Slot::Placeholder(t) => t,
        }
    }
    fn is_placeholder(&self) -> bool {
        matches!(self, Slot::Placeholder(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OpStub {
    /// Display name (original case from the source).
    name: String,
    is_function: bool,
    params: Vec<Slot>,
    /// `Some` for a function; the return type slot.
    ret: Option<Slot>,
}

/// How to declare a referenced stub type. Default is a numeric derived type (a
/// handle threaded through calls); refined to a String subtype when the compiler
/// reports a string literal against it, or to an enumeration when it is used as
/// an array index / with `use all type` and its literals are referenced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TypeForm {
    #[default]
    Numeric,
    StringLike,
    Enumeration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct TypeStub {
    name: String,
    form: TypeForm,
    /// Enumeration literals (only when `form == Enumeration`); insertion order is
    /// preserved so the declared positions are stable across rounds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    literals: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PkgStub {
    /// Referenced type names to declare (lower-key -> stub).
    types: BTreeMap<String, TypeStub>,
    /// Referenced bare-value names (constants/enum values).
    consts: BTreeMap<String, String>,
    /// Referenced exceptions (`raise Pkg.X`).
    exceptions: BTreeMap<String, String>,
    /// Subprograms, keyed by lowercased name (v1: no overload distinction).
    ops: BTreeMap<String, OpStub>,
}

/// The accumulating, persisted model of every external package being stubbed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalStubModel {
    packages: BTreeMap<String, PkgStub>,
    /// placeholder type name -> the slot it fills, so a compiler mismatch on that
    /// name resolves the exact parameter/return.
    placeholders: BTreeMap<String, PlaceholderSlot>,
    next_placeholder: u32,
    /// Client unit stem (e.g. `spat-preconditions`) -> the stubbed enumeration
    /// type keys (`Pkg\u{1}typekey`) it makes visible via `use [all] type`. Lets
    /// an `"X" is undefined` error in that unit attribute X as a literal of the
    /// enum it uses.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    enum_use_sites: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PlaceholderSlot {
    package: String,
    op: String,
    /// `Some(i)` = parameter i; `None` = the return type.
    param: Option<usize>,
}

impl ExternalStubModel {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self).unwrap_or_default())
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    pub fn stubbed_packages(&self) -> impl Iterator<Item = &str> {
        self.packages.keys().map(String::as_str)
    }

    fn fresh_placeholder(&mut self, package: &str, op: &str, param: Option<usize>) -> String {
        let name = format!("{PLACEHOLDER_PREFIX}{}", self.next_placeholder);
        self.next_placeholder += 1;
        self.placeholders.insert(
            name.clone(),
            PlaceholderSlot {
                package: package.to_owned(),
                op: op.to_owned(),
                param,
            },
        );
        name
    }

    /// Seed the model from the client SOURCE for the given external packages.
    /// Idempotent: only ADDS entities/ops it hasn't seen. Returns whether anything
    /// changed.
    pub fn seed_from_sources(&mut self, sources: &[String], packages: &BTreeSet<String>) -> bool {
        let mut changed = false;
        for source in sources {
            for usage in scan_ada_usages(source, packages) {
                changed |= self.apply_usage(usage);
            }
        }
        changed |= self.seed_enum_use_clauses(sources, packages);
        changed
    }

    /// Detect `use [all] type Pkg.T` clauses: they make `T`'s enumeration literals
    /// directly visible, so `T` (in a stubbed `Pkg`) is an enumeration. Records the
    /// referencing unit -> enum type so a later `"X" is undefined` error in it
    /// attributes `X` as one of `T`'s literals. Two passes over `sources`: the first
    /// marks qualified `Pkg.T` enums, the second resolves unqualified `use all type
    /// T` by leaf name against those (a client often re-exports the enum as its own
    /// subtype and uses it unqualified).
    fn seed_enum_use_clauses(&mut self, sources: &[String], packages: &BTreeSet<String>) -> bool {
        let mut changed = false;
        let known = |m: &Self, package: &str| {
            packages.iter().any(|p| p.eq_ignore_ascii_case(package))
                || m.packages.keys().any(|p| p.eq_ignore_ascii_case(package))
        };
        // Pass 1: qualified clauses mark the enum type in its package.
        for source in sources {
            for qualified in use_all_type_targets(source) {
                let Some((package, entity)) = qualified.rsplit_once('.') else {
                    continue;
                };
                if !known(self, package) {
                    continue;
                }
                let pkg = self.packages.entry(package.to_owned()).or_default();
                let ty = pkg
                    .types
                    .entry(entity.to_ascii_lowercase())
                    .or_insert_with(|| TypeStub {
                        name: entity.to_owned(),
                        form: TypeForm::Enumeration,
                        literals: Vec::new(),
                    });
                if ty.form != TypeForm::Enumeration {
                    ty.form = TypeForm::Enumeration;
                    changed = true;
                }
            }
        }
        // Leaf name -> (package, key) for every enum type now known.
        let enum_by_leaf: BTreeMap<String, (String, String)> = self
            .packages
            .iter()
            .flat_map(|(pkg, stub)| {
                stub.types
                    .iter()
                    .filter(|(_, t)| t.form == TypeForm::Enumeration)
                    .map(move |(key, t)| (t.name.to_ascii_lowercase(), (pkg.clone(), key.clone())))
            })
            .collect();
        // Pass 2: record each unit's enum use-sites (qualified or leaf-resolved).
        for source in sources {
            let Some(stem) = unit_stem_of_source(source) else {
                continue;
            };
            for target in use_all_type_targets(source) {
                let leaf = target
                    .rsplit('.')
                    .next()
                    .unwrap_or(&target)
                    .to_ascii_lowercase();
                if let Some((package, key)) = enum_by_leaf.get(&leaf) {
                    let site_key = format!("{package}\u{1}{key}");
                    changed |= self
                        .enum_use_sites
                        .entry(stem.clone())
                        .or_default()
                        .insert(site_key);
                }
            }
        }
        changed
    }

    fn apply_usage(&mut self, usage: Usage) -> bool {
        let package = usage.package.clone();
        self.packages.entry(package.clone()).or_default();
        let op_key = usage.entity.to_ascii_lowercase();
        match usage.kind {
            UsageKind::Call { arity, is_function } => {
                let existing_len = self.packages[&package]
                    .ops
                    .get(&op_key)
                    .map(|o| o.params.len());
                match existing_len {
                    Some(len) => {
                        // Grow arity if a later call passes more args (v1 heuristic).
                        if arity <= len {
                            return false;
                        }
                        for i in len..arity {
                            let ph = self.fresh_placeholder(&package, &op_key, Some(i));
                            self.packages
                                .get_mut(&package)
                                .unwrap()
                                .ops
                                .get_mut(&op_key)
                                .unwrap()
                                .params
                                .push(Slot::Placeholder(ph));
                        }
                        true
                    }
                    None => {
                        let params: Vec<Slot> = (0..arity)
                            .map(|i| {
                                Slot::Placeholder(self.fresh_placeholder(
                                    &package,
                                    &op_key,
                                    Some(i),
                                ))
                            })
                            .collect();
                        let ret = is_function.then(|| {
                            Slot::Placeholder(self.fresh_placeholder(&package, &op_key, None))
                        });
                        self.packages.get_mut(&package).unwrap().ops.insert(
                            op_key,
                            OpStub {
                                name: usage.entity,
                                is_function,
                                params,
                                ret,
                            },
                        );
                        true
                    }
                }
            }
            UsageKind::Type => {
                use std::collections::btree_map::Entry;
                let types = &mut self.packages.get_mut(&package).unwrap().types;
                match types.entry(op_key) {
                    Entry::Occupied(_) => false,
                    Entry::Vacant(e) => {
                        e.insert(TypeStub {
                            name: usage.entity,
                            form: TypeForm::default(),
                            literals: Vec::new(),
                        });
                        true
                    }
                }
            }
            UsageKind::Value => self
                .packages
                .get_mut(&package)
                .unwrap()
                .consts
                .insert(op_key, usage.entity)
                .is_none(),
            UsageKind::Exception => self
                .packages
                .get_mut(&package)
                .unwrap()
                .exceptions
                .insert(op_key, usage.entity)
                .is_none(),
        }
    }

    /// Refine the model from GNAT build output: resolve placeholder slots to the
    /// real type the compiler expected/found, add newly-undeclared entities, and
    /// reclassify a subprogram named where a type was expected. Returns whether
    /// anything changed (so the caller knows to re-render + rebuild).
    pub fn refine_from_build_output(&mut self, stderr: &str) -> bool {
        let mut changed = false;
        // 1) Resolve placeholder slots from `expected/found` type-mismatch pairs.
        //    GNAT prints them on two consecutive lines.
        let lines: Vec<&str> = stderr.lines().collect();
        for window in lines.windows(2) {
            let (Some(expected), Some(found)) = (
                parse_type_note(window[0], "expected"),
                parse_type_note(window[1], "found"),
            ) else {
                continue;
            };
            changed |= self.resolve_from_pair(&expected, &found);
        }
        // GNAT sometimes prints `found` first, `expected` second.
        for window in lines.windows(2) {
            let (Some(found), Some(expected)) = (
                parse_type_note(window[0], "found"),
                parse_type_note(window[1], "expected"),
            ) else {
                continue;
            };
            changed |= self.resolve_from_pair(&expected, &found);
        }
        // 2) String-literal mismatches: for a string literal argument GNAT prints
        //    `found a string type` (no name) instead of `found type "..."`. The
        //    paired `expected type "T"` names the stub type/placeholder that must
        //    be String-compatible. Handle both line orders and both directions.
        for window in lines.windows(2) {
            if is_string_type_note(window[1], "found") {
                if let Some(t) = parse_type_note(window[0], "expected") {
                    changed |= self.mark_string_like(&t);
                }
            }
            if is_string_type_note(window[0], "found") {
                if let Some(t) = parse_type_note(window[1], "expected") {
                    changed |= self.mark_string_like(&t);
                }
            }
            if is_string_type_note(window[1], "expected") {
                if let Some(t) = parse_type_note(window[0], "found") {
                    changed |= self.mark_string_like(&t);
                }
            }
            if is_string_type_note(window[0], "expected") {
                if let Some(t) = parse_type_note(window[1], "found") {
                    changed |= self.mark_string_like(&t);
                }
            }
        }
        // 3) A placeholder used with an operator (e.g. a stubbed function result
        //    compared to a constant) draws `operator for type "P" ... is not
        //    directly visible`. Resolving it to Standard.Integer makes the
        //    predefined operator universally visible.
        for line in &lines {
            if let Some(ph) = parse_quoted_after(line, "operator for type \"") {
                if placeholder_of(&ph).is_some() {
                    changed |= self.resolve_from_pair(&ph, "Integer");
                }
            }
        }
        // 4) `"X" is undefined` in a unit that `use [all] type`s exactly one
        //    stubbed enumeration -> X is one of that enum's literals. This is how a
        //    kind-discriminant enum (`JSON_Value_Type`, whose `JSON_Int_Type` ...
        //    literals the client references) gets its literal set.
        for line in &lines {
            let Some(ident) = undefined_identifier(line) else {
                continue;
            };
            let Some(stem) = error_unit_stem(line) else {
                continue;
            };
            let Some(sites) = self.enum_use_sites.get(&stem) else {
                continue;
            };
            if sites.len() != 1 {
                continue; // ambiguous: multiple enums in scope
            }
            let key = sites.iter().next().unwrap().clone();
            let Some((package, type_key)) = key.split_once('\u{1}') else {
                continue;
            };
            if let Some(pkg) = self.packages.get_mut(package) {
                if let Some(ty) = pkg.types.get_mut(type_key) {
                    if ty.form == TypeForm::Enumeration && !ty.literals.contains(&ident) {
                        ty.literals.push(ident);
                        changed = true;
                    }
                }
            }
        }
        changed
    }

    /// The compiler saw a String where the stub type/placeholder `spelling` is
    /// used. If it names a placeholder slot, resolve it to `String`; if it names
    /// a stub type (matched by leaf name), flip that type to a `String` subtype.
    fn mark_string_like(&mut self, spelling: &str) -> bool {
        if placeholder_of(spelling).is_some() {
            return self.resolve_from_pair(spelling, "String");
        }
        let leaf = spelling
            .rsplit('.')
            .next()
            .unwrap_or(spelling)
            .to_ascii_lowercase();
        let mut changed = false;
        for pkg in self.packages.values_mut() {
            for ty in pkg.types.values_mut() {
                if ty.name.to_ascii_lowercase() == leaf && ty.form != TypeForm::StringLike {
                    ty.form = TypeForm::StringLike;
                    changed = true;
                }
            }
        }
        changed
    }

    /// Given an `expected`/`found` type pair, if exactly one names a placeholder,
    /// resolve that placeholder's slot to the OTHER (real) type.
    fn resolve_from_pair(&mut self, expected: &str, found: &str) -> bool {
        let exp_ph = placeholder_of(expected);
        let found_ph = placeholder_of(found);
        let (ph, real) = match (exp_ph, found_ph) {
            (Some(p), None) => (p, normalize_ada_type(found)),
            (None, Some(p)) => (p, normalize_ada_type(expected)),
            _ => return false, // both/neither placeholders: nothing to learn
        };
        if real.is_empty() || placeholder_of(&real).is_some() {
            return false;
        }
        let Some(slot) = self.placeholders.get(&ph).cloned() else {
            return false;
        };
        let Some(pkg) = self.packages.get_mut(&slot.package) else {
            return false;
        };
        let Some(op) = pkg.ops.get_mut(&slot.op) else {
            return false;
        };
        let target = match slot.param {
            Some(i) => op.params.get_mut(i),
            None => op.ret.as_mut(),
        };
        let Some(target) = target else { return false };
        if target.is_placeholder() && target.spelling() == ph {
            *target = Slot::Resolved(real);
            self.placeholders.remove(&ph);
            return true;
        }
        false
    }

    /// Render every stubbed package's `.ads` + `.adb` into `out_dir`.
    pub fn render(&self, out_dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
        std::fs::create_dir_all(out_dir)?;
        let mut written = Vec::new();
        // A child unit (`A.B`) needs its parent (`A`) to exist; synthesize an
        // empty spec for any ancestor package that isn't itself stubbed.
        for parent in self.ancestor_packages() {
            let stem = ada_unit_stem(&parent);
            let spec_path = out_dir.join(format!("{stem}.ads"));
            std::fs::write(&spec_path, render_empty_parent_spec(&parent))?;
            written.push(spec_path);
        }
        for (package, stub) in &self.packages {
            let stem = ada_unit_stem(package);
            let spec_path = out_dir.join(format!("{stem}.ads"));
            std::fs::write(&spec_path, self.render_spec(package, stub))?;
            written.push(spec_path);
            // A body is legal only when the spec requires one — i.e. it declares a
            // subprogram. A package with only types/constants/exceptions must NOT
            // have a body ("spec of this package does not allow a body").
            let body_path = out_dir.join(format!("{stem}.adb"));
            if stub.ops.is_empty() {
                let _ = std::fs::remove_file(&body_path);
            } else {
                std::fs::write(&body_path, render_body(package, stub))?;
                written.push(body_path);
            }
        }
        Ok(written)
    }

    /// Every strict ancestor package of a stubbed child unit that is not itself
    /// stubbed (`Vendorbig.Json` -> `Vendorbig`).
    fn ancestor_packages(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for package in self.packages.keys() {
            let parts: Vec<&str> = package.split('.').collect();
            for end in 1..parts.len() {
                let ancestor = parts[..end].join(".");
                if !self.packages.contains_key(&ancestor) {
                    out.insert(ancestor);
                }
            }
        }
        out
    }

    /// Map every stubbed type's leaf name (lowercased) to its owning package, so a
    /// slot resolved to that type in another package can `with`/`use` the owner.
    fn type_owners(&self) -> BTreeMap<String, String> {
        let mut owners = BTreeMap::new();
        for (package, stub) in &self.packages {
            for ty in stub.types.values() {
                owners.insert(ty.name.to_ascii_lowercase(), package.clone());
            }
        }
        owners
    }

    fn render_spec(&self, package: &str, stub: &PkgStub) -> String {
        let mut out = String::new();
        out.push_str("--  SPDX-License-Identifier: Apache-2.0\n");
        out.push_str("--  Force-fuzz stub for a missing external library package.\n");
        // A slot resolved to a type declared in a *sibling* stub package needs
        // that package `with`/`use`d for the (unqualified) type name to resolve.
        let owners = self.type_owners();
        let mut deps: BTreeSet<&str> = BTreeSet::new();
        for op in stub.ops.values() {
            for slot in op.params.iter().chain(op.ret.iter()) {
                if let Slot::Resolved(spelling) = slot {
                    let leaf = spelling.rsplit('.').next().unwrap_or(spelling);
                    if let Some(owner) = owners.get(&leaf.to_ascii_lowercase()) {
                        if owner != package {
                            deps.insert(owner.as_str());
                        }
                    }
                }
            }
        }
        for dep in &deps {
            out.push_str(&format!("with {dep}; use {dep};\n"));
        }
        out.push_str(&format!("package {package} is\n"));
        // Placeholder types for this package's still-unresolved slots.
        let mut placeholders: BTreeSet<&str> = BTreeSet::new();
        for op in stub.ops.values() {
            for slot in op.params.iter().chain(op.ret.iter()) {
                if let Slot::Placeholder(name) = slot {
                    placeholders.insert(name.as_str());
                }
            }
        }
        for ph in &placeholders {
            out.push_str(&format!("   type {ph} is new Integer;\n"));
        }
        // Referenced (opaque) types. A numeric derived type supports assignment,
        // comparison, and being passed around — enough for a handle the code only
        // threads through calls. Refined to a String subtype once the compiler
        // reports a string literal against it. Never a placeholder name.
        for ty in stub.types.values() {
            match ty.form {
                // An enumeration with known literals (a kind-discriminant type used
                // as an array index / with `use all type`). Empty literal set can't
                // form a legal enum, so fall back to the numeric form until the
                // literals are learned from the build oracle.
                TypeForm::Enumeration if !ty.literals.is_empty() => out.push_str(&format!(
                    "   type {} is ({});\n",
                    ty.name,
                    ty.literals.join(", ")
                )),
                TypeForm::StringLike => {
                    out.push_str(&format!("   subtype {} is String;\n", ty.name))
                }
                TypeForm::Numeric | TypeForm::Enumeration => {
                    out.push_str(&format!("   type {} is new Integer;\n", ty.name))
                }
            }
        }
        // Bare-value references: nullable constants. Skip any name that is also a
        // subprogram or type in this package (a parameterless call parsed as a
        // bare name) to avoid a duplicate declaration.
        for (key, name) in &stub.consts {
            if stub.ops.contains_key(key) || stub.types.contains_key(key) {
                continue;
            }
            out.push_str(&format!("   {name} : constant Integer := 0;\n"));
        }
        for name in stub.exceptions.values() {
            out.push_str(&format!("   {name} : exception;\n"));
        }
        for op in stub.ops.values() {
            out.push_str(&format!("   {};\n", op_signature(op, true)));
        }
        out.push_str(&format!("end {package};\n"));
        out
    }
}

/// An empty parent package so a stubbed child unit (`A.B`) has its parent (`A`).
fn render_empty_parent_spec(package: &str) -> String {
    format!(
        "--  SPDX-License-Identifier: Apache-2.0\n\
         --  Force-fuzz stub: synthesized parent package.\n\
         package {package} is\nend {package};\n"
    )
}

fn render_body(package: &str, stub: &PkgStub) -> String {
    let mut out = String::new();
    out.push_str("--  SPDX-License-Identifier: Apache-2.0\n");
    out.push_str("--  Force-fuzz stub for a missing external library package.\n");
    out.push_str(&format!("package body {package} is\n"));
    for op in stub.ops.values() {
        // The body profile must be FULLY conformant with the spec, which requires
        // repeating the identical parameter defaults (GNAT RM 6.3.1).
        if op.is_function {
            let ret = op.ret.as_ref().map(Slot::spelling).unwrap_or("Integer");
            out.push_str(&format!("   {} is\n", op_signature(op, true)));
            out.push_str(&format!(
                "   begin\n      return {};\n   end {};\n",
                default_value(ret),
                op.name
            ));
        } else {
            out.push_str(&format!(
                "   {} is\n   begin\n      null;\n   end {};\n",
                op_signature(op, true),
                op.name
            ));
        }
    }
    out.push_str(&format!("end {package};\n"));
    out
}

fn op_signature(op: &OpStub, with_defaults: bool) -> String {
    let params = if op.params.is_empty() {
        String::new()
    } else {
        let ps: Vec<String> = op
            .params
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                // Default every parameter (spec only) so call sites that omit a
                // trailing / optional argument (the real API's default params)
                // still resolve against the stub.
                if with_defaults {
                    format!(
                        "P{} : {} := {}",
                        i + 1,
                        slot.spelling(),
                        default_value(slot.spelling())
                    )
                } else {
                    format!("P{} : {}", i + 1, slot.spelling())
                }
            })
            .collect();
        format!(" ({})", ps.join("; "))
    };
    if op.is_function {
        let ret = op.ret.as_ref().map(Slot::spelling).unwrap_or("Integer");
        format!("function {}{} return {}", op.name, params, ret)
    } else {
        format!("procedure {}{}", op.name, params)
    }
}

/// A neutral default value for a return type spelling.
fn default_value(ty: &str) -> String {
    let base = ty.rsplit('.').next().unwrap_or(ty).to_ascii_lowercase();
    match base.as_str() {
        // Any String subtype (predefined or a StringLike stub type such as
        // `UTF8_String`) takes the empty string; `'First` would be an index value.
        b if b.ends_with("string") => "\"\"".to_owned(),
        "boolean" => "False".to_owned(),
        "character" => "' '".to_owned(),
        "float" | "long_float" | "duration" => "0.0".to_owned(),
        _ => {
            // Scalar/derived-numeric (placeholders + `new Integer` handles + Integer
            // /Natural/Positive) all support `'First`; access types support `null`.
            if ty.contains("_Access") || base.ends_with("_ptr") || base.ends_with("_access") {
                "null".to_owned()
            } else {
                format!("{ty}'First")
            }
        }
    }
}

/// A referenced entity in the client source and how it is used.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Usage {
    package: String,
    entity: String,
    kind: UsageKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UsageKind {
    Call { arity: usize, is_function: bool },
    Type,
    Value,
    Exception,
}

/// Scan an Ada source with tree-sitter for uses of the given external packages:
/// `Pkg.Entity(args)` (call), `X : Pkg.T` (type), `Pkg.Const` (value), `raise
/// Pkg.E` (exception). Only qualified (`Pkg.Entity`) references are collected —
/// `use`-clause bare references are ambiguous and left to GNAT to surface.
fn scan_ada_usages(source: &str, packages: &BTreeSet<String>) -> Vec<Usage> {
    let Some(tree) = ada_parser::parse_with_tree_sitter(source) else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let pkg_lower: BTreeSet<String> = packages.iter().map(|p| p.to_ascii_lowercase()).collect();
    let mut usages = Vec::new();
    let root = tree.root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_call" | "procedure_call_statement" => {
                if let Some(u) = call_usage(node, bytes, &pkg_lower) {
                    usages.push(u);
                }
            }
            // A type mark in a declaration: `V : Pkg.T`, `F (P : Pkg.T)`, a
            // component, a subtype/derived definition, or a return type. The type
            // is a DIRECT `selected_component`/`name` child (an init expression is
            // wrapped in its own `function_call`/`name`, not a bare child here).
            "object_declaration"
            | "component_declaration"
            | "parameter_specification"
            | "subtype_indication"
            | "derived_type_definition"
            | "subtype_declaration" => {
                if let Some(u) = type_position_ref(node, bytes, &pkg_lower) {
                    usages.push(u);
                }
            }
            // `raise Pkg.Some_Error;` or an exception handler `when Pkg.E =>`.
            "raise_statement" | "exception_choice" => {
                if let Some(u) = qualified_ref(node, bytes, &pkg_lower, UsageKind::Exception) {
                    usages.push(u);
                }
            }
            // A bare `Pkg.Const` / `Pkg.Enum_Literal` used as a value (e.g.
            // `if Kind = Pkg.JSON_Int_Type`). Only outermost qualified references
            // in a plain expression position — call names and type marks are
            // handled above and excluded here.
            "selected_component" => {
                if let Some(u) = value_ref(node, bytes, &pkg_lower) {
                    usages.push(u);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    usages
}

fn call_usage(
    node: tree_sitter::Node,
    bytes: &[u8],
    pkg_lower: &BTreeSet<String>,
) -> Option<Usage> {
    let is_function = node.kind() == "function_call";
    // The called name is the first `name`/`selected_component`/`identifier` child;
    // the arguments live in an `actual_parameter_part`.
    let mut name_node = None;
    let mut arity = 0usize;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "selected_component" | "name" | "identifier" if name_node.is_none() => {
                name_node = Some(child);
            }
            "actual_parameter_part" => {
                arity = count_actual_params(child);
            }
            _ => {}
        }
    }
    let (package, entity) = qualified_name(name_node?, bytes)?;
    if !pkg_lower.contains(&package.to_ascii_lowercase()) {
        return None;
    }
    Some(Usage {
        package,
        entity,
        kind: UsageKind::Call { arity, is_function },
    })
}

fn count_actual_params(part: tree_sitter::Node) -> usize {
    // Count top-level `,`-separated actuals: any named child that is not a
    // separator token. tree-sitter exposes each actual as a named child.
    let mut cursor = part.walk();
    part.named_children(&mut cursor).count()
}

fn qualified_ref(
    node: tree_sitter::Node,
    bytes: &[u8],
    pkg_lower: &BTreeSet<String>,
    kind: UsageKind,
) -> Option<Usage> {
    // Find a `selected_component` (Pkg.Entity) under this node.
    let sel = find_first(node, "selected_component")?;
    let (package, entity) = qualified_name(sel, bytes)?;
    if !pkg_lower.contains(&package.to_ascii_lowercase()) {
        return None;
    }
    Some(Usage {
        package,
        entity,
        kind,
    })
}

/// The type mark of a declaration: the FIRST direct-child `selected_component`
/// (an initializer expression is wrapped in its own `function_call`/`name`, so a
/// bare child here is the subtype mark) that qualifies an external package.
fn type_position_ref(
    node: tree_sitter::Node,
    bytes: &[u8],
    pkg_lower: &BTreeSet<String>,
) -> Option<Usage> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "selected_component" {
            continue;
        }
        let Some((package, entity)) = qualified_name(child, bytes) else {
            continue;
        };
        if pkg_lower.contains(&package.to_ascii_lowercase()) {
            return Some(Usage {
                package,
                entity,
                kind: UsageKind::Type,
            });
        }
    }
    None
}

/// A bare `Pkg.Entity` value reference (a constant or enum literal) in plain
/// expression position. Call names (parent `*_call`), type marks (the first
/// `selected_component` child of a declaration), and nested sub-names (parent
/// `selected_component`) are handled elsewhere and excluded here.
fn value_ref(node: tree_sitter::Node, bytes: &[u8], pkg_lower: &BTreeSet<String>) -> Option<Usage> {
    let parent = node.parent()?;
    match parent.kind() {
        "selected_component" | "function_call" | "procedure_call_statement" => return None,
        // Package names in context clauses, and exception names in handlers, are
        // handled elsewhere and must not become value constants.
        "with_clause" | "use_clause" | "use_package_clause" | "use_type_clause"
        | "exception_choice" | "raise_statement" => return None,
        "object_declaration"
        | "component_declaration"
        | "parameter_specification"
        | "subtype_indication"
        | "derived_type_definition"
        | "subtype_declaration" => {
            // The type mark is the first `selected_component` child; a later one
            // (an initializer value) still seeds as a value.
            if first_selected_component(parent).map(|c| c.id()) == Some(node.id()) {
                return None;
            }
        }
        _ => {}
    }
    let (package, entity) = qualified_name(node, bytes)?;
    if !pkg_lower.contains(&package.to_ascii_lowercase()) {
        return None;
    }
    Some(Usage {
        package,
        entity,
        kind: UsageKind::Value,
    })
}

fn first_selected_component(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let mut cursor = node.walk();
    let mut found = None;
    for child in node.children(&mut cursor) {
        if child.kind() == "selected_component" {
            found = Some(child);
            break;
        }
    }
    found
}

/// Extract `(Package, Entity)` from a `selected_component` (`A.B` or `A.B.C`).
/// The package is everything before the last `.`, the entity is the last leaf.
fn qualified_name(node: tree_sitter::Node, bytes: &[u8]) -> Option<(String, String)> {
    if node.kind() == "identifier" {
        return None; // unqualified — ambiguous, skip
    }
    let text = node.utf8_text(bytes).ok()?.trim();
    // Keep only a dotted-name shape (letters/digits/_/.), else skip.
    if text.is_empty()
        || !text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return None;
    }
    let (package, entity) = text.rsplit_once('.')?;
    if package.is_empty() || entity.is_empty() {
        return None;
    }
    Some((package.to_owned(), entity.to_owned()))
}

fn find_first<'a>(node: tree_sitter::Node<'a>, kind: &str) -> Option<tree_sitter::Node<'a>> {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if n.kind() == kind {
            return Some(n);
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

/// Parse a GNAT type note line, e.g.
///   `parser.adb:5:31: error: expected type "Gf_Stub" defined at vendorlib.ads:2`
///   `parser.adb:5:31: error: found type "Standard.String"`
/// Returns the quoted type spelling for the requested keyword (`expected`/`found`).
fn parse_type_note(line: &str, keyword: &str) -> Option<String> {
    let needle = format!("{keyword} type \"");
    parse_quoted_after(line, &needle)
}

/// The identifier in a GNAT `error: "X" is undefined` diagnostic.
fn undefined_identifier(line: &str) -> Option<String> {
    if !line.contains("is undefined") {
        return None;
    }
    let ident = parse_quoted_after(line, "error: \"")?;
    (!ident.is_empty() && ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then_some(ident)
}

/// The GNAT file stem in a diagnostic's leading `file.ads:line:col:` locus.
fn error_unit_stem(line: &str) -> Option<String> {
    let first = line.split(':').next()?.trim();
    let base = first.rsplit('/').next().unwrap_or(first);
    let stem = base
        .strip_suffix(".ads")
        .or_else(|| base.strip_suffix(".adb"))?;
    Some(stem.to_ascii_lowercase())
}

/// Extract the first double-quoted token following `prefix` in `line`.
fn parse_quoted_after(line: &str, prefix: &str) -> Option<String> {
    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// True when a GNAT diagnostic line reports an unnamed string type for the given
/// direction, e.g. `... error: found a string type` / `expected a string type`.
/// GNAT uses this form for string-literal actuals instead of a named type note.
fn is_string_type_note(line: &str, keyword: &str) -> bool {
    line.contains(&format!("{keyword} a string type"))
}

fn placeholder_of(ty: &str) -> Option<String> {
    let base = ty.rsplit('.').next().unwrap_or(ty).trim();
    base.starts_with(PLACEHOLDER_PREFIX)
        .then(|| base.to_owned())
}

/// Normalize a GNAT type spelling for use in a stub: drop a leading `Standard.`
/// (predefined types are directly visible) but keep other qualifications.
fn normalize_ada_type(ty: &str) -> String {
    ty.trim()
        .strip_prefix("Standard.")
        .unwrap_or(ty.trim())
        .to_owned()
}

/// GNAT crunched file stem for a unit name (`A.B` -> `a-b`).
fn ada_unit_stem(unit: &str) -> String {
    unit.to_ascii_lowercase()
        .chars()
        .map(|c| if c == '.' { '-' } else { c })
        .collect()
}

/// The GNAT file stem of the compilation unit a source declares, e.g. a source
/// with `package body SPAT.Preconditions` -> `spat-preconditions`. Used to match
/// a build error's filename back to the unit that produced it.
fn unit_stem_of_source(source: &str) -> Option<String> {
    for raw in source.lines() {
        let line = strip_ada_comment(raw).trim();
        let low = line.to_ascii_lowercase();
        let rest = low
            .strip_prefix("package body ")
            .or_else(|| low.strip_prefix("package "))
            .or_else(|| low.strip_prefix("private package "));
        if let Some(rest) = rest {
            // Original-case unit name at the same offset.
            let start = line.len() - rest.len();
            let name: String = line[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
                .collect();
            if !name.is_empty() {
                return Some(ada_unit_stem(&name));
            }
        }
    }
    None
}

/// Qualified type names named in `use [all] type <T>;` clauses (one per match).
fn use_all_type_targets(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in source.lines() {
        let line = strip_ada_comment(raw);
        let low = line.to_ascii_lowercase();
        // Accept `use type`, `use all type`, and a leading `for ... use` is not a
        // clause we care about (that has no `type` keyword after `use`).
        let Some(pos) = low.find("use ") else {
            continue;
        };
        let after = line[pos + 4..].trim_start();
        let after_low = after.to_ascii_lowercase();
        let after = after_low
            .strip_prefix("all type ")
            .map(|_| &after[9..])
            .or_else(|| after_low.strip_prefix("type ").map(|_| &after[5..]));
        let Some(after) = after else { continue };
        let name: String = after
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        if !name.is_empty() {
            out.push(name);
        }
    }
    out
}

/// Drop a trailing `--` Ada line comment.
fn strip_ada_comment(line: &str) -> &str {
    match line.find("--") {
        Some(i) => &line[..i],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkgset(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn use_all_type_plus_undefined_literals_infer_an_enumeration() {
        // A kind-discriminant enum: the client `use all type`s it and references
        // its literals; the stub starts numeric, then GNAT's `"X" is undefined`
        // errors supply the literal set so it becomes a real enumeration (fixing
        // the `array (T)` packed-index overflow too).
        let unit = "with GNATCOLL.JSON;\n\
                    package body Spat.Preconditions is\n\
                    use all type GNATCOLL.JSON.JSON_Value_Type;\n\
                    procedure Go is\n   begin\n null; end Go;\n\
                    end Spat.Preconditions;\n";
        let mut model = ExternalStubModel::default();
        assert!(model.seed_from_sources(&[unit.to_owned()], &pkgset(&["GNATCOLL.JSON"])));
        // Marked as an enumeration, but no literals yet -> renders numeric.
        let spec0 = model.render_spec("GNATCOLL.JSON", &model.packages["GNATCOLL.JSON"]);
        assert!(
            spec0.contains("type JSON_Value_Type is new Integer"),
            "no literals yet -> numeric fallback: {spec0}"
        );

        // GNAT reports the referenced literals as undefined in that unit.
        let out = "spat-preconditions.ads:21:09: error: \"JSON_Int_Type\" is undefined\n\
                   spat-preconditions.ads:22:09: error: \"JSON_Float_Type\" is undefined (more references follow)\n";
        assert!(model.refine_from_build_output(out));
        let spec1 = model.render_spec("GNATCOLL.JSON", &model.packages["GNATCOLL.JSON"]);
        assert!(
            spec1.contains("type JSON_Value_Type is (JSON_Int_Type, JSON_Float_Type)"),
            "literals form the enumeration: {spec1}"
        );
    }

    #[test]
    fn seeds_a_function_call_with_arity_and_converges_via_gnat_oracle() {
        let src = "with Vendorlib;\n\
                   package body Parser is\n\
                   function Parse (Data : String) return Integer is\n\
                   begin\n   return Vendorlib.Score (Data);\n   end Parse;\n\
                   end Parser;\n";
        let mut model = ExternalStubModel::default();
        assert!(model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorlib"])));

        // Seeded: Vendorlib.Score as a 1-arg function with placeholder types.
        let spec0 = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(spec0.contains("function Score"), "{spec0}");
        assert!(spec0.contains("P1 : Gf_Ext_Stub_0"), "{spec0}");
        assert!(spec0.contains("return Gf_Ext_Stub_1"), "{spec0}");

        // Refine param: GNAT says the arg it FOUND is a String where it expected
        // the placeholder -> param 0 is String.
        let round1 =
            "parser.adb:5:31: error: expected type \"Gf_Ext_Stub_0\" defined at vendorlib.ads:1\n\
                      parser.adb:5:31: error: found type \"Standard.String\"\n";
        assert!(model.refine_from_build_output(round1));
        let spec1 = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(spec1.contains("P1 : String"), "param resolved: {spec1}");
        assert!(
            spec1.contains("return Gf_Ext_Stub_1"),
            "return still placeholder: {spec1}"
        );

        // Refine return: GNAT says it expected Integer but FOUND the placeholder.
        let round2 = "parser.adb:5:23: error: expected type \"Standard.Integer\"\n\
                      parser.adb:5:23: error: found type \"Gf_Ext_Stub_1\" defined at vendorlib.ads:1\n";
        assert!(model.refine_from_build_output(round2));
        let spec2 = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(
            spec2.contains("function Score (P1 : String := \"\") return Integer"),
            "fully resolved (params default in spec): {spec2}"
        );
        // No placeholder types remain.
        assert!(
            !spec2.contains("Gf_Ext_Stub_"),
            "no placeholders left: {spec2}"
        );

        // The body returns a neutral value of the resolved type, and its profile
        // repeats the spec's parameter defaults (GNAT full-conformance rule).
        let body = render_body("Vendorlib", &model.packages["Vendorlib"]);
        assert!(body.contains("return Integer'First"), "{body}");
        assert!(
            body.contains("function Score (P1 : String := \"\") return Integer"),
            "body profile repeats spec defaults: {body}"
        );
    }

    #[test]
    fn seeds_a_type_reference_from_an_object_declaration() {
        let src = "with GNATCOLL.JSON;\n\
                   package body Client is\n\
                   procedure Go is\n      V : GNATCOLL.JSON.JSON_Value;\n   begin\n null; end Go;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["GNATCOLL.JSON"]));
        let spec = model.render_spec("GNATCOLL.JSON", &model.packages["GNATCOLL.JSON"]);
        assert!(spec.contains("type JSON_Value is new Integer"), "{spec}");
    }

    #[test]
    fn parse_type_note_extracts_quoted_spelling() {
        let line = "parser.adb:5:31: error: expected type \"Gf_Ext_Stub_0\" defined at x.ads:1";
        assert_eq!(
            parse_type_note(line, "expected").as_deref(),
            Some("Gf_Ext_Stub_0")
        );
        assert_eq!(parse_type_note(line, "found"), None);
    }

    #[test]
    fn string_literal_flips_a_stub_type_to_a_string_subtype() {
        // A stub `type UTF8_String is new Integer;` gets a string literal against
        // it: GNAT prints `found a string type` with no named type. The stub type
        // must become a String subtype.
        let src = "with GNATCOLL.JSON;\n\
                   package body Client is\n\
                   procedure Go is\n      V : GNATCOLL.JSON.UTF8_String;\n   begin\n null; end Go;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["GNATCOLL.JSON"]));
        let spec0 = model.render_spec("GNATCOLL.JSON", &model.packages["GNATCOLL.JSON"]);
        assert!(spec0.contains("type UTF8_String is new Integer"), "{spec0}");

        // The paired diagnostic: expected the (derived) stub type, found a string.
        let out = "client.adb:9:20: error: expected type \"UTF8_String\" defined at gnatcoll-json.ads:1\n\
                   client.adb:9:20: error: found a string type\n";
        assert!(model.refine_from_build_output(out));
        let spec1 = model.render_spec("GNATCOLL.JSON", &model.packages["GNATCOLL.JSON"]);
        assert!(spec1.contains("subtype UTF8_String is String"), "{spec1}");
        assert!(
            !spec1.contains("type UTF8_String is new Integer"),
            "{spec1}"
        );
    }

    #[test]
    fn string_literal_resolves_a_placeholder_slot_to_string() {
        // A call arg that is a string literal: the placeholder param resolves to
        // String even though GNAT reports `found a string type` (unnamed).
        let src = "with Vendorlib;\n\
                   package body Parser is\n\
                   procedure Go is\n   begin\n   Vendorlib.Emit (\"hello\");\n   end Go;\n\
                   end Parser;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorlib"]));
        let out =
            "parser.adb:5:19: error: expected type \"Gf_Ext_Stub_0\" defined at vendorlib.ads:1\n\
                   parser.adb:5:19: error: found a string type\n";
        assert!(model.refine_from_build_output(out));
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(spec.contains("P1 : String"), "{spec}");
        assert!(!spec.contains("Gf_Ext_Stub_"), "{spec}");
    }

    #[test]
    fn seeds_a_bare_value_reference_as_a_constant() {
        // `Pkg.Enum_Literal` in expression position (not a call, not a type mark)
        // becomes a stub constant so the reference resolves.
        let src = "with GNATCOLL.JSON;\n\
                   package body Client is\n\
                   function Is_Int (K : Integer) return Boolean is\n\
                   begin\n   return K = GNATCOLL.JSON.JSON_Int_Type;\n   end Is_Int;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        assert!(model.seed_from_sources(&[src.to_owned()], &pkgset(&["GNATCOLL.JSON"])));
        let spec = model.render_spec("GNATCOLL.JSON", &model.packages["GNATCOLL.JSON"]);
        assert!(spec.contains("JSON_Int_Type : constant Integer"), "{spec}");
    }

    #[test]
    fn a_call_name_is_not_double_seeded_as_a_value() {
        // `Pkg.Score (X)` must seed only the function, never also a same-named
        // constant (which would duplicate-declare).
        let src = "with Vendorlib;\n\
                   package body Parser is\n\
                   function Go (D : String) return Integer is\n\
                   begin\n   return Vendorlib.Score (D);\n   end Go;\n\
                   end Parser;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorlib"]));
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(spec.contains("function Score"), "{spec}");
        assert!(!spec.contains("Score : constant"), "{spec}");
    }
}
