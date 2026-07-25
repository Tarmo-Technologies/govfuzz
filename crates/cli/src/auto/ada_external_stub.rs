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

/// One formal parameter of a stubbed subprogram. `name` is `Some` when a call
/// site used a named association (`Help => "..."`), in which case the stub MUST
/// declare that exact name for the call to resolve; positional call sites leave
/// it `None` and the parameter renders as `P{i+1}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Param {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    ty: Slot,
}

impl Param {
    fn positional(ty: Slot) -> Self {
        Self { name: None, ty }
    }

    fn named(name: String, ty: Slot) -> Self {
        Self {
            name: Some(name),
            ty,
        }
    }

    /// The identifier to declare for the parameter at index `i`.
    fn declared_name(&self, i: usize) -> String {
        self.name.clone().unwrap_or_else(|| format!("P{}", i + 1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpStub {
    /// Display name (original case from the source).
    name: String,
    is_function: bool,
    params: Vec<Param>,
    /// `Some` for a function; the return type slot.
    ret: Option<Slot>,
}

impl OpStub {
    /// Every type slot in the profile: the parameters, then the return type.
    fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.params.iter().map(|p| &p.ty).chain(self.ret.iter())
    }
}

/// How strong the evidence behind a modeled formal is, so a second instantiation
/// only replaces it with something better.
///
/// A kind mismatch is a hard compile error, so a type or subprogram formal always
/// wins. Among formal OBJECTS, one typed by the generic's own formal type outranks
/// one typed concretely: `Default_Val : Arg_Type` satisfies every instance, whereas
/// `Default_Val : Float` (inferred from a `0.0` actual in one instantiation) breaks
/// the instance that passes a string-like actual.
fn formal_rank(formal: &Formal, formal_types: &BTreeSet<String>) -> u8 {
    match formal {
        Formal::Type { .. } => 8,
        Formal::Subprogram { .. } => 6,
        Formal::Object { ty, .. } => match ty {
            Slot::Placeholder(_) => 2,
            Slot::Resolved(spelling) => {
                let leaf = spelling
                    .rsplit('.')
                    .next()
                    .unwrap_or(spelling)
                    .to_ascii_lowercase();
                if formal_types.contains(&leaf) {
                    5
                } else {
                    4
                }
            }
        },
    }
}

/// The position encoded in a synthetic positional-formal name (`Gf_Formal_3` -> 2).
fn formal_index(name: &str) -> Option<usize> {
    name.strip_prefix(SYNTHETIC_FORMAL_PREFIX)?
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
}

/// Prefix of a synthesized name for a POSITIONAL generic formal (a named
/// association supplies the real name instead).
const SYNTHETIC_FORMAL_PREFIX: &str = "Gf_Formal_";

/// True when a parameter carries exactly this (case-insensitive) Ada name.
fn named_eq(param: &Param, name: &str) -> bool {
    param
        .name
        .as_deref()
        .is_some_and(|n| n.eq_ignore_ascii_case(name))
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
    /// `type X is tagged null record;` — required when a client makes a
    /// PREFIX-NOTATION call on an object of the type (`Object.Get (...)`), which Ada
    /// allows only for a tagged type.
    Tagged,
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

/// How to declare a generic formal type. Plain `is private` accepts any definite,
/// non-limited actual, which covers most real instantiations; each flag is turned
/// on only when GNAT rejects an actual for that specific reason. Both widen what
/// the formal accepts, so turning one on never invalidates an instantiation that
/// already worked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct FormalTypeForm {
    /// `type T (<>) is private;` — the actual is indefinite: an unconstrained
    /// array (`type Name is new String`), a class-wide type, or one with unknown
    /// discriminants.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    indefinite: bool,
    /// `type T is limited private;` — the actual cannot be copied.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    limited: bool,
}

impl FormalTypeForm {
    fn declaration(&self, name: &str) -> String {
        let discriminants = if self.indefinite { " (<>)" } else { "" };
        let limited = if self.limited { "limited " } else { "" };
        format!("type {name}{discriminants} is {limited}private;")
    }

    /// True when an uninitialized object of the formal type can be declared, which
    /// is how a stub body produces a value of it without raising.
    fn is_definite(&self) -> bool {
        !self.indefinite
    }
}

/// One generic formal parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Formal {
    /// `Short : String := "";`
    Object { name: String, ty: Slot },
    /// `type Arg_Type is private;`
    Type { name: String, form: FormalTypeForm },
    /// `with function Convert (Arg : String) return Arg_Type is <>;`
    Subprogram {
        name: String,
        is_function: bool,
        params: Vec<Param>,
        ret: Option<Slot>,
    },
}

impl Formal {
    fn name(&self) -> &str {
        match self {
            Formal::Object { name, .. }
            | Formal::Type { name, .. }
            | Formal::Subprogram { name, .. } => name,
        }
    }

    /// Every type slot this formal owns (for placeholder collection).
    fn slots(&self) -> Vec<&Slot> {
        match self {
            Formal::Object { ty, .. } => vec![ty],
            Formal::Type { .. } => Vec::new(),
            Formal::Subprogram { params, ret, .. } => {
                params.iter().map(|p| &p.ty).chain(ret.iter()).collect()
            }
        }
    }
}

/// A stubbed generic unit nested inside a stubbed package.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct GenericStub {
    /// Display name (original case), e.g. `Parse_Option`.
    name: String,
    /// `false` for a generic subprogram.
    is_package: bool,
    /// Formals in declaration order.
    formals: Vec<Formal>,
    /// Entities reached THROUGH an instance (`Project.Get` -> `ops["get"]`).
    inner: PkgStub,
    /// A generic subprogram's own profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    op: Option<OpStub>,
}

impl GenericStub {
    /// The names of this generic's formal types, lowercased.
    fn formal_type_names(&self) -> BTreeSet<String> {
        self.formals
            .iter()
            .filter_map(|f| match f {
                Formal::Type { name, .. } => Some(name.to_ascii_lowercase()),
                _ => None,
            })
            .collect()
    }

    /// The name of a formal object declared with type `ty`, if any. A stub body
    /// returns it to produce a value of an otherwise unconstructible formal type.
    fn formal_object_of_type(&self, ty: &str) -> Option<&str> {
        self.formals.iter().find_map(|f| match f {
            Formal::Object { name, ty: slot } if slot.spelling().eq_ignore_ascii_case(ty) => {
                Some(name.as_str())
            }
            _ => None,
        })
    }

    fn formal_type_form(&self, ty: &str) -> Option<FormalTypeForm> {
        self.formals.iter().find_map(|f| match f {
            Formal::Type { name, form } if name.eq_ignore_ascii_case(ty) => Some(*form),
            _ => None,
        })
    }
}

/// One instantiation of a stubbed generic, recorded so entities used through the
/// instance can be routed into the generic, and so a concrete type can be
/// generalized back to the formal it was passed for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct InstanceInfo {
    package: String,
    generic: String,
    /// Lowercased concrete type spelling -> the formal type name it was passed for.
    type_actuals: BTreeMap<String, String>,
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
    /// Generic units declared in this package, keyed by lowercased name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    generics: BTreeMap<String, GenericStub>,
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
    /// Lowercased instance alias (both the qualified and the simple name) -> the
    /// generic it instantiates.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    instances: BTreeMap<String, InstanceInfo>,
    /// Fingerprint of the (sources, packages) the model was last seeded from.
    ///
    /// Seeding tree-sitter-parses every staged source in the project. The repair
    /// loop calls it once per round, and a round rarely changes the sources at
    /// all — so the same hundred files were re-parsed up to the round cap for
    /// every target in a sweep. Seeding is a pure function of its inputs and only
    /// ever adds entities, so an unchanged fingerprint means an unchanged result
    /// and the parse can be skipped outright.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_seed_fingerprint: Option<u64>,
}

/// Which declarative region an entity belongs to: a stubbed package, or the
/// declarative part of a generic nested inside one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Region {
    Package(String),
    Generic { package: String, generic: String },
}

impl Region {
    fn package(&self) -> &str {
        match self {
            Region::Package(p) | Region::Generic { package: p, .. } => p,
        }
    }

    fn generic(&self) -> Option<&str> {
        match self {
            Region::Package(_) => None,
            Region::Generic { generic, .. } => Some(generic),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PlaceholderSlot {
    package: String,
    /// `Some` when the slot lives inside a generic nested in `package`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generic: Option<String>,
    site: SlotSite,
}

impl PlaceholderSlot {
    fn region(&self) -> Region {
        match &self.generic {
            Some(generic) => Region::Generic {
                package: self.package.clone(),
                generic: generic.clone(),
            },
            None => Region::Package(self.package.clone()),
        }
    }
}

/// Where in a region a placeholder-typed slot sits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SlotSite {
    /// A subprogram in the region's declarative part. `param` is `Some(i)` for
    /// parameter i and `None` for the return type.
    Op { op: String, param: Option<usize> },
    /// A generic formal object's type.
    FormalObject { name: String },
    /// A generic formal subprogram's profile.
    FormalSub { name: String, param: Option<usize> },
    /// The generic SUBPROGRAM's own profile.
    GenericOp { param: Option<usize> },
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

    /// Allocate a placeholder type naming one exact slot, so a compiler mismatch
    /// on that name resolves precisely that parameter / return / formal.
    fn fresh_placeholder_in(&mut self, region: &Region, site: SlotSite) -> String {
        let name = format!("{PLACEHOLDER_PREFIX}{}", self.next_placeholder);
        self.next_placeholder += 1;
        self.placeholders.insert(
            name.clone(),
            PlaceholderSlot {
                package: region.package().to_owned(),
                generic: region.generic().map(str::to_owned),
                site,
            },
        );
        name
    }

    /// The declarative region a stub entity lives in: a generic's inner part when
    /// the reference went through an instance alias, else the package itself.
    fn region_of(&self, package: &str) -> Region {
        match self.instances.get(&package.to_ascii_lowercase()) {
            Some(info) => Region::Generic {
                package: info.package.clone(),
                generic: info.generic.clone(),
            },
            None => Region::Package(self.canonical_package(package)),
        }
    }

    /// Fold a package name onto the spelling already in the model when one matches
    /// case-insensitively. Ada is case-insensitive and a missing unit's name reaches
    /// the model from two directions — a GNAT diagnostic (often folded from a file
    /// name) and the client source — so without this the SAME package can be keyed
    /// twice and the two stubs render to one file, each overwriting the other.
    fn canonical_package(&self, package: &str) -> String {
        self.packages
            .keys()
            .find(|known| known.eq_ignore_ascii_case(package))
            .cloned()
            .unwrap_or_else(|| package.to_owned())
    }

    fn region_stub(&self, region: &Region) -> Option<&PkgStub> {
        let pkg = self.packages.get(region.package())?;
        match region.generic() {
            None => Some(pkg),
            Some(generic) => pkg.generics.get(generic).map(|g| &g.inner),
        }
    }

    fn region_stub_mut(&mut self, region: &Region) -> Option<&mut PkgStub> {
        let pkg = self.packages.get_mut(region.package())?;
        match region.generic() {
            None => Some(pkg),
            Some(generic) => pkg.generics.get_mut(generic).map(|g| &mut g.inner),
        }
    }

    fn generic_mut(&mut self, package: &str, generic: &str) -> Option<&mut GenericStub> {
        self.packages.get_mut(package)?.generics.get_mut(generic)
    }

    /// Resolve a placeholder address to the slot it names.
    fn slot_at(&mut self, addr: &PlaceholderSlot) -> Option<&mut Slot> {
        let region = addr.region();
        match &addr.site {
            SlotSite::Op { op, param } => {
                let op = self.region_stub_mut(&region)?.ops.get_mut(op)?;
                match param {
                    Some(i) => op.params.get_mut(*i).map(|p| &mut p.ty),
                    None => op.ret.as_mut(),
                }
            }
            SlotSite::FormalObject { name } => {
                let generic = self.generic_mut(region.package(), region.generic()?)?;
                generic.formals.iter_mut().find_map(|f| match f {
                    Formal::Object { name: n, ty } if n.eq_ignore_ascii_case(name) => Some(ty),
                    _ => None,
                })
            }
            SlotSite::FormalSub { name, param } => {
                let generic = self.generic_mut(region.package(), region.generic()?)?;
                let formal = generic
                    .formals
                    .iter_mut()
                    .find(|f| f.name().eq_ignore_ascii_case(name))?;
                match formal {
                    Formal::Subprogram { params, ret, .. } => match param {
                        Some(i) => params.get_mut(*i).map(|p| &mut p.ty),
                        None => ret.as_mut(),
                    },
                    _ => None,
                }
            }
            SlotSite::GenericOp { param } => {
                let generic = self.generic_mut(region.package(), region.generic()?)?;
                let op = generic.op.as_mut()?;
                match param {
                    Some(i) => op.params.get_mut(*i).map(|p| &mut p.ty),
                    None => op.ret.as_mut(),
                }
            }
        }
    }

    /// Seed the model from the client SOURCE for the given external packages.
    /// Seed only when the (sources, packages) pair differs from the last seed.
    ///
    /// [`Self::seed_from_sources`] parses every staged source, and the repair loop
    /// calls it once per round even though a round usually changes nothing about
    /// them. Because seeding is idempotent and additive, re-running it on
    /// identical inputs can only return `false`, so skipping it is
    /// indistinguishable from running it — minus the parse.
    pub fn seed_from_sources_if_changed(
        &mut self,
        sources: &[String],
        packages: &BTreeSet<String>,
    ) -> bool {
        let fingerprint = seed_fingerprint(sources, packages);
        if self.last_seed_fingerprint == Some(fingerprint) {
            return false;
        }
        let changed = self.seed_from_sources(sources, packages);
        self.last_seed_fingerprint = Some(fingerprint);
        changed
    }

    /// Idempotent: only ADDS entities/ops it hasn't seen. Returns whether anything
    /// changed.
    pub fn seed_from_sources(&mut self, sources: &[String], packages: &BTreeSet<String>) -> bool {
        // Generics first: an instantiation registers an alias, and pass two routes
        // `Instance.Entity` uses into the generic instead of inventing a package.
        let mut changed = self.seed_generics(sources, packages);
        // Every alias is a package of interest for the usage scan.
        let mut of_interest = packages.clone();
        for info in self.instances.values() {
            of_interest.insert(info.package.clone());
        }
        of_interest.extend(self.instances.keys().cloned());
        // Units the CLIENT itself declares under a stubbed package's namespace. spat,
        // for instance, vendors `GNATCOLL.Opt_Parse.Extension`: a reference to it must
        // not be stubbed as a constant of `GNATCOLL.Opt_Parse`, which would be a
        // homograph of the real child unit.
        let client_units: BTreeSet<String> = sources
            .iter()
            .filter_map(|source| {
                crate::auto::ada_client_symbols::enclosing_unit_name(source)
                    .map(|unit| unit.to_ascii_lowercase())
            })
            .collect();
        // Leaf type name -> owning stubbed package, so a prefix-notation call on an
        // object of one can be attributed. Only types seen so far are known, which is
        // why this runs after the type-mark pass has had a round to seed them.
        let stub_types: BTreeMap<String, String> = self
            .packages
            .iter()
            .flat_map(|(package, stub)| {
                stub.types
                    .values()
                    .map(move |ty| (ty.name.to_ascii_lowercase(), package.clone()))
            })
            .collect();
        for source in sources {
            for usage in scan_ada_usages(source, &of_interest, &stub_types) {
                let qualified = format!("{}.{}", usage.package, usage.entity).to_ascii_lowercase();
                if client_units.contains(&qualified) {
                    continue;
                }
                changed |= self.apply_usage(usage);
            }
        }
        changed |= self.seed_enum_use_clauses(sources, packages);
        changed
    }

    /// Model every instantiation of a missing library's generic: register the
    /// instance alias and build the generic's formal part from the actuals.
    fn seed_generics(&mut self, sources: &[String], packages: &BTreeSet<String>) -> bool {
        use crate::auto::ada_generic_stub as gen;
        let known: BTreeSet<String> = packages
            .iter()
            .cloned()
            .chain(self.packages.keys().cloned())
            .collect();
        let instantiations: Vec<gen::Instantiation> = sources
            .iter()
            .flat_map(|source| gen::scan_instantiations(source, &known))
            .collect();
        if instantiations.is_empty() {
            return false;
        }
        let symbols = crate::auto::ada_client_symbols::ClientSymbols::from_sources(sources);
        let mut changed = false;
        // TWO passes, and the split matters: building a formal generalizes concrete
        // types against the type actuals of EVERY instance of that generic, so all
        // instances must be registered first. Otherwise the instantiation that
        // happens to be seen first bakes in its own concrete types (`Convert`
        // returning `Report_Mode` instead of `Arg_Type`) and the later, better
        // evidence cannot displace it.
        for inst in &instantiations {
            changed |= self.register_instance(inst, &symbols);
        }
        for inst in &instantiations {
            changed |= self.build_instantiation_formals(inst, &symbols);
        }
        changed
    }

    /// Declare the generic and record the instance alias plus its type actuals.
    fn register_instance(
        &mut self,
        inst: &crate::auto::ada_generic_stub::Instantiation,
        symbols: &crate::auto::ada_client_symbols::ClientSymbols,
    ) -> bool {
        use crate::auto::ada_generic_stub as gen;
        let key = inst.generic_key();
        let owner = self.canonical_package(&inst.owner);
        self.packages.entry(owner.clone()).or_default();
        let existed = self
            .packages
            .get(&owner)
            .is_some_and(|p| p.generics.contains_key(&key));
        if !existed {
            self.packages.get_mut(&owner).unwrap().generics.insert(
                key.clone(),
                GenericStub {
                    name: inst.generic.clone(),
                    is_package: inst.is_package,
                    ..GenericStub::default()
                },
            );
        }
        let mut type_actuals: BTreeMap<String, String> = BTreeMap::new();
        for (index, (named, actual)) in inst.actuals.iter().enumerate() {
            // Type-ness never depends on the overload choice, so an empty set is fine
            // here — the type actuals are exactly what this pass is collecting.
            if !matches!(
                gen::infer_formal_shape(actual, symbols, &BTreeSet::new()),
                gen::FormalShape::Type
            ) {
                continue;
            }
            let name = gen::formal_name(named.as_ref(), index);
            type_actuals.insert(actual.to_ascii_lowercase(), name.clone());
            if let Some(leaf) = actual.rsplit('.').next() {
                type_actuals.insert(leaf.to_ascii_lowercase(), name);
            }
        }
        // Register the alias under both the qualified and the simple name: a client
        // in the declaring unit refers to the instance without qualification.
        let info = InstanceInfo {
            package: owner,
            generic: key,
            type_actuals,
        };
        let mut changed = !existed;
        for alias in [
            inst.instance.to_ascii_lowercase(),
            inst.simple_name.to_ascii_lowercase(),
        ] {
            if self.instances.get(&alias) != Some(&info) {
                self.instances.insert(alias, info.clone());
                changed = true;
            }
        }
        changed
    }

    /// Build (or upgrade) the generic's formal part from one instantiation's actuals.
    fn build_instantiation_formals(
        &mut self,
        inst: &crate::auto::ada_generic_stub::Instantiation,
        symbols: &crate::auto::ada_client_symbols::ClientSymbols,
    ) -> bool {
        use crate::auto::ada_generic_stub as gen;
        let region = Region::Generic {
            package: self.canonical_package(&inst.owner),
            generic: inst.generic_key(),
        };
        // The type actuals of THIS instantiation select the right overload for a
        // subprogram actual, so gather them before building any formal.
        let type_actuals: BTreeSet<String> = self
            .instances
            .values()
            .filter(|info| {
                info.package == *region.package() && Some(info.generic.as_str()) == region.generic()
            })
            .flat_map(|info| info.type_actuals.keys().cloned())
            .collect();
        let mut changed = false;
        for (index, (named, actual)) in inst.actuals.iter().enumerate() {
            let name = gen::formal_name(named.as_ref(), index);
            let shape = gen::infer_formal_shape(actual, symbols, &type_actuals);
            changed |= self.declare_actual_of_stubbed_package(actual, &shape);
            changed |= self.merge_formal(&region, index, &name, shape);
        }
        changed
    }

    /// An actual can name an entity of a stubbed package itself — spat passes
    /// `Convert => GNATCOLL.Opt_Parse.Convert`. Nothing else references it, so
    /// without this the instantiation fails with `"Convert" not declared in
    /// "Opt_Parse"`. The formal it fills is modeled from the same evidence as any
    /// other actual, and declaring the entity to match keeps both sides consistent.
    fn declare_actual_of_stubbed_package(
        &mut self,
        actual: &str,
        shape: &crate::auto::ada_generic_stub::FormalShape,
    ) -> bool {
        use crate::auto::ada_generic_stub::FormalShape;
        // Only for an actual the client source could not explain: anything it DID
        // explain belongs to the client, not to the stubbed library.
        if !matches!(shape, FormalShape::OpaqueObject) {
            return false;
        }
        let Some((prefix, entity)) = actual.rsplit_once('.') else {
            return false;
        };
        let Some(owner) = self
            .packages
            .keys()
            .find(|p| p.eq_ignore_ascii_case(prefix))
            .cloned()
        else {
            return false;
        };
        let key = entity.to_ascii_lowercase();
        let stub = self.packages.get_mut(&owner).expect("owner just matched");
        if stub.ops.contains_key(&key)
            || stub.types.contains_key(&key)
            || stub.generics.contains_key(&key)
        {
            return false;
        }
        stub.consts.insert(key, entity.to_owned()).is_none()
    }

    /// Add (or upgrade) the generic's formal at `index`.
    ///
    /// Formals are keyed by NAME, so two instantiations naming the same formal
    /// share one declaration. Positional actuals are keyed by their synthetic name,
    /// which encodes the position, so they stay aligned. When two instantiations
    /// imply different kinds for one formal the more specific evidence wins (see
    /// [`gen::FormalShape::merge`]) — a kind mismatch cannot be repaired later,
    /// unlike a type mismatch, which the GNAT oracle fixes.
    fn merge_formal(
        &mut self,
        region: &Region,
        index: usize,
        name: &str,
        shape: crate::auto::ada_generic_stub::FormalShape,
    ) -> bool {
        let (package, generic) = match region {
            Region::Generic { package, generic } => (package.clone(), generic.clone()),
            Region::Package(_) => return false,
        };
        let existing = self
            .generic_mut(&package, &generic)
            .and_then(|g| g.formals.iter().position(|f| f.name() == name));
        // An existing formal only changes when the new evidence outranks it.
        if let Some(position) = existing {
            let current = self
                .generic_mut(&package, &generic)
                .map(|g| g.formals[position].clone());
            let Some(current) = current else {
                return false;
            };
            let candidate = self.build_formal(region, name, shape);
            let formal_types = self
                .packages
                .get(&package)
                .and_then(|p| p.generics.get(&generic))
                .map(GenericStub::formal_type_names)
                .unwrap_or_default();
            if formal_rank(&candidate, &formal_types) <= formal_rank(&current, &formal_types) {
                return false;
            }
            if let Some(g) = self.generic_mut(&package, &generic) {
                g.formals[position] = candidate;
                return true;
            }
            return false;
        }
        let formal = self.build_formal(region, name, shape);
        // Formals are declared in the order the actuals appear; a formal object
        // typed by a formal type must follow it, which that order preserves.
        if let Some(g) = self.generic_mut(&package, &generic) {
            let at = g
                .formals
                .iter()
                .position(|f| formal_index(f.name()).is_some_and(|i| i > index))
                .unwrap_or(g.formals.len());
            g.formals.insert(at, formal);
            return true;
        }
        false
    }

    fn build_formal(
        &mut self,
        region: &Region,
        name: &str,
        shape: crate::auto::ada_generic_stub::FormalShape,
    ) -> Formal {
        use crate::auto::ada_generic_stub::FormalShape;
        match shape {
            FormalShape::Type => Formal::Type {
                name: name.to_owned(),
                form: FormalTypeForm::default(),
            },
            FormalShape::Object(ty) => Formal::Object {
                name: name.to_owned(),
                ty: Slot::Resolved(self.generalize_in(region, &ty)),
            },
            FormalShape::OpaqueObject => {
                let ph = self.fresh_placeholder_in(
                    region,
                    SlotSite::FormalObject {
                        name: name.to_owned(),
                    },
                );
                Formal::Object {
                    name: name.to_owned(),
                    ty: Slot::Placeholder(ph),
                }
            }
            FormalShape::Subprogram(profile) => {
                let params = profile
                    .params
                    .iter()
                    .map(|(pname, pty)| {
                        Param::named(
                            pname.clone(),
                            Slot::Resolved(self.generalize_in(region, pty)),
                        )
                    })
                    .collect();
                let ret = profile
                    .ret
                    .as_ref()
                    .map(|r| Slot::Resolved(self.generalize_in(region, r)));
                Formal::Subprogram {
                    name: name.to_owned(),
                    is_function: profile.is_function,
                    params,
                    ret,
                }
            }
        }
    }

    /// [`Self::generalize`] for a region, used while BUILDING a generic: a formal
    /// object or subprogram profile mentioning a type that some instantiation
    /// passed as a type actual must name the formal instead of the concrete type.
    fn generalize_in(&self, region: &Region, ty: &str) -> String {
        let ty = strip_package_prefix(ty, region.package());
        match region {
            Region::Generic { package, generic } => self.generalize(package, generic, &ty),
            Region::Package(_) => ty,
        }
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
        // A reference through an instance alias (`SPAT.Command_Line.Project.Get`)
        // belongs in the GENERIC's declarative part, not in a package of its own.
        let region = self.region_of(&usage.package);
        if let Region::Package(package) = &region {
            self.packages.entry(package.clone()).or_default();
        }
        if self.region_stub(&region).is_none() {
            return false; // an instance of a generic that is no longer modeled
        }
        let op_key = usage.entity.to_ascii_lowercase();
        // A bare `Instance.Entity` read is nearly always a parameterless getter of
        // the instance (`Project.Get`), and modeling it as a function gives the
        // reference a REFINABLE return slot — a stub constant is always `Integer`
        // and could never be corrected to the instance's actual type.
        let kind = match (&usage.kind, &region) {
            (UsageKind::Value, Region::Generic { .. }) => UsageKind::Call {
                args: Vec::new(),
                is_function: true,
            },
            _ => usage.kind,
        };
        match kind {
            UsageKind::Call { args, is_function } => {
                let known = self
                    .region_stub(&region)
                    .is_some_and(|s| s.ops.contains_key(&op_key));
                if !known {
                    if let Some(stub) = self.region_stub_mut(&region) {
                        stub.ops.insert(
                            op_key.clone(),
                            OpStub {
                                name: usage.entity,
                                is_function,
                                params: Vec::new(),
                                ret: None,
                            },
                        );
                    }
                    // Parameters first, then the return: placeholder numbering then
                    // follows the profile's reading order.
                    self.merge_call_args(&region, &op_key, &args);
                    if is_function {
                        let ph = self.fresh_placeholder_in(
                            &region,
                            SlotSite::Op {
                                op: op_key.clone(),
                                param: None,
                            },
                        );
                        if let Some(op) = self.op_mut(&region, &op_key) {
                            op.ret = Some(Slot::Placeholder(ph));
                        }
                    }
                    return true;
                }
                self.merge_call_args(&region, &op_key, &args)
            }
            UsageKind::Type => {
                use std::collections::btree_map::Entry;
                let Some(types) = self.region_stub_mut(&region).map(|s| &mut s.types) else {
                    return false;
                };
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
            UsageKind::PrimitiveCall {
                type_name,
                args,
                is_function,
            } => {
                // The controlling operand comes FIRST (`Object.Get (F => X)` is
                // `Get (Object, F => X)`), and its type is what makes the call legal.
                let mut changed = false;
                if let Some(stub) = self.region_stub_mut(&region) {
                    if let Some(ty) = stub.types.get_mut(&type_name) {
                        if ty.form != TypeForm::Tagged {
                            ty.form = TypeForm::Tagged;
                            changed = true;
                        }
                    }
                    if !stub.ops.contains_key(&op_key) {
                        stub.ops.insert(
                            op_key.clone(),
                            OpStub {
                                name: usage.entity.clone(),
                                is_function,
                                params: Vec::new(),
                                ret: None,
                            },
                        );
                        changed = true;
                    }
                }
                let mut all_args = vec![None];
                all_args.extend(args);
                changed |= self.merge_call_args(&region, &op_key, &all_args);
                // Pin the controlling parameter to the tagged type itself.
                let controlling = self
                    .region_stub(&region)
                    .and_then(|s| s.types.get(&type_name))
                    .map(|ty| ty.name.clone());
                if let (Some(name), Some(op)) = (controlling, self.op_mut(&region, &op_key)) {
                    if let Some(first) = op.params.first_mut() {
                        if first.ty != Slot::Resolved(name.clone()) {
                            first.ty = Slot::Resolved(name);
                            changed = true;
                        }
                    }
                    if is_function && op.ret.is_none() {
                        changed = true;
                    }
                }
                if is_function
                    && self
                        .op_mut(&region, &op_key)
                        .is_some_and(|o| o.ret.is_none())
                {
                    let ph = self.fresh_placeholder_in(
                        &region,
                        SlotSite::Op {
                            op: op_key.clone(),
                            param: None,
                        },
                    );
                    if let Some(op) = self.op_mut(&region, &op_key) {
                        op.ret = Some(Slot::Placeholder(ph));
                    }
                }
                changed
            }
            UsageKind::Value => self
                .region_stub_mut(&region)
                .is_some_and(|s| s.consts.insert(op_key, usage.entity).is_none()),
            UsageKind::Exception => self
                .region_stub_mut(&region)
                .is_some_and(|s| s.exceptions.insert(op_key, usage.entity).is_none()),
        }
    }

    /// Fold one call site's actuals into an op's parameter list. Ada requires
    /// positional actuals to precede named ones, so the leading `None`s pin the
    /// positional arity and every named association contributes a parameter of
    /// that exact name. Different call sites are UNIONED (the widest arity, the
    /// union of names) because every parameter is defaulted, so a site that omits
    /// one still resolves. Returns whether the list grew.
    fn merge_call_args(&mut self, region: &Region, op_key: &str, args: &[Option<String>]) -> bool {
        let positional = args.iter().take_while(|a| a.is_none()).count();
        let named: Vec<&String> = args.iter().flatten().collect();
        let mut changed = false;
        // Grow the positional prefix. A parameter that some other site named
        // still counts as a slot here: an actual can be passed positionally to it
        // only if it comes first, which the prefix already guarantees.
        loop {
            let len = self.op_params_len(region, op_key);
            if len >= positional {
                break;
            }
            let ph = self.fresh_placeholder_in(
                region,
                SlotSite::Op {
                    op: op_key.to_owned(),
                    param: Some(len),
                },
            );
            if let Some(op) = self.op_mut(region, op_key) {
                op.params.push(Param::positional(Slot::Placeholder(ph)));
                changed = true;
            } else {
                break;
            }
        }
        for name in named {
            let already = self
                .op_mut(region, op_key)
                .is_some_and(|op| op.params.iter().any(|p| named_eq(p, name)));
            if already {
                continue;
            }
            let index = self.op_params_len(region, op_key);
            let ph = self.fresh_placeholder_in(
                region,
                SlotSite::Op {
                    op: op_key.to_owned(),
                    param: Some(index),
                },
            );
            if let Some(op) = self.op_mut(region, op_key) {
                op.params
                    .push(Param::named(name.clone(), Slot::Placeholder(ph)));
                changed = true;
            }
        }
        changed
    }

    fn op_mut(&mut self, region: &Region, op_key: &str) -> Option<&mut OpStub> {
        self.region_stub_mut(region)?.ops.get_mut(op_key)
    }

    fn op_params_len(&self, region: &Region, op_key: &str) -> usize {
        self.region_stub(region)
            .and_then(|s| s.ops.get(op_key))
            .map(|o| o.params.len())
            .unwrap_or(0)
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
        // 3c) A placeholder used with an operator that is not defined for a numeric
        //     derived type: `operator "NOT" not defined for type "Gf_Ext_Stub_13"`.
        //     The operator names the type the slot must have — a logical operator
        //     means Boolean (a stubbed predicate used in a condition), while the
        //     arithmetic and relational ones are satisfied by Integer.
        for line in &lines {
            let Some(operator) = parse_quoted_after(line, "operator \"") else {
                continue;
            };
            if !line.contains("not defined for type") {
                continue;
            }
            let Some(placeholder) = parse_quoted_after(line, "not defined for type \"") else {
                continue;
            };
            if placeholder_of(&placeholder).is_none() {
                continue;
            }
            let resolved = match operator.to_ascii_uppercase().as_str() {
                "NOT" | "AND" | "OR" | "XOR" => "Boolean",
                _ => "Integer",
            };
            changed |= self.resolve_from_pair(&placeholder, resolved);
        }
        // 3a) A binary operator whose operands disagree, e.g. a client adding a
        //     stubbed function's result to an Integer:
        //       invalid operand types for operator "+"
        //       left operand has type "Standard.Integer"
        //       right operand has type "Gf_Ext_Stub_1" defined at vendorx-doc.ads:4
        //     Same inference as an expected/found pair — the real operand names the
        //     placeholder's type — just a different diagnostic shape.
        for window in lines.windows(2) {
            let (Some(left), Some(right)) = (
                parse_quoted_after(window[0], "left operand has type \""),
                parse_quoted_after(window[1], "right operand has type \""),
            ) else {
                continue;
            };
            changed |= self.resolve_from_pair(&left, &right);
        }
        // 3b) A generic formal type whose declared form is too narrow for an actual.
        //     GNAT names the formal, so the exact declaration can be widened:
        //       actual for "Arg_Type" must be a definite subtype
        //       actual for non-limited "Arg_Type" cannot be a limited type
        for line in &lines {
            if let Some(formal) = parse_quoted_after(line, "actual for \"") {
                if line.contains("must be a definite subtype") {
                    changed |= self.widen_formal_type(&formal, |form| {
                        !std::mem::replace(&mut form.indefinite, true)
                    });
                }
            }
            if let Some(formal) = parse_quoted_after(line, "actual for non-limited \"") {
                if line.contains("cannot be a limited type") {
                    changed |= self.widen_formal_type(&formal, |form| {
                        !std::mem::replace(&mut form.limited, true)
                    });
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

    /// An identifier GNAT reports as undefined inside a CLIENT unit that is a CHILD
    /// of a stubbed package is a missing declaration of that stubbed PARENT.
    ///
    /// A child unit sees its parent's declarations without qualification, so such a
    /// reference carries no `Pkg.` prefix for the usage scanner (which only collects
    /// qualified references) to notice. spat vendors
    /// `GNATCOLL.Opt_Parse.Extension` itself and writes
    /// `Args : Parsed_Arguments := No_Parsed_Arguments`, naming two entities of the
    /// missing parent library with nothing to attach them to.
    ///
    /// GNAT reports the exact column, so the role is read off the source rather than
    /// guessed: an identifier in type-mark position (after `:`) becomes a type, one
    /// in default-value position (after `:=`) becomes a constant.
    pub fn refine_child_unit_undefined(&mut self, stderr: &str, sources: &[String]) -> bool {
        let by_stem: BTreeMap<String, &String> = sources
            .iter()
            .filter_map(|source| {
                crate::auto::ada_client_symbols::enclosing_unit_name(source)
                    .map(|unit| (ada_unit_stem(&unit), source))
            })
            .collect();
        let mut changed = false;
        for line in stderr.lines() {
            let Some(ident) = undefined_identifier(line) else {
                continue;
            };
            let Some(locus) = parse_locus(line) else {
                continue;
            };
            // The enumeration-literal rule (below) is more specific; leave its units
            // to it.
            if self
                .enum_use_sites
                .get(&locus.stem)
                .is_some_and(|sites| sites.len() == 1)
            {
                continue;
            }
            let unit = locus.stem.replace('-', ".");
            let Some(parent) = self.longest_stubbed_ancestor(&unit) else {
                continue;
            };
            let Some(source) = by_stem.get(&locus.stem) else {
                continue;
            };
            let Some(text) = source.lines().nth(locus.line.saturating_sub(1)) else {
                continue;
            };
            let key = ident.to_ascii_lowercase();
            let stub = self.packages.entry(parent.clone()).or_default();
            if stub.types.contains_key(&key)
                || stub.consts.contains_key(&key)
                || stub.ops.contains_key(&key)
            {
                continue;
            }
            let default_value_position = is_default_value_position(text, locus.column);
            if default_value_position {
                // Adopt it as a parameterless FUNCTION rather than a constant: the
                // value has to have the type of the declaration it defaults
                // (`Args : Parsed_Arguments := No_Parsed_Arguments`), and a stub
                // constant is hardwired to `Integer`. A function's RETURN slot is
                // refinable, so the expected/found oracle pins the real type — and a
                // parameterless call is a legal default expression.
                let region = Region::Package(parent.clone());
                let placeholder = self.fresh_placeholder_in(
                    &region,
                    SlotSite::Op {
                        op: key.clone(),
                        param: None,
                    },
                );
                let Some(stub) = self.packages.get_mut(&parent) else {
                    continue;
                };
                stub.ops.insert(
                    key,
                    OpStub {
                        name: ident,
                        is_function: true,
                        params: Vec::new(),
                        ret: Some(Slot::Placeholder(placeholder)),
                    },
                );
            } else {
                let Some(stub) = self.packages.get_mut(&parent) else {
                    continue;
                };
                stub.types.insert(
                    key,
                    TypeStub {
                        name: ident,
                        form: TypeForm::default(),
                        literals: Vec::new(),
                    },
                );
            }
            changed = true;
        }
        changed
    }

    /// The longest stubbed package that is a strict dotted ancestor of `unit`.
    fn longest_stubbed_ancestor(&self, unit: &str) -> Option<String> {
        self.packages
            .keys()
            .filter(|package| {
                let prefix = format!("{}.", package.to_ascii_lowercase());
                unit.to_ascii_lowercase().starts_with(&prefix)
            })
            .max_by_key(|package| package.len())
            .cloned()
    }

    /// Widen every formal type called `formal` so an actual GNAT rejected becomes
    /// acceptable. The diagnostic names only the formal, not its generic, so all
    /// same-named formals are widened; that is safe because both widenings only ADD
    /// accepted actuals (a `(<>)` formal still takes a definite actual, a `limited
    /// private` formal still takes a non-limited one).
    fn widen_formal_type(
        &mut self,
        formal: &str,
        mut widen: impl FnMut(&mut FormalTypeForm) -> bool,
    ) -> bool {
        let mut changed = false;
        for pkg in self.packages.values_mut() {
            for generic in pkg.generics.values_mut() {
                for f in generic.formals.iter_mut() {
                    if let Formal::Type { name, form } = f {
                        if name.eq_ignore_ascii_case(formal) {
                            changed |= widen(form);
                        }
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
    /// Resolve a parameter that a call site satisfies with `X'Access` — a
    /// callback — by declaring an access-to-subprogram type with `X`'s profile.
    ///
    /// GNAT reports the actual as `found type access to procedure "X"`, which
    /// names the client subprogram but not its profile; that comes from the
    /// client's own declaration of `X`.
    ///
    /// The recorded boundary here claimed such a profile is always written in
    /// CLIENT types the stub cannot name without a circular unit dependency.
    /// Reading a real case showed otherwise: a library's callback is written in
    /// the LIBRARY's types, which this model declares itself. So the profile is
    /// synthesized when every type in it is one the stub can name — a type it
    /// already stubs, or a predefined one — and declined otherwise, which is
    /// where the boundary genuinely is.
    pub fn refine_access_to_subprogram(&mut self, stderr: &str, sources: &[String]) -> bool {
        let symbols = crate::auto::ada_client_symbols::ClientSymbols::from_sources(sources);
        let lines: Vec<&str> = stderr.lines().collect();
        let mut changed = false;
        // GNAT prints the pair on CONSECUTIVE lines — `expected type "X"` then
        // `found type access to procedure "Y"` — never on one, so the placeholder
        // is read from the preceding line.
        for window in lines.windows(2) {
            let Some((kind, name)) = parse_access_to_subprogram_note(window[1]) else {
                continue;
            };
            let Some(expected) = parse_type_note(window[0], "expected") else {
                continue;
            };
            let Some(ph) = placeholder_of(&expected) else {
                continue;
            };
            let Some(slot) = self.placeholders.get(&ph).cloned() else {
                continue;
            };
            let Some(profile) = symbols
                .profiles_for(&name)
                .and_then(|profiles| profiles.first())
                .cloned()
            else {
                continue;
            };
            let Some(rendered) = self.render_access_profile(&slot.package, kind, &profile) else {
                // A profile naming a type this stub cannot declare is the real
                // boundary; leave the slot alone rather than emit something that
                // does not conform to the actual.
                continue;
            };
            // An ANONYMOUS access parameter, not a named library-level access
            // type. Ada's accessibility rule rejects `X'Access` when X is nested
            // more deeply than the access type — and a callback is very often a
            // subprogram declared inside the very body making the call, which is
            // exactly the case that motivated this. An anonymous access parameter
            // takes its accessibility from the parameter, so a nested subprogram
            // is legal; it is also how the real libraries declare these.
            changed |= self.resolve_from_pair(&expected, &format!("access {rendered}"));
        }
        changed
    }

    /// The `access procedure (...)` / `access function (...) return T` spelling
    /// for a client profile, or `None` when it names a type this stub cannot.
    fn render_access_profile(
        &self,
        package: &str,
        kind: AccessSubprogramKind,
        profile: &crate::auto::ada_client_symbols::SubProfile,
    ) -> Option<String> {
        let nameable = |ty: &str| -> Option<String> {
            let spelling = normalize_ada_type(ty);
            let leaf = spelling.rsplit('.').next().unwrap_or(&spelling);
            if is_predefined_ada_type(leaf) {
                return Some(leaf.to_owned());
            }
            // A type this model already stubs is nameable, and inside the owning
            // package it is named without qualification.
            self.type_owners()
                .get(&leaf.to_ascii_lowercase())
                .map(|owner| {
                    if owner.eq_ignore_ascii_case(package) {
                        leaf.to_owned()
                    } else {
                        format!("{owner}.{leaf}")
                    }
                })
        };
        let mut params = Vec::new();
        for (index, (name, ty)) in profile.params.iter().enumerate() {
            let spelled = nameable(ty)?;
            let name = if name.trim().is_empty() {
                format!("P{}", index + 1)
            } else {
                name.clone()
            };
            params.push(format!("{name} : {spelled}"));
        }
        let list = if params.is_empty() {
            String::new()
        } else {
            format!(" ({})", params.join("; "))
        };
        match kind {
            AccessSubprogramKind::Procedure => Some(format!("procedure{list}")),
            AccessSubprogramKind::Function => {
                let ret = nameable(profile.ret.as_deref()?)?;
                Some(format!("function{list} return {ret}"))
            }
        }
    }

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
        // A slot INSIDE a generic must be typed by a formal, not by one instance's
        // concrete actual, or a second instance of the same generic would conflict.
        let real = strip_package_prefix(&real, &slot.package);
        let real = match slot.generic.as_deref() {
            Some(generic) => self.generalize(&slot.package, generic, &real),
            None => real,
        };
        let Some(target) = self.slot_at(&slot) else {
            return false;
        };
        if target.is_placeholder() && target.spelling() == ph {
            *target = Slot::Resolved(real);
            self.placeholders.remove(&ph);
            return true;
        }
        false
    }

    /// Rewrite a concrete type to the generic formal it was passed for.
    ///
    /// `Project.Get` returns `SPAT.Subject_Name` and `Cut_Off.Get` returns
    /// `Duration`, but both instantiate `Parse_Option` with that type as its
    /// `Arg_Type` actual — so the single declaration inside the generic is
    /// `function Get return Arg_Type` and both instances are satisfied.
    ///
    /// No attribution to a particular instance is needed (and the GNAT diagnostic
    /// carries none): if every instance that passed this type passed it for the
    /// SAME formal, that formal is the answer. When instances disagree — two
    /// different formals got the same actual type — the concrete type is kept,
    /// since guessing would break one of them either way.
    fn generalize(&self, package: &str, generic: &str, concrete: &str) -> String {
        let formals = self.formals_for_actual(package, generic, concrete);
        match formals.len() {
            1 => formals.into_iter().next().unwrap_or_default(),
            _ => concrete.to_owned(),
        }
    }

    /// The formal type names that `concrete` was passed for, across every
    /// instantiation of this generic.
    fn formals_for_actual(&self, package: &str, generic: &str, concrete: &str) -> BTreeSet<String> {
        let key = concrete.to_ascii_lowercase();
        let leaf = key.rsplit('.').next().unwrap_or(&key).to_owned();
        self.instances
            .values()
            .filter(|info| info.package == package && info.generic == generic)
            .filter_map(|info| {
                info.type_actuals
                    .get(&key)
                    .or_else(|| info.type_actuals.get(&leaf))
                    .cloned()
            })
            .collect()
    }

    /// Render every stubbed package's `.ads` + `.adb` into `out_dir`.
    /// Returns the units whose CONTENT changed (or that did not exist yet). A unit
    /// whose text is already on disk is left untouched: rewriting it would move its
    /// timestamp and make gprbuild recompile it — and everything that depends on
    /// it — on a round where nothing about it actually changed. The returned list
    /// therefore doubles as the "did the stub set advance on disk" signal.
    pub fn render(&self, out_dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
        std::fs::create_dir_all(out_dir)?;
        let forms = self.type_forms();
        let mut written = Vec::new();
        fn write_if_changed(
            written: &mut Vec<std::path::PathBuf>,
            path: std::path::PathBuf,
            text: String,
        ) -> std::io::Result<()> {
            if std::fs::read_to_string(&path).is_ok_and(|current| current == text) {
                return Ok(());
            }
            std::fs::write(&path, text)?;
            written.push(path);
            Ok(())
        }
        // A child unit (`A.B`) needs its parent (`A`) to exist; synthesize an
        // empty spec for any ancestor package that isn't itself stubbed.
        for parent in self.ancestor_packages() {
            let stem = ada_unit_stem(&parent);
            write_if_changed(
                &mut written,
                out_dir.join(format!("{stem}.ads")),
                render_empty_parent_spec(&parent),
            )?;
        }
        for (package, stub) in &self.packages {
            let stem = ada_unit_stem(package);
            write_if_changed(
                &mut written,
                out_dir.join(format!("{stem}.ads")),
                self.render_spec(package, stub),
            )?;
            // A body is legal only when the spec requires one — i.e. it declares a
            // subprogram, or a nested generic that itself requires a body. A package
            // with only types/constants/exceptions must NOT have a body ("spec of
            // this package does not allow a body").
            let body_path = out_dir.join(format!("{stem}.adb"));
            if stub.ops.is_empty() && !stub.generics.values().any(generic_needs_body) {
                if body_path.exists() {
                    std::fs::remove_file(&body_path)?;
                    written.push(body_path);
                }
            } else {
                write_if_changed(&mut written, body_path, render_body(package, stub, &forms))?;
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

    /// Map every stubbed type's leaf name (lowercased) to how it is DECLARED, so a
    /// renderer can tell whether a value of it can be written at all. A tagged type
    /// has no `'First`, so a parameter of one takes no default.
    fn type_forms(&self) -> TypeForms {
        let mut forms = TypeForms::new();
        let mut collect = |stub: &PkgStub| {
            for ty in stub.types.values() {
                forms.insert(ty.name.to_ascii_lowercase(), ty.form);
            }
        };
        for stub in self.packages.values() {
            collect(stub);
            for generic in stub.generics.values() {
                collect(&generic.inner);
            }
        }
        forms
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
        for slot in stub_resolved_slots(stub) {
            let leaf = slot.rsplit('.').next().unwrap_or(slot);
            if let Some(owner) = owners.get(&leaf.to_ascii_lowercase()) {
                // Case-insensitively: a package must never `with` ITSELF, which Ada
                // rejects as a circular unit dependency.
                if !owner.eq_ignore_ascii_case(package) {
                    deps.insert(owner.as_str());
                }
            }
        }
        for dep in &deps {
            out.push_str(&format!("with {dep}; use {dep};\n"));
        }
        out.push_str(&format!("package {package} is\n"));
        // A generic's formal slots are declared in the ENCLOSING package: the
        // formal part is elaborated there, so a placeholder it names must be
        // visible before the generic.
        let mut formal_placeholders: BTreeSet<&str> = BTreeSet::new();
        for generic in stub.generics.values() {
            for formal in &generic.formals {
                for slot in formal.slots() {
                    if let Slot::Placeholder(name) = slot {
                        formal_placeholders.insert(name.as_str());
                    }
                }
            }
        }
        let forms = self.type_forms();
        out.push_str(&render_declarations(
            stub,
            "   ",
            &formal_placeholders,
            &forms,
        ));
        for generic in stub.generics.values() {
            out.push_str(&render_generic_spec(generic, &forms));
        }
        out.push_str(&format!("end {package};\n"));
        out
    }
}

/// Every resolved type spelling anywhere in a package stub, including inside its
/// generics, so the `with`/`use` set covers them all.
fn stub_resolved_slots(stub: &PkgStub) -> Vec<&str> {
    let mut slots: Vec<&Slot> = Vec::new();
    for op in stub.ops.values() {
        slots.extend(op.slots());
    }
    for generic in stub.generics.values() {
        for formal in &generic.formals {
            slots.extend(formal.slots());
        }
        for op in generic.inner.ops.values() {
            slots.extend(op.slots());
        }
        if let Some(op) = &generic.op {
            slots.extend(op.slots());
        }
    }
    slots
        .into_iter()
        .filter_map(|slot| match slot {
            Slot::Resolved(spelling) => Some(spelling.as_str()),
            Slot::Placeholder(_) => None,
        })
        .collect()
}

/// Render one declarative region — placeholder types, referenced types, constants,
/// exceptions, and subprogram declarations — at `indent`. Shared by a stubbed
/// package's spec and the declarative part of a generic nested inside it.
///
/// `skip_placeholders` names placeholders declared by an enclosing region, so a
/// generic does not redeclare the ones its own formal part uses.
fn render_declarations(
    stub: &PkgStub,
    indent: &str,
    skip_placeholders: &BTreeSet<&str>,
    forms: &TypeForms,
) -> String {
    let mut out = String::new();
    let mut placeholders: BTreeSet<&str> = BTreeSet::new();
    for op in stub.ops.values() {
        for slot in op.slots() {
            if let Slot::Placeholder(name) = slot {
                if !skip_placeholders.contains(name.as_str()) {
                    placeholders.insert(name.as_str());
                }
            }
        }
    }
    for ph in skip_placeholders.iter().chain(placeholders.iter()) {
        out.push_str(&format!("{indent}type {ph} is new Integer;\n"));
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
                "{indent}type {} is ({});\n",
                ty.name,
                ty.literals.join(", ")
            )),
            TypeForm::StringLike => {
                out.push_str(&format!("{indent}subtype {} is String;\n", ty.name))
            }
            TypeForm::Tagged => out.push_str(&format!(
                "{indent}type {} is tagged null record;\n",
                ty.name
            )),
            TypeForm::Numeric | TypeForm::Enumeration => {
                out.push_str(&format!("{indent}type {} is new Integer;\n", ty.name))
            }
        }
    }
    // Bare-value references: nullable constants. Skip any name that is also a
    // subprogram, type, exception, or generic in this package (a parameterless call
    // parsed as a bare name, or an exception also named in a plain expression) to
    // avoid a duplicate declaration.
    for (key, name) in &stub.consts {
        if stub.ops.contains_key(key)
            || stub.types.contains_key(key)
            || stub.exceptions.contains_key(key)
            || stub.generics.contains_key(key)
        {
            continue;
        }
        out.push_str(&format!("{indent}{name} : constant Integer := 0;\n"));
    }
    for name in stub.exceptions.values() {
        out.push_str(&format!("{indent}{name} : exception;\n"));
    }
    for op in stub.ops.values() {
        out.push_str(&format!("{indent}{};\n", op_signature(op, true, forms)));
    }
    out
}

/// Render a generic unit nested inside its owner package's spec.
///
/// It must be NESTED, not a child unit: the client only `with`s the owner package
/// (`with GNATCOLL.Opt_Parse;` then `is new GNATCOLL.Opt_Parse.Parse_Option`), and
/// a child unit would need a `with` of its own that the client does not have.
fn render_generic_spec(generic: &GenericStub, forms: &TypeForms) -> String {
    let mut out = String::new();
    out.push_str("   generic\n");
    for formal in &generic.formals {
        out.push_str(&format!(
            "      {}\n",
            render_formal(formal, generic, forms)
        ));
    }
    if generic.is_package {
        out.push_str(&format!("   package {} is\n", generic.name));
        out.push_str(&render_declarations(
            &generic.inner,
            "      ",
            &BTreeSet::new(),
            forms,
        ));
        out.push_str(&format!("   end {};\n", generic.name));
    } else {
        let op = generic.op.clone().unwrap_or_else(|| OpStub {
            name: generic.name.clone(),
            is_function: true,
            params: Vec::new(),
            ret: Some(Slot::Resolved("Integer".to_owned())),
        });
        out.push_str(&format!("   {};\n", op_signature(&op, true, forms)));
    }
    out
}

fn render_formal(formal: &Formal, generic: &GenericStub, forms: &TypeForms) -> String {
    match formal {
        Formal::Type { name, form } => form.declaration(name),
        Formal::Object { name, ty } => {
            let spelling = ty.spelling();
            // Default every formal object so an instantiation that omits it (the
            // real generic's own default) still resolves. A formal object of a
            // FORMAL type has no value to default to, so it stays required —
            // every instantiation that reaches here passed one anyway.
            match default_value_for_formal(spelling, generic, forms) {
                Some(value) => format!("{name} : {spelling} := {value};"),
                None => format!("{name} : {spelling};"),
            }
        }
        Formal::Subprogram {
            name,
            is_function,
            params,
            ret,
        } => {
            let op = OpStub {
                name: name.clone(),
                is_function: *is_function,
                params: params.clone(),
                ret: ret.clone(),
            };
            // `is <>` takes the matching visible subprogram when an instantiation
            // omits the actual; a formal procedure can additionally default to
            // `is null`, but `is <>` covers both uniformly.
            format!("with {} is <>;", op_signature(&op, false, forms))
        }
    }
}

/// A default for a generic formal object of `ty`, or `None` when no value of that
/// type can be written here — which is exactly the case where `ty` is one of this
/// generic's own formal types, whose actual is unknown until instantiation.
fn default_value_for_formal(ty: &str, generic: &GenericStub, forms: &TypeForms) -> Option<String> {
    let leaf = ty.rsplit('.').next().unwrap_or(ty).to_ascii_lowercase();
    if generic.formal_type_names().contains(&leaf) {
        return None;
    }
    writable_default(ty, forms)
}

/// An empty parent package so a stubbed child unit (`A.B`) has its parent (`A`).
///
/// It is `Preelaborate` because the diagnostic-driven Ada unit stubber marks the
/// children it synthesizes that way, and a preelaborated unit may not depend on a
/// non-preelaborated one — an unmarked parent makes the whole closure illegal. An
/// empty package with no dependencies and no elaboration code always qualifies.
fn render_empty_parent_spec(package: &str) -> String {
    format!(
        "--  SPDX-License-Identifier: Apache-2.0\n\
         --  Force-fuzz stub: synthesized parent package.\n\
         package {package} is\n   pragma Preelaborate;\nend {package};\n"
    )
}

fn render_body(package: &str, stub: &PkgStub, forms: &TypeForms) -> String {
    let mut out = String::new();
    out.push_str("--  SPDX-License-Identifier: Apache-2.0\n");
    out.push_str("--  Force-fuzz stub for a missing external library package.\n");
    out.push_str(&format!("package body {package} is\n"));
    for op in stub.ops.values() {
        out.push_str(&render_op_body(op, "   ", None, forms));
    }
    // A generic's body belongs in the ENCLOSING package body, since the generic is
    // declared in the enclosing spec.
    for generic in stub.generics.values() {
        if !generic_needs_body(generic) {
            continue;
        }
        if generic.is_package {
            out.push_str(&format!("   package body {} is\n", generic.name));
            for op in generic.inner.ops.values() {
                out.push_str(&render_op_body(op, "      ", Some(generic), forms));
            }
            out.push_str(&format!("   end {};\n", generic.name));
        } else if let Some(op) = &generic.op {
            out.push_str(&render_op_body(op, "   ", Some(generic), forms));
        }
    }
    out.push_str(&format!("end {package};\n"));
    out
}

/// True when a stubbed generic declares something that requires a body, which in
/// turn makes the enclosing package require one.
fn generic_needs_body(generic: &GenericStub) -> bool {
    match generic.is_package {
        true => !generic.inner.ops.is_empty(),
        false => generic.op.is_some(),
    }
}

/// One stub subprogram body. The profile must be FULLY conformant with the spec,
/// which requires repeating the identical parameter names and defaults
/// (GNAT RM 6.3.1).
fn render_op_body(
    op: &OpStub,
    indent: &str,
    generic: Option<&GenericStub>,
    forms: &TypeForms,
) -> String {
    let mut out = format!("{indent}{} is\n", op_signature(op, true, forms));
    if !op.is_function {
        out.push_str(&format!(
            "{indent}begin\n{indent}   null;\n{indent}end {};\n",
            op.name
        ));
        return out;
    }
    let ret = op.ret.as_ref().map(Slot::spelling).unwrap_or("Integer");
    match function_result(ret, generic, forms) {
        FunctionResult::Value(value) => {
            out.push_str(&format!(
                "{indent}begin\n{indent}   return {value};\n{indent}end {};\n",
                op.name
            ));
        }
        FunctionResult::UninitializedLocal => {
            // A formal private type has no writable literal, but it IS definite, so
            // an uninitialized object of it is a legal (if arbitrary) result.
            out.push_str(&format!(
                "{indent}   Gf_Result : {ret};\n{indent}begin\n{indent}   return Gf_Result;\n{indent}end {};\n",
                op.name
            ));
        }
        FunctionResult::Raise => {
            // Nothing of this type can be constructed here. An Ada 2012 raise
            // EXPRESSION needs no value at all, and the marker message tells the
            // crash oracle this fault is a stub, not a defect.
            out.push_str(&format!(
                "{indent}begin\n{indent}   return raise Program_Error with \"{}\";\n{indent}end {};\n",
                crate::auto::ada_body_stub::STUB_RAISE_MARKER,
                op.name
            ));
        }
    }
    out
}

/// How a stub function can produce a result of its return type.
enum FunctionResult {
    /// A literal / attribute value of the type.
    Value(String),
    /// Declare an uninitialized local of the type and return it.
    UninitializedLocal,
    /// No value can be written; raise instead.
    Raise,
}

fn function_result(ret: &str, generic: Option<&GenericStub>, forms: &TypeForms) -> FunctionResult {
    let Some(generic) = generic else {
        return match writable_default(ret, forms) {
            Some(value) => FunctionResult::Value(value),
            // A tagged stub type has no writable literal, but it IS definite.
            None => FunctionResult::UninitializedLocal,
        };
    };
    let leaf = ret.rsplit('.').next().unwrap_or(ret).to_ascii_lowercase();
    if !generic.formal_type_names().contains(&leaf) {
        return match writable_default(ret, forms) {
            Some(value) => FunctionResult::Value(value),
            None => FunctionResult::UninitializedLocal,
        };
    }
    // The return type is one of the generic's formal types. Returning a formal
    // OBJECT of that type is best: it is a real value the caller can use, so a
    // fuzz target reading the result does not immediately fault.
    if let Some(object) = generic.formal_object_of_type(ret) {
        return FunctionResult::Value(object.to_owned());
    }
    match generic.formal_type_form(ret) {
        Some(form) if form.is_definite() => FunctionResult::UninitializedLocal,
        _ => FunctionResult::Raise,
    }
}

fn op_signature(op: &OpStub, with_defaults: bool, forms: &TypeForms) -> String {
    let params = if op.params.is_empty() {
        String::new()
    } else {
        let ps: Vec<String> = op
            .params
            .iter()
            .enumerate()
            .map(|(i, param)| {
                let name = param.declared_name(i);
                let ty = param.ty.spelling();
                // Default every parameter (spec only) so call sites that omit a
                // trailing / optional argument (the real API's default params)
                // still resolve against the stub.
                match with_defaults.then(|| writable_default(ty, forms)).flatten() {
                    Some(value) => format!("{name} : {ty} := {value}"),
                    // No value of this type can be written (a tagged stub type), so
                    // the parameter stays required. Only a call that omits it breaks,
                    // and the controlling operand of a prefix call is never omitted.
                    None => format!("{name} : {ty}"),
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

/// Leaf type name (lowercased) -> how the stub declares it.
type TypeForms = BTreeMap<String, TypeForm>;

/// A default value for `ty`, or `None` when no value of it can be written — which is
/// the case for a TAGGED stub type: it has no `'First`, and an aggregate would have
/// to match a record definition the stub does not model.
fn writable_default(ty: &str, forms: &TypeForms) -> Option<String> {
    // An anonymous access-to-subprogram parameter (`access procedure (...)`) has
    // no `'First`; its neutral value is `null`.
    if is_anonymous_access_profile(ty) {
        return Some("null".to_owned());
    }
    let leaf = ty.rsplit('.').next().unwrap_or(ty).to_ascii_lowercase();
    match forms.get(&leaf) {
        Some(TypeForm::Tagged) => None,
        _ => Some(default_value(ty)),
    }
}

/// Whether a slot spelling is an anonymous access-to-subprogram profile rather
/// than a type NAME. Such a spelling is written straight into the parameter and
/// must not be treated as a name to qualify, default with `'First`, or `with`.
pub(crate) fn is_anonymous_access_profile(ty: &str) -> bool {
    let t = ty.trim_start();
    t.starts_with("access procedure") || t.starts_with("access function")
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
    Call {
        /// One entry per actual, in call order: `Some(name)` for a named
        /// association, `None` for a positional one.
        args: Vec<Option<String>>,
        is_function: bool,
    },
    Type,
    Value,
    Exception,
    /// A PREFIX-NOTATION call on an object of a stubbed type (`Object.Get (...)`,
    /// i.e. `Get (Object, ...)`). Ada allows this only for a TAGGED type, and the
    /// operation must be a primitive of it — so the type's declaration and the op's
    /// controlling first parameter both follow from the call.
    PrimitiveCall {
        /// The stubbed type the object is declared with (leaf name).
        type_name: String,
        args: Vec<Option<String>>,
        is_function: bool,
    },
}

/// Scan an Ada source with tree-sitter for uses of the given external packages:
/// `Pkg.Entity(args)` (call), `X : Pkg.T` (type), `Pkg.Const` (value), `raise
/// Pkg.E` (exception). Only qualified (`Pkg.Entity`) references are collected —
/// `use`-clause bare references are ambiguous and left to GNAT to surface.
fn scan_ada_usages(
    source: &str,
    packages: &BTreeSet<String>,
    stub_types: &BTreeMap<String, String>,
) -> Vec<Usage> {
    let Some(tree) = ada_parser::parse_with_tree_sitter(source) else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let pkg_lower: BTreeSet<String> = packages.iter().map(|p| p.to_ascii_lowercase()).collect();
    // Local objects/parameters, so `Object.Get (...)` can be traced to the stubbed
    // type `Object` is declared with.
    let locals = crate::auto::ada_client_symbols::local_object_types(source);
    let mut usages = Vec::new();
    let root = tree.root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_call" | "procedure_call_statement" => {
                if let Some(u) = call_usage(node, bytes, &pkg_lower) {
                    usages.push(u);
                } else if let Some(u) = primitive_call_usage(node, bytes, &locals, stub_types) {
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
    // A generic instantiation's actual list arrives as a `function_call` under the
    // instantiation's `generic_name` field, so the generic's own name would look
    // like a call of the stubbed package. Those are modeled as generics instead.
    if is_within_generic_instantiation(node) {
        return None;
    }
    // The called name is the first `name`/`selected_component`/`identifier` child;
    // the arguments live in an `actual_parameter_part`.
    let mut name_node = None;
    let mut args = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "selected_component" | "name" | "identifier" if name_node.is_none() => {
                name_node = Some(child);
            }
            "actual_parameter_part" => {
                args = actual_argument_names(child, bytes);
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
        kind: UsageKind::Call { args, is_function },
    })
}

/// A PREFIX-NOTATION call `Object.Op (...)` where `Object` is a local object or
/// parameter declared with a STUBBED type. Ada permits the form only for a tagged
/// type, so the call tells us both that the stub type must be tagged and that `Op` is
/// one of its primitives.
fn primitive_call_usage(
    node: tree_sitter::Node,
    bytes: &[u8],
    locals: &BTreeMap<String, String>,
    stub_types: &BTreeMap<String, String>,
) -> Option<Usage> {
    if is_within_generic_instantiation(node) {
        return None;
    }
    let is_function = node.kind() == "function_call";
    let mut name_node = None;
    let mut args = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "selected_component" | "name" | "identifier" if name_node.is_none() => {
                name_node = Some(child);
            }
            "actual_parameter_part" => args = actual_argument_names(child, bytes),
            _ => {}
        }
    }
    let (prefix, entity) = qualified_name(name_node?, bytes)?;
    // Only a SIMPLE prefix can be an object; a dotted one is a package path.
    if prefix.contains('.') {
        return None;
    }
    let declared = locals.get(&prefix.to_ascii_lowercase())?;
    let leaf = declared
        .rsplit('.')
        .next()
        .unwrap_or(declared)
        .to_ascii_lowercase();
    let package = stub_types.get(&leaf)?.clone();
    let type_name = leaf;
    Some(Usage {
        package,
        entity,
        kind: UsageKind::PrimitiveCall {
            type_name,
            args,
            is_function,
        },
    })
}

/// True when `node` sits inside a `generic_instantiation` (which owns its actual
/// list through a nested `function_call`).
pub(crate) fn is_within_generic_instantiation(node: tree_sitter::Node) -> bool {
    let mut current = node.parent();
    while let Some(n) = current {
        match n.kind() {
            "generic_instantiation" => return true,
            // Stop at the enclosing declaration/statement: an instantiation never
            // spans one, so anything above is irrelevant.
            "package_declaration" | "package_body" | "subprogram_body" => return false,
            _ => current = n.parent(),
        }
    }
    false
}

/// One entry per top-level actual, in call order: `Some(formal name)` for a named
/// association (`Help => "x"`), `None` for a positional one.
pub(crate) fn actual_argument_names(part: tree_sitter::Node, bytes: &[u8]) -> Vec<Option<String>> {
    let mut out = Vec::new();
    let mut cursor = part.walk();
    for child in part.children(&mut cursor) {
        if child.kind() == "parameter_association" {
            out.push(association_name(child, bytes));
        }
    }
    if out.is_empty() {
        // `actual_parameter_part` can hold a bare conditional/quantified
        // expression instead of associations; each named child is one actual.
        let mut cursor = part.walk();
        return part.named_children(&mut cursor).map(|_| None).collect();
    }
    out
}

/// The formal name of a `parameter_association`, i.e. the identifier before `=>`.
fn association_name(assoc: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let mut cursor = assoc.walk();
    let choice = assoc
        .children(&mut cursor)
        .find(|c| c.kind() == "component_choice_list")?;
    let text = choice.utf8_text(bytes).ok()?.trim();
    (!text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then(|| text.to_owned())
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
    // An instantiation actual is classified by the generic's formal kind (a type,
    // a subprogram, or an object), never blindly as a constant.
    if is_within_generic_instantiation(node) {
        return None;
    }
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
/// Which kind of subprogram a callback actual denotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessSubprogramKind {
    Procedure,
    Function,
}

/// Read GNAT's `found type access to procedure "X"` / `... function "X"`.
///
/// This is how a callback actual is reported: the diagnostic names the client
/// subprogram whose `'Access` was passed, and pairs it with the stub's
/// placeholder as the expected type on the same line.
fn parse_access_to_subprogram_note(line: &str) -> Option<(AccessSubprogramKind, String)> {
    let kind = if line.contains("access to procedure") {
        AccessSubprogramKind::Procedure
    } else if line.contains("access to function") {
        AccessSubprogramKind::Function
    } else {
        return None;
    };
    let marker = match kind {
        AccessSubprogramKind::Procedure => "access to procedure \"",
        AccessSubprogramKind::Function => "access to function \"",
    };
    Some((kind, parse_quoted_after(line, marker)?))
}

/// Whether a leaf type name is one Ada makes visible without any `with`, so a
/// synthesized profile may name it directly.
fn is_predefined_ada_type(leaf: &str) -> bool {
    const PREDEFINED: &[&str] = &[
        "boolean",
        "character",
        "duration",
        "float",
        "integer",
        "long_float",
        "long_integer",
        "natural",
        "positive",
        "string",
        "wide_character",
        "wide_string",
    ];
    PREDEFINED.contains(&leaf.to_ascii_lowercase().as_str())
}

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

/// A GNAT diagnostic's `file.ads:line:col:` position.
struct Locus {
    stem: String,
    line: usize,
    column: usize,
}

fn parse_locus(text: &str) -> Option<Locus> {
    let mut parts = text.split(':');
    let stem = error_unit_stem(text)?;
    parts.next()?; // file
    let line = parts.next()?.trim().parse::<usize>().ok()?;
    let column = parts.next()?.trim().parse::<usize>().ok()?;
    Some(Locus { stem, line, column })
}

/// True when the identifier at `column` (1-based) sits in DEFAULT-VALUE position —
/// i.e. the nearest declaration separator before it is `:=` rather than `:`. In
/// `Args : Parsed_Arguments := No_Parsed_Arguments`, the first name is a type mark
/// and the second is a value.
fn is_default_value_position(text: &str, column: usize) -> bool {
    let upto = &text[..text.len().min(column.saturating_sub(1))];
    let assign = upto.rfind(":=");
    let colon = upto.rfind(':').filter(|at| Some(*at) != assign);
    match (assign, colon) {
        (Some(a), Some(c)) => a > c,
        (Some(_), None) => true,
        _ => false,
    }
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

/// Drop a type's own package qualification when it is declared in the very package
/// being rendered. A fully expanded name that walks back in through the unit being
/// declared (`GNATCOLL.Opt_Parse.Argument_Parser` inside `GNATCOLL.Opt_Parse`) is at
/// best fragile; the simple name is directly visible there.
fn strip_package_prefix(ty: &str, package: &str) -> String {
    let prefix = format!("{package}.");
    if ty.len() > prefix.len() && ty[..prefix.len()].eq_ignore_ascii_case(&prefix) {
        let rest = &ty[prefix.len()..];
        // Only when what remains is a simple name; a deeper qualification names a
        // different (nested) unit and must keep its prefix.
        if !rest.contains('.') {
            return rest.to_owned();
        }
    }
    ty.to_owned()
}

/// Normalize a GNAT type spelling for use in a stub: drop a leading `Standard.`
/// (predefined types are directly visible) but keep other qualifications.
fn normalize_ada_type(ty: &str) -> String {
    ty.trim()
        .strip_prefix("Standard.")
        .unwrap_or(ty.trim())
        .to_owned()
}

/// Content hash of everything [`ExternalStubModel::seed_from_sources`] reads.
///
/// Content, not mtimes: the staged tree is rewritten between rounds (stub bodies
/// are overlaid onto it), so timestamps change even when the text does not. The
/// hash only has to detect change, never resist attack.
fn seed_fingerprint(sources: &[String], packages: &BTreeSet<String>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    sources.len().hash(&mut hasher);
    for source in sources {
        source.hash(&mut hasher);
    }
    for package in packages {
        package.hash(&mut hasher);
    }
    hasher.finish()
}

/// GNAT crunched file stem for a unit name (`A.B` -> `a-b`).
pub(crate) fn ada_unit_stem(unit: &str) -> String {
    unit.to_ascii_lowercase()
        .chars()
        .map(|c| if c == '.' { '-' } else { c })
        .collect()
}

/// The GNAT file stem of the compilation unit a source declares, e.g. a source
/// with `package body SPAT.Preconditions` -> `spat-preconditions`. Used to match
/// a build error's filename back to the unit that produced it.
fn unit_stem_of_source(source: &str) -> Option<String> {
    crate::auto::ada_client_symbols::enclosing_unit_name(source).map(|unit| ada_unit_stem(&unit))
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

    const SEED_SRC: &str = "with Vendorlib;\n\
                            package body Client is\n\
                            procedure Go is\n\
                            begin\n\
                            Vendorlib.Emit (\"a\", 2);\n\
                            end Go;\n\
                            end Client;\n";

    #[test]
    fn skipping_an_unchanged_seed_leaves_the_model_identical_to_seeding_it() {
        let sources = vec![SEED_SRC.to_owned()];
        let packages = pkgset(&["Vendorlib"]);

        let mut skipping = ExternalStubModel::default();
        skipping.seed_from_sources_if_changed(&sources, &packages);
        let after_first = skipping.render_spec("Vendorlib", &skipping.packages["Vendorlib"]);
        // Three more rounds that change nothing, as a repair loop would do.
        for _ in 0..3 {
            skipping.seed_from_sources_if_changed(&sources, &packages);
        }

        let mut always = ExternalStubModel::default();
        for _ in 0..4 {
            always.seed_from_sources(&sources, &packages);
        }

        assert_eq!(
            skipping.render_spec("Vendorlib", &skipping.packages["Vendorlib"]),
            always.render_spec("Vendorlib", &always.packages["Vendorlib"]),
            "skipping the re-seed must not change what the model produces"
        );
        assert_eq!(
            after_first,
            skipping.render_spec("Vendorlib", &skipping.packages["Vendorlib"]),
            "an unchanged tree must not move the model at all"
        );
    }

    #[test]
    fn an_unchanged_seed_reports_no_progress_so_the_repair_loop_can_stop() {
        let sources = vec![SEED_SRC.to_owned()];
        let packages = pkgset(&["Vendorlib"]);
        let mut model = ExternalStubModel::default();
        assert!(
            model.seed_from_sources_if_changed(&sources, &packages),
            "the first seed discovers the API and IS progress"
        );
        assert!(
            !model.seed_from_sources_if_changed(&sources, &packages),
            "an unchanged tree is not progress"
        );
    }

    #[test]
    fn changed_sources_are_seeded_again() {
        let packages = pkgset(&["Vendorlib"]);
        let mut model = ExternalStubModel::default();
        model.seed_from_sources_if_changed(&[SEED_SRC.to_owned()], &packages);
        let grown = SEED_SRC.replace(
            "Vendorlib.Emit (\"a\", 2);",
            "Vendorlib.Emit (\"a\", 2);\n Vendorlib.Flush;",
        );
        assert!(
            model.seed_from_sources_if_changed(&[grown], &packages),
            "a new call site must still be picked up"
        );
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(spec.contains("Flush"), "{spec}");
    }

    #[test]
    fn a_new_package_is_seeded_even_when_the_sources_are_identical() {
        // The source has always referenced both libraries; the repair loop only
        // learns the second one is missing on a later round. The tree it scans
        // has not changed, but the question being asked has — so the cache must
        // not suppress the re-seed.
        let source = "with Vendorlib;\nwith Otherlib;\n\
                      package body Client is\n\
                      procedure Go is\n\
                      begin\n\
                      Vendorlib.Emit (\"a\", 2);\n\
                      Otherlib.Store (\"b\");\n\
                      end Go;\n\
                      end Client;\n";
        let sources = vec![source.to_owned()];
        let mut model = ExternalStubModel::default();
        model.seed_from_sources_if_changed(&sources, &pkgset(&["Vendorlib"]));
        assert!(
            !model.packages.contains_key("Otherlib"),
            "not yet known to be missing, so not yet stubbed"
        );
        assert!(
            model.seed_from_sources_if_changed(&sources, &pkgset(&["Vendorlib", "Otherlib"])),
            "the package set is part of the seed input, not just the sources"
        );
        assert!(
            model.packages.contains_key("Otherlib"),
            "the newly-missing package must get stubbed on the round it is reported"
        );
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
        let body = render_body(
            "Vendorlib",
            &model.packages["Vendorlib"],
            &model.type_forms(),
        );
        assert!(body.contains("return Integer'First"), "{body}");
        assert!(
            body.contains("function Score (P1 : String := \"\") return Integer"),
            "body profile repeats spec defaults: {body}"
        );
    }

    #[test]
    fn named_call_arguments_become_the_stub_parameter_names() {
        // The GNATColl style: every actual is named. A positional `P1/P2` stub
        // draws `"Help" is not a parameter`, so the stub must declare the names
        // the call site uses.
        let src = "with GNATCOLL.Opt_Parse;\n\
                   package Client is\n\
                   P : GNATCOLL.Opt_Parse.Argument_Parser :=\n\
                     GNATCOLL.Opt_Parse.Create_Argument_Parser\n\
                       (Help => \"h\", Command_Name => \"run\");\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        assert!(model.seed_from_sources(&[src.to_owned()], &pkgset(&["GNATCOLL.Opt_Parse"])));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(
            spec.contains("Help : ") && spec.contains("Command_Name : "),
            "named actuals name the parameters: {spec}"
        );
        assert!(!spec.contains("P1 : "), "no positional fallback: {spec}");
        // The body profile must repeat the names and defaults verbatim.
        let body = render_body(
            "GNATCOLL.Opt_Parse",
            &model.packages["GNATCOLL.Opt_Parse"],
            &model.type_forms(),
        );
        let spec_line = spec
            .lines()
            .find(|l| l.contains("function Create_Argument_Parser"))
            .unwrap()
            .trim()
            .trim_end_matches(';');
        assert!(
            body.contains(spec_line),
            "body repeats the spec profile for full conformance:\n{spec_line}\n{body}"
        );
    }

    #[test]
    fn a_call_mixing_positional_and_named_actuals_orders_the_parameters() {
        // Ada requires positional actuals to precede named ones, so the leading
        // positionals pin slots 1..N and the named formal must follow them.
        let src = "with Vendorlib;\n\
                   package body Client is\n\
                   procedure Go is\n\
                   begin\n\
                      Vendorlib.Emit (\"a\", 2, Level => 3);\n\
                   end Go;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorlib"]));
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        let sig = spec
            .lines()
            .find(|l| l.contains("procedure Emit"))
            .unwrap_or_default();
        let p1 = sig
            .find("P1 : ")
            .unwrap_or_else(|| panic!("P1 missing: {sig}"));
        let p2 = sig
            .find("P2 : ")
            .unwrap_or_else(|| panic!("P2 missing: {sig}"));
        let level = sig
            .find("Level : ")
            .unwrap_or_else(|| panic!("Level missing: {sig}"));
        assert!(
            p1 < p2 && p2 < level,
            "named formal follows the positional prefix: {sig}"
        );
    }

    #[test]
    fn a_named_actual_is_only_added_once_across_call_sites() {
        let src = "with Vendorlib;\n\
                   package body Client is\n\
                   procedure Go is\n\
                   begin\n\
                      Vendorlib.Emit (Level => 1);\n\
                      Vendorlib.Emit (Level => 2);\n\
                   end Go;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorlib"]));
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert_eq!(
            spec.matches("Level : ").count(),
            1,
            "one parameter, not one per call site: {spec}"
        );
    }

    /// The spat / GNATColl `Opt_Parse` shape: two instantiations of one generic
    /// with different `Arg_Type` actuals, each read back through its instance.
    fn opt_parse_client() -> Vec<String> {
        // The option type, its null value, and its converter live in the ROOT unit,
        // and the instantiations in a child unit that qualifies them — the layout
        // real spat uses (`spat.ads` + `spat-command_line.ads`).
        let root = "package SPAT is\n\
             type Subject_Name is new String;\n\
             Null_Name : constant Subject_Name := \"\";\n\
             function To_Name (Source : in String) return Subject_Name;\n\
             end SPAT;\n";
        let spec = "with GNATCOLL.Opt_Parse;\n\
             package SPAT.Command_Line is\n\
             Parser : GNATCOLL.Opt_Parse.Argument_Parser :=\n\
               GNATCOLL.Opt_Parse.Create_Argument_Parser (Help => \"h\");\n\
             package Project is new GNATCOLL.Opt_Parse.Parse_Option\n\
               (Parser      => Parser,\n\
                Short       => \"-P\",\n\
                Arg_Type    => SPAT.Subject_Name,\n\
                Default_Val => SPAT.Null_Name,\n\
                Convert     => SPAT.To_Name);\n\
             package Cut_Off is new GNATCOLL.Opt_Parse.Parse_Option\n\
               (Parser      => Parser,\n\
                Short       => \"-p\",\n\
                Arg_Type    => Duration,\n\
                Default_Val => 0.0,\n\
                Convert     => Convert);\n\
             function Convert (Value : in String) return Duration;\n\
             end SPAT.Command_Line;\n";
        let user = "with SPAT.Command_Line;\n\
             package body Run_Spat is\n\
             procedure Go is\n\
                Name : constant SPAT.Subject_Name := SPAT.Command_Line.Project.Get;\n\
                Cut  : constant Duration := SPAT.Command_Line.Cut_Off.Get;\n\
             begin\n null;\n end Go;\n\
             end Run_Spat;\n";
        vec![root.to_owned(), spec.to_owned(), user.to_owned()]
    }

    #[test]
    fn a_generic_instantiation_is_stubbed_as_a_nested_generic() {
        let mut model = ExternalStubModel::default();
        assert!(model.seed_from_sources(&opt_parse_client(), &pkgset(&["GNATCOLL.Opt_Parse"])));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);

        // Nested inside the package, not a child unit: the client only `with`s
        // GNATCOLL.Opt_Parse.
        assert!(spec.contains("generic"), "{spec}");
        assert!(spec.contains("package Parse_Option is"), "{spec}");
        // Formal names come from the named associations; kinds from the client's
        // own declarations.
        assert!(spec.contains("type Arg_Type is private;"), "{spec}");
        assert!(spec.contains("Short : String"), "{spec}");
        assert!(
            spec.contains("Parser : Argument_Parser"),
            "formal object of a stubbed type: {spec}"
        );
        // The formal subprogram mirrors the client function's profile, with its
        // result generalized to the formal type. (An actual is matched to a formal
        // subprogram by profile, not by parameter name, so either client overload's
        // parameter name is fine here.)
        assert!(
            spec.contains("with function Convert (")
                && spec.contains(": String) return Arg_Type is <>;"),
            "formal subprogram mirrors the client profile, generalized: {spec}"
        );
        // `Default_Val => SPAT.Null_Name` is an object of Subject_Name, which THIS
        // instance passed as Arg_Type, so the formal must be typed by the formal.
        assert!(
            spec.contains("Default_Val : Arg_Type;"),
            "concrete actual generalized to the formal: {spec}"
        );
        // The generic must not also appear as a function of the package.
        assert!(
            !spec.contains("function Parse_Option"),
            "an instantiation is not a call: {spec}"
        );
    }

    #[test]
    fn two_instances_of_one_generic_converge_on_a_formal_typed_entity() {
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&opt_parse_client(), &pkgset(&["GNATCOLL.Opt_Parse"]));
        // `Project.Get` and `Cut_Off.Get` are the SAME entity inside the generic.
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert_eq!(
            spec.matches("function Get").count(),
            1,
            "one Get inside the generic: {spec}"
        );

        // GNAT reports the first instance's mismatch: Get returned the placeholder
        // where Subject_Name was expected.
        let ph = spec
            .split("function Get")
            .nth(1)
            .and_then(|rest| {
                rest.split_whitespace()
                    .find(|w| w.starts_with("Gf_Ext_Stub_"))
            })
            .map(|w| w.trim_end_matches(';').to_owned())
            .unwrap_or_else(|| panic!("Get should return a placeholder: {spec}"));
        let round = format!(
            "run_spat.adb:4:52: error: expected type \"Subject_Name\" defined at spat.ads:3\n\
             run_spat.adb:4:52: error: found type \"{ph}\" defined at gnatcoll-opt_parse.ads:9\n"
        );
        assert!(model.refine_from_build_output(&round));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(
            spec.contains("function Get") && spec.contains("return Arg_Type"),
            "resolved to the FORMAL, so the Duration instance also compiles: {spec}"
        );
        assert!(
            !spec.contains("return Subject_Name"),
            "must not bake in one instance's actual: {spec}"
        );

        // The generic's body returns the formal object of that type rather than
        // raising, so a fuzz target can use the result.
        let body = render_body(
            "GNATCOLL.Opt_Parse",
            &model.packages["GNATCOLL.Opt_Parse"],
            &model.type_forms(),
        );
        assert!(body.contains("package body Parse_Option is"), "{body}");
        assert!(
            body.contains("return Default_Val;"),
            "a formal object of Arg_Type is a real value: {body}"
        );
    }

    #[test]
    fn a_formal_typed_result_with_no_formal_object_uses_an_uninitialized_local() {
        // The generic has no `Default_Val`-like formal object, so no value of
        // `Element` can be written — but a definite formal private type still admits
        // an uninitialized object, which beats raising at run time.
        let src = "with Vendorlib;\n\
                   package Client is\n\
                   type Payload is new Integer;\n\
                   package Holder is new Vendorlib.Boxes (Element => Payload);\n\
                   function Peek return Payload is (Holder.Peek);\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorlib"]));
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(spec.contains("type Element is private;"), "{spec}");
        let ph = spec
            .split("function Peek")
            .nth(1)
            .and_then(|rest| {
                rest.split_whitespace()
                    .find(|w| w.starts_with(PLACEHOLDER_PREFIX))
            })
            .map(|w| w.trim_end_matches(';').to_owned())
            .unwrap_or_else(|| panic!("Peek should return a placeholder: {spec}"));

        // GNAT: Peek's result was used where the instance's actual was expected.
        let round = format!(
            "client.ads:5:38: error: expected type \"Payload\" defined at client.ads:3\n\
             client.ads:5:38: error: found type \"{ph}\" defined at vendorlib.ads:4\n"
        );
        assert!(model.refine_from_build_output(&round));
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(
            spec.contains("function Peek return Element"),
            "generalized to the formal type: {spec}"
        );
        let body = render_body(
            "Vendorlib",
            &model.packages["Vendorlib"],
            &model.type_forms(),
        );
        assert!(
            body.contains("Gf_Result : Element;") && body.contains("return Gf_Result;"),
            "definite formal private type -> uninitialized local: {body}"
        );
    }

    #[test]
    fn a_formal_is_generalized_against_every_instance_not_just_the_first_seen() {
        // The client declares two `Convert` overloads and instantiates the generic
        // twice. Whichever instantiation is visited first must NOT bake its own
        // concrete types into the shared formal part: `Convert`'s result and
        // `Default_Val`'s type both have to come out as the formal `Arg_Type`, or the
        // other instantiation cannot compile.
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&opt_parse_client(), &pkgset(&["GNATCOLL.Opt_Parse"]));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(
            spec.contains("return Arg_Type is <>;"),
            "the formal subprogram's result must be the formal type: {spec}"
        );
        assert!(
            spec.contains("Default_Val : Arg_Type;"),
            "the formal object's type must be the formal type: {spec}"
        );
        // Neither instance's concrete actual may appear in the formal part.
        let formal_part = spec
            .split("generic")
            .nth(1)
            .and_then(|s| s.split("package Parse_Option").next())
            .unwrap_or_default();
        for concrete in ["Subject_Name", "Duration", "Float"] {
            assert!(
                !formal_part.contains(concrete),
                "{concrete} is one instance's actual, not a shared formal: {formal_part}"
            );
        }
    }

    #[test]
    fn an_exception_also_read_as_a_value_is_declared_once() {
        // `Pkg.Some_Error` appears both in a handler (an exception) and in a plain
        // expression, which seeds it as a constant too. Declaring both is a duplicate
        // declaration that fails to compile.
        let src = "with Vendorlib;\n\
                   package body Client is\n\
                   procedure Go is\n\
                      Id : Integer := 0;\n\
                   begin\n\
                      Id := Vendorlib.Some_Error'Identity'Size;\n\
                   exception\n\
                      when Vendorlib.Some_Error => null;\n\
                   end Go;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorlib"]));
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert_eq!(
            spec.matches("Some_Error").count(),
            1,
            "declared once, as the exception: {spec}"
        );
        assert!(spec.contains("Some_Error : exception;"), "{spec}");
    }

    #[test]
    fn a_client_owned_child_unit_is_not_stubbed_as_a_constant() {
        // spat vendors `GNATCOLL.Opt_Parse.Extension` itself. Seeding `Extension` as a
        // constant of the stubbed parent would be a homograph of that real unit.
        let parent_use = "with GNATCOLL.Opt_Parse.Extension;\n\
                          package Client is\n\
                          X : Integer := GNATCOLL.Opt_Parse.Extension.Width;\n\
                          end Client;\n";
        let vendored = "package GNATCOLL.Opt_Parse.Extension is\n\
                        Width : constant Integer := 4;\n\
                        end GNATCOLL.Opt_Parse.Extension;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(
            &[parent_use.to_owned(), vendored.to_owned()],
            &pkgset(&["GNATCOLL.Opt_Parse"]),
        );
        // Nothing else in the closure needs stubbing, so the parent is not modeled at
        // all; if it were, it must still not declare `Extension`.
        let spec = model
            .packages
            .get("GNATCOLL.Opt_Parse")
            .map(|stub| model.render_spec("GNATCOLL.Opt_Parse", stub))
            .unwrap_or_default();
        assert!(
            !spec.contains("Extension"),
            "the client's own child unit must not be stubbed in its parent: {spec}"
        );
    }

    #[test]
    fn an_actual_naming_an_entity_of_the_stubbed_library_is_declared_there() {
        // spat writes `Convert => GNATCOLL.Opt_Parse.Convert`. Nothing else in the
        // client mentions that entity, so the stub must declare it or the
        // instantiation fails with `"Convert" not declared in "Opt_Parse"`.
        let src = "with Vendorgen.Opt;\n\
                   package Client is\n\
                   type Payload is new Integer;\n\
                   package Inst is new Vendorgen.Opt.Parse_List\n\
                     (Arg_Type => Payload, Convert => Vendorgen.Opt.Convert);\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorgen.Opt"]));
        let spec = model.render_spec("Vendorgen.Opt", &model.packages["Vendorgen.Opt"]);
        assert!(
            spec.contains("Convert : constant"),
            "the entity passed as an actual must exist in the stub: {spec}"
        );
        // And the formal it fills is an object, so the two sides agree.
        assert!(
            spec.contains("Convert : Gf_Ext_Stub_"),
            "formal object for an unexplainable actual: {spec}"
        );
    }

    #[test]
    fn a_prefix_notation_call_makes_the_stub_type_tagged_with_a_primitive() {
        // spat's `Object.Get (Field => ...)` on a `JSON_Value` parameter. Ada allows
        // the prefix form only for a TAGGED type, and only for a primitive whose
        // first parameter is that type — so a numeric handle stub cannot compile it.
        let src = "with Vendorx.Doc;\n\
                   package body Client is\n\
                   function Rule (Object : in Vendorx.Doc.Handle) return String is\n\
                   begin\n\
                      return Object.Get (Field => \"rule\");\n\
                   end Rule;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        // Round one seeds the TYPE from the parameter's type mark.
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorx.Doc"]));
        // Round two sees the prefix call now that the type is known.
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorx.Doc"]));
        let spec = model.render_spec("Vendorx.Doc", &model.packages["Vendorx.Doc"]);
        assert!(
            spec.contains("type Handle is tagged null record;"),
            "a prefix call requires a tagged type: {spec}"
        );
        let signature = spec
            .lines()
            .find(|line| line.contains("function Get"))
            .unwrap_or_default();
        assert!(
            signature.contains("P1 : Handle"),
            "the controlling operand comes first and is the tagged type: {signature}"
        );
        assert!(
            signature.contains("Field : "),
            "the named actual keeps its name: {signature}"
        );
        // A tagged type has no writable literal, so its parameter takes NO default.
        assert!(
            !signature.contains("P1 : Handle :="),
            "no default for a tagged parameter: {signature}"
        );
        // And a body returning one declares an uninitialized object rather than
        // attempting an aggregate.
        let body = render_body(
            "Vendorx.Doc",
            &model.packages["Vendorx.Doc"],
            &model.type_forms(),
        );
        assert!(body.contains("function Get"), "{body}");
    }

    #[test]
    fn a_logical_operator_resolves_a_placeholder_to_boolean() {
        // A stubbed predicate used in a condition: `if not Vendorx.Doc.Valid (D)`.
        // `not` is not defined for a numeric derived type, and the operator itself
        // says which type the slot must have.
        let src = "with Vendorx.Doc;\n\
                   package body Client is\n\
                   procedure Go (D : Integer) is\n\
                   begin\n   if not Vendorx.Doc.Valid (D) then\n null;\n end if;\n   end Go;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorx.Doc"]));
        let out = "client.adb:5:10: error: operator \"NOT\" not defined for type \"Gf_Ext_Stub_1\" defined at vendorx-doc.ads:7\n";
        assert!(model.refine_from_build_output(out));
        let spec = model.render_spec("Vendorx.Doc", &model.packages["Vendorx.Doc"]);
        assert!(
            spec.contains("return Boolean"),
            "a logical operator means the slot is Boolean: {spec}"
        );
    }

    #[test]
    fn an_operand_type_mismatch_resolves_a_placeholder() {
        // A client doing arithmetic on a stubbed function's result: GNAT reports the
        // two operand types instead of an expected/found pair, but the inference is
        // the same — the real operand names the placeholder's type.
        let src = "with Vendorx.Doc;\n\
                   package body Client is\n\
                   function Score (Input : String) return Integer is\n\
                   begin\n   return Input'Length + Vendorx.Doc.Weight (Input);\n   end Score;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorx.Doc"]));
        let out = "client.adb:5:25: error: invalid operand types for operator \"+\"\n\
                   client.adb:5:25: error: left operand has type \"Standard.Integer\"\n\
                   client.adb:5:25: error: right operand has type \"Gf_Ext_Stub_1\" defined at vendorx-doc.ads:4\n";
        assert!(model.refine_from_build_output(out));
        let spec = model.render_spec("Vendorx.Doc", &model.packages["Vendorx.Doc"]);
        assert!(
            spec.contains("return Integer"),
            "the placeholder result takes the other operand's type: {spec}"
        );
    }

    #[test]
    fn a_client_child_units_unqualified_names_are_declared_in_the_stubbed_parent() {
        // spat VENDORS `GNATCOLL.Opt_Parse.Extension`, whose spec names two entities
        // of the missing parent library with no qualification (a child unit sees its
        // parent's declarations). The qualified-reference scan cannot see those, so
        // GNAT's `is undefined` diagnostics are the only evidence — and its column
        // says which is a type and which is a value.
        let vendored = "package GNATCOLL.Opt_Parse.Extension is\n\
                        generic\n\
                           type Arg_Type is private;\n\
                        package Parse_Option_With_Default is\n\
                           function Get\n\
                             (Args : Parsed_Arguments := No_Parsed_Arguments) return Arg_Type;\n\
                        end Parse_Option_With_Default;\n\
                        end GNATCOLL.Opt_Parse.Extension;\n";
        let mut model = ExternalStubModel::default();
        // The parent package is being stubbed (a client elsewhere uses it).
        model.seed_from_sources(
            &["with GNATCOLL.Opt_Parse;\n\
                 package Client is\n\
                 P : GNATCOLL.Opt_Parse.Argument_Parser := GNATCOLL.Opt_Parse.Create;\n\
                 end Client;\n"
                .to_owned()],
            &pkgset(&["GNATCOLL.Opt_Parse"]),
        );

        let out = "gnatcoll-opt_parse-extension.ads:6:24: error: \"Parsed_Arguments\" is undefined\n\
                   gnatcoll-opt_parse-extension.ads:6:44: error: \"No_Parsed_Arguments\" is undefined\n";
        assert!(model.refine_child_unit_undefined(out, &[vendored.to_owned()]));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(
            spec.contains("type Parsed_Arguments"),
            "type-mark position -> a type: {spec}"
        );
        // A default VALUE must have the type of the declaration it defaults, which a
        // hardwired `constant Integer` cannot. It is adopted as a parameterless
        // function so its return slot stays refinable — a legal default expression.
        assert!(
            spec.contains("function No_Parsed_Arguments return Gf_Ext_Stub_"),
            "default-value position -> a refinable parameterless function: {spec}"
        );
        // Idempotent across rounds.
        assert!(!model.refine_child_unit_undefined(out, &[vendored.to_owned()]));

        // GNAT then reports the mismatch against the real type, and the oracle pins it.
        let round = "gnatcoll-opt_parse-extension.ads:6:44: error: expected type \"Parsed_Arguments\" defined at gnatcoll-opt_parse.ads:5\n\
                     gnatcoll-opt_parse-extension.ads:6:44: error: found type \"Gf_Ext_Stub_0\"\n";
        assert!(model.refine_from_build_output(round));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(
            spec.contains("function No_Parsed_Arguments return Parsed_Arguments"),
            "the default's type is learned from the oracle: {spec}"
        );
    }

    #[test]
    fn an_undefined_name_in_an_unrelated_unit_is_not_adopted() {
        // Only a unit that is a CHILD of a stubbed package may donate declarations to
        // it; an undefined name anywhere else is somebody else's problem.
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(
            &["with GNATCOLL.Opt_Parse;\n\
                 package Client is\n\
                 P : GNATCOLL.Opt_Parse.Argument_Parser := GNATCOLL.Opt_Parse.Create;\n\
                 end Client;\n"
                .to_owned()],
            &pkgset(&["GNATCOLL.Opt_Parse"]),
        );
        let unrelated = "package Spat.Other is\n   X : Integer := Typo_Name;\nend Spat.Other;\n";
        let out = "spat-other.ads:2:20: error: \"Typo_Name\" is undefined\n";
        assert!(!model.refine_child_unit_undefined(out, &[unrelated.to_owned()]));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(!spec.contains("Typo_Name"), "{spec}");
    }

    #[test]
    fn declaration_role_is_read_from_the_reported_column() {
        let text = "        (Args : Parsed_Arguments := No_Parsed_Arguments) return Arg_Type;";
        let type_col = text.find("Parsed_Arguments").expect("type mark") + 1;
        let value_col = text.find("No_Parsed_Arguments").expect("default") + 1;
        assert!(!is_default_value_position(text, type_col));
        assert!(is_default_value_position(text, value_col));
    }

    #[test]
    fn a_stub_package_never_withs_itself() {
        // The generic's formal object is typed by `Argument_Parser`, declared in the
        // very package being rendered. Emitting `with Vendorgen.Opt;` there is a
        // circular unit dependency that kills the whole build.
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&opt_parse_client(), &pkgset(&["GNATCOLL.Opt_Parse"]));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(
            !spec.contains("with GNATCOLL.Opt_Parse;"),
            "a package must not with itself: {spec}"
        );
        // The type is referred to by its simple name, which is directly visible.
        assert!(spec.contains("Parser : Argument_Parser"), "{spec}");
    }

    #[test]
    fn a_package_named_in_two_casings_is_modeled_once() {
        // A missing unit's name reaches the model from GNAT (often folded from a file
        // name, `vendorgen.opt`) and from the client source (`Vendorgen.Opt`). Keying
        // both would render two stubs to the SAME file, each overwriting the other —
        // silently dropping half the API.
        let src = "with Vendorgen.Opt;\n\
                   package Client is\n\
                   type Payload is new Integer;\n\
                   P : Vendorgen.Opt.Argument_Parser := Vendorgen.Opt.Create (Help => \"h\");\n\
                   package Inst is new Vendorgen.Opt.Parse_Option (Arg_Type => Payload);\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        // The missing-unit name arrives lowercased, as a GNAT diagnostic gives it.
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["vendorgen.opt"]));
        let keys: Vec<&str> = model.stubbed_packages().collect();
        assert_eq!(keys.len(), 1, "one package, not one per casing: {keys:?}");
        // Both the plain API and the generic land in that single stub.
        let stub = &model.packages[keys[0]];
        assert!(stub.ops.contains_key("create"), "{:?}", stub.ops.keys());
        assert!(
            stub.generics.contains_key("parse_option"),
            "{:?}",
            stub.generics.keys()
        );
        assert!(stub.types.contains_key("argument_parser"));
    }

    #[test]
    fn an_indefinite_actual_widens_the_formal_type() {
        // `type Subject_Name is new String` is INDEFINITE, which a plain `is private`
        // formal rejects. GNAT names the formal, so the declaration is widened.
        // (Message text verified against the local GNAT.)
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&opt_parse_client(), &pkgset(&["GNATCOLL.Opt_Parse"]));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(spec.contains("type Arg_Type is private;"), "{spec}");

        let out = "spat-command_line.ads:9:26: error: actual for \"Arg_Type\" must be a definite subtype\n";
        assert!(model.refine_from_build_output(out));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(spec.contains("type Arg_Type (<>) is private;"), "{spec}");
        // Idempotent: the same diagnostic in a later round is not "progress".
        assert!(!model.refine_from_build_output(out));
    }

    #[test]
    fn a_limited_actual_widens_the_formal_type_independently() {
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&opt_parse_client(), &pkgset(&["GNATCOLL.Opt_Parse"]));
        let out =
            "lim.ads:6:69: error: actual for non-limited \"Arg_Type\" cannot be a limited type\n";
        assert!(model.refine_from_build_output(out));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(spec.contains("type Arg_Type is limited private;"), "{spec}");
        // Both widenings compose: Ada allows `(<>) is limited private`.
        let indefinite = "x.ads:1:1: error: actual for \"Arg_Type\" must be a definite subtype\n";
        assert!(model.refine_from_build_output(indefinite));
        let spec = model.render_spec("GNATCOLL.Opt_Parse", &model.packages["GNATCOLL.Opt_Parse"]);
        assert!(
            spec.contains("type Arg_Type (<>) is limited private;"),
            "{spec}"
        );
    }

    #[test]
    fn an_indefinite_formal_result_falls_back_to_the_marked_raise() {
        // With no formal object of the type and an indefinite formal type, no object
        // can be declared either, so the body raises — with the marker that stops it
        // being reported as a finding.
        let src = "with Vendorlib;\n\
                   package Client is\n\
                   type Payload is new String;\n\
                   package Holder is new Vendorlib.Boxes (Element => Payload);\n\
                   function Peek return Payload is (Holder.Peek);\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["Vendorlib"]));
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        let ph = spec
            .split("function Peek")
            .nth(1)
            .and_then(|rest| {
                rest.split_whitespace()
                    .find(|w| w.starts_with(PLACEHOLDER_PREFIX))
            })
            .map(|w| w.trim_end_matches(';').to_owned())
            .unwrap_or_else(|| panic!("Peek should return a placeholder: {spec}"));
        let round = format!(
            "client.ads:5:38: error: expected type \"Payload\" defined at client.ads:3\n\
             client.ads:5:38: error: found type \"{ph}\" defined at vendorlib.ads:4\n\
             client.ads:4:47: error: actual for \"Element\" must be a definite subtype\n"
        );
        assert!(model.refine_from_build_output(&round));
        let body = render_body(
            "Vendorlib",
            &model.packages["Vendorlib"],
            &model.type_forms(),
        );
        assert!(
            body.contains(&format!(
                "return raise Program_Error with \"{}\"",
                crate::auto::ada_body_stub::STUB_RAISE_MARKER
            )),
            "indefinite formal type -> marked raise: {body}"
        );
        assert!(
            !body.contains("Gf_Result :"),
            "an object of an indefinite type is illegal: {body}"
        );
    }

    #[test]
    fn a_generic_subprogram_instantiation_is_stubbed_as_a_generic_subprogram() {
        let src = "with SI_Units.Metric;\n\
                   package body Client is\n\
                   function Image is new SI_Units.Metric.Fixed_Image (Item => Duration, Aft => 3);\n\
                   procedure Go is\n\
                      S : constant String := Image (1.0);\n\
                   begin\n null;\n end Go;\n\
                   end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[src.to_owned()], &pkgset(&["SI_Units.Metric"]));
        let spec = model.render_spec("SI_Units.Metric", &model.packages["SI_Units.Metric"]);
        assert!(spec.contains("generic"), "{spec}");
        assert!(
            spec.contains("type Item is private;"),
            "type actual -> formal type: {spec}"
        );
        assert!(spec.contains("Aft : Integer"), "{spec}");
        assert!(
            spec.contains("function Fixed_Image"),
            "a generic subprogram, not a package: {spec}"
        );
        assert!(
            !spec.contains("package Fixed_Image"),
            "must not be a generic package: {spec}"
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

#[cfg(test)]
mod access_to_subprogram_tests {
    //! A callback parameter — a call site passing `X'Access` — was recorded as a
    //! closed boundary: the claim was that such a profile is always written in
    //! CLIENT types a stub cannot name without a circular unit dependency.
    //!
    //! Reading a real consumer showed the premise is usually false. GNATColl's
    //! `Map_JSON_Object` takes a callback whose parameters are `UTF8_String` and
    //! `JSON_Value` — both types of GNATColl ITSELF, which the stub declares. The
    //! boundary is real only when the profile names something the stub cannot,
    //! and that case is declined rather than mis-declared.
    use super::*;

    fn pkgset(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// The shape of the real case: the client declares a local callback in the
    /// LIBRARY's types and passes it to a library operation.
    const CLIENT: &str = "with Vendorlib;\n\
                          package body Client is\n\
                          procedure Add_Time (Name  : Vendorlib.UTF8_String;\n\
                                              Value : Vendorlib.JSON_Value) is\n\
                          begin\n\
                             null;\n\
                          end Add_Time;\n\
                          procedure Go (Object : Vendorlib.JSON_Value) is\n\
                          begin\n\
                             Vendorlib.Map_Object (Object, Add_Time'Access);\n\
                          end Go;\n\
                          end Client;\n";

    fn seeded_model() -> ExternalStubModel {
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[CLIENT.to_owned()], &pkgset(&["Vendorlib"]));
        model
    }

    fn placeholder_for_second_param(model: &ExternalStubModel) -> String {
        let stub = &model.packages["Vendorlib"];
        let op = stub
            .ops
            .values()
            .find(|op| op.name.eq_ignore_ascii_case("Map_Object"))
            .expect("the call site seeded the operation");
        op.params[1].ty.spelling().to_owned()
    }

    #[test]
    fn a_callback_actual_becomes_an_access_to_subprogram_type() {
        let mut model = seeded_model();
        let placeholder = placeholder_for_second_param(&model);
        let stderr = format!(
            "client.adb:10:41: error: expected type \"{placeholder}\"\n\
             client.adb:10:41: error: found type access to procedure \"Add_Time\"\n"
        );

        assert!(
            model.refine_access_to_subprogram(&stderr, &[CLIENT.to_owned()]),
            "the callback parameter must be resolved, not left as a placeholder"
        );

        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        // An ANONYMOUS access parameter, not a named library-level access type.
        // Ada rejects `X'Access` when X is nested more deeply than the access
        // type, and a callback is usually declared inside the body making the
        // call — so a named type would compile here and fail on the real thing.
        assert!(
            spec.contains("access procedure (Name : UTF8_String; Value : JSON_Value)"),
            "the parameter must be an anonymous access-to-subprogram carrying the \
             client's profile: {spec}"
        );
        assert!(
            !spec.contains("is access procedure"),
            "no named access type may be declared — it would reintroduce the \
             accessibility rejection: {spec}"
        );
        assert!(
            spec.contains(":= null"),
            "an access parameter defaults to null, not to 'First: {spec}"
        );
    }

    #[test]
    fn a_profile_naming_an_unstubbable_type_is_declined() {
        // THIS is where the boundary really is: a callback written in a client
        // type the stub does not declare and cannot see. Emitting an access type
        // over some other type would not conform to the actual, so nothing is
        // emitted and the parameter stays unresolved.
        let client = "with Vendorlib;\n\
                      package body Client is\n\
                      procedure On_Row (Row : Client_Only_Record) is\n\
                      begin\n\
                         null;\n\
                      end On_Row;\n\
                      procedure Go is\n\
                      begin\n\
                         Vendorlib.Each (On_Row'Access);\n\
                      end Go;\n\
                      end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[client.to_owned()], &pkgset(&["Vendorlib"]));
        let stub = &model.packages["Vendorlib"];
        let op = stub
            .ops
            .values()
            .find(|op| op.name.eq_ignore_ascii_case("Each"))
            .expect("seeded");
        let placeholder = op.params[0].ty.spelling().to_owned();
        let stderr = format!(
            "client.adb:9:22: error: expected type \"{placeholder}\"\n\
             client.adb:9:22: error: found type access to procedure \"On_Row\"\n"
        );

        assert!(
            !model.refine_access_to_subprogram(&stderr, &[client.to_owned()]),
            "a profile the stub cannot name must be declined, not guessed at"
        );
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(
            !spec.contains("access procedure"),
            "nothing may be emitted for an unnameable profile: {spec}"
        );
    }

    #[test]
    fn a_callback_with_no_parameters_renders_a_bare_access_procedure() {
        let client = "with Vendorlib;\n\
                      package body Client is\n\
                      procedure Tick is\n\
                      begin\n\
                         null;\n\
                      end Tick;\n\
                      procedure Go is\n\
                      begin\n\
                         Vendorlib.At_Exit (Tick'Access);\n\
                      end Go;\n\
                      end Client;\n";
        let mut model = ExternalStubModel::default();
        model.seed_from_sources(&[client.to_owned()], &pkgset(&["Vendorlib"]));
        let op_placeholder = {
            let stub = &model.packages["Vendorlib"];
            let op = stub
                .ops
                .values()
                .find(|op| op.name.eq_ignore_ascii_case("At_Exit"))
                .expect("seeded");
            op.params[0].ty.spelling().to_owned()
        };
        let stderr = format!(
            "client.adb:9:25: error: expected type \"{op_placeholder}\"\n\
             client.adb:9:25: error: found type access to procedure \"Tick\"\n"
        );

        assert!(model.refine_access_to_subprogram(&stderr, &[client.to_owned()]));
        let spec = model.render_spec("Vendorlib", &model.packages["Vendorlib"]);
        assert!(
            spec.contains("access procedure := null"),
            "a parameterless callback takes no parameter list: {spec}"
        );
    }

    #[test]
    fn an_unrelated_diagnostic_pair_changes_nothing() {
        let mut model = seeded_model();
        let stderr = "client.adb:3:1: error: expected type \"Integer\"\n\
                      client.adb:3:1: error: found type \"String\"\n";
        assert!(!model.refine_access_to_subprogram(stderr, &[CLIENT.to_owned()]));
    }
}
