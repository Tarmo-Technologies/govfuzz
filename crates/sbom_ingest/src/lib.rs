// SPDX-License-Identifier: Apache-2.0

//! Multi-language, evidence-graded SBOM component ingestion for GovFuzz.
//!
//! Offline, deterministic, untrusted-input-safe. Catalogers produce
//! `Component`s carrying an evidence ladder; the orchestrator (the
//! `governance` crate) merges, grades, and renders them.

mod evidence;

pub use evidence::{top_rung, usage_label, Evidence, EvidenceKind};

mod component;

pub use component::{Component, ComponentKey, HashRef};

mod merge;

pub use merge::merge_by_identity;

mod soname_map;

pub use soname_map::soname_to_library_name;

mod cataloger;

pub use cataloger::{CatalogContext, CatalogError, Cataloger};

mod license;

pub mod purl;

pub mod catalogers;

/// All built-in catalogers, in deterministic order.
pub fn registry() -> Vec<Box<dyn Cataloger>> {
    let mut v = catalogers::native_manifest::all();
    v.push(Box::new(catalogers::cargo::CargoCataloger));
    v.push(Box::new(catalogers::python::PythonCataloger));
    v.push(Box::new(catalogers::go::GoCataloger));
    v.push(Box::new(catalogers::npm::NpmLockCataloger));
    v.push(Box::new(catalogers::ruby::RubyCataloger));
    v.push(Box::new(catalogers::perl::PerlCataloger));
    v.push(Box::new(catalogers::php::PhpCataloger));
    v.push(Box::new(catalogers::maven::MavenCataloger));
    v.push(Box::new(catalogers::gradle::GradleCataloger));
    v.push(Box::new(catalogers::java_classpath::JavaClasspathCataloger));
    v.push(Box::new(catalogers::nuget::NugetCataloger));
    v.push(Box::new(catalogers::conan::ConanCataloger));
    v.push(Box::new(catalogers::vcpkg::VcpkgCataloger));
    v.push(Box::new(catalogers::alire::AlireCataloger));
    v.push(Box::new(catalogers::c_source::CSourceCataloger));
    v.push(Box::new(catalogers::ada_source::AdaSourceCataloger));
    v.push(Box::new(catalogers::meson::MesonCataloger));
    v.push(Box::new(catalogers::cmake::CMakeCataloger));
    v
}
