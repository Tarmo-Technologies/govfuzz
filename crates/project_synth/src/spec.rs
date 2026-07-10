// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::AdaStandard;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::ProjectSynthError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSpec {
    pub project_name: String,
    pub source_roots: Vec<SourceRoot>,
    pub object_dir: PathBuf,
    pub main_adb: Option<String>,
    pub ada_standard: AdaStandard,
    pub target: Option<String>,
    pub runtime: Option<String>,
    pub toolchain: Option<String>,
    pub switches: Switches,
    pub with_clauses: Vec<PathBuf>,
    /// When set, rename the `main_adb` main's executable to this name via a
    /// `Builder` package. Used so a `<parent>-gf_harness.adb` main still
    /// produces `obj/main`. `None` leaves GNAT's default (the main's base name).
    #[serde(default)]
    pub executable_name: Option<String>,
    /// Declare `C` alongside `Ada` in the generated project's `Languages` so
    /// gprbuild compiles + links the C glue many real Ada libraries bind to
    /// (gnatcoll's `gnatcoll_support.c` / `libc-wrappers.c`, GMP/zlib thin
    /// bindings, …). Set when the source dirs actually carry `.c` sources;
    /// left `false` keeps the historical Ada-only project for pure-Ada trees so
    /// a stray non-compiling `.c` can't break a build that worked before.
    #[serde(default)]
    pub compile_c: bool,
    /// C source *base names* to drop from the build via `Excluded_Source_Files`.
    /// gprbuild rejects two sources in one project that produce the same object
    /// file, so a same-stem Ada body/spec + C source in the closure (`sxxx.adb`
    /// and `sxxx.c` both -> `sxxx.o`) fails the whole project. The Ada unit is the
    /// harness target and wins; the colliding C file is excluded. Empty (the norm)
    /// emits no line, keeping the historical byte-for-byte output.
    #[serde(default)]
    pub excluded_source_files: Vec<String>,
}

impl ProjectSpec {
    pub fn validate(&self) -> Result<(), ProjectSynthError> {
        if is_ada_identifier(&self.project_name) {
            Ok(())
        } else {
            Err(ProjectSynthError::InvalidProjectName {
                name: self.project_name.clone(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRoot {
    pub path: PathBuf,
    pub language: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Switches {
    pub default: Vec<String>,
    pub debug: bool,
    pub warnings_as_errors: bool,
}

impl Default for Switches {
    fn default() -> Self {
        Self {
            default: vec!["-g".to_owned(), "-gnatwa".to_owned()],
            debug: true,
            warnings_as_errors: false,
        }
    }
}

fn is_ada_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    first.is_ascii_alphabetic()
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}
