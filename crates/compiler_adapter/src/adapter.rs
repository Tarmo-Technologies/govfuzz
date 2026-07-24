// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::CompilerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerKind {
    Gprbuild,
    Gnatmake,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ToolchainConfig {
    pub target: Option<String>,
    pub runtime: Option<String>,
    pub toolchain: Option<String>,
}

impl ToolchainConfig {
    pub fn compiler_prefix(&self) -> Option<&str> {
        self.toolchain.as_deref().or(self.target.as_deref())
    }

    fn prefixed_tool_name(&self, tool: &str) -> String {
        tool_name(self.compiler_prefix(), tool)
    }

    fn missing_tool_error(&self, missing: String) -> CompilerError {
        let toolchain = self
            .toolchain
            .clone()
            .or_else(|| self.target.clone())
            .unwrap_or_else(|| "default".to_owned());
        let target = self
            .target
            .clone()
            .or_else(|| self.toolchain.clone())
            .unwrap_or_else(|| "host".to_owned());

        CompilerError::TargetToolchainNotFound {
            toolchain,
            target,
            missing,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanaryCompilerKind {
    Gprbuild,
    Gnatmake,
    Gnat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerAdapter {
    gprbuild: Option<PathBuf>,
    gnatmake: Option<PathBuf>,
    gnat: Option<PathBuf>,
    toolchain: ToolchainConfig,
}

impl CompilerAdapter {
    pub fn with_binary(kind: CompilerKind, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        match kind {
            CompilerKind::Gprbuild => Self {
                gprbuild: Some(path),
                gnatmake: None,
                gnat: None,
                toolchain: ToolchainConfig::default(),
            },
            CompilerKind::Gnatmake => Self {
                gprbuild: None,
                gnatmake: Some(path),
                gnat: None,
                toolchain: ToolchainConfig::default(),
            },
        }
    }

    pub fn with_binaries(
        gprbuild: Option<PathBuf>,
        gnatmake: Option<PathBuf>,
        gnat: Option<PathBuf>,
        toolchain: ToolchainConfig,
    ) -> Self {
        Self {
            gprbuild,
            gnatmake,
            gnat,
            toolchain,
        }
    }

    pub fn discover() -> Result<Self, CompilerError> {
        Self::discover_for(ToolchainConfig::default())
    }

    pub fn discover_for(toolchain: ToolchainConfig) -> Result<Self, CompilerError> {
        let gprbuild_name = toolchain.prefixed_tool_name("gprbuild");
        let gnatmake_name = toolchain.prefixed_tool_name("gnatmake");
        let gnat_name = toolchain.prefixed_tool_name("gnat");
        let requires_prefixed_tools = toolchain.compiler_prefix().is_some();
        let gprbuild = which::which(&gprbuild_name).ok();
        let gnatmake = which::which(&gnatmake_name).ok();
        let gnat = which::which(&gnat_name).ok();
        let adapter = Self {
            gprbuild,
            gnatmake,
            gnat,
            toolchain,
        };

        if requires_prefixed_tools {
            if adapter.gprbuild.is_none() {
                return Err(adapter.toolchain.missing_tool_error(gprbuild_name));
            }
            if adapter.gnat.is_none() {
                return Err(adapter.toolchain.missing_tool_error(gnat_name));
            }
            return Ok(adapter);
        }

        if adapter.gprbuild.is_none() && adapter.gnatmake.is_none() {
            Err(CompilerError::NoCompilerFound)
        } else {
            Ok(adapter)
        }
    }

    pub fn gprbuild_path(&self) -> Option<&Path> {
        self.gprbuild.as_deref()
    }

    pub fn gnatmake_path(&self) -> Option<&Path> {
        self.gnatmake.as_deref()
    }

    pub fn gnat_path(&self) -> Option<&Path> {
        self.gnat.as_deref()
    }

    pub fn toolchain(&self) -> &ToolchainConfig {
        &self.toolchain
    }

    pub fn preferred_binary(&self) -> Option<&Path> {
        self.gprbuild.as_deref().or(self.gnatmake.as_deref())
    }

    pub fn preferred_kind(&self) -> Option<CompilerKind> {
        if self.gprbuild.is_some() {
            Some(CompilerKind::Gprbuild)
        } else if self.gnatmake.is_some() {
            Some(CompilerKind::Gnatmake)
        } else {
            None
        }
    }

    pub(crate) fn preferred_compiler(&self) -> Result<(CompilerKind, &Path), CompilerError> {
        match (self.preferred_kind(), self.preferred_binary()) {
            (Some(kind), Some(path)) => Ok((kind, path)),
            _ => Err(CompilerError::NoCompilerFound),
        }
    }

    pub(crate) fn canary_compiler(&self) -> Result<(CanaryCompilerKind, &Path), CompilerError> {
        if self.toolchain.compiler_prefix().is_some() {
            let gnat = self.gnat.as_deref().ok_or_else(|| {
                self.toolchain
                    .missing_tool_error(self.toolchain.prefixed_tool_name("gnat"))
            })?;
            return Ok((CanaryCompilerKind::Gnat, gnat));
        }

        match self.preferred_compiler()? {
            (CompilerKind::Gprbuild, path) => Ok((CanaryCompilerKind::Gprbuild, path)),
            (CompilerKind::Gnatmake, path) => Ok((CanaryCompilerKind::Gnatmake, path)),
        }
    }

    pub fn build(&self, project: &Path) -> Result<BuildResult, CompilerError> {
        self.run(project, BuildMode::Full)
    }

    pub fn check(&self, project: &Path) -> Result<BuildResult, CompilerError> {
        self.run(project, BuildMode::CheckOnly)
    }

    fn run(&self, project: &Path, mode: BuildMode) -> Result<BuildResult, CompilerError> {
        let bin = self.project_build_binary()?;
        let start = Instant::now();
        let mut command = Command::new(bin);
        command.arg("-P").arg(project);
        // Put the root project's OWN directory on gprbuild's project search path,
        // so a `.gpr` written next to it resolves a `with` regardless of the
        // process CWD. This is where govfuzz drops a synthesized stub project for a
        // missing external `with`ed import under --force (see build.rs / repair.rs
        // StubGprImport); without it the stub is only found when gprbuild happens
        // to run from that directory. Prepend to any inherited GPR_PROJECT_PATH so
        // real dependency paths still resolve.
        if let Some(project_dir) = project.parent() {
            let mut search_path = project_dir.as_os_str().to_os_string();
            if let Some(inherited) = std::env::var_os("GPR_PROJECT_PATH") {
                if !inherited.is_empty() {
                    search_path.push(":");
                    search_path.push(inherited);
                }
            }
            command.env("GPR_PROJECT_PATH", search_path);
        }
        if mode == BuildMode::CheckOnly {
            command.args(["-c", "-cargs", "-gnatc"]);
        }

        let output = command.output()?;
        let duration_ms = millis_u64(start.elapsed().as_millis());
        let exit_code = output.status.code().map_or(-1, |code| code);

        Ok(BuildResult {
            mode,
            exit_code,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration_ms,
        })
    }

    fn project_build_binary(&self) -> Result<&Path, CompilerError> {
        if let Some(path) = self.gprbuild.as_deref() {
            Ok(path)
        } else if self.gnatmake.is_some() {
            Err(CompilerError::ProjectBuildRequiresGprbuild)
        } else {
            Err(CompilerError::NoCompilerFound)
        }
    }
}

fn tool_name(prefix: Option<&str>, tool: &str) -> String {
    match prefix {
        Some(prefix) if prefix.ends_with('-') => format!("{prefix}{tool}"),
        Some(prefix) => format!("{prefix}-{tool}"),
        None => tool.to_owned(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMode {
    Full,
    CheckOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildResult {
    pub mode: BuildMode,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

fn millis_u64(milliseconds: u128) -> u64 {
    if milliseconds > u128::from(u64::MAX) {
        u64::MAX
    } else {
        milliseconds as u64
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::{CompilerAdapter, CompilerError};

    use super::CompilerKind;

    #[test]
    fn build_with_gnatmake_only_returns_project_build_requires_gprbuild() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let fake_gnatmake = write_strict_fake_gnatmake(temp.path());
        let adapter = CompilerAdapter::with_binary(CompilerKind::Gnatmake, fake_gnatmake.clone());

        assert_eq!(adapter.preferred_kind(), Some(CompilerKind::Gnatmake));
        assert_eq!(adapter.preferred_binary(), Some(fake_gnatmake.as_path()));

        let result = adapter.build(Path::new("anything.gpr"));

        assert!(matches!(
            result,
            Err(CompilerError::ProjectBuildRequiresGprbuild)
        ));
    }

    #[test]
    fn check_with_gprbuild_passes_dash_gnatc_via_dash_cargs() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let fake_gprbuild = write_strict_fake_gprbuild_check(temp.path());
        let adapter = CompilerAdapter::with_binary(CompilerKind::Gprbuild, fake_gprbuild);

        let result = adapter.check(Path::new("proj.gpr")).expect("check runs");

        assert_eq!(result.exit_code, 0, "{}", result.stderr);
    }

    fn write_strict_fake_gnatmake(dir: &Path) -> PathBuf {
        write_executable(
            dir,
            "gnatmake",
            r#"#!/bin/sh
printf '%s\n' 'gnatmake must not be invoked for project builds' >&2
exit 1
"#,
        )
    }

    fn write_strict_fake_gprbuild_check(dir: &Path) -> PathBuf {
        write_executable(
            dir,
            "gprbuild",
            r#"#!/bin/sh
if [ "$#" -eq 5 ] &&
   [ "$1" = "-P" ] &&
   [ "$2" = "proj.gpr" ] &&
   [ "$3" = "-c" ] &&
   [ "$4" = "-cargs" ] &&
   [ "$5" = "-gnatc" ]; then
  exit 0
fi

printf 'unexpected argv:' >&2
for arg in "$@"; do
  printf ' <%s>' "$arg" >&2
done
printf '\n' >&2
exit 1
"#,
        )
    }

    fn write_executable(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("fake compiler is written");
        make_executable(&path);
        path
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(path)
            .expect("fake compiler metadata is readable")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("fake compiler is executable");
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}
}
