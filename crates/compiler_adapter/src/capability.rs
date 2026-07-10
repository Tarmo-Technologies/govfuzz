// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::AdaStandard;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use crate::adapter::CanaryCompilerKind;
use crate::{CompilerAdapter, CompilerError, ToolchainConfig};

static CAPABILITY_CACHE: OnceLock<Mutex<HashMap<CapabilityCacheKey, CompilerCapabilities>>> =
    OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CapabilityCacheKey {
    binary: PathBuf,
    toolchain: ToolchainConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerCapabilities {
    pub compiler_id: String,
    pub version: String,
    pub target: String,
    pub runtime: String,
    pub ada_standard_max: AdaStandard,
}

pub fn probe_compiler(adapter: &CompilerAdapter) -> Result<CompilerCapabilities, CompilerError> {
    let bin = adapter
        .preferred_binary()
        .ok_or(CompilerError::NoCompilerFound)?
        .to_path_buf();
    let cache_key = CapabilityCacheKey {
        binary: bin,
        toolchain: adapter.toolchain().clone(),
    };
    if let Some(capabilities) = cached_capabilities(&cache_key) {
        return Ok(capabilities);
    }

    let capabilities = probe_compiler_uncached(adapter)?;
    store_capabilities(cache_key, capabilities.clone());
    Ok(capabilities)
}

fn probe_compiler_uncached(
    adapter: &CompilerAdapter,
) -> Result<CompilerCapabilities, CompilerError> {
    let (_, bin) = adapter.preferred_compiler()?;
    let mut version_command = Command::new(bin);
    version_command.arg("--version");
    let version_output = output_with_executable_busy_retry(&mut version_command)?;
    let version_text = String::from_utf8_lossy(&version_output.stdout);
    let (compiler_id, version) = parse_version(&version_text)?;
    let (mut target, mut runtime) = parse_target_runtime(&version_text);
    if let Some(requested_target) = &adapter.toolchain().target {
        target = requested_target.clone();
    }
    if let Some(requested_runtime) = &adapter.toolchain().runtime {
        runtime = requested_runtime.clone();
    }
    let ada_standard_max = probe_max_ada_standard(adapter)?;

    Ok(CompilerCapabilities {
        compiler_id,
        version,
        target,
        runtime,
        ada_standard_max,
    })
}

pub(crate) fn parse_version(raw: &str) -> Result<(String, String), CompilerError> {
    let Some(first_line) = raw.lines().map(str::trim).find(|line| !line.is_empty()) else {
        return Err(CompilerError::UnparseableVersion {
            raw: raw.to_owned(),
        });
    };
    let version_re = Regex::new(
        r"(?i)\b(?:gprbuild\s+pro|gprbuild|gnatmake|gnat\s+pro|gnat)\b[^\d]*(\d+(?:\.\d+)+[[:alnum:]]*)",
    )
            .map_err(|_| CompilerError::UnparseableVersion {
                raw: raw.to_owned(),
            })?;
    let Some(captures) = version_re.captures(first_line) else {
        return Err(CompilerError::UnparseableVersion {
            raw: raw.to_owned(),
        });
    };
    let Some(version_match) = captures.get(1) else {
        return Err(CompilerError::UnparseableVersion {
            raw: raw.to_owned(),
        });
    };

    let version = version_match.as_str().to_owned();
    let compiler_id = compiler_id_for_line(first_line, &version);
    Ok((compiler_id, version))
}

pub(crate) fn parse_target_runtime(raw: &str) -> (String, String) {
    let mut target = "unknown".to_owned();
    let mut runtime = "unknown".to_owned();

    for line in raw.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("target:") {
            if let Some((_, value)) = line.split_once(':') {
                target = value.trim().to_owned();
            }
        } else if lower.starts_with("runtime:") {
            if let Some((_, value)) = line.split_once(':') {
                runtime = value.trim().to_owned();
            }
        }
    }

    (target, runtime)
}

fn compiler_id_for_line(first_line: &str, version: &str) -> String {
    let lower = first_line.to_ascii_lowercase();
    if lower.contains("gprbuild pro") {
        format!("AdaCore GPRbuild Pro {version}")
    } else if lower.contains("gprbuild") {
        format!("GPRbuild {version}")
    } else if lower.contains("gnat pro") {
        format!("AdaCore GNAT Pro {version}")
    } else if lower.contains("gnat") {
        format!("FSF GNAT {version}")
    } else {
        first_line.to_owned()
    }
}

fn probe_max_ada_standard(adapter: &CompilerAdapter) -> Result<AdaStandard, CompilerError> {
    let (kind, bin) = adapter.canary_compiler()?;

    for standard in ADA_STANDARDS_DESCENDING {
        if try_canary(kind, bin, standard)? {
            return Ok(standard);
        }
    }

    Err(CompilerError::CanaryFailed {
        stderr: "all Ada standard canaries failed".to_owned(),
    })
}

fn try_canary(
    kind: CanaryCompilerKind,
    bin: &Path,
    standard: AdaStandard,
) -> Result<bool, CompilerError> {
    let temp_dir = tempfile::TempDir::new()?;
    let canary_path = temp_dir.path().join("canary.adb");
    std::fs::write(&canary_path, canary_source())?;
    let dialect_switch = dialect_switch(standard);

    let output = match kind {
        CanaryCompilerKind::Gnatmake | CanaryCompilerKind::Gnat => {
            let mut command = Command::new(bin);
            command
                .args(["-c", "-gnatc", dialect_switch])
                .arg(&canary_path);
            output_with_executable_busy_retry(&mut command)?
        }
        CanaryCompilerKind::Gprbuild => {
            let project_path = temp_dir.path().join("canary.gpr");
            std::fs::create_dir(temp_dir.path().join("obj"))?;
            std::fs::write(&project_path, canary_project(dialect_switch))?;
            let mut command = Command::new(bin);
            command.arg("-P").arg(&project_path).arg("-c");
            output_with_executable_busy_retry(&mut command)?
        }
    };

    Ok(output.status.success())
}

fn output_with_executable_busy_retry(command: &mut Command) -> io::Result<Output> {
    const MAX_ATTEMPTS: usize = 4;

    for attempt in 0..MAX_ATTEMPTS {
        match command.output() {
            Ok(output) => return Ok(output),
            Err(error) if is_executable_busy(&error) && attempt + 1 < MAX_ATTEMPTS => {
                thread::sleep(Duration::from_millis(10 * (attempt as u64 + 1)));
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("retry loop returns on success or final error")
}

fn is_executable_busy(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ExecutableFileBusy || error.raw_os_error() == Some(26)
}

const ADA_STANDARDS_DESCENDING: [AdaStandard; 4] = [
    AdaStandard::Ada2022,
    AdaStandard::Ada2012,
    AdaStandard::Ada2005,
    AdaStandard::Ada95,
];

fn canary_project(dialect: &str) -> String {
    format!(
        "project Canary is\n   for Source_Dirs use (\".\");\n   for Object_Dir use \"obj\";\n   package Compiler is\n      for Default_Switches (\"Ada\") use (\"{dialect}\");\n   end Compiler;\nend Canary;\n"
    )
}

fn canary_source() -> &'static str {
    "procedure Canary is begin null; end Canary;\n"
}

fn dialect_switch(standard: AdaStandard) -> &'static str {
    match standard {
        AdaStandard::Ada83 => "-gnat83",
        AdaStandard::Ada95 => "-gnat95",
        AdaStandard::Ada2005 => "-gnat05",
        AdaStandard::Ada2012 => "-gnat12",
        AdaStandard::Ada2022 => "-gnat2022",
    }
}

fn cached_capabilities(key: &CapabilityCacheKey) -> Option<CompilerCapabilities> {
    let guard = cache_guard();
    guard.get(key).cloned()
}

fn store_capabilities(key: CapabilityCacheKey, capabilities: CompilerCapabilities) {
    let mut guard = cache_guard();
    guard.insert(key, capabilities);
}

fn cache_guard() -> MutexGuard<'static, HashMap<CapabilityCacheKey, CompilerCapabilities>> {
    let cache = CAPABILITY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::adapter::CompilerKind;
    use crate::CompilerAdapter;

    #[test]
    fn canary_for_gprbuild_creates_project_file_and_invokes_dash_p() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let fake_gprbuild = write_strict_fake_gprbuild(temp.path());
        let adapter = CompilerAdapter::with_binary(CompilerKind::Gprbuild, fake_gprbuild);

        let result = super::probe_max_ada_standard(&adapter);

        assert!(result.is_ok(), "expected canary to succeed; got {result:?}");
    }

    #[test]
    fn canary_for_gnatmake_invokes_raw_source_with_dialect_switch() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let fake_gnatmake = write_strict_fake_gnatmake(temp.path());
        let adapter = CompilerAdapter::with_binary(CompilerKind::Gnatmake, fake_gnatmake);

        let result = super::probe_max_ada_standard(&adapter);

        assert!(result.is_ok(), "expected canary to succeed; got {result:?}");
    }

    fn write_strict_fake_gprbuild(dir: &Path) -> PathBuf {
        write_executable(
            dir,
            "gprbuild",
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' 'GNATMAKE 13.2.0 20240106 (experimental)' 'Target: x86_64-pc-linux-gnu' 'Runtime: default'
  exit 0
fi

project=
compile_only=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -P)
      shift
      project=$1
      ;;
    -c)
      compile_only=1
      ;;
    -gnat*)
      printf '%s\n' 'dialect switch must not be passed as a top-level gprbuild arg' >&2
      exit 1
      ;;
  esac
  shift
done

case "$project" in
  */canary.gpr|canary.gpr) ;;
  *)
    printf 'expected -P canary.gpr, got <%s>\n' "$project" >&2
    exit 1
    ;;
esac

if [ "$compile_only" != "1" ]; then
  printf '%s\n' 'expected compile-only -c' >&2
  exit 1
fi
if [ ! -f "$project" ]; then
  printf 'project file does not exist: %s\n' "$project" >&2
  exit 1
fi
project_dir=${project%/*}
if [ "$project_dir" = "$project" ]; then
  project_dir=.
fi
if [ ! -f "$project_dir/canary.adb" ]; then
  printf '%s\n' 'canary.adb was not written next to canary.gpr' >&2
  exit 1
fi
if [ "$(/bin/cat "$project_dir/canary.adb")" != "procedure Canary is begin null; end Canary;" ]; then
  printf '%s\n' 'unexpected canary.adb body' >&2
  exit 1
fi
dialect_found=
while IFS= read -r line; do
  case "$line" in
    *'for Default_Switches ("Ada") use ("-gnat2022");'*)
      dialect_found=1
      ;;
  esac
done < "$project"
if [ "$dialect_found" != "1" ]; then
  printf '%s\n' 'dialect switch missing from canary.gpr' >&2
  exit 1
fi

exit 0
"#,
        )
    }

    fn write_strict_fake_gnatmake(dir: &Path) -> PathBuf {
        write_executable(
            dir,
            "gnatmake",
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' 'GNATMAKE 13.2.0 20240106 (experimental)' 'Target: x86_64-pc-linux-gnu' 'Runtime: default'
  exit 0
fi

if [ "$#" -eq 4 ] &&
   [ "$1" = "-c" ] &&
   [ "$2" = "-gnatc" ]; then
  case "$3" in
    -gnat*) ;;
    *)
      printf 'expected dialect switch, got <%s>\n' "$3" >&2
      exit 1
      ;;
  esac
  case "$4" in
    *.adb)
      if [ -f "$4" ] &&
         [ "$(/bin/cat "$4")" = "procedure Canary is begin null; end Canary;" ]; then
        exit 0
      fi
      ;;
  esac
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
        use std::io::Write;

        let path = dir.join(name);
        {
            let mut file = std::fs::File::create(&path).expect("fake compiler is created");
            file.write_all(contents.as_bytes())
                .expect("fake compiler is written");
            file.sync_all().expect("fake compiler is synced");
        }
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
