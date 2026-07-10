// SPDX-License-Identifier: Apache-2.0

pub use adapter::{BuildMode, BuildResult, CompilerAdapter, CompilerKind, ToolchainConfig};
pub use capability::{probe_compiler, CompilerCapabilities};
pub use error::CompilerError;

pub mod adapter;
pub mod capability;
pub mod error;

pub fn crate_name() -> &'static str {
    "compiler_adapter"
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use ada_parser::ast::AdaStandard;

    use crate::capability::{parse_target_runtime, parse_version};
    use crate::{BuildMode, CompilerAdapter, CompilerError, ToolchainConfig};

    static PATH_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn compiler_adapter_discover_finds_gprbuild_when_present() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("discover_gprbuild");
        dir.write_executable("gprbuild", "#!/bin/sh\nexit 0\n");
        let _path = PathEnvGuard::set(dir.path());

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");

        assert!(adapter.gprbuild_path().is_some());
        assert!(adapter.gnatmake_path().is_none());
    }

    #[test]
    fn compiler_adapter_discover_finds_gnatmake_when_only_one_present() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("discover_gnatmake");
        dir.write_executable("gnatmake", "#!/bin/sh\nexit 0\n");
        let _path = PathEnvGuard::set(dir.path());

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");

        assert!(adapter.gprbuild_path().is_none());
        assert!(adapter.gnatmake_path().is_some());
    }

    #[test]
    fn compiler_adapter_discover_returns_error_when_neither_present() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("discover_none");
        let _path = PathEnvGuard::set(dir.path());

        let error = CompilerAdapter::discover().expect_err("compiler is missing");

        assert!(matches!(error, CompilerError::NoCompilerFound));
    }

    #[test]
    fn compiler_adapter_discover_prefers_gprbuild_over_gnatmake_when_both_present() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("discover_both");
        dir.write_executable("gprbuild", "#!/bin/sh\nexit 0\n");
        dir.write_executable("gnatmake", "#!/bin/sh\nexit 0\n");
        let _path = PathEnvGuard::set(dir.path());

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let preferred = adapter
            .preferred_binary()
            .expect("preferred compiler exists")
            .file_name()
            .expect("compiler path has a file name");

        assert_eq!(preferred, "gprbuild");
    }

    #[test]
    fn compiler_adapter_discover_for_target_uses_target_prefix() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("discover_target_prefix");
        dir.write_executable("aarch64-linux-gnu-gprbuild", "#!/bin/sh\nexit 0\n");
        dir.write_executable("aarch64-linux-gnu-gnat", "#!/bin/sh\nexit 0\n");
        let _path = PathEnvGuard::set(dir.path());

        let adapter = CompilerAdapter::discover_for(ToolchainConfig {
            target: Some("aarch64-linux-gnu".to_owned()),
            runtime: None,
            toolchain: None,
        })
        .expect("prefixed adapter is discovered");

        assert_eq!(
            adapter
                .gprbuild_path()
                .and_then(|path| path.file_name())
                .expect("gprbuild path has a filename"),
            "aarch64-linux-gnu-gprbuild"
        );
        assert_eq!(
            adapter
                .gnat_path()
                .and_then(|path| path.file_name())
                .expect("gnat path has a filename"),
            "aarch64-linux-gnu-gnat"
        );
    }

    #[test]
    fn compiler_adapter_discover_for_toolchain_reports_missing_prefixed_gnat() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("discover_target_missing_gnat");
        dir.write_executable("arm-eabi-gprbuild", "#!/bin/sh\nexit 0\n");
        let _path = PathEnvGuard::set(dir.path());

        let error = CompilerAdapter::discover_for(ToolchainConfig {
            target: Some("arm-eabi".to_owned()),
            runtime: Some("light-cortex-m3".to_owned()),
            toolchain: None,
        })
        .expect_err("prefixed gnat is missing");

        match error {
            CompilerError::TargetToolchainNotFound {
                toolchain,
                target,
                missing,
            } => {
                assert_eq!(toolchain, "arm-eabi");
                assert_eq!(target, "arm-eabi");
                assert_eq!(missing, "arm-eabi-gnat");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn build_invokes_compiler_with_dash_p_project_path() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("build_args");
        dir.write_executable("gprbuild", fake_compiler_script());
        let log_path = dir.file_path("args.log");
        let _path = PathEnvGuard::set(dir.path());
        let _arg_log = EnvVarGuard::set("GOVFUZZ_ARG_LOG", log_path.as_os_str());

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let project = dir.file_path("govfuzz_build.gpr");
        let _result = adapter.build(&project).expect("build runs");

        let argv = std::fs::read_to_string(log_path).expect("argv log is readable");
        assert_eq!(argv, format!("-P\n{}\n", project.display()));
    }

    #[test]
    fn check_passes_dash_gnatc_via_dash_cargs_to_compiler() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("check_args");
        dir.write_executable("gprbuild", fake_compiler_script());
        let log_path = dir.file_path("args.log");
        let _path = PathEnvGuard::set(dir.path());
        let _arg_log = EnvVarGuard::set("GOVFUZZ_ARG_LOG", log_path.as_os_str());

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let project = dir.file_path("govfuzz_build.gpr");
        let _result = adapter.check(&project).expect("check runs");

        let argv = std::fs::read_to_string(log_path).expect("argv log is readable");
        assert_eq!(
            argv,
            format!("-P\n{}\n-c\n-cargs\n-gnatc\n", project.display())
        );
    }

    #[test]
    fn build_captures_stdout_and_stderr() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("build_output");
        dir.write_executable("gprbuild", fake_compiler_script());
        let _path = PathEnvGuard::set(dir.path());

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let result = adapter
            .build(&dir.file_path("govfuzz_build.gpr"))
            .expect("build runs");

        assert_eq!(result.stdout, "fake compiler stdout\n");
        assert_eq!(result.stderr, "fake compiler stderr\n");
    }

    #[test]
    fn build_returns_exit_code_of_subprocess() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("build_exit");
        dir.write_executable("gprbuild", fake_compiler_script());
        let _path = PathEnvGuard::set(dir.path());
        let _exit = EnvVarGuard::set("GOVFUZZ_FAKE_EXIT", "7");

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let result = adapter
            .build(&dir.file_path("govfuzz_build.gpr"))
            .expect("build runs");

        assert_eq!(result.exit_code, 7);
        assert_eq!(result.mode, BuildMode::Full);
    }

    #[test]
    fn build_records_duration() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("build_duration");
        dir.write_executable("gprbuild", fake_compiler_script());
        let _path = PathEnvGuard::set(dir.path());
        let _sleep = EnvVarGuard::set("GOVFUZZ_FAKE_SLEEP", "0.02");

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let result = adapter
            .build(&dir.file_path("govfuzz_build.gpr"))
            .expect("build runs");

        assert!(result.duration_ms >= 10);
    }

    #[test]
    fn parse_version_handles_fsf_gnat_13_format() {
        let raw = "GNATMAKE 13.2.0 20240106 (experimental)\n";

        let (compiler_id, version) = parse_version(raw).expect("version parses");

        assert_eq!(compiler_id, "FSF GNAT 13.2.0");
        assert_eq!(version, "13.2.0");
    }

    #[test]
    fn parse_version_handles_adacore_gnat_pro_format() {
        let raw = "GNAT Pro 24.0 (20240501)\n";

        let (compiler_id, version) = parse_version(raw).expect("version parses");

        assert_eq!(compiler_id, "AdaCore GNAT Pro 24.0");
        assert_eq!(version, "24.0");
    }

    #[test]
    fn parse_version_handles_gprbuild_pro_format() {
        let raw = "GPRBUILD Pro 18.0w (19940713) (x86_64-linux-gnu)\n";

        let (compiler_id, version) = parse_version(raw).expect("version parses");

        assert_eq!(compiler_id, "AdaCore GPRbuild Pro 18.0w");
        assert_eq!(version, "18.0w");
    }

    #[test]
    fn parse_version_returns_error_on_empty_output() {
        let error = parse_version("").expect_err("empty version output is invalid");

        assert!(matches!(error, CompilerError::UnparseableVersion { .. }));
    }

    #[test]
    fn parse_target_runtime_extracts_target_triple() {
        let raw = "GNATMAKE 13.2.0\nTarget: x86_64-pc-linux-gnu\nRuntime: default\n";

        let (target, runtime) = parse_target_runtime(raw);

        assert_eq!(target, "x86_64-pc-linux-gnu");
        assert_eq!(runtime, "default");
    }

    #[test]
    fn parse_target_runtime_defaults_to_unknown_when_missing() {
        let (target, runtime) = parse_target_runtime("GNATMAKE 13.2.0\n");

        assert_eq!(target, "unknown");
        assert_eq!(runtime, "unknown");
    }

    #[test]
    fn probe_compiler_returns_capabilities_when_compiler_present() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("probe_capabilities");
        dir.write_executable("gprbuild", fake_version_compiler_script());
        let _path = PathEnvGuard::set(dir.path());

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let capabilities =
            crate::probe_compiler(&adapter).expect("compiler capabilities are probed");

        assert_eq!(capabilities.compiler_id, "FSF GNAT 13.2.0");
        assert_eq!(capabilities.version, "13.2.0");
        assert_eq!(capabilities.target, "x86_64-pc-linux-gnu");
        assert_eq!(capabilities.runtime, "default");
        assert_eq!(capabilities.ada_standard_max, AdaStandard::Ada2022);
    }

    #[test]
    fn probe_compiler_for_target_runs_prefixed_gnat_canary() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("probe_target_gnat");
        dir.write_executable("aarch64-linux-gnu-gprbuild", fake_version_compiler_script());
        dir.write_executable("aarch64-linux-gnu-gnat", fake_raw_gnat_canary_script());
        let log_path = dir.file_path("raw-gnat.log");
        let _path = PathEnvGuard::set(dir.path());
        let _log = EnvVarGuard::set("GOVFUZZ_RAW_GNAT_LOG", log_path.as_os_str());

        let adapter = CompilerAdapter::discover_for(ToolchainConfig {
            target: Some("aarch64-linux-gnu".to_owned()),
            runtime: Some("ravenscar-full".to_owned()),
            toolchain: None,
        })
        .expect("prefixed adapter is discovered");
        let capabilities =
            crate::probe_compiler(&adapter).expect("compiler capabilities are probed");

        let log = std::fs::read_to_string(log_path).expect("raw gnat log is readable");
        assert_eq!(capabilities.target, "aarch64-linux-gnu");
        assert_eq!(capabilities.runtime, "ravenscar-full");
        assert_eq!(capabilities.ada_standard_max, AdaStandard::Ada2022);
        assert!(log.contains("aarch64-linux-gnu-gnat"));
        assert!(log.contains("-gnatc"));
        assert!(log.contains("-gnat2022"));
    }

    #[test]
    fn canary_probes_ada2022_when_supported() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("canary_ada2022");
        dir.write_executable("gprbuild", fake_canary_compiler_script());
        let log_path = dir.file_path("canary.log");
        let _path = PathEnvGuard::set(dir.path());
        let _log = EnvVarGuard::set("GOVFUZZ_CANARY_LOG", log_path.as_os_str());

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let capabilities =
            crate::probe_compiler(&adapter).expect("compiler capabilities are probed");

        let log = std::fs::read_to_string(log_path).expect("canary log is readable");
        assert_eq!(capabilities.ada_standard_max, AdaStandard::Ada2022);
        assert!(log.contains("-gnat2022"));
    }

    #[test]
    fn canary_falls_back_to_ada2012_when_2022_rejected() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("canary_fallback");
        dir.write_executable("gprbuild", fake_canary_compiler_script());
        let log_path = dir.file_path("canary.log");
        let _path = PathEnvGuard::set(dir.path());
        let _log = EnvVarGuard::set("GOVFUZZ_CANARY_LOG", log_path.as_os_str());
        let _reject = EnvVarGuard::set("GOVFUZZ_REJECT_ADA2022", "1");

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let capabilities =
            crate::probe_compiler(&adapter).expect("compiler capabilities are probed");

        let log = std::fs::read_to_string(log_path).expect("canary log is readable");
        assert_eq!(capabilities.ada_standard_max, AdaStandard::Ada2012);
        assert!(log.contains("-gnat2022"));
        assert!(log.contains("-gnat12"));
    }

    #[test]
    fn probe_caches_result_after_first_call() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("probe_cache");
        dir.write_executable("gprbuild", fake_canary_compiler_script());
        let count_path = dir.file_path("probe-count.txt");
        let _path = PathEnvGuard::set(dir.path());
        let _counter = EnvVarGuard::set("GOVFUZZ_PROBE_COUNT", count_path.as_os_str());

        let adapter = CompilerAdapter::discover().expect("adapter is discovered");
        let first = crate::probe_compiler(&adapter).expect("first probe runs");
        let second = crate::probe_compiler(&adapter).expect("second probe is cached");

        let count = std::fs::read_to_string(count_path).expect("probe count is readable");
        assert_eq!(first, second);
        assert_eq!(count.trim(), "2");
    }

    #[test]
    fn probe_cache_key_includes_requested_toolchain_config() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let dir = TestPathDir::new("probe_cache_toolchain_config");
        dir.write_executable("gprbuild", fake_canary_compiler_script());
        let gprbuild = dir.file_path("gprbuild");
        let count_path = dir.file_path("probe-count.txt");
        let _counter = EnvVarGuard::set("GOVFUZZ_PROBE_COUNT", count_path.as_os_str());

        let adapter_one = CompilerAdapter::with_binaries(
            Some(gprbuild.clone()),
            None,
            None,
            ToolchainConfig {
                target: None,
                runtime: Some("ravenscar-full".to_owned()),
                toolchain: None,
            },
        );
        let adapter_two = CompilerAdapter::with_binaries(
            Some(gprbuild),
            None,
            None,
            ToolchainConfig {
                target: None,
                runtime: Some("zfp".to_owned()),
                toolchain: None,
            },
        );

        let first = crate::probe_compiler(&adapter_one).expect("first probe runs");
        let second = crate::probe_compiler(&adapter_two).expect("second probe runs");

        let count = std::fs::read_to_string(count_path).expect("probe count is readable");
        assert_eq!(first.runtime, "ravenscar-full");
        assert_eq!(second.runtime, "zfp");
        assert_eq!(count.trim(), "4");
    }

    struct TestPathDir {
        path: PathBuf,
    }

    impl TestPathDir {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "govfuzz-compiler-adapter-{test_name}-{}",
                std::process::id()
            ));
            if path.exists() {
                std::fs::remove_dir_all(&path).expect("old test directory is removed");
            }
            std::fs::create_dir_all(&path).expect("test directory is created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write_executable(&self, name: &str, contents: &str) {
            let path = self.path.join(name);
            std::fs::write(&path, contents).expect("fake compiler is written");
            make_executable(&path);
        }

        fn file_path(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestPathDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    struct PathEnvGuard {
        original: Option<OsString>,
    }

    impl PathEnvGuard {
        fn set(path: &Path) -> Self {
            let original = std::env::var_os("PATH");
            std::env::set_var("PATH", path);
            Self { original }
        }
    }

    impl Drop for PathEnvGuard {
        fn drop(&mut self) {
            if let Some(original) = &self.original {
                std::env::set_var("PATH", original);
            } else {
                std::env::remove_var("PATH");
            }
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        original: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set<V>(key: &'static str, value: V) -> Self
        where
            V: AsRef<std::ffi::OsStr>,
        {
            let original = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(original) = &self.original {
                std::env::set_var(self.key, original);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn fake_compiler_script() -> &'static str {
        r#"#!/bin/sh
if [ -n "$GOVFUZZ_ARG_LOG" ]; then
  printf '%s\n' "$@" > "$GOVFUZZ_ARG_LOG"
fi
echo "fake compiler stdout"
echo "fake compiler stderr" >&2
if [ -n "$GOVFUZZ_FAKE_SLEEP" ]; then
  /bin/sleep "$GOVFUZZ_FAKE_SLEEP"
fi
exit "${GOVFUZZ_FAKE_EXIT:-0}"
"#
    }

    fn fake_version_compiler_script() -> &'static str {
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' 'GNATMAKE 13.2.0 20240106 (experimental)' 'Target: x86_64-pc-linux-gnu' 'Runtime: default'
  exit 0
fi
exit 0
"#
    }

    fn fake_canary_compiler_script() -> &'static str {
        r#"#!/bin/sh
if [ -n "$GOVFUZZ_PROBE_COUNT" ]; then
  count=0
  if [ -f "$GOVFUZZ_PROBE_COUNT" ]; then
    IFS= read -r count < "$GOVFUZZ_PROBE_COUNT"
  fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$GOVFUZZ_PROBE_COUNT"
fi

if [ "$1" = "--version" ]; then
  printf '%s\n' 'GNATMAKE 13.2.0 20240106 (experimental)' 'Target: x86_64-pc-linux-gnu' 'Runtime: default'
  exit 0
fi

project=
previous=
for arg in "$@"; do
  if [ "$previous" = "-P" ]; then
    project=$arg
    previous=
  elif [ "$arg" = "-P" ]; then
    previous=-P
  fi
done

canary_text=$*
if [ -n "$project" ] && [ -f "$project" ]; then
  while IFS= read -r line; do
    canary_text="$canary_text
$line"
  done < "$project"
fi

if [ -n "$GOVFUZZ_CANARY_LOG" ]; then
  printf '%s\n' "$*" >> "$GOVFUZZ_CANARY_LOG"
  if [ -n "$project" ] && [ -f "$project" ]; then
    while IFS= read -r line; do
      printf '%s\n' "$line" >> "$GOVFUZZ_CANARY_LOG"
    done < "$project"
  fi
fi

case "$canary_text" in
  *-gnat2022*)
    if [ -n "$GOVFUZZ_REJECT_ADA2022" ]; then
      printf '%s\n' 'rejecting Ada 2022' >&2
      exit 1
    fi
    ;;
esac

exit 0
"#
    }

    fn fake_raw_gnat_canary_script() -> &'static str {
        r#"#!/bin/sh
if [ -n "$GOVFUZZ_RAW_GNAT_LOG" ]; then
  printf '%s\n' "$0" "$@" > "$GOVFUZZ_RAW_GNAT_LOG"
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
      if [ -f "$4" ]; then
        exit 0
      fi
      ;;
  esac
fi

printf 'unexpected raw gnat argv:' >&2
for arg in "$@"; do
  printf ' <%s>' "$arg" >&2
done
printf '\n' >&2
exit 1
"#
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
