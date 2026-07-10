// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::path::{Path, PathBuf};

use fuzz_engine_builtin::{
    AflCustomMutatorFeedback, CoverageFeedback, EngineFeedback, EngineFeedbackTranslator,
};

pub const PERSISTENT_SHIM_C_FILENAME: &str = "govfuzz_afl_persistent_shim.c";
pub const AFL_CUSTOM_MUTATOR_LIBRARY_ENV: &str = "AFL_CUSTOM_MUTATOR_LIBRARY";
pub const AFL_CUSTOM_MUTATOR_ONLY_ENV: &str = "AFL_CUSTOM_MUTATOR_ONLY";
pub const AFL_CUSTOM_MUTATOR_HOOKS: &[&str] = &[
    "afl_custom_queue_get",
    "afl_custom_fuzz_count",
    "afl_custom_describe",
];

pub fn crate_name() -> &'static str {
    "fuzz_engine_afl_adapter"
}

pub fn persistent_shim_c_source() -> &'static str {
    include_str!("../c/govfuzz_afl_persistent_shim.c")
}

pub fn write_persistent_shim_c(path: impl AsRef<Path>) -> io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, persistent_shim_c_source())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AflShimBuildPlan {
    pub compiler: String,
    pub source_path: PathBuf,
    pub output_path: PathBuf,
    pub extra_args: Vec<String>,
}

impl AflShimBuildPlan {
    pub fn new(source_path: impl Into<PathBuf>, output_path: impl Into<PathBuf>) -> Self {
        Self {
            compiler: "afl-clang-fast".to_owned(),
            source_path: source_path.into(),
            output_path: output_path.into(),
            extra_args: Vec::new(),
        }
    }

    pub fn with_compiler(mut self, compiler: impl Into<String>) -> Self {
        self.compiler = compiler.into();
        self
    }

    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_args.push(arg.into());
        self
    }

    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(4 + self.extra_args.len());
        argv.push(self.compiler.clone());
        argv.push(self.source_path.to_string_lossy().into_owned());
        argv.extend(self.extra_args.iter().cloned());
        argv.push("-o".to_owned());
        argv.push(self.output_path.to_string_lossy().into_owned());
        argv
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AflFeedbackHookPlan {
    pub library_env_var: &'static str,
    pub mutator_only_env_var: &'static str,
    pub event_path_env_var: &'static str,
    pub hooks: &'static [&'static str],
}

impl Default for AflFeedbackHookPlan {
    fn default() -> Self {
        Self {
            library_env_var: AFL_CUSTOM_MUTATOR_LIBRARY_ENV,
            mutator_only_env_var: AFL_CUSTOM_MUTATOR_ONLY_ENV,
            event_path_env_var: "GOVFUZZ_EVENTS_PATH",
            hooks: AFL_CUSTOM_MUTATOR_HOOKS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AflCustomMutatorHookState {
    translator: EngineFeedbackTranslator,
    current: EngineFeedback,
}

impl Default for AflCustomMutatorHookState {
    fn default() -> Self {
        Self::new(EngineFeedbackTranslator::default())
    }
}

impl AflCustomMutatorHookState {
    pub fn new(translator: EngineFeedbackTranslator) -> Self {
        Self {
            translator,
            current: translator.translate_counts(0, 0),
        }
    }

    pub fn record_coverage(&mut self, feedback: CoverageFeedback) -> EngineFeedback {
        self.record_engine_feedback(self.translator.translate_coverage(feedback))
    }

    pub fn record_engine_feedback(&mut self, feedback: EngineFeedback) -> EngineFeedback {
        self.current = feedback;
        feedback
    }

    pub fn current_feedback(&self) -> EngineFeedback {
        self.current
    }

    pub fn afl_custom_queue_get(&self) -> bool {
        self.current.afl.queue_get
    }

    pub fn afl_custom_fuzz_count(&self) -> u32 {
        self.current.afl.fuzz_count
    }

    pub fn afl_custom_describe(&self) -> &'static str {
        self.current.afl.describe
    }
}

pub fn translate_feedback_for_afl(feedback: CoverageFeedback) -> AflCustomMutatorFeedback {
    EngineFeedbackTranslator::default()
        .translate_coverage(feedback)
        .afl
}

pub fn describe_engine_feedback_for_afl(feedback: CoverageFeedback) -> &'static str {
    translate_engine_feedback_for_afl(feedback).afl.describe
}

pub fn translate_engine_feedback_for_afl(feedback: CoverageFeedback) -> EngineFeedback {
    EngineFeedbackTranslator::default().translate_coverage(feedback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn persistent_shim_source_uses_afl_persistent_loop_and_fuzz_buffer() {
        let source = persistent_shim_c_source();

        assert!(source.contains("__AFL_FUZZ_INIT"));
        assert!(source.contains("__AFL_INIT"));
        assert!(source.contains("__AFL_LOOP"));
        assert!(source.contains("__AFL_FUZZ_TESTCASE_BUF"));
        assert!(source.contains("__AFL_FUZZ_TESTCASE_LEN"));
    }

    #[test]
    fn persistent_shim_source_forks_harness_and_pipes_input_to_stdin() {
        let source = persistent_shim_c_source();

        assert!(source.contains("pipe(pipefd)"));
        assert!(source.contains("fork()"));
        assert!(source.contains("dup2(pipefd[0], STDIN_FILENO)"));
        assert!(source.contains("execv(harness_path, child_argv)"));
        assert!(source.contains("waitpid(pid, &status, 0)"));
    }

    #[test]
    fn build_plan_defaults_to_user_installed_afl_clang_fast() {
        let plan = AflShimBuildPlan::new("shim.c", "govfuzz-afl-shim");

        assert_eq!(plan.compiler, "afl-clang-fast");
        assert_eq!(
            plan.argv(),
            vec![
                "afl-clang-fast".to_owned(),
                "shim.c".to_owned(),
                "-o".to_owned(),
                "govfuzz-afl-shim".to_owned(),
            ]
        );
    }

    #[test]
    fn build_plan_allows_compiler_override_and_extra_args() {
        let plan = AflShimBuildPlan::new("shim.c", "shim")
            .with_compiler("afl-cc")
            .with_arg("-O2")
            .with_arg("-DGOVFUZZ_TEST=1");

        assert_eq!(
            plan.argv(),
            vec![
                "afl-cc".to_owned(),
                "shim.c".to_owned(),
                "-O2".to_owned(),
                "-DGOVFUZZ_TEST=1".to_owned(),
                "-o".to_owned(),
                "shim".to_owned(),
            ]
        );
    }

    #[test]
    fn write_persistent_shim_c_writes_apache_source() {
        let root =
            std::env::temp_dir().join(format!("govfuzz-afl-shim-test-{}", std::process::id()));
        let path = root.join(PERSISTENT_SHIM_C_FILENAME);
        std::fs::create_dir_all(&root).expect("temp dir is created");

        write_persistent_shim_c(&path).expect("shim source is written");

        let written = std::fs::read_to_string(&path).expect("shim source is readable");
        assert!(written.starts_with("// SPDX-License-Identifier: Apache-2.0"));
        assert_eq!(written, persistent_shim_c_source());

        std::fs::remove_dir_all(root).expect("temp dir is removed");
    }

    #[test]
    fn feedback_hook_plan_names_afl_custom_mutator_hooks() {
        let plan = AflFeedbackHookPlan::default();

        assert_eq!(plan.library_env_var, "AFL_CUSTOM_MUTATOR_LIBRARY");
        assert_eq!(plan.mutator_only_env_var, "AFL_CUSTOM_MUTATOR_ONLY");
        assert_eq!(plan.event_path_env_var, "GOVFUZZ_EVENTS_PATH");
        assert!(plan.hooks.contains(&"afl_custom_queue_get"));
        assert!(plan.hooks.contains(&"afl_custom_fuzz_count"));
        assert!(plan.hooks.contains(&"afl_custom_describe"));
    }

    #[test]
    fn translates_exception_and_breadcrumb_feedback_for_afl_hooks() {
        let translated = translate_engine_feedback_for_afl(CoverageFeedback {
            new_exception_signatures: 1,
            new_breadcrumb_bits: 3,
            ..CoverageFeedback::default()
        });

        assert!(translated.afl.queue_get);
        assert_eq!(translated.afl.fuzz_count, 20);
        assert_eq!(
            translated.afl.describe,
            "govfuzz:exception-signature+bitmap"
        );
        assert!(translated.libafl.is_objective);
    }

    #[test]
    fn empty_feedback_disables_afl_queue_get() {
        let translated = translate_feedback_for_afl(CoverageFeedback::default());

        assert!(!translated.queue_get);
        assert_eq!(translated.fuzz_count, 0);
        assert_eq!(translated.describe, "govfuzz:none");
    }

    #[test]
    fn custom_mutator_hook_state_tracks_last_translated_feedback() {
        let mut state = AflCustomMutatorHookState::default();

        assert!(!state.afl_custom_queue_get());
        assert_eq!(state.afl_custom_fuzz_count(), 0);
        assert_eq!(state.afl_custom_describe(), "govfuzz:none");

        let translated = state.record_coverage(CoverageFeedback {
            new_exception_signatures: 1,
            new_raise_bits: 2,
            ..CoverageFeedback::default()
        });

        assert_eq!(translated, state.current_feedback());
        assert!(state.afl_custom_queue_get());
        assert_eq!(state.afl_custom_fuzz_count(), 19);
        assert_eq!(
            state.afl_custom_describe(),
            "govfuzz:exception-signature+bitmap"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fallback_shim_propagates_child_signal_to_own_status() {
        use std::io::Write;
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};

        let root = temp_dir("signal-propagation");
        let shim_source = root.join(PERSISTENT_SHIM_C_FILENAME);
        let harness_source = root.join("crashing_harness.c");
        let shim_bin = root.join("govfuzz-afl-shim");
        let harness_bin = root.join("crashing-harness");

        write_persistent_shim_c(&shim_source).expect("shim source is written");
        std::fs::write(
            &harness_source,
            r#"// SPDX-License-Identifier: Apache-2.0

#include <signal.h>
#include <unistd.h>

int main(void) {
   char buf[256];
   while (read(STDIN_FILENO, buf, sizeof(buf)) > 0) {
   }
   raise(SIGABRT);
   return 0;
}
"#,
        )
        .expect("crashing harness source is written");

        compile_c(&shim_source, &shim_bin);
        compile_c(&harness_source, &harness_bin);

        let mut child = Command::new(&shim_bin)
            .arg(&harness_bin)
            .stdin(Stdio::piped())
            .spawn()
            .expect("shim starts");
        child
            .stdin
            .as_mut()
            .expect("shim stdin is piped")
            .write_all(b"seed")
            .expect("seed input is written");
        drop(child.stdin.take());

        let status = child.wait().expect("shim exits");

        assert!(
            status.signal().is_some(),
            "shim should propagate the child signal instead of exiting with code {:?}",
            status.code()
        );

        std::fs::remove_dir_all(root).expect("temp dir is removed");
    }

    #[cfg(unix)]
    fn compile_c(source: &Path, output: &Path) {
        let status = std::process::Command::new("cc")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg(source)
            .arg("-o")
            .arg(output)
            .status()
            .expect("cc starts");

        assert!(
            status.success(),
            "cc failed compiling {} to {}",
            source.display(),
            output.display()
        );
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("govfuzz-afl-shim-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp dir is created");
        root
    }
}
