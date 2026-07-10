// SPDX-License-Identifier: Apache-2.0

//! Compile-time inventory of every fake-resource plugin in the
//! runtrace_shim cdylib. Lives in its own crate so the cli can
//! list-fakes WITHOUT linking the LD_PRELOAD interceptors (whose
//! `#[no_mangle] extern "C" fn getpid()` etc. symbols would
//! override libc's `getpid` in the cli binary and infinite-recurse).
//!
//! The shim crate consumes `MANIFEST` to cross-check its internal
//! `REGISTRY` of `&dyn FakeResource` impls.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestEntry {
    pub name: &'static str,
    pub intercepts: &'static [&'static [u8]],
    /// Env var that gates the plugin, or `""` for always-on plugins.
    pub env_var: &'static str,
    pub describe: &'static str,
}

impl ManifestEntry {
    pub const fn always_on(
        name: &'static str,
        intercepts: &'static [&'static [u8]],
        describe: &'static str,
    ) -> Self {
        Self {
            name,
            intercepts,
            env_var: "",
            describe,
        }
    }

    pub const fn gated(
        name: &'static str,
        intercepts: &'static [&'static [u8]],
        env_var: &'static str,
        describe: &'static str,
    ) -> Self {
        Self {
            name,
            intercepts,
            env_var,
            describe,
        }
    }

    pub fn is_gated(&self) -> bool {
        !self.env_var.is_empty()
    }
}

pub const MANIFEST: &[ManifestEntry] = &[
    ManifestEntry::always_on(
        "env",
        &[b"getenv\0", b"secure_getenv\0"],
        "log target reads of unset environment variables for between-pass injection",
    ),
    ManifestEntry::always_on(
        "net",
        &[b"connect\0", b"getaddrinfo\0"],
        "log connect/getaddrinfo failures and substitute fake socket peers",
    ),
    ManifestEntry::always_on(
        "fs",
        &[
            b"open\0",
            b"openat\0",
            b"close\0",
            b"stat\0",
            b"fopen\0",
            b"unlink\0",
            b"unlinkat\0",
            b"remove\0",
            b"mkdir\0",
            b"mkdirat\0",
            b"rmdir\0",
            b"rename\0",
            b"renameat\0",
            b"symlink\0",
            b"symlinkat\0",
            b"link\0",
            b"linkat\0",
            b"truncate\0",
        ],
        "log missing-file ENOENT, fd lifecycle, controlled destructive path ops, and substitute fake file fds",
    ),
    ManifestEntry::always_on(
        "dl",
        &[b"dlopen\0", b"dlmopen\0", b"dlclose\0"],
        "fake dlopen handles for missing .so files and audit controlled library loads",
    ),
    ManifestEntry::always_on(
        "dlsym",
        &[b"dlsym\0"],
        "resolve dlsym lookups against fake dlopen handles",
    ),
    ManifestEntry::always_on(
        "proc",
        &[
            b"system\0",
            b"popen\0",
            b"execv\0",
            b"execvp\0",
            b"execvpe\0",
            b"execve\0",
            b"fexecve\0",
            b"posix_spawn\0",
            b"posix_spawnp\0",
        ],
        "log command strings and program/argv passed to process-execution APIs",
    ),
    ManifestEntry::always_on(
        "format",
        &[
            b"printf\0",
            b"fprintf\0",
            b"sprintf\0",
            b"snprintf\0",
            b"dprintf\0",
        ],
        "log printf-style format strings and whether they match current fuzz input",
    ),
    ManifestEntry::always_on(
        "assertion",
        &[b"__assert_fail\0", b"__assert_perror_fail\0"],
        "log native C/C++ assertion failures before forwarding to libc",
    ),
    ManifestEntry::gated(
        "identity",
        &[b"getpid\0", b"getuid\0", b"getgid\0", b"getppid\0"],
        "GOVFUZZ_FAKE_IDENTITY",
        "fake POSIX identity calls for deterministic replay",
    ),
    ManifestEntry::gated(
        "cmplog",
        &[b"strcmp\0", b"strncmp\0", b"memcmp\0"],
        "GOVFUZZ_CMPLOG",
        "record strcmp/strncmp/memcmp operands so the engine can splice them into inputs",
    ),
    ManifestEntry::always_on(
        "mem",
        &[
            b"shm_open\0",
            b"shm_unlink\0",
            b"shmget\0",
            b"shmat\0",
            b"shmdt\0",
            b"shmctl\0",
            b"mmap\0",
            b"mmap64\0",
        ],
        "virtualize POSIX (shm_open), System V (shmget/shmat), and anonymous mmap(MAP_SHARED) shared memory as private memory so there is no foreign writer",
    ),
    ManifestEntry::always_on(
        "mqueue",
        &[
            b"mq_open\0",
            b"mq_receive\0",
            b"mq_timedreceive\0",
            b"mq_send\0",
            b"mq_getattr\0",
            b"mq_close\0",
            b"mq_unlink\0",
        ],
        "deliver fuzz input as POSIX message-queue messages (mq_receive) to a partition's handler",
    ),
    ManifestEntry::always_on(
        "sql",
        &[
            b"sqlite3_exec\0",
            b"sqlite3_prepare\0",
            b"sqlite3_prepare_v2\0",
            b"sqlite3_prepare_v3\0",
            b"PQexec\0",
            b"PQexecParams\0",
            b"mysql_query\0",
            b"mysql_real_query\0",
        ],
        "audit fuzz-controlled SQL text reaching database-execution APIs",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_lists_all_v0_1_plugins() {
        let names: Vec<&str> = MANIFEST.iter().map(|e| e.name).collect();
        assert!(names.contains(&"env"));
        assert!(names.contains(&"net"));
        assert!(names.contains(&"fs"));
        assert!(names.contains(&"dl"));
        assert!(names.contains(&"dlsym"));
        assert!(names.contains(&"proc"));
        assert!(names.contains(&"format"));
        assert!(names.contains(&"assertion"));
        assert!(names.contains(&"identity"));
    }

    #[test]
    fn identity_plugin_is_env_gated() {
        let identity = MANIFEST
            .iter()
            .find(|e| e.name == "identity")
            .expect("identity present");
        assert_eq!(identity.env_var, "GOVFUZZ_FAKE_IDENTITY");
        assert!(identity.is_gated());
    }

    #[test]
    fn env_plugin_lists_secure_getenv() {
        let env = MANIFEST
            .iter()
            .find(|e| e.name == "env")
            .expect("env present");

        assert!(env.intercepts.iter().any(|symbol| *symbol == b"getenv\0"));
        assert!(env
            .intercepts
            .iter()
            .any(|symbol| *symbol == b"secure_getenv\0"));
    }

    #[test]
    fn legacy_plugins_are_always_on() {
        for name in [
            "env",
            "net",
            "fs",
            "dl",
            "dlsym",
            "proc",
            "format",
            "assertion",
        ] {
            let entry = MANIFEST
                .iter()
                .find(|e| e.name == name)
                .expect("plugin present");
            assert!(!entry.is_gated(), "{name} should be always-on");
        }
    }
}
