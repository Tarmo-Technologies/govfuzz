// SPDX-License-Identifier: Apache-2.0

//! Rust-side reader for the JSONL events `libgovfuzz_runtrace.so`
//! emits during a fuzz run. Each line is one event; the parser
//! turns it into a typed `RuntraceEvent` the attempt loop and
//! report aggregator consume.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, std::hash::Hash, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntraceEvent {
    /// An environment lookup API returned NULL.
    EnvVarMissing { api: String, name: String },
    /// An environment lookup API returned a value; value is redacted.
    EnvVarAccess { api: String, name: String },
    /// A path-related syscall failed with ENOENT. `taint_offset` is the
    /// offset in the fuzz input where the path bytes originate when the
    /// path was derived from the input (#422), else `None`.
    FileMissing {
        syscall: String,
        path: String,
        taint_offset: Option<u32>,
    },
    /// A successful access/permission check on a path (TOCTOU time-of-check).
    PathChecked { syscall: String, path: String },
    /// A file descriptor was opened successfully. `taint_offset` carries
    /// fuzz-input byte-origin taint for the path, as in `FileMissing`.
    FileOpened {
        syscall: String,
        fd: i32,
        path: String,
        taint_offset: Option<u32>,
    },
    /// A file descriptor was closed successfully.
    FileClosed { fd: i32 },
    /// A file deletion API removed a path successfully.
    FileDeleted { syscall: String, path: String },
    /// A chmod/fchmod assigned setuid/setgid/world-writable permissions.
    InsecurePermissions {
        api: String,
        path: String,
        mode: i64,
    },
    /// A file was created in a world-writable temp dir without O_EXCL.
    InsecureTempFile {
        api: String,
        path: String,
        flags: i64,
    },
    /// `connect()` failed with ECONNREFUSED/ENOENT, or
    /// `getaddrinfo()` failed.
    NetworkUnreachable { family: i32, address: String },
    /// `dlopen` returned NULL.
    DlopenFailed { library: String },
    /// A process-execution API received a command string. `taint_offset`
    /// carries the fuzz-input offset a contiguous run of the command was
    /// derived from (#422), or `None` when no run was input-derived.
    CommandExecuted {
        api: String,
        command: String,
        taint_offset: Option<u32>,
    },
    /// An `exec*`/`posix_spawn` API received a program path (and, flattened,
    /// its argv). `taint_offset` carries the fuzz-input offset a controlled run
    /// of the program/argv came from (#422), or `None`. Feeds the process-exec
    /// sink oracle (GF-431).
    ProcessExec {
        api: String,
        program: String,
        taint_offset: Option<u32>,
    },
    /// A network-egress API (`getaddrinfo`/`connect`) received a destination
    /// (hostname or address). `taint_offset` carries the fuzz-input offset a
    /// controlled run of the destination came from (#422), or `None`. Feeds the
    /// SSRF sink oracle (GF-433).
    NetworkEgress {
        api: String,
        address: String,
        taint_offset: Option<u32>,
    },
    /// A dynamic loader (`dlopen`/`dlmopen`) received a library path.
    /// `taint_offset` carries the fuzz-input offset a controlled run of the
    /// path came from (#422), or `None`. Feeds the controlled-library-load sink
    /// oracle (GF-435).
    LibraryLoad {
        api: String,
        library: String,
        taint_offset: Option<u32>,
    },
    /// A database-execution API (`sqlite3_exec`/`PQexec`/`mysql_query`/...)
    /// received SQL text. `taint_offset` carries the fuzz-input offset a
    /// controlled run of the query came from (#422), or `None`. Feeds the SQL
    /// injection sink oracle (GF-441).
    SqlQuery {
        api: String,
        query: String,
        taint_offset: Option<u32>,
    },
    /// A destructive filesystem API (`unlink`/`rename`/`mkdir`/`symlink`/...)
    /// received a path. `taint_offset` carries the fuzz-input offset a
    /// controlled run of the path came from (#422), or `None`. Feeds the
    /// destructive-path sink oracle (GF-440).
    DestructiveFsOp {
        api: String,
        path: String,
        taint_offset: Option<u32>,
    },
    /// A printf-style formatting API received a format string.
    FormatString {
        api: String,
        format: String,
        controlled: bool,
    },
    /// Ada/runtime instrumentation observed a language runtime check.
    RuntimeCheck {
        api: String,
        language: String,
        exception: String,
        check: String,
        handled: bool,
        message: String,
        source: String,
    },
    /// Unknown event variant in the log (forward compat).
    Unknown { raw: String },
}

/// Parse a runtrace JSONL log into events. Lines that fail to
/// parse are returned as `RuntraceEvent::Unknown` so the consumer
/// can surface them without dropping signal.
pub fn parse_log(path: &Path) -> Result<Vec<RuntraceEvent>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read runtrace log {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(parse_str(&text))
}

pub fn parse_str(text: &str) -> Vec<RuntraceEvent> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_line(line) {
            Some(ev) if should_keep_event(&ev) => out.push(ev),
            Some(_) => {}
            None => out.push(RuntraceEvent::Unknown {
                raw: line.to_owned(),
            }),
        }
    }
    out
}

pub(crate) fn is_internal_env_name(name: &str) -> bool {
    // Language-runtime / locale configuration the interpreter or libc probes at
    // startup (CPython reads ~30 PYTHON* vars; Perl reads PERL5LIB/PERL_*; libc
    // setlocale reads LC_*/LANG; the Go runtime reads GODEBUG/GOGC/...). These are
    // never the TARGET's external dependency or attack surface, so faking them as
    // "missing env deps" is pure noise (and can perturb the interpreter). Drop them
    // alongside the fuzzer/sanitizer's own control vars.
    const EXACT: &[&str] = &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LANG",
        "LANGUAGE",
        "GODEBUG",
        "GOGC",
        "GOMAXPROCS",
        "GOTRACEBACK",
        "GOFLAGS",
        // glibc dynamic-tunables knob the crash symbolizer reads at startup.
        "GLIBCXX_TUNABLES",
        // The Rust std panic handler probes these while formatting a backtrace on
        // the crash path; they are the runtime's own config, not a TARGET env
        // dependency, and must not be fabricated/injected (#33).
        "RUST_BACKTRACE",
        "RUST_LIB_BACKTRACE",
    ];
    const PREFIXES: &[&str] = &[
        "GOVFUZZ_",
        "AFL_",
        "ASAN_",
        "UBSAN_",
        "LSAN_",
        "MSAN_",
        "PYTHON",
        "PERL5",
        "PERL_",
        "LC_",
        // Belt-and-suspenders for the ASan crash symbolizer (llvm-symbolizer /
        // addr2line / debuginfod), which inherits our LD_PRELOAD + runtrace log
        // and probes these config families. The shim already process-scopes the
        // symbolizer (jsonl::process_is_symbolizer); these prefixes also drop the
        // same families from any pre-existing log so they never read as a TARGET
        // dependency / attack surface.
        "LLVM_",
        "DEBUGINFOD_",
        "OPENSSL_",
        "GNUTLS_",
        "NETTLE_",
        "P11_KIT_",
    ];
    EXACT.contains(&name) || PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// A filesystem path owned by the ASan crash symbolizer / debuginfod client
/// (llvm-symbolizer, addr2line), not the fuzzed target. On a crash the
/// statically linked sanitizer spawns these helpers, which inherit our
/// LD_PRELOAD + runtrace log and stat()/open() their own cache and binary
/// paths (`~/.cache/llvm-debuginfod`, `/proc/self/...`). Treating those as the
/// target's missing files produced bogus "missing dependency" rows. The shim
/// now process-scopes the symbolizer wholesale; this is the parse-side
/// belt-and-suspenders for any path the symbolizer logged before that gate (or
/// from a separate tool).
fn is_sanitizer_owned_path(path: &str) -> bool {
    let trimmed = path.trim();
    trimmed.contains("/.cache/llvm-debuginfod")
        || trimmed.contains("/llvm-debuginfod/")
        || trimmed.contains("llvm-symbolizer")
}

fn should_keep_event(event: &RuntraceEvent) -> bool {
    match event {
        RuntraceEvent::EnvVarMissing { name, .. } | RuntraceEvent::EnvVarAccess { name, .. } => {
            !is_internal_env_name(name)
        }
        // A path-probe by the sanitizer's own symbolizer is not the target's
        // missing file — drop it rather than reporting it as a dependency.
        RuntraceEvent::FileMissing { path, .. } => !is_sanitizer_owned_path(path),
        _ => true,
    }
}

pub fn dedupe_in_place(events: &mut Vec<RuntraceEvent>) {
    let mut seen = std::collections::HashSet::new();
    events.retain(|event| seen.insert(event.clone()));
}

pub fn oracle_hits_from_events(
    events: &[RuntraceEvent],
) -> Vec<finding_rules::oracle_sdk::OracleHit> {
    let mut hits = Vec::new();
    for event in events {
        let Some(runtime_event) = oracle_runtime_event(event) else {
            continue;
        };
        for oracle in finding_rules::oracle_registry::ORACLE_REGISTRY {
            if let Some(hit) = oracle.evaluate(&runtime_event) {
                hits.push(hit);
            }
        }
    }
    for runtime_event in resource_leak_runtime_events(events) {
        for oracle in finding_rules::oracle_registry::ORACLE_REGISTRY {
            if let Some(hit) = oracle.evaluate(&runtime_event) {
                hits.push(hit);
            }
        }
    }
    for runtime_event in toctou_runtime_events(events) {
        for oracle in finding_rules::oracle_registry::ORACLE_REGISTRY {
            if let Some(hit) = oracle.evaluate(&runtime_event) {
                hits.push(hit);
            }
        }
    }
    hits
}

/// The class of dangerous sink a fuzz-controlled value reached during a fuzz
/// execution. Selects the taint-confirmed oracle (and its CWE) that a confirmed
/// sink maps to. `Ord` so the cross-execution tracker keys deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SinkClass {
    /// A path reaching a file-open API (open/openat/fopen/...). GF-405, CWE-22.
    OpenPath,
    /// A path reaching a destructive filesystem op (unlink/rename/mkdir/...).
    /// GF-440, CWE-73.
    DestructivePath,
    /// A command/program reaching a process-execution API (system/popen/exec*/
    /// posix_spawn). GF-431, CWE-78.
    ProcessExec,
    /// A destination reaching a network-egress API (getaddrinfo/connect).
    /// GF-433, CWE-918.
    NetworkEgress,
    /// A path reaching a dynamic library loader (dlopen/dlmopen). GF-435,
    /// CWE-427.
    LibraryLoad,
    /// SQL text reaching a database-execution API. GF-441, CWE-89.
    SqlQuery,
}

/// A dangerous sink confirmed fuzz-controlled across a run (#422), ready for
/// oracle emission. `input` is a representative testcase that drove the tainted
/// sink, attached to the finding. `subject` is the tainted value that reached
/// the sink (a path / command / address / library / query).
#[derive(Debug, Clone)]
pub struct ConfirmedSink {
    pub class: SinkClass,
    pub api: String,
    pub subject: String,
    pub taint_offset: u32,
    pub input: Vec<u8>,
}

#[derive(Debug, Clone)]
struct SinkStat {
    api: String,
    taint_offset: Option<u32>,
    untainted_seen: bool,
    representative_input: Vec<u8>,
}

/// Project a runtrace event onto a single-execution sink observation
/// `(class, api, subject, taint)`, or `None` if the event is not a taint sink.
/// This is the one place that maps the shim's event vocabulary onto the sink
/// classes; adding a sink is an arm here plus an oracle.
fn sink_observation(event: &RuntraceEvent) -> Option<(SinkClass, &str, &str, Option<u32>)> {
    match event {
        RuntraceEvent::FileOpened {
            syscall,
            path,
            taint_offset,
            ..
        } => Some((SinkClass::OpenPath, syscall, path, *taint_offset)),
        RuntraceEvent::FileMissing {
            syscall,
            path,
            taint_offset,
        } => Some((SinkClass::OpenPath, syscall, path, *taint_offset)),
        RuntraceEvent::CommandExecuted {
            api,
            command,
            taint_offset,
        } => Some((SinkClass::ProcessExec, api, command, *taint_offset)),
        RuntraceEvent::ProcessExec {
            api,
            program,
            taint_offset,
        } => Some((SinkClass::ProcessExec, api, program, *taint_offset)),
        RuntraceEvent::NetworkEgress {
            api,
            address,
            taint_offset,
        } => Some((SinkClass::NetworkEgress, api, address, *taint_offset)),
        RuntraceEvent::LibraryLoad {
            api,
            library,
            taint_offset,
        } => Some((SinkClass::LibraryLoad, api, library, *taint_offset)),
        RuntraceEvent::SqlQuery {
            api,
            query,
            taint_offset,
        } => Some((SinkClass::SqlQuery, api, query, *taint_offset)),
        RuntraceEvent::DestructiveFsOp {
            api,
            path,
            taint_offset,
        } => Some((SinkClass::DestructivePath, api, path, *taint_offset)),
        _ => None,
    }
}

/// Cross-execution correlation for every taint-confirmed sink oracle (#422) —
/// the unified successor to the per-sink open/command trackers. A
/// `(class, subject)` is confirmed fuzz-controlled only if it carried
/// byte-origin taint on at least one execution AND was never reached *without*
/// that taint during the run.
///
/// The "never untainted" clause is load-bearing: govfuzz harvests the target's
/// own string constants into its auto-dictionary / cmplog tokens, so a fixed
/// subject like `open("/etc/app.conf")` or `system("git status")` is sometimes
/// echoed verbatim into a fuzz input and would otherwise look "controlled" by a
/// naive substring match. A genuine program constant is reached on (near) every
/// execution — including inputs that do not contain it — so it accumulates an
/// untainted sighting and is suppressed. A subject the target copies *from* the
/// input is only ever reached when its bytes are present, so it stays
/// tainted-only and is confirmed. Distinct subjects key distinctly, but the
/// emitter dedupes them to one finding per `(rule | oracle | api)`.
///
/// Fed one execution at a time via [`observe`](Self::observe) (the events are
/// read per-input from the runtrace stream) and queried once at run end via
/// [`confirmed`](Self::confirmed).
#[derive(Debug, Default)]
pub struct SinkTaintTracker {
    entries: BTreeMap<(SinkClass, String), SinkStat>,
}

impl SinkTaintTracker {
    /// Fold the sinks one execution reached, tagged with the `input` that
    /// produced them.
    pub fn observe(&mut self, events: &[RuntraceEvent], input: &[u8]) {
        for event in events {
            let Some((class, api, subject, taint)) = sink_observation(event) else {
                continue;
            };
            let stat = self
                .entries
                .entry((class, subject.to_owned()))
                .or_insert_with(|| SinkStat {
                    api: api.to_owned(),
                    taint_offset: None,
                    untainted_seen: false,
                    representative_input: Vec::new(),
                });
            match taint {
                Some(offset) => {
                    if stat.taint_offset.is_none() {
                        stat.taint_offset = Some(offset);
                        stat.representative_input = input.to_vec();
                        stat.api = api.to_owned();
                    }
                }
                None => stat.untainted_seen = true,
            }
        }
    }

    /// Sinks confirmed fuzz-controlled: tainted at least once, never seen
    /// untainted. Deterministically ordered by `(class, subject)`.
    pub fn confirmed(&self) -> Vec<ConfirmedSink> {
        self.entries
            .iter()
            .filter_map(|((class, subject), stat)| {
                let taint_offset = stat.taint_offset?;
                if stat.untainted_seen {
                    return None;
                }
                Some(ConfirmedSink {
                    class: *class,
                    api: stat.api.clone(),
                    subject: subject.clone(),
                    taint_offset,
                    input: stat.representative_input.clone(),
                })
            })
            .collect()
    }
}

/// Build the taint-confirmed oracle hit for a confirmed sink by mapping its
/// class onto the matching runtime event and running it through the oracle
/// registry (GF-405/431/433/435/439/440).
pub fn confirmed_sink_hit(
    confirmed: &ConfirmedSink,
) -> Option<finding_rules::oracle_sdk::OracleHit> {
    use finding_rules::oracle_sdk::OracleRuntimeEvent as E;
    let api = confirmed.api.clone();
    let subject = confirmed.subject.clone();
    let taint_offset = confirmed.taint_offset;
    let event = match confirmed.class {
        SinkClass::OpenPath => E::TaintedFilePath {
            api,
            path: subject,
            taint_offset,
        },
        SinkClass::DestructivePath => E::TaintedDestructivePath {
            api,
            path: subject,
            taint_offset,
        },
        SinkClass::ProcessExec => E::TaintedCommand {
            api,
            command: subject,
            taint_offset,
        },
        SinkClass::NetworkEgress => E::TaintedNetworkAddress {
            api,
            address: subject,
            taint_offset,
        },
        SinkClass::LibraryLoad => E::TaintedLibrary {
            api,
            library: subject,
            taint_offset,
        },
        SinkClass::SqlQuery => E::TaintedSqlQuery {
            api,
            query: subject,
            taint_offset,
        },
    };
    finding_rules::oracle_registry::ORACLE_REGISTRY
        .iter()
        .find_map(|oracle| oracle.evaluate(&event))
}

/// Correlate TOCTOU pairs (CWE-367): a successful path check (access/faccessat)
/// followed by an open of the *same* path within one harness execution. The
/// correlation lives here in the cli — over the already-captured JSONL stream —
/// rather than in the signal-constrained LD_PRELOAD shim. One event per path.
fn toctou_runtime_events(
    events: &[RuntraceEvent],
) -> Vec<finding_rules::oracle_sdk::OracleRuntimeEvent> {
    use finding_rules::oracle_sdk::OracleRuntimeEvent;
    let mut checked = BTreeMap::<String, String>::new();
    let mut emitted = std::collections::HashSet::new();
    let mut out = Vec::new();
    for event in events {
        match event {
            RuntraceEvent::PathChecked { syscall, path } => {
                checked
                    .entry(path.clone())
                    .or_insert_with(|| syscall.clone());
            }
            RuntraceEvent::FileOpened { syscall, path, .. } => {
                if let Some(check_api) = checked.get(path) {
                    if emitted.insert(path.clone()) {
                        out.push(OracleRuntimeEvent::Toctou {
                            api: format!("{check_api}->{syscall}"),
                            path: path.clone(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn oracle_runtime_event(
    event: &RuntraceEvent,
) -> Option<finding_rules::oracle_sdk::OracleRuntimeEvent> {
    use finding_rules::oracle_sdk::OracleRuntimeEvent;
    match event {
        RuntraceEvent::FileMissing { syscall, path, .. } => Some(OracleRuntimeEvent::FilePath {
            api: syscall.clone(),
            path: path.clone(),
        }),
        RuntraceEvent::FileOpened { syscall, path, .. } => Some(OracleRuntimeEvent::FilePath {
            api: syscall.clone(),
            path: path.clone(),
        }),
        RuntraceEvent::FileDeleted { syscall, path } => Some(OracleRuntimeEvent::FileDeletion {
            api: syscall.clone(),
            path: path.clone(),
        }),
        RuntraceEvent::InsecurePermissions { api, path, mode } => {
            Some(OracleRuntimeEvent::InsecurePermissions {
                api: api.clone(),
                path: path.clone(),
                mode: *mode,
            })
        }
        RuntraceEvent::InsecureTempFile { api, path, .. } => {
            Some(OracleRuntimeEvent::InsecureTempFile {
                api: api.clone(),
                path: path.clone(),
            })
        }
        RuntraceEvent::NetworkUnreachable { address, .. } => {
            Some(OracleRuntimeEvent::NetworkAddress {
                api: "connect".to_owned(),
                address: address.clone(),
            })
        }
        RuntraceEvent::EnvVarMissing { api, name } | RuntraceEvent::EnvVarAccess { api, name } => {
            Some(OracleRuntimeEvent::EnvVar {
                api: api.clone(),
                name: name.clone(),
            })
        }
        RuntraceEvent::DlopenFailed { library } => Some(OracleRuntimeEvent::Library {
            api: "dlopen".to_owned(),
            library: library.clone(),
        }),
        // The per-event path only feeds the shell-metacharacter heuristic
        // (GF-304). Taint-confirmed command injection (GF-431) is emitted at
        // run end from cross-execution correlation, so `taint_offset` is not
        // consulted here.
        RuntraceEvent::CommandExecuted { api, command, .. } => Some(OracleRuntimeEvent::Command {
            api: api.clone(),
            command: command.clone(),
        }),
        RuntraceEvent::FormatString {
            api,
            format,
            controlled,
        } => Some(OracleRuntimeEvent::FormatString {
            api: api.clone(),
            format: format.clone(),
            controlled: *controlled,
        }),
        RuntraceEvent::RuntimeCheck {
            api,
            language,
            exception,
            check,
            handled,
            message,
            source,
        } => {
            let mut evidence = Vec::new();
            if !message.is_empty() {
                let key = if is_native_assertion_runtime_check(language, exception, check) {
                    "expression"
                } else {
                    "message"
                };
                evidence.push((key.to_owned(), message.clone()));
            }
            if !source.is_empty() {
                evidence.push(("source".to_owned(), source.clone()));
            }
            Some(OracleRuntimeEvent::RuntimeCheck {
                api: api.clone(),
                language: language.clone(),
                exception: exception.clone(),
                check: check.clone(),
                handled: *handled,
                evidence,
            })
        }
        // PathChecked is consumed only by the TOCTOU correlation pass below,
        // not as a standalone per-event oracle input. The taint-sink events
        // (ProcessExec/NetworkEgress/LibraryLoad/SqlQuery/DestructiveFsOp) are
        // confirmed at run end via SinkTaintTracker/confirmed_sink_hit — never
        // from a single raw event — so they do not map here (no per-input flood).
        RuntraceEvent::FileClosed { .. }
        | RuntraceEvent::PathChecked { .. }
        | RuntraceEvent::ProcessExec { .. }
        | RuntraceEvent::NetworkEgress { .. }
        | RuntraceEvent::LibraryLoad { .. }
        | RuntraceEvent::SqlQuery { .. }
        | RuntraceEvent::DestructiveFsOp { .. }
        | RuntraceEvent::Unknown { .. } => None,
    }
}

fn is_native_assertion_runtime_check(language: &str, exception: &str, check: &str) -> bool {
    matches!(
        language.trim().to_ascii_lowercase().as_str(),
        "c" | "cpp" | "c++"
    ) && exception == "AssertionFailure"
        && check == "assertion"
}

#[derive(Debug, Clone)]
struct OpenResource {
    api: String,
    path: String,
}

/// File resources that govfuzz's own infrastructure opens during a run — the
/// per-iteration fuzz input files, scratch/temp files, work-dir artifacts
/// (event logs, coverage/value-profile/cmplog shared-memory maps) and control
/// fds (`/dev/null`). The GF-306 resource-leak oracle is for resources the
/// *target* leaks; reporting one of these as a leak is a false positive on
/// govfuzz's own plumbing — the harness reads the input file / mmaps the
/// coverage map and the process exits before an explicit `close()`, so the fd
/// looks "unreleased" in the trace.
///
/// Matching is by path substring/prefix/suffix so a future infra path is a
/// one-line addition. Genuine leaks are unaffected: a target that opens a file
/// under the scanned source tree (or any other user path) and never closes it
/// matches nothing here and still trips GF-306.
pub fn is_govfuzz_owned_resource(path: &str) -> bool {
    // Distinctive work-dir subdirectory components: the per-iteration input
    // files (`fuzz_inputs/input-<pid>-<nonce>.bin`), the harness scratch cwd
    // (`fuzz_scratch/`), the runtrace event logs (`fuzz_runs/`), and the
    // injected fake-env tree used for missing env-derived paths.
    const OWNED_SUBSTRINGS: &[&str] = &[
        "/fuzz_inputs/",
        "/fuzz_scratch/",
        "/fuzz_runs/",
        "/govfuzz/fake_env/",
    ];
    // `gf_make_tempfile()` materializes fuzz bytes at `/tmp/gf_inXXXXXX`;
    // attempt/stub scratch and the fake-env dir live under `/tmp/govfuzz*`
    // (`std::env::temp_dir()` is `/tmp`).
    const OWNED_PREFIXES: &[&str] = &["/tmp/gf_", "/tmp/govfuzz"];
    // Shared-memory maps the C/C++ driver opens from `<work_dir>/build/<id>/`.
    const OWNED_SUFFIXES: &[&str] = &[
        "/coverage.shm",
        "/coverage_cnt.shm",
        "/vp.shm",
        "/cmp_progress.shm",
    ];
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed == "/dev/null" {
        return true;
    }
    OWNED_SUBSTRINGS
        .iter()
        .any(|needle| trimmed.contains(needle))
        || OWNED_PREFIXES.iter().any(|p| trimmed.starts_with(p))
        || OWNED_SUFFIXES.iter().any(|s| trimmed.ends_with(s))
}

fn resource_leak_runtime_events(
    events: &[RuntraceEvent],
) -> Vec<finding_rules::oracle_sdk::OracleRuntimeEvent> {
    let mut opened = BTreeMap::<i32, OpenResource>::new();
    let mut leaks = Vec::new();
    for event in events {
        match event {
            RuntraceEvent::FileOpened {
                syscall, fd, path, ..
            } if *fd >= 0 => {
                // Govfuzz's own input-plumbing / scaffolding opens must never
                // count toward a target resource leak (the FP this guards).
                if is_govfuzz_owned_resource(path) {
                    continue;
                }
                if let Some(previous) = opened.insert(
                    *fd,
                    OpenResource {
                        api: syscall.clone(),
                        path: path.clone(),
                    },
                ) {
                    leaks.push(resource_leak_event(*fd, previous));
                }
            }
            RuntraceEvent::FileClosed { fd } => {
                opened.remove(fd);
            }
            _ => {}
        }
    }
    leaks.extend(
        opened
            .into_iter()
            .map(|(fd, resource)| resource_leak_event(fd, resource)),
    );
    leaks
}

fn resource_leak_event(
    fd: i32,
    resource: OpenResource,
) -> finding_rules::oracle_sdk::OracleRuntimeEvent {
    finding_rules::oracle_sdk::OracleRuntimeEvent::ResourceLeak {
        api: resource.api,
        resource: format!("fd:{fd} path:{}", resource.path),
        evidence: vec![
            ("fd".to_owned(), fd.to_string()),
            ("path".to_owned(), resource.path),
        ],
    }
}

/// Read byte-origin taint fields (#422) from a path event: `u` is the
/// controlled flag, `o` the fuzz-input offset the path bytes came from.
/// Returns the offset only when the event is marked controlled, so an
/// untainted open carries `None` and never confirms GF-405.
fn parse_taint_offset(obj: &serde_json::Map<String, Value>) -> Option<u32> {
    let controlled = obj
        .get("u")
        .and_then(|value| {
            value
                .as_bool()
                .or_else(|| value.as_i64().map(|number| number != 0))
        })
        .unwrap_or(false);
    if !controlled {
        return None;
    }
    obj.get("o")
        .and_then(Value::as_i64)
        .and_then(|offset| u32::try_from(offset).ok())
}

fn parse_line(line: &str) -> Option<RuntraceEvent> {
    let v: Value = serde_json::from_str(line).ok()?;
    let obj = v.as_object()?;
    let kind = obj.get("e").and_then(Value::as_str)?;
    match kind {
        "getenv" | "secure_getenv" => {
            let name = obj.get("n").and_then(Value::as_str)?.to_owned();
            let api = kind.to_owned();
            if obj.get("r").map(Value::is_null).unwrap_or(true) {
                Some(RuntraceEvent::EnvVarMissing { api, name })
            } else {
                Some(RuntraceEvent::EnvVarAccess { api, name })
            }
        }
        "open" | "openat" => {
            let path = obj.get("p").and_then(Value::as_str)?.to_owned();
            let result = obj.get("r").and_then(Value::as_i64).unwrap_or(-1);
            let taint_offset = parse_taint_offset(obj);
            if result >= 0 {
                let fd = obj.get("d").and_then(Value::as_i64).unwrap_or(result) as i32;
                Some(RuntraceEvent::FileOpened {
                    syscall: kind.to_owned(),
                    fd,
                    path,
                    taint_offset,
                })
            } else {
                Some(RuntraceEvent::FileMissing {
                    syscall: kind.to_owned(),
                    path,
                    taint_offset,
                })
            }
        }
        "stat" | "access" | "faccessat" | "readlink" | "readlinkat" => {
            let path = obj.get("p").and_then(Value::as_str)?.to_owned();
            Some(RuntraceEvent::FileMissing {
                syscall: kind.to_owned(),
                path,
                taint_offset: None,
            })
        }
        "path_check" => {
            let syscall = obj
                .get("a")
                .and_then(Value::as_str)
                .unwrap_or("access")
                .to_owned();
            let path = obj.get("p").and_then(Value::as_str)?.to_owned();
            Some(RuntraceEvent::PathChecked { syscall, path })
        }
        "close" => {
            let result = obj.get("r").and_then(Value::as_i64).unwrap_or(-1);
            if result == 0 {
                let fd = obj.get("d").and_then(Value::as_i64)? as i32;
                Some(RuntraceEvent::FileClosed { fd })
            } else {
                None
            }
        }
        "unlink" | "unlinkat" | "remove" => {
            let result = obj.get("r").and_then(Value::as_i64).unwrap_or(-1);
            if result == 0 {
                let path = obj.get("p").and_then(Value::as_str)?.to_owned();
                Some(RuntraceEvent::FileDeleted {
                    syscall: kind.to_owned(),
                    path,
                })
            } else {
                None
            }
        }
        "insecure_chmod" => {
            let path = obj
                .get("p")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_default();
            let mode = obj.get("m").and_then(Value::as_i64).unwrap_or(0);
            Some(RuntraceEvent::InsecurePermissions {
                api: "chmod".to_owned(),
                path,
                mode,
            })
        }
        "insecure_mkdir" => {
            let api = obj
                .get("a")
                .and_then(Value::as_str)
                .unwrap_or("mkdir")
                .to_owned();
            let path = obj
                .get("p")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_default();
            let mode = obj.get("m").and_then(Value::as_i64).unwrap_or(0);
            Some(RuntraceEvent::InsecurePermissions { api, path, mode })
        }
        "insecure_tempfile" => {
            let api = obj
                .get("a")
                .and_then(Value::as_str)
                .unwrap_or("open")
                .to_owned();
            let path = obj
                .get("p")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_default();
            let flags = obj.get("f").and_then(Value::as_i64).unwrap_or(0);
            Some(RuntraceEvent::InsecureTempFile { api, path, flags })
        }
        "connect" => {
            let family = obj.get("f").and_then(Value::as_i64).unwrap_or(0) as i32;
            let address = obj
                .get("a")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            Some(RuntraceEvent::NetworkUnreachable { family, address })
        }
        "getaddrinfo" => {
            let address = obj.get("n").and_then(Value::as_str)?.to_owned();
            Some(RuntraceEvent::NetworkUnreachable { family: 0, address })
        }
        "dlopen" => {
            let library = obj.get("l").and_then(Value::as_str)?.to_owned();
            Some(RuntraceEvent::DlopenFailed { library })
        }
        "system" | "popen" => {
            let command = obj.get("c").and_then(Value::as_str)?.to_owned();
            let taint_offset = parse_taint_offset(obj);
            Some(RuntraceEvent::CommandExecuted {
                api: kind.to_owned(),
                command,
                taint_offset,
            })
        }
        "exec" => {
            let api = obj.get("a").and_then(Value::as_str)?.to_owned();
            let program = obj.get("p").and_then(Value::as_str)?.to_owned();
            let taint_offset = parse_taint_offset(obj);
            Some(RuntraceEvent::ProcessExec {
                api,
                program,
                taint_offset,
            })
        }
        "net_egress" => {
            let api = obj.get("a").and_then(Value::as_str)?.to_owned();
            let address = obj.get("d").and_then(Value::as_str)?.to_owned();
            let taint_offset = parse_taint_offset(obj);
            Some(RuntraceEvent::NetworkEgress {
                api,
                address,
                taint_offset,
            })
        }
        "lib_load" => {
            let api = obj.get("a").and_then(Value::as_str)?.to_owned();
            let library = obj.get("l").and_then(Value::as_str)?.to_owned();
            let taint_offset = parse_taint_offset(obj);
            Some(RuntraceEvent::LibraryLoad {
                api,
                library,
                taint_offset,
            })
        }
        "sql" => {
            let api = obj.get("a").and_then(Value::as_str)?.to_owned();
            let query = obj.get("q").and_then(Value::as_str)?.to_owned();
            let taint_offset = parse_taint_offset(obj);
            Some(RuntraceEvent::SqlQuery {
                api,
                query,
                taint_offset,
            })
        }
        "fs_destroy" => {
            let api = obj.get("a").and_then(Value::as_str)?.to_owned();
            let path = obj.get("p").and_then(Value::as_str)?.to_owned();
            let taint_offset = parse_taint_offset(obj);
            Some(RuntraceEvent::DestructiveFsOp {
                api,
                path,
                taint_offset,
            })
        }
        "format" => {
            let api = obj.get("a").and_then(Value::as_str)?.to_owned();
            let format = obj.get("f").and_then(Value::as_str)?.to_owned();
            let controlled = obj
                .get("u")
                .and_then(|value| {
                    value
                        .as_bool()
                        .or_else(|| value.as_i64().map(|number| number != 0))
                })
                .unwrap_or(false);
            Some(RuntraceEvent::FormatString {
                api,
                format,
                controlled,
            })
        }
        "runtime_check" => {
            let api = obj
                .get("a")
                .and_then(Value::as_str)
                .unwrap_or("ada-runtime")
                .to_owned();
            let language = obj
                .get("l")
                .and_then(Value::as_str)
                .unwrap_or("ada")
                .to_owned();
            let exception = obj.get("x").and_then(Value::as_str)?.to_owned();
            let check = obj.get("c").and_then(Value::as_str)?.to_owned();
            let handled = obj
                .get("h")
                .and_then(|value| {
                    value
                        .as_bool()
                        .or_else(|| value.as_i64().map(|number| number != 0))
                })
                .unwrap_or(false);
            let message = obj
                .get("m")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let source = obj
                .get("s")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            Some(RuntraceEvent::RuntimeCheck {
                api,
                language,
                exception,
                check,
                handled,
                message,
                source,
            })
        }
        "assertion_failed" => {
            let api = obj
                .get("a")
                .and_then(Value::as_str)
                .unwrap_or("__assert_fail")
                .to_owned();
            let language = obj
                .get("l")
                .and_then(Value::as_str)
                .unwrap_or("c")
                .to_owned();
            let expression = obj
                .get("x")
                .or_else(|| obj.get("m"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let file = obj.get("f").and_then(Value::as_str).unwrap_or("");
            let line = obj.get("n").and_then(Value::as_i64);
            let function = obj.get("g").and_then(Value::as_str).unwrap_or("");
            Some(RuntraceEvent::RuntimeCheck {
                api,
                language,
                exception: "AssertionFailure".to_owned(),
                check: "assertion".to_owned(),
                handled: false,
                message: expression,
                source: format_assertion_source(file, line, function),
            })
        }
        _ => None,
    }
}

fn format_assertion_source(file: &str, line: Option<i64>, function: &str) -> String {
    let file = file.trim();
    let function = function.trim();
    match (file.is_empty(), line, function.is_empty()) {
        (true, None, true) => String::new(),
        (true, Some(line), false) => format!("{line}:{function}"),
        (true, Some(line), true) => line.to_string(),
        (true, None, false) => function.to_owned(),
        (false, Some(line), true) => format!("{file}:{line}"),
        (false, Some(line), false) => format!("{file}:{line}:{function}"),
        (false, None, true) => file.to_owned(),
        (false, None, false) => format!("{file}:{function}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_getenv_event() {
        let log = r#"{"e":"getenv","n":"FOO_HOME","r":null}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::EnvVarMissing { api, name }
                if api == "getenv" && name == "FOO_HOME"
        ));
    }

    #[test]
    fn parses_secure_getenv_event() {
        let log = r#"{"e":"secure_getenv","n":"DB_PASSWORD","r":null}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::EnvVarMissing { api, name }
                if api == "secure_getenv" && name == "DB_PASSWORD"
        ));
    }

    #[test]
    fn parses_present_getenv_event_as_redacted_access() {
        let log = r#"{"e":"getenv","n":"DB_PASSWORD","r":1}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::EnvVarAccess { api, name }
                if api == "getenv" && name == "DB_PASSWORD"
        ));
    }

    #[test]
    fn symbolizer_config_env_events_are_dropped() {
        // The ASan crash symbolizer inherits our LD_PRELOAD + runtrace log and
        // probes these config families; they must be filtered out so they are
        // never misattributed to the target as a faked env var.
        let log = concat!(
            "{\"e\":\"getenv\",\"n\":\"OPENSSL_CONF\",\"r\":null}\n",
            "{\"e\":\"getenv\",\"n\":\"LLVM_SYMBOLIZER_PATH\",\"r\":null}\n",
            "{\"e\":\"getenv\",\"n\":\"DEBUGINFOD_URLS\",\"r\":null}\n",
            "{\"e\":\"getenv\",\"n\":\"GLIBCXX_TUNABLES\",\"r\":null}\n",
            "{\"e\":\"getenv\",\"n\":\"ACME_HOME\",\"r\":null}\n",
        );

        let evs = parse_str(log);

        assert_eq!(
            evs,
            vec![RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME_HOME".to_owned(),
            }]
        );
        assert!(is_internal_env_name("OPENSSL_CONF"));
        assert!(is_internal_env_name("GLIBCXX_TUNABLES"));
        // #33: the Rust panic handler's backtrace knobs are runtime infra, not a
        // target env dependency.
        assert!(is_internal_env_name("RUST_BACKTRACE"));
        assert!(is_internal_env_name("RUST_LIB_BACKTRACE"));
    }

    #[test]
    fn sanitizer_symbolizer_file_probes_are_dropped() {
        // llvm-symbolizer's own debuginfod cache miss is not the target's
        // missing file — it must not become a missing-dependency row.
        let log = concat!(
            "{\"e\":\"open\",\"p\":\"/home/u/.cache/llvm-debuginfod/x\",\"r\":-1,\"n\":2}\n",
            "{\"e\":\"open\",\"p\":\"/etc/app.conf\",\"r\":-1,\"n\":2}\n",
        );
        let evs = parse_str(log);
        assert_eq!(
            evs,
            vec![RuntraceEvent::FileMissing {
                syscall: "open".to_owned(),
                path: "/etc/app.conf".to_owned(),
                taint_offset: None,
            }]
        );
    }

    #[test]
    fn internal_govfuzz_getenv_events_are_dropped() {
        let log = concat!(
            "{\"e\":\"getenv\",\"n\":\"GOVFUZZ_FAKE_IDENTITY\",\"r\":null}\n",
            "{\"e\":\"getenv\",\"n\":\"ACME_HOME\",\"r\":null}\n",
        );

        let evs = parse_str(log);

        assert_eq!(
            evs,
            vec![RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME_HOME".to_owned(),
            }]
        );
    }

    #[test]
    fn parses_open_event() {
        let log = r#"{"e":"open","p":"/etc/missing.conf","r":-1,"n":2}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::FileMissing { syscall, path, .. }
                if syscall == "open" && path == "/etc/missing.conf"
        ));
    }

    #[test]
    fn parses_tainted_open_records_offset() {
        // `u`=controlled flag, `o`=fuzz-input offset (#422).
        let log = r#"{"e":"open","p":"../../etc/passwd","r":-1,"n":2,"u":1,"o":5}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::FileMissing { syscall, path, taint_offset }
                if syscall == "open" && path == "../../etc/passwd" && *taint_offset == Some(5)
        ));
    }

    #[test]
    fn parses_untainted_open_has_no_offset() {
        // No `u` flag => not controlled, even if an `o` field is present.
        let log = r#"{"e":"open","p":"/etc/hosts","r":-1,"n":2,"o":3}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::FileMissing { taint_offset, .. } if taint_offset.is_none()
        ));
    }

    #[test]
    fn parses_successful_open_and_close_events() {
        let log = concat!(
            "{\"e\":\"open\",\"p\":\"/tmp/acme.conf\",\"d\":7,\"r\":7}\n",
            "{\"e\":\"close\",\"d\":7,\"r\":0}\n",
        );

        let evs = parse_str(log);

        assert_eq!(
            evs,
            vec![
                RuntraceEvent::FileOpened {
                    syscall: "open".to_owned(),
                    fd: 7,
                    path: "/tmp/acme.conf".to_owned(),
                    taint_offset: None,
                },
                RuntraceEvent::FileClosed { fd: 7 },
            ]
        );
    }

    #[test]
    fn parses_unlink_event() {
        let log = r#"{"e":"unlink","p":"../state/session.db","r":0}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::FileDeleted { syscall, path }
                if syscall == "unlink" && path == "../state/session.db"
        ));
    }

    #[test]
    fn parses_insecure_chmod_event() {
        let log = r#"{"e":"insecure_chmod","p":"/tmp/extracted","m":2541}"#; // 0o4755 (setuid)
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::InsecurePermissions { api, path, mode }
                if api == "chmod" && path == "/tmp/extracted" && *mode == 0o4755
        ));
    }

    #[test]
    fn parses_insecure_tempfile_event() {
        let log = r#"{"e":"insecure_tempfile","a":"open","p":"/tmp/scratch.123","f":65}"#; // O_WRONLY|O_CREAT
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::InsecureTempFile { api, path, flags }
                if api == "open" && path == "/tmp/scratch.123" && *flags == 65
        ));
    }

    #[test]
    fn parses_insecure_mkdir_event() {
        let log = r#"{"e":"insecure_mkdir","a":"mkdir","p":"/tmp/shared","m":511}"#; // 0o777
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::InsecurePermissions { api, path, mode }
                if api == "mkdir" && path == "/tmp/shared" && *mode == 0o777
        ));
    }

    #[test]
    fn oracle_hits_from_events_flags_world_writable_mkdir() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::InsecurePermissions {
            api: "mkdir".to_owned(),
            path: "/tmp/shared".to_owned(),
            mode: 0o777,
        }]);
        assert!(
            hits.iter()
                .any(|h| h.rule_id == "GF-416" && h.api == "mkdir"),
            "world-writable mkdir must flag GF-416"
        );
    }

    #[test]
    fn parses_path_check_event() {
        let log = r#"{"e":"path_check","a":"access","p":"/var/run/app/state"}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::PathChecked { syscall, path }
                if syscall == "access" && path == "/var/run/app/state"
        ));
    }

    #[test]
    fn parses_connect_event() {
        let log = r#"{"e":"connect","f":1,"a":"/var/run/acme.sock","r":-1,"n":111}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::NetworkUnreachable { family, address }
                if *family == 1 && address == "/var/run/acme.sock"
        ));
    }

    #[test]
    fn parses_dlopen_event() {
        let log = r#"{"e":"dlopen","l":"libfoo.so.4","r":null}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::DlopenFailed { library } if library == "libfoo.so.4"
        ));
    }

    #[test]
    fn parses_system_command_event() {
        let log = r#"{"e":"system","c":"echo ok; id","r":0}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::CommandExecuted { api, command, taint_offset: None }
                if api == "system" && command == "echo ok; id"
        ));
    }

    #[test]
    fn parses_tainted_command_event_offset() {
        // The shim marks a fuzz-controlled command with `u`=1 and `o`=offset.
        let log = r#"{"e":"popen","c":"convert AAAA out.png","u":1,"o":8}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::CommandExecuted { api, taint_offset: Some(8), .. }
                if api == "popen"
        ));
    }

    #[test]
    fn parses_new_taint_sink_events() {
        // Each new shim sink event round-trips into its RuntraceEvent with the
        // byte-origin taint offset, so the SinkTaintTracker can consume it.
        let log = concat!(
            r#"{"e":"exec","a":"execve","p":"/nonexistent/AAAA","u":1,"o":13}"#,
            "\n",
            r#"{"e":"net_egress","a":"getaddrinfo","d":"evil.example","u":1,"o":0}"#,
            "\n",
            r#"{"e":"lib_load","a":"dlopen","l":"/tmp/AAAA.so","u":1,"o":5}"#,
            "\n",
            r#"{"e":"sql","a":"sqlite3_exec","q":"SELECT 'AAAA'","u":1,"o":2}"#,
            "\n",
            r#"{"e":"fs_destroy","a":"unlink","p":"/nonexistent/AAAA","u":1,"o":13}"#,
        );
        let evs = parse_str(log);
        assert_eq!(evs.len(), 5);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::ProcessExec { api, taint_offset: Some(13), .. } if api == "execve"
        ));
        assert!(matches!(
            &evs[1],
            RuntraceEvent::NetworkEgress { api, address, taint_offset: Some(0) }
                if api == "getaddrinfo" && address == "evil.example"
        ));
        assert!(matches!(
            &evs[2],
            RuntraceEvent::LibraryLoad { api, taint_offset: Some(5), .. } if api == "dlopen"
        ));
        assert!(matches!(
            &evs[3],
            RuntraceEvent::SqlQuery { api, taint_offset: Some(2), .. } if api == "sqlite3_exec"
        ));
        assert!(matches!(
            &evs[4],
            RuntraceEvent::DestructiveFsOp { api, taint_offset: Some(13), .. } if api == "unlink"
        ));
    }

    #[test]
    fn parses_controlled_format_string_event() {
        let log = r#"{"e":"format","a":"printf","f":"%x %x %n","u":1}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::FormatString { api, format, controlled }
                if api == "printf" && format == "%x %x %n" && *controlled
        ));
    }

    #[test]
    fn parses_handled_runtime_check_event() {
        let log = r#"{"e":"runtime_check","a":"ada-runtime","l":"ada","x":"Constraint_Error","c":"index_check","h":1,"m":"range check failed","s":"parser.adb:42"}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::RuntimeCheck { api, language, exception, check, handled, message, source }
                if api == "ada-runtime"
                    && language == "ada"
                    && exception == "Constraint_Error"
                    && check == "index_check"
                    && *handled
                    && message == "range check failed"
                    && source == "parser.adb:42"
        ));
    }

    #[test]
    fn parses_native_assertion_failure_event() {
        let log = r#"{"e":"assertion_failed","a":"__assert_fail","x":"len < cap","f":"parser.c","n":42,"g":"parse_frame"}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            RuntraceEvent::RuntimeCheck { api, language, exception, check, handled, message, source }
                if api == "__assert_fail"
                    && language == "c"
                    && exception == "AssertionFailure"
                    && check == "assertion"
                    && !*handled
                    && message == "len < cap"
                    && source == "parser.c:42:parse_frame"
        ));
    }

    #[test]
    fn unknown_event_kind_preserved_as_raw() {
        let log = r#"{"e":"future_event","x":1}"#;
        let evs = parse_str(log);
        assert_eq!(evs.len(), 1);
        assert!(matches!(&evs[0], RuntraceEvent::Unknown { .. }));
    }

    #[test]
    fn empty_and_garbage_lines_handled() {
        let log = "\n\nnot json at all\n{\"e\":\"open\",\"p\":\"/x\",\"r\":-1,\"n\":2}\n";
        let evs = parse_str(log);
        assert_eq!(evs.len(), 2);
        assert!(matches!(&evs[0], RuntraceEvent::Unknown { .. }));
        assert!(matches!(&evs[1], RuntraceEvent::FileMissing { .. }));
    }

    #[test]
    fn dedupe_in_place_keeps_first_occurrence_order() {
        let mut evs = vec![
            RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME".to_owned(),
            },
            RuntraceEvent::FileMissing {
                syscall: "open".to_owned(),
                path: "/etc/acme.conf".to_owned(),
                taint_offset: None,
            },
            RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME".to_owned(),
            },
        ];

        dedupe_in_place(&mut evs);

        assert_eq!(
            evs,
            vec![
                RuntraceEvent::EnvVarMissing {
                    api: "getenv".to_owned(),
                    name: "ACME".to_owned(),
                },
                RuntraceEvent::FileMissing {
                    syscall: "open".to_owned(),
                    path: "/etc/acme.conf".to_owned(),
                    taint_offset: None,
                },
            ]
        );
    }

    #[test]
    fn oracle_hits_from_events_maps_parent_path_file_events() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::FileMissing {
            syscall: "open".to_owned(),
            path: "../secrets/token.txt".to_owned(),
            taint_offset: None,
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "path-traversal-ada");
        assert_eq!(hits[0].rule_id, "GF-101");
        assert_eq!(hits[0].api, "open");
        assert_eq!(hits[0].evidence_value("path"), Some("../secrets/token.txt"));
    }

    #[test]
    fn raw_tainted_open_does_not_emit_gf405_per_input() {
        // GF-405 is confirmed only by cross-execution correlation, never
        // by a single raw open event — so the per-input oracle pass must
        // not emit it (that is what prevents a per-input flood).
        let hits = oracle_hits_from_events(&[RuntraceEvent::FileMissing {
            syscall: "open".to_owned(),
            path: "config/../../etc/passwd".to_owned(),
            taint_offset: Some(0),
        }]);
        assert!(
            !hits.iter().any(|h| h.rule_id == "GF-405"),
            "GF-405 must not be emitted from the per-input oracle pass"
        );
    }

    #[test]
    fn sink_tracker_confirms_consistently_tainted_open_path() {
        // A path tainted on every execution that opens it (and never
        // untainted) is a genuine fuzz-controlled open → GF-405.
        let mut tracker = SinkTaintTracker::default();
        tracker.observe(
            &[RuntraceEvent::FileMissing {
                syscall: "open".to_owned(),
                path: "../../etc/passwd".to_owned(),
                taint_offset: Some(4),
            }],
            b"GET ../../etc/passwd",
        );

        let confirmed = tracker.confirmed();
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].class, SinkClass::OpenPath);
        assert_eq!(confirmed[0].subject, "../../etc/passwd");
        assert_eq!(confirmed[0].taint_offset, 4);
        assert_eq!(confirmed[0].input, b"GET ../../etc/passwd");

        let hit = confirmed_sink_hit(&confirmed[0]).expect("confirmed open yields GF-405");
        assert_eq!(hit.rule_id, "GF-405");
        assert_eq!(hit.oracle_name, "path-controlled-open-runtime");
        assert_eq!(hit.evidence_value("path"), Some("../../etc/passwd"));
        assert!(
            hit.evidence_value("taint_path")
                .is_some_and(|p| p.contains("→ open(path)")),
            "GF-405 hit must carry a source→sink taint path"
        );
    }

    #[test]
    fn sink_tracker_suppresses_path_also_seen_untainted() {
        // A program constant the auto-dictionary echoes into one input
        // (tainted there) but that is opened on other inputs WITHOUT being
        // present (untainted) must NOT be confirmed — this is the 0-FP
        // guarantee for a sanitized/fixed-path open.
        let mut tracker = SinkTaintTracker::default();
        // Execution 1: the constant happened to appear in the input.
        tracker.observe(
            &[RuntraceEvent::FileMissing {
                syscall: "open".to_owned(),
                path: "/etc/app.conf".to_owned(),
                taint_offset: Some(7),
            }],
            b"junk...../etc/app.conf",
        );
        // Execution 2: same constant opened, but not derived from the input.
        tracker.observe(
            &[RuntraceEvent::FileMissing {
                syscall: "open".to_owned(),
                path: "/etc/app.conf".to_owned(),
                taint_offset: None,
            }],
            b"unrelated input",
        );
        assert!(
            tracker.confirmed().is_empty(),
            "a path also opened untainted must be suppressed (program constant)"
        );
    }

    #[test]
    fn raw_tainted_command_does_not_emit_gf431_per_input() {
        // GF-431 is confirmed only by cross-execution correlation, never by a
        // single raw command event — the per-input oracle pass must not emit it
        // (that is what prevents a per-input flood and keeps it taint-gated).
        let hits = oracle_hits_from_events(&[RuntraceEvent::CommandExecuted {
            api: "system".to_owned(),
            command: "convert AAAA out.png".to_owned(),
            taint_offset: Some(8),
        }]);
        assert!(
            !hits.iter().any(|h| h.rule_id == "GF-431"),
            "GF-431 must not be emitted from the per-input oracle pass"
        );
    }

    #[test]
    fn sink_tracker_confirms_consistently_tainted_command() {
        // A command tainted on every execution that runs it (and never
        // untainted) is a genuine fuzz-controlled shell exec → GF-431.
        let mut tracker = SinkTaintTracker::default();
        tracker.observe(
            &[RuntraceEvent::CommandExecuted {
                api: "system".to_owned(),
                command: "convert /tmp/AAAA out.png".to_owned(),
                taint_offset: Some(5),
            }],
            b"AAAA",
        );

        let confirmed = tracker.confirmed();
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].class, SinkClass::ProcessExec);
        assert_eq!(confirmed[0].subject, "convert /tmp/AAAA out.png");
        assert_eq!(confirmed[0].taint_offset, 5);
        assert_eq!(confirmed[0].input, b"AAAA");

        let hit = confirmed_sink_hit(&confirmed[0]).expect("confirmed command yields GF-431");
        assert_eq!(hit.rule_id, "GF-431");
        assert_eq!(hit.oracle_name, "command-controlled-runtime");
        assert_eq!(hit.api, "system");
        assert!(
            hit.evidence_value("taint_path")
                .is_some_and(|p| p.contains("→ system(command)")),
            "GF-431 hit must carry a source→sink taint path"
        );
    }

    #[test]
    fn sink_tracker_suppresses_command_also_seen_untainted() {
        // A hardcoded command the auto-dictionary echoes into one input
        // (tainted there) but that also runs on other inputs WITHOUT being
        // present (untainted) must NOT be confirmed — the 0-FP guarantee for a
        // constant command that merely contains shell metacharacters.
        let mut tracker = SinkTaintTracker::default();
        tracker.observe(
            &[RuntraceEvent::CommandExecuted {
                api: "system".to_owned(),
                command: "git status".to_owned(),
                taint_offset: Some(3),
            }],
            b"xxxgit status",
        );
        tracker.observe(
            &[RuntraceEvent::CommandExecuted {
                api: "system".to_owned(),
                command: "git status".to_owned(),
                taint_offset: None,
            }],
            b"unrelated input",
        );
        assert!(
            tracker.confirmed().is_empty(),
            "a command also run untainted must be suppressed (program constant)"
        );
    }

    #[test]
    fn sink_tracker_confirms_every_new_sink_class() {
        // Each new taint sink class, tainted-and-never-untainted, confirms its
        // oracle with a source→sink taint path. Exec/network/library/sql/
        // destructive-fs cover the full breadth of the sink-oracle subsystem.
        let cases: &[(RuntraceEvent, SinkClass, &str, &str, &str)] = &[
            (
                RuntraceEvent::ProcessExec {
                    api: "execve".to_owned(),
                    program: "/tmp/AAAA/payload".to_owned(),
                    taint_offset: Some(0),
                },
                SinkClass::ProcessExec,
                "GF-431",
                "command-controlled-runtime",
                "→ execve(command)",
            ),
            (
                RuntraceEvent::NetworkEgress {
                    api: "getaddrinfo".to_owned(),
                    address: "attacker.example".to_owned(),
                    taint_offset: Some(2),
                },
                SinkClass::NetworkEgress,
                "GF-433",
                "ssrf-controlled-runtime",
                "→ getaddrinfo(address)",
            ),
            (
                RuntraceEvent::LibraryLoad {
                    api: "dlopen".to_owned(),
                    library: "/tmp/AAAA/evil.so".to_owned(),
                    taint_offset: Some(1),
                },
                SinkClass::LibraryLoad,
                "GF-435",
                "library-load-controlled-runtime",
                "→ dlopen(path)",
            ),
            (
                RuntraceEvent::SqlQuery {
                    api: "sqlite3_exec".to_owned(),
                    query: "SELECT * FROM t WHERE x='AAAA'".to_owned(),
                    taint_offset: Some(3),
                },
                SinkClass::SqlQuery,
                "GF-441",
                "sql-injection-runtime",
                "→ sqlite3_exec(sql)",
            ),
            (
                RuntraceEvent::DestructiveFsOp {
                    api: "unlink".to_owned(),
                    path: "/tmp/AAAA".to_owned(),
                    taint_offset: Some(0),
                },
                SinkClass::DestructivePath,
                "GF-440",
                "destructive-path-controlled-runtime",
                "→ unlink(path)",
            ),
        ];
        for (event, class, rule, oracle, taint_needle) in cases {
            let mut tracker = SinkTaintTracker::default();
            tracker.observe(std::slice::from_ref(event), b"AAAA");
            let confirmed = tracker.confirmed();
            assert_eq!(confirmed.len(), 1, "{rule}: one confirmed sink");
            assert_eq!(confirmed[0].class, *class, "{rule}: class");
            let hit = confirmed_sink_hit(&confirmed[0])
                .unwrap_or_else(|| panic!("{rule}: confirmed sink must yield a hit"));
            assert_eq!(hit.rule_id, *rule);
            assert_eq!(hit.oracle_name, *oracle);
            assert_eq!(hit.evidence_value("controlled"), Some("true"));
            assert!(
                hit.evidence_value("taint_path")
                    .is_some_and(|p| p.contains(taint_needle)),
                "{rule}: taint_path must contain {taint_needle:?}"
            );
        }
    }

    #[test]
    fn sink_tracker_suppresses_every_class_when_also_untainted() {
        // The never-untainted 0-FP guarantee holds uniformly across classes: a
        // constant destination/library/query reached without taint on any
        // execution is never confirmed, even if echoed into one input.
        let tainted_then_clean = |tainted: RuntraceEvent, clean: RuntraceEvent| {
            let mut tracker = SinkTaintTracker::default();
            tracker.observe(&[tainted], b"echoed-constant-xyz");
            tracker.observe(&[clean], b"unrelated");
            tracker.confirmed().is_empty()
        };
        assert!(tainted_then_clean(
            RuntraceEvent::NetworkEgress {
                api: "getaddrinfo".to_owned(),
                address: "metrics.internal".to_owned(),
                taint_offset: Some(1),
            },
            RuntraceEvent::NetworkEgress {
                api: "getaddrinfo".to_owned(),
                address: "metrics.internal".to_owned(),
                taint_offset: None,
            },
        ));
        assert!(tainted_then_clean(
            RuntraceEvent::SqlQuery {
                api: "PQexec".to_owned(),
                query: "SELECT version()".to_owned(),
                taint_offset: Some(0),
            },
            RuntraceEvent::SqlQuery {
                api: "PQexec".to_owned(),
                query: "SELECT version()".to_owned(),
                taint_offset: None,
            },
        ));
    }

    #[test]
    fn oracle_hits_from_events_correlates_toctou_check_then_open() {
        // access(P) then open(P) on the same path is a TOCTOU race.
        let hits = oracle_hits_from_events(&[
            RuntraceEvent::PathChecked {
                syscall: "access".to_owned(),
                path: "/var/run/app/state".to_owned(),
            },
            RuntraceEvent::FileOpened {
                syscall: "open".to_owned(),
                fd: 5,
                path: "/var/run/app/state".to_owned(),
                taint_offset: None,
            },
        ]);
        let toctou: Vec<_> = hits.iter().filter(|h| h.rule_id == "GF-418").collect();
        assert_eq!(toctou.len(), 1, "exactly one TOCTOU hit");
        assert_eq!(toctou[0].api, "access->open");
        assert_eq!(toctou[0].evidence_value("path"), Some("/var/run/app/state"));
    }

    #[test]
    fn oracle_hits_from_events_ignores_check_and_open_of_different_paths() {
        let hits = oracle_hits_from_events(&[
            RuntraceEvent::PathChecked {
                syscall: "access".to_owned(),
                path: "/var/run/app/a".to_owned(),
            },
            RuntraceEvent::FileOpened {
                syscall: "open".to_owned(),
                fd: 5,
                path: "/var/run/app/b".to_owned(),
                taint_offset: None,
            },
        ]);
        assert!(
            !hits.iter().any(|h| h.rule_id == "GF-418"),
            "different paths must not correlate as TOCTOU"
        );
    }

    #[test]
    fn oracle_hits_from_events_maps_network_egress_events() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::NetworkUnreachable {
            family: 2,
            address: "metadata.google.internal:80".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "ssrf-ada");
        assert_eq!(hits[0].rule_id, "GF-303");
        assert_eq!(hits[0].api, "connect");
        assert_eq!(
            hits[0].evidence_value("address"),
            Some("metadata.google.internal:80")
        );
    }

    #[test]
    fn oracle_hits_from_events_maps_sensitive_env_access() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::EnvVarMissing {
            api: "getenv".to_owned(),
            name: "DB_PASSWORD".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "sensitive-env-ada");
        assert_eq!(hits[0].rule_id, "GF-305");
        assert_eq!(hits[0].api, "getenv");
        assert_eq!(hits[0].evidence_value("env_var"), Some("DB_PASSWORD"));
    }

    #[test]
    fn oracle_hits_from_events_preserves_secure_env_api() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::EnvVarMissing {
            api: "secure_getenv".to_owned(),
            name: "DB_PASSWORD".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "sensitive-env-ada");
        assert_eq!(hits[0].rule_id, "GF-305");
        assert_eq!(hits[0].api, "secure_getenv");
        assert_eq!(hits[0].evidence_value("env_var"), Some("DB_PASSWORD"));
    }

    #[test]
    fn oracle_hits_from_events_maps_present_sensitive_env_access() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::EnvVarAccess {
            api: "getenv".to_owned(),
            name: "AWS_SECRET_ACCESS_KEY".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "sensitive-env-ada");
        assert_eq!(hits[0].rule_id, "GF-305");
        assert_eq!(hits[0].api, "getenv");
        assert_eq!(
            hits[0].evidence_value("env_var"),
            Some("AWS_SECRET_ACCESS_KEY")
        );
    }

    #[test]
    fn oracle_hits_from_events_ignores_ordinary_env_access() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::EnvVarMissing {
            api: "getenv".to_owned(),
            name: "ACME_CONFIG_DIR".to_owned(),
        }]);

        assert!(hits.is_empty());
    }

    #[test]
    fn oracle_hits_from_events_maps_relative_dlopen_library() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::DlopenFailed {
            library: "plugins/libcodec.so".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "dynamic-library-load-runtime");
        assert_eq!(hits[0].rule_id, "GF-413");
        assert_eq!(hits[0].api, "dlopen");
        assert_eq!(
            hits[0].evidence_value("library"),
            Some("plugins/libcodec.so")
        );
    }

    #[test]
    fn oracle_hits_from_events_maps_command_injection() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::CommandExecuted {
            api: "system".to_owned(),
            command: "echo ok; id".to_owned(),
            taint_offset: None,
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "command-injection-ada");
        assert_eq!(hits[0].rule_id, "GF-304");
        assert_eq!(hits[0].api, "system");
        assert_eq!(hits[0].evidence_value("command"), Some("echo ok; id"));
    }

    #[test]
    fn oracle_hits_from_events_ignores_plain_command() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::CommandExecuted {
            api: "system".to_owned(),
            command: "/usr/bin/true".to_owned(),
            taint_offset: None,
        }]);

        assert!(hits.is_empty());
    }

    #[test]
    fn oracle_hits_from_events_maps_controlled_format_string() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::FormatString {
            api: "printf".to_owned(),
            format: "%p %p %n".to_owned(),
            controlled: true,
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "format-string-runtime");
        assert_eq!(hits[0].rule_id, "GF-408");
        assert_eq!(hits[0].api, "printf");
        assert_eq!(hits[0].evidence_value("format"), Some("%p %p %n"));
    }

    #[test]
    fn oracle_hits_from_events_maps_handled_runtime_constraint_check() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::RuntimeCheck {
            api: "ada-runtime".to_owned(),
            language: "ada".to_owned(),
            exception: "Constraint_Error".to_owned(),
            check: "index_check".to_owned(),
            handled: true,
            message: "range check failed".to_owned(),
            source: "parser.adb:42".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "ada-runtime-constraint-check");
        assert_eq!(hits[0].rule_id, "GF-102");
        assert_eq!(hits[0].api, "ada-runtime");
        assert_eq!(
            hits[0].evidence_value("exception"),
            Some("Constraint_Error")
        );
        assert_eq!(hits[0].evidence_value("check"), Some("index_check"));
        assert_eq!(hits[0].evidence_value("handled"), Some("true"));
        assert_eq!(
            hits[0].evidence_value("message"),
            Some("range check failed")
        );
        assert_eq!(hits[0].evidence_value("source"), Some("parser.adb:42"));
    }

    #[test]
    fn oracle_hits_from_events_maps_handled_runtime_storage_error() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::RuntimeCheck {
            api: "ada-runtime".to_owned(),
            language: "ada".to_owned(),
            exception: "Storage_Error".to_owned(),
            check: "allocation_check".to_owned(),
            handled: true,
            message: "allocator exhausted".to_owned(),
            source: "allocator.adb:17".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "ada-runtime-storage-error");
        assert_eq!(hits[0].rule_id, "GF-103");
        assert_eq!(hits[0].api, "ada-runtime");
        assert_eq!(hits[0].evidence_value("exception"), Some("Storage_Error"));
        assert_eq!(hits[0].evidence_value("check"), Some("allocation_check"));
        assert_eq!(hits[0].evidence_value("handled"), Some("true"));
        assert_eq!(
            hits[0].evidence_value("message"),
            Some("allocator exhausted")
        );
        assert_eq!(hits[0].evidence_value("source"), Some("allocator.adb:17"));
    }

    #[test]
    fn oracle_hits_from_events_maps_handled_runtime_tasking_error() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::RuntimeCheck {
            api: "ada-runtime".to_owned(),
            language: "ada".to_owned(),
            exception: "Tasking_Error".to_owned(),
            check: "task_activation".to_owned(),
            handled: true,
            message: "task activation failed".to_owned(),
            source: "workers.adb:88".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "ada-runtime-tasking-error");
        assert_eq!(hits[0].rule_id, "GF-104");
        assert_eq!(hits[0].api, "ada-runtime");
        assert_eq!(hits[0].evidence_value("exception"), Some("Tasking_Error"));
        assert_eq!(hits[0].evidence_value("check"), Some("task_activation"));
        assert_eq!(hits[0].evidence_value("handled"), Some("true"));
        assert_eq!(
            hits[0].evidence_value("message"),
            Some("task activation failed")
        );
        assert_eq!(hits[0].evidence_value("source"), Some("workers.adb:88"));
    }

    #[test]
    fn oracle_hits_from_events_maps_handled_runtime_user_exception() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::RuntimeCheck {
            api: "ada-runtime".to_owned(),
            language: "ada".to_owned(),
            exception: "Protocol.Bad_Frame".to_owned(),
            check: "explicit_raise".to_owned(),
            handled: true,
            message: "bad frame marker".to_owned(),
            source: "protocol.adb:54".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "ada-runtime-user-exception");
        assert_eq!(hits[0].rule_id, "GF-105");
        assert_eq!(hits[0].api, "ada-runtime");
        assert_eq!(
            hits[0].evidence_value("exception"),
            Some("Protocol.Bad_Frame")
        );
        assert_eq!(hits[0].evidence_value("check"), Some("explicit_raise"));
        assert_eq!(hits[0].evidence_value("handled"), Some("true"));
        assert_eq!(hits[0].evidence_value("message"), Some("bad frame marker"));
        assert_eq!(hits[0].evidence_value("source"), Some("protocol.adb:54"));
    }

    #[test]
    fn oracle_hits_from_events_maps_native_assertion_contract() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::RuntimeCheck {
            api: "__assert_fail".to_owned(),
            language: "c".to_owned(),
            exception: "AssertionFailure".to_owned(),
            check: "assertion".to_owned(),
            handled: false,
            message: "len < cap".to_owned(),
            source: "parser.c:42:parse_frame".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "native-assertion-contract");
        assert_eq!(hits[0].rule_id, "GF-415");
        assert_eq!(hits[0].api, "__assert_fail");
        assert_eq!(
            hits[0].evidence_value("exception"),
            Some("AssertionFailure")
        );
        assert_eq!(hits[0].evidence_value("check"), Some("assertion"));
        assert_eq!(hits[0].evidence_value("expression"), Some("len < cap"));
        assert_eq!(
            hits[0].evidence_value("source"),
            Some("parser.c:42:parse_frame")
        );
    }

    #[test]
    fn oracle_hits_from_events_maps_unclosed_file_descriptor() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::FileOpened {
            syscall: "open".to_owned(),
            fd: 7,
            path: "/tmp/acme.conf".to_owned(),
            taint_offset: None,
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "resource-leak-ada");
        assert_eq!(hits[0].rule_id, "GF-306");
        assert_eq!(hits[0].api, "open");
        assert_eq!(hits[0].evidence_value("fd"), Some("7"));
        assert_eq!(hits[0].evidence_value("path"), Some("/tmp/acme.conf"));
    }

    #[test]
    fn oracle_hits_from_events_ignores_closed_file_descriptor() {
        let hits = oracle_hits_from_events(&[
            RuntraceEvent::FileOpened {
                syscall: "open".to_owned(),
                fd: 7,
                path: "/tmp/acme.conf".to_owned(),
                taint_offset: None,
            },
            RuntraceEvent::FileClosed { fd: 7 },
        ]);

        assert!(hits.is_empty());
    }

    #[test]
    fn is_govfuzz_owned_resource_ignores_infra_but_not_target_paths() {
        // govfuzz's own input-plumbing / scaffolding fds — never a leak.
        for owned in [
            "/home/u/campaign-work/work/mpack/fuzz_inputs/input-1545529-99.bin",
            "/tmp/gf_inwZay20",
            "/tmp/govfuzz/fake_env/ACME_HOME",
            "/tmp/govfuzz-attempt-foo-3",
            "/home/u/work/build/H-1/coverage.shm",
            "/home/u/work/build/H-1/coverage_cnt.shm",
            "/home/u/work/build/H-1/vp.shm",
            "/home/u/work/fuzz_scratch/cwd",
            "/home/u/work/fuzz_runs/fuzz-events-1-2.bin",
            "/dev/null",
        ] {
            assert!(
                is_govfuzz_owned_resource(owned),
                "{owned} must be treated as govfuzz-owned"
            );
        }
        // Genuine target / user paths — must remain leak-eligible.
        for target in [
            "/etc/hostname",
            "/home/u/dogfood-scratch/mpack/state.db",
            "/var/lib/app/session.sock",
            "/tmp/acme.conf",
            "",
        ] {
            assert!(
                !is_govfuzz_owned_resource(target),
                "{target} must NOT be treated as govfuzz-owned"
            );
        }
    }

    #[test]
    fn oracle_hits_from_events_ignores_govfuzz_owned_unclosed_open() {
        // The false positive: govfuzz's per-iteration fuzz INPUT file (and its
        // /tmp/gf_* temp scaffolding) left open at testcase exit is govfuzz's
        // own plumbing, not a target leak — GF-306 must not fire.
        for owned in [
            "/home/u/campaign-work/work/mpack/fuzz_inputs/input-1545529-99.bin",
            "/tmp/gf_inwZay20",
        ] {
            let hits = oracle_hits_from_events(&[RuntraceEvent::FileOpened {
                syscall: "open".to_owned(),
                fd: 3,
                path: owned.to_owned(),
                taint_offset: None,
            }]);
            assert!(
                !hits.iter().any(|h| h.rule_id == "GF-306"),
                "{owned} must not be reported as a GF-306 resource leak"
            );
        }
    }

    #[test]
    fn oracle_hits_from_events_still_flags_genuine_target_leak() {
        // A target that opens a real user-tree file and never closes it is a
        // genuine resource leak and MUST still trip GF-306.
        let hits = oracle_hits_from_events(&[RuntraceEvent::FileOpened {
            syscall: "open".to_owned(),
            fd: 9,
            path: "/etc/hostname".to_owned(),
            taint_offset: None,
        }]);
        assert!(
            hits.iter()
                .any(|h| h.rule_id == "GF-306" && h.evidence_value("path") == Some("/etc/hostname")),
            "an unclosed open of a genuine user-tree path must still trip GF-306"
        );
    }

    #[test]
    fn oracle_hits_from_events_maps_parent_path_file_deletion() {
        let hits = oracle_hits_from_events(&[RuntraceEvent::FileDeleted {
            syscall: "unlink".to_owned(),
            path: "../state/session.db".to_owned(),
        }]);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].oracle_name, "file-deletion-runtime");
        assert_eq!(hits[0].rule_id, "GF-414");
        assert_eq!(hits[0].api, "unlink");
        assert_eq!(hits[0].evidence_value("path"), Some("../state/session.db"));
    }
}
