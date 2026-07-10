<!-- SPDX-License-Identifier: Apache-2.0 -->
# Taint-confirmed sink oracles

A crash-only fuzzer reports a bug when a sanitizer aborts. That misses the whole
class of vulnerabilities where the program does exactly what it was told — but
what it was told came from the attacker: run *this* command, open *this* path,
connect to *this* host, load *this* library, execute *this* SQL. govfuzz calls
these **sink oracles**: during fuzzing it watches the dangerous "sinks" a program
reaches and reports the ones an input *provably controls*.

The word *provably* is the point. A static scanner can flag `system(buf)` as a
possible command injection, but it cannot tell you whether `buf` is ever actually
attacker-controlled on a reachable path — so it produces noise. govfuzz confirms
control with **dynamic byte-origin taint** (#422): it watches the exact bytes the
fuzzer fed this iteration and checks whether a contiguous run of them flows into
the sink's dangerous argument, unsanitized. If it does — and the site is never
reached *without* that taint — the finding is confirmed with a source→sink path
(`fuzz_input[N..] → system(command)`), not a guess.

## How it works

The LD_PRELOAD runtime shim interposes the sink APIs and emits an event for each
call, tagging it when a run of the argument (≥ 4 bytes) matches the live fuzz
input. The CLI folds those events across the whole run with one rule:

> A `(sink, subject)` is **confirmed fuzz-controlled** only if it carried
> byte-origin taint on at least one execution **and was never reached without
> that taint** during the run.

That "never untainted" clause is what keeps false positives at zero. govfuzz
harvests a target's own string constants into its mutation dictionary, so a fixed
path like `open("/etc/app.conf")` is sometimes echoed verbatim into an input and
would look "controlled" by a naive substring match. But a genuine program
constant is reached on nearly every execution — including inputs that do not
contain it — so it accumulates an untainted sighting and is suppressed. A value
the target copies *from* the input is only ever reached when its bytes are
present, so it stays tainted-only and is confirmed. A sanitized variant
(canonicalization, an allow-list, a bound parameter) severs the byte-origin match
and reports nothing.

Confirmation happens once, at the end of the run, so a target that reaches a
fresh input-derived sink every iteration produces one finding per defect, not a
flood.

## The sink matrix

Every sink class below is confirmed by the same unified taint correlator, carries
a most-specific CWE, and emits a source→sink taint path on the finding.

| Sink class | APIs interposed | Rule | CWE |
|---|---|---|---|
| **File-open path traversal** | `open`, `openat`, `fopen` | GF-405 | CWE-22 |
| **Process execution** | `system`, `popen`, `execv`, `execvp`, `execvpe`, `execve`, `fexecve`, `posix_spawn`, `posix_spawnp` | GF-431 | CWE-78 |
| **Network egress / SSRF** | `getaddrinfo` (hostname), `connect` (destination) | GF-433 | CWE-918 |
| **Controlled library load** | `dlopen`, `dlmopen` | GF-435 | CWE-427 |
| **SQL injection** | `sqlite3_exec`, `sqlite3_prepare[_v2/_v3]`, `PQexec`, `PQexecParams`, `mysql_query`, `mysql_real_query` | GF-441 | CWE-89 |
| **Destructive filesystem op** | `unlink`, `unlinkat`, `remove`, `rename`, `renameat`, `mkdir`, `mkdirat`, `rmdir`, `symlink`, `symlinkat`, `link`, `linkat`, `truncate` | GF-440 | CWE-73 |
| **Format string** | `printf`, `fprintf`, `sprintf`, `snprintf`, `dprintf` | GF-408 | CWE-134 |

Notes on individual classes:

- **Process execution.** `system`/`popen` hand their whole argument to `/bin/sh
  -c`, so any controlled span is shell-interpreted — command injection by
  construction, no shell metacharacter required. The `exec*`/`posix_spawn` forms
  run an attacker-chosen program or argument vector directly. The variadic
  `execl*` convenience wrappers take compile-time-fixed arguments (a dynamically
  controlled command uses the argv-array forms), so they are not separately
  interposed.
- **SSRF.** The `getaddrinfo` hostname is the classic attacker-controllable
  destination; `connect` also covers controlled AF_UNIX socket paths. Loopback is
  excluded as noise.
- **SQL injection.** The SQL client symbols are library symbols, not libc — the
  shim exports them so an LD_PRELOAD run interposes them whenever the target
  dynamically links the client library, and forwards to the real symbol. Taint in
  the *query text* (rather than a bound parameter) is the injection signal; a
  parameterized query keeps untrusted values out of the text and reports nothing.
- **Destructive filesystem.** Distinct from the read/open traversal sink: this
  covers *mutating* operations where a controlled name lets an attacker delete,
  move, clobber, or link arbitrary files. Two-path operations
  (`rename`/`link`/`symlink`) audit both the source and destination.

## Where the boundary is (and why)

The sink oracle observes what a native program does through the C library and a
handful of dominant client libraries. Some vulnerability classes are deliberately
**not** confirmed here, and the honest reasons matter:

- **Deserialization (CWE-502)** has no common libc/library sink to interpose —
  every serializer (protobuf, msgpack, bespoke) exposes a different entrypoint.
  For native targets this is a design-review / static concern, not a
  taint-confirmable runtime sink. (Java's `ObjectInputStream` *is* a single sink,
  but the JVM lane uses its own coverage agent, not this shim.)
- **XML external entity (CWE-611)** is not discriminating as a taint sink: a
  fuzzer's input usually *is* the XML, so "controlled input reached a parser" is
  true on every iteration. XXE is better caught by the static scanner (GF-430),
  which checks whether the parser is configured to resolve external entities.
- **LDAP injection (CWE-90)** and other niche library sinks are extensible by the
  same interposition pattern the SQL hook uses, but are not shipped by default;
  they are rare enough in the government/legacy corpus govfuzz targets that the
  symbol bloat is not yet warranted.

Everything the shim *can* observe with byte-origin taint — command execution,
path traversal, destructive filesystem operations, network egress, dynamic code
loading, SQL, and format strings — is covered. When a class is left to the static
layer or another lane, it is because taint-confirmation there would manufacture
false negatives or false positives, not because the mechanism is missing.
