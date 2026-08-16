<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

## 0.2.31 - 2026-08-15

**Large auto campaigns are now bounded, compactable, and findings-first.** The
reported 40+ GiB work directory from v0.2.27 was reproducible from retained Rust
Cargo `target/` trees: one real candidate consumed about 589 MiB, multiplied once
per attempted harness. The build now removes those intermediates on every return
path after the final replay binary has consumed them, startup compacts legacy
trees, and `govfuzz clean <work> --compact` reclaims caches/scratch without
deleting findings, reports, corpora, checkpoints, generated source, or replay
binaries. `--max-work-dir-mb` defaults to a 4096 MiB allocated-size admission
ceiling (`0` disables), while `--max-corpus-mb` defaults to 64 MiB per target for
both active and persisted coverage corpora. Finding testcases are never evicted.

Findings now lead every handoff: `<work>/FINDINGS.md` is impact ordered and carries
evidence, remediation, and replay commands; root `<work>/findings.csv` is the
grouped machine index; full evidence remains in `<work>/findings/`; and the old
`auto/findings.csv` path is kept as an identical compatibility alias. The terminal
and `run.md` point there before campaign coverage and blockers.

**A pinned 200-project, all-language audit closed expert-harness setup gaps with
measured controls.** The durable run completed 200/200 rows, proved entry for 118
selected calls, and covered 105 project bodies. Focused final-binary Go and C++
reruns produce an explicitly labeled 113/200 cross-run composite. The independent
expert set entered and covered 16/16 endpoints; exact normalized semantic target
selection rose from 6/16 to 13/16. The generators now checkpoint immediately
before calls; rank identifier tokens rather than substrings; materialize file
operands for JavaScript/Ruby/COBOL; await JavaScript promises; mine Go feeder →
terminal sequences; construct typed PHP object graphs; support common C++ member
templates/defaults; emit Fortran character-array descriptors; isolate C# target
IL; and retry exact-package Go coverage before black-box fallback.

The checked-in benchmark pins every repository/revision and includes one expert
driver per language plus durable runners and comparison scripts. Its residual
report names the remaining manual-harness territory: private Rust in-crate
targets, full generated/platform build graphs, framework hosts and unavailable
packages, coupled scientific array shapes, and general multi-step resource
protocols.

## 0.2.30 - 2026-07-31

**A freshly built executable is no longer a coin flip to launch.** The kernel
refuses to `exec` a file that is still open for writing anywhere (`ETXTBSY`), and
govfuzz's whole shape is build-then-run: a harness build followed immediately by a
fuzz or replay of the binary it just produced. In a multi-threaded process a child
forked by one thread inherits a write descriptor another thread has not closed yet,
so the window is real but microseconds wide — it surfaces only under load, as an
intermittent failure that reads like a broken harness rather than a race.

0.2.27 fixed this for `replay` alone. Two other paths were still exposed and both
were failing in CI:

  * the multicore worker spawn — `worker 0 failed to spawn: Text file busy`, which
    had been misattributed to an unrelated dependency bump;
  * the ThreadSanitizer and MemorySanitizer corpus replays, which `make` a
    sanitizer binary and exec it immediately. There the failure was SILENT: the
    spawn error was indistinguishable from a completed run, so the replay reported
    zero findings — a clean bill of health for a binary that never started. The
    TSan case was diagnosed from its CI timing: the test failed in 0.69s, where the
    timeout path it was first attributed to would have taken 150s.

The retry now lives at the single spawn every bounded subprocess goes through, so
harness builds, replays, fuzz children and the multicore workers are all covered
rather than three call sites being patched one incident at a time. `WouldBlock`
(`EAGAIN`) is retried alongside it, for a loaded box briefly out of process slots.

**A ThreadSanitizer replay run that never completed is now reported as UNMEASURED
rather than counted as clean.** `run_tsan_replay` returns findings AND the number of
corpus inputs whose run never finished, and `auto` prints the latter, saying those
inputs are not clean. A timed-out child arrives as an ordinary non-success exit —
`output_with_timeout` kills it and discards the `timed_out` flag — so the replay had
no way to tell "ran, no race" from "never ran"; `output_with_timeout_flagged` exposes
it. This is the same false-clean class as `stub_only` (#417) and `built_not_entered`
(#95).

**The C# lane reports itself accurately, and tells an offline host what it needs.**
The preflight banner resolved `sharpfuzz` on PATH only while the build also accepts
the default dotnet global-tools location, so a host that had run
`dotnet tool install --global` — which writes to `~/.dotnet/tools`, not on PATH —
was told "C# MISSING sharpfuzz" and then built and fuzzed the lane anyway. Both now
share one resolver, which also gained the Windows path
(`%USERPROFILE%\.dotnet\tools\sharpfuzz.exe`) it never had. The install hint named
a command that needs the network, on the hosts least able to run it, and omitted
NuGet entirely — yet the generated harness references SharpFuzz 2.3.0 plus every
`PackageReference` copied from the target csproj, so an offline host with both tools
staged passed preflight and then failed EVERY target at restore. The hint now names
the offline path and `NUGET_PACKAGES`.

## 0.2.29 - 2026-07-31

**`auto` now shows where the run is, and lets you steer it without killing it.**
The sweep printed one line per target — position, name, outcome — which answers
"what is happening" but not "how far along is this", "is it yielding anything",
or "which of the two `--force` phases am I in". On a 26k-candidate tree the
position counter is also the wrong progress signal: with `--max-targets 50` the
run ends at 50 *fuzzed*, and `[213/26409]` says nothing about that.

A terminal run now keeps a status block pinned below the scrolling results,
carrying the constraint that will actually end the run (with an ETA derived from
the binding one — success rate under a cap, attempt rate otherwise, never past a
`--campaign-time` deadline), a live yield tally with the most common blocker, host
CPU/RSS against the run's own budget, and one line per in-flight target showing
its stage, execs/s, edges, and how long since it last found anything. `--force`
phase 2 is named in the block rather than only in a banner that has scrolled away.

**The run is also steerable from the keyboard.** Every one of these previously
meant killing the sweep and restarting with different flags, discarding every
completed target:

* `q` stops cleanly — no new targets start, in-flight ones finish and are
  persisted, and the report and summary are written. Ctrl-C's outcome (a run
  killed mid-sweep) was previously the only way to stop early. A forced phase 2 is
  skipped rather than started after a stop request.
* `p` pauses and resumes, for when the box is needed elsewhere.
* `+` / `-` retune `--jobs`, clamped to 1..cores.
* `]` / `[` retune `--max-targets`, never below what has already fuzzed. An
  uncapped run can be capped down but not raised — it is already unlimited, and
  inventing a ceiling would silently restrict it.
* `>` / `<` retune `--per-target-time`, applied from the next target (the running
  one keeps its planned pass cascade). Refused when a `--campaign-time` split owns
  the budget rather than fighting it.
* `f` adds or drops the forced phase 2 — decided at the phase boundary, so it
  works on a run that never passed `--force`.
* `v` toggles per-target detail.

Nothing baked into discovery or a harness build (`--sanitizers`, `--cxx-std`,
`--build-command`) is adjustable: changing those mid-sweep would make targets
within one report incomparable.

None of it requires knowing the keys in advance. The legend is a permanent line
of the block and picks one of three widths so a narrow terminal shortens it
instead of cutting it off mid-list — a truncated legend hides that the remaining
keys exist at all. `?` expands it in place into what each key does and what each
value currently is; any key that does something dismisses it again. The block is
also now capped to the terminal height, reporting what it hid: a block taller
than the screen cannot be erased correctly, because the cursor cannot walk up
past the top.

The parallel sweep gained live per-target progress in the process: it previously
ran with no progress sink at all, because concurrent rewrites of a single terminal
line corrupt the display. Each worker now owns a dashboard slot instead. Piped and
CI output is unchanged; `--verbose` adds a run-level heartbeat every 30 s.

Ctrl-C behaviour is untouched — the key reader disables line buffering and echo
but leaves `ISIG` on.

Two smaller corrections fell out of the same work. Every `eprintln!` in the crate
now routes through the run's console (`gfeprintln!`): a bare write landing inside
the sticky region desynchronised the erase, which wiped the message and stranded
block fragments in the scrollback — observed in a real sweep, not theorised. And
the console summary and `run.md` no longer report the shortfall left by an
operator stop as "dropped by cap", which blamed flags the operator may never have
passed.

## 0.2.28 - 2026-07-30

**GF-440 no longer reports govfuzz deleting its own temp input as a target
vulnerability.** Reported from the field: govfuzz claimed attacker input could
delete a file via a function whose only call is `statvfs` — a read-only stat that
cannot appear in GF-440's API list at all. The finding showed api `unlink`, path
`/tmp/gf_in032dWa`, taint `fuzz_input[2..] -> unlink(path)`.

That file is govfuzz's own: `gf_make_tempfile()` materialises the fuzz bytes at
`/tmp/gf_inXXXXXX` so a `const char *path` parameter can be supplied at all, then
govfuzz removes it. The shim saw the unlink, the path really was input-derived,
and the oracle billed it to whatever target was under test.

A gap rather than a bad heuristic: `is_govfuzz_owned_resource` already knew these
paths — its comment names `gf_make_tempfile()` — but had exactly one call site,
the resource-leak oracle. The sink oracles were added later and never consulted
it, and a `ConfirmedSink` carries no frame, so unlike the crash path (which
suppresses "no target frame" as a harness fault) nothing could tell target from
scaffolding.

Scope was set by measurement: a first attempt suppressed any filesystem sink
resolving inside the work dir and immediately failed
`auto_confirms_path_controlled_open_gf405`, because a target OPENING an
attacker-named file relative to its CWD is a real GF-405 and the fuzz child's CWD
is inside the work dir. Narrowed to DESTRUCTIVE sinks on govfuzz's own `/tmp/gf_*`
artifacts only — a target deleting a file in its own scratch directory still
reports, and so does any traversal.

## 0.2.27 - 2026-07-30

- **`replay` no longer fails intermittently on a freshly built harness.** The
  kernel refuses to `exec` a file that is still open for writing anywhere, so
  building a harness and immediately replaying it races the writer's descriptor
  closing. Both spawn paths now retry that (`ExecutableFileBusy`) and a transient
  fork failure on a loaded box (`WouldBlock`), matched on `ErrorKind` so it
  compiles on every target.

- **The failure says why.** `failed to start harness <path>` kept its cause in the
  `#[source]` chain, and the top-level `error:` line is all a CI log shows — so it
  could not be told apart from a missing file or a permissions problem. The errno
  is in the message now. That ambiguity is why the first two attempts at this fix
  patched the wrong spawn sites, in the wrong crate.

Stated plainly: the retry is a well-founded mitigation, not a confirmed fix — the
errno was never visible, which the second change makes impossible next time.

## 0.2.26 - 2026-07-29

`static-scan` is **13.6x faster on Java** with byte-identical output, and every
per-lane toolchain spawn is now bounded.

| tree | lane | before | after |
|---|---|---:|---:|
| elasticsearch (4.99M SLOC) | Java | 616.6s | **45.4s** (13.6x) |
| kubernetes | Go | 59.2s | **15.4s** (3.8x) |
| Proton | C/C++ | 10.6s | 10.4s |

8.1k -> 110k SLOC/s on Java, memory unchanged or slightly lower.

**The harness came first.** `scripts/validation/finding-parity.py` captures a
normalised digest of a scan — findings as a MULTISET of `rule:path:line:slug`
(several findings legitimately share a site, so set semantics would hide a change
in how many), totals per rule, severity and CWE, and `analysis_gaps` by reason —
and fails on any difference. The gaps matter most: they are where the engine
admits it stopped, so exploring LESS shows up as MORE gaps even when the finding
count holds. Speed is easy to measure and easy to fool yourself about; losing a
finding looks exactly like a faster scan. Every number above is parity-gated, on
Java, Go and C/C++.

**The 0.2.25 write-up blamed the wrong pass** — it named the interprocedural taint
worklist, from reading the code. Measurement put 24 of a 28-second Java scan in
`annotate_reachability`, the call-graph BFS that LABELS findings, and 1.3s in
taint. Both real causes were there:

- **`reachable` was a `BTreeSet<FunctionKey>`, and a key holds a `PathBuf`.** Every
  probe cost ~17 comparisons of long path strings, and the BFS probes once per
  candidate target per call site. It is membership-only and never iterated, so it
  is now a hash set — 3.1x on its own, and it helped Go as much as Java.
- **Each call site walked EVERY function in the tree sharing that name**, and that
  list grows with the tree: the actual source of the O(n^1.6). A name whose whole
  candidate set is already reachable can never contribute again, whichever subset
  the preference rules would pick, so such names are retired. The reachable set
  only grows, so saturation is monotonic and cannot go stale. A further 2.7x, and
  the BFS went 79.1s -> 2.0s on the full tree.

`call_targets` also stopped allocating a `String` per lookup and cloning the whole
candidate list — kept because it is strictly better, though on its own it was
worth only 1.03x.

**Per-lane toolchain spawns are bounded**, the same class as the gprbuild spawn
that ate a campaign and orphaned for 39 hours — found by auditing for it rather
than waiting for it to bite again. C# `have()`/`dotnet --list-sdks`, Java
`javac -version`, JS `node --version` and `node -c <module>` (a real 120s budget,
since it reads user JavaScript), Go `go mod tidy` and `go env GOVERSION`, and the
Rust `cargo +nightly` probe all previously ran with no timeout and no process
group.

Left alone deliberately: the per-file rule packs (23.9s, already parallel at
cores-1) and the taint worklist (16.0s, single-threaded for a mono-language tree
because `scan_taint_project` parallelizes across LANGUAGES). That worklist shares
mutable state and is the pass that can silently change findings, so it needs a
real decomposition rather than a `par_iter` swap.

## 0.2.25 - 2026-07-29

Documentation release on top of 0.2.24, which carried the performance work.

- `docs/expected-gaps.md` now records the one measured performance outlier left
  after the timeout sweep, with its root causes rather than just its symptom:
  `static-scan`'s interprocedural taint pass runs at **8.1k SLOC/s on Java**
  against **924k SLOC/s on C**, and scales at about **O(n^1.6)** (1,050 Java files
  in 2.5s, 4,912 in 30.4s, extrapolating to the 616s measured over elasticsearch's
  31,243). `scan_taint_project` parallelizes across LANGUAGES rather than within
  one, so a single-language tree runs the whole phase on one core; and the
  worklist revisits a function once per distinct taint signature.

## 0.2.24 - 2026-07-29

Performance and robustness release. **Every project that timed out in the
500-project sweep now completes**, and two long-standing process bugs are gone.

Validated on a 16-lane sweep (`benchmarks/campaign-2026-07-25/results-0729/`, 48
projects, 3 per lane): **zero problems — no timeouts, no crashes** — 1,676
targets attempted, 568 fuzzed (33.9%), 121 findings.

**The eight timeouts.** Measured under the real sweep invocation
(`--campaign-time 240`, 510s outer): Proton 449s, sumatrapdf 457s, emscripten
406s, serenity 351s, envoy 366s, rocksdb 361s, whisper.cpp 325s, gnat-llvm 244s.

Four causes, all found by measuring — the first two guesses were wrong and
changed nothing, so the stage timings that found them stay behind
`GOVFUZZ_PROFILE`:

- **A header classifier that parsed each file twice.** `classify_c_header`
  counted C functions *and* C++ functions to pick a language, then the real parse
  ran a third time: **33 seconds** on simdjson's 187k-line amalgamated header
  before any real work. The cheap predicates already in the same `||` chain now
  answer first.
- **A per-target rescan of the whole source.** Two loop-invariant guards sat
  inside the per-target loop behind a lazy `.or_else`: 7,264 targets × 7.7 MB ≈
  **56 GB of scanning**, 83 of 99 seconds.
- **A per-target linear scan in `list targets`**, allocating a name string per
  comparison — ~74M times on one file.
- **Single-threaded parsing.** Both discovery surfaces ran on one core while the
  static scan had used a worker pool for ages. Now `cores - 1` with the 256 MiB
  stacks discovery already needed, and byte-identical output (entries are visited
  in sorted order and `par_iter().collect()` preserves it).

`list targets`: simdjson 900s TIMEOUT → 143s, Proton 888s → 475s, sumatrapdf
305s → 118s.

**No phase is unbudgeted any more.** Discovery is deliberately not billed to
`--campaign-time`, but unbilled is not unbounded — Proton indexed for 447s
against a declared 240s campaign and was killed having fuzzed nothing. Discovery,
its C++ member-access pass, and the **declaration index (173s, the largest phase
of all)** now honour one deadline for the phase, degrade to a clearly-labelled
PARTIAL result, and say what they skipped. `GOVFUZZ_DISCOVERY_TIME` overrides.
The in-flight grace scales with the campaign instead of being a flat two minutes,
and no single subprocess may take more than a quarter of it.

**Two process bugs, both observed on real runs:**

- **Orphaned compilers outlived govfuzz indefinitely.** `compiler_adapter` ran
  gprbuild with a plain `Command::output()` — no timeout, no process group, no
  `PR_SET_PDEATHSIG` — so a killed run left `gprbuild`/`gcc`/`gnat1` with PPID 1.
  Processes were found still burning CPU **39 hours** after their sweep, stealing
  time from every run since. That is also why gnat-llvm timed out on a 4 MB tree:
  one generated harness sent `gnat1` into a spin and nothing stopped it. Verified
  zero orphans after a run that previously left them.

- **Target code ran in the caller's working directory.** An empty file named
  `AAAAAA` — a fuzz input used as a filename — appeared in a source checkout.
  Three paths that execute the built harness set no working directory, so writes
  landed wherever govfuzz was invoked from, very often the tree being scanned.
  They now run beside the harness binary, under the work dir.

**`--resume` is reliable instead of "works the second time".** Two independent
causes:

- Per-target `result.json` records live in `harnesses/`, which was treated as
  regenerable — so any refresh (a work dir from a different build, say) deleted
  every record. `--resume` then honestly reported "no completed targets" and
  re-ran everything; that run wrote fresh records, so the *next* resume worked. A
  refresh now clears build products and keeps records. Records from a different
  build are kept where they FUZZED and re-attempted otherwise, so a stale "no"
  cannot cap what the new binary reaches.

- Resume treated "discovery cache hit" as proof the tree was unchanged. It is
  not: fuzzing executes the target, and a target that writes or rewrites a
  source-extension file — codegen, compilers — changes the digest the next run
  compares against, so a run can invalidate its own fingerprint. Resume is now
  decided **per source file**: a target is stale only when its own file moved.
  The per-file hashes are a by-product of the fingerprint walk that already ran,
  so this adds no extra walk and no extra reads; only the verdict is kept.

## 0.2.23 - 2026-07-28

Follow-up to 0.2.22, from a second full 500-project sweep (`results-0728/`: 482
measured, **1,212,086 targets discovered, 3,638 attempted, 1,069 built+fuzzed —
29.4%**, 366 findings, all 16 lanes).

The headline defect is a crash, not a gap. **carbon-language/carbon-lang was
SIGKILLed during discovery in BOTH `list targets` and `auto`** — govfuzz
produced no target list at all, which is worse than any residual blocker,
because a hard kill leaves nothing to act on and is indistinguishable from a
hang.

- **Recursive C/C++ types no longer explode type resolution.** Resolving one
  1205-line header from carbon-lang's `toolchain/sem_ir` took **13.0 GiB and
  88 seconds**. `MAX_RESOLVE_DEPTH` bounds recursion DEPTH but not BREADTH: a
  struct with F fields expands F subtrees, each expanding F more, so a
  self-referential type unrolled to the 16-deep limit materializes on the order
  of F^16 field vectors.

  Two changes, both needed. Resolved shapes are memoized on (spelling, depth) —
  keying on depth as well as spelling keeps results byte-identical to the
  uncached walk, including the `Opaque` truncation at the limit. That halved the
  time but not the memory, because a cache hit still CLONES the subtree:
  memoization avoids recomputation, not materialization. So resolution now also
  stops at a cycle — a type that transitively contains itself resolves to
  `Opaque` at the point of recurrence instead of unrolling. Nothing is lost: a
  decoder cannot build an infinitely nested value, so the unroll and the
  `Opaque` are equally undrivable, but the shape is now the size of the type
  rather than exponential in the depth limit.

  carbon-lang, whole tree: **12.9 GiB and SIGKILLed with no output → 52 MiB,
  exit 0, 5,092 targets listed and 4,040 fuzzable**. The single header: 13.0 GiB
  / 88s → **77 MiB / 1.2s**. The same fix took `simdjson` from a 900-second
  `list targets` timeout to completing in 481s with 14,690 targets.

- **Discovery degrades under memory pressure instead of being OOM-killed.** The
  static scan already survived these trees by stopping at an RSS ceiling;
  discovery had no memory bound at all. Both discovery surfaces now share that
  watchdog and report a PARTIAL target list rather than dying silently.
  `list targets` parses five lanes itself and defers the other eleven to `auto`,
  so guarding only the shared walk would have left C++ — carbon-lang's own
  language — unguarded. Honest note: this guard did **not** save carbon-lang on
  its own, because a single file crossed the ceiling and blew past it between
  two 500ms samples; the type-resolution fix above is the real one. This is the
  backstop for trees that grow past memory gradually.

- **A C++ target in a header that cannot compile standalone is now driven
  through its owner translation unit.** `blocked_by_non_self_contained_header`
  was the largest C++ residual class in the sweep (49 targets, plus 10 in C).
  Such a header routinely compiles as part of the `.cpp` that owns it — the same
  move the C lane already makes for a static target or a private handle, one
  step further out. A candidate is adopted only when it PREFLIGHT-COMPILES, so a
  wrong guess is rejected rather than baked in, and a header no translation unit
  can make compile is still rejected.

- **A repair no longer breaks the code it was meant to unblock.** The loop
  answered an undeclared identifier with `#define ScannerLimit …`, which is
  force-included ahead of every translation unit and rewrote the enumerator's
  own definition — `enum : size_t { ScannerLimit = 4 }` became
  `enum : size_t { 1 = 4 }`, "expected identifier", in a source that compiled
  fine before. Same hazard as the existing tree-function and tree-type vetoes,
  one construct over, and it now gets the same veto and the same
  reserved-identifier escape hatch.

- **An opaque C handle whose struct is defined in the target's own translation
  unit is now drivable** rather than reported as incomplete.

`docs/expected-gaps.md` is re-measured against this sweep.

## 0.2.22 - 2026-07-28

Correctness release. Nineteen defects, found by re-running the full 500-project
sweep and then by reading what the sweep could not explain — plus the three CI
workflows that had been failing unattended while Actions was assumed dead.

Two of these are the kind that hide in plain sight: **no Ada target could be
built on GNAT 11 at all**, and **`list targets` was blind to 11 of the 16
supported languages**. Both had been true for a long time and neither showed up
as an error anyone read.

Found by re-running the full 500-project sweep (`benchmarks/campaign-2026-07-25`,
`results-0727/`: 463 measured, 1.1M targets discovered, 3,594 attempted, 1,057
built+fuzzed, 354 findings).

- **A cyclic construction recipe no longer eats 12 GiB during discovery.** The
  sweep lost 22 projects to `exit=-9` — SIGKILL, no timeout, 44 to 250 seconds
  in, before a target was ever attempted. It was govfuzz's own memory: one
  `govfuzz auto` on simdjson, alone on an idle box, peaks at **12.4 GiB and is
  OOM-killed**, where `list targets` over the same 39 MB tree uses 225 MiB. The
  C++ parameter decoder's recipe block documented an invariant — recipes exist
  only for a target's DIRECT parameters, so a constructor's arguments are always
  directly decodable — that the producer graph had since made false. That graph
  resolves what a chosen constructor's arguments need, to a fixed point, and is
  explicitly cyclic (`A(B)`, `B(A)`); the consumer following those recipes had no
  bound. It now carries the chain of keys it is expanding and treats a repeat as
  "not decodable", the same clean skip the parameter got before recipes existed.
  Depth is not what is cut: a three-deep acyclic chain still resolves.

- **POSIX and GLib integer aliases are scalars, not opaque handles.** `pid_t` is
  an int, but the typedef chases into glibc's `__pid_t`, which is not in the
  scanned tree — so fastfetch's `ffProcessGetInfoLinux(pid_t pid, …)` skipped
  with "opaque type 'pid_t' … needs lifecycle support (Phase C)", and HandBrake's
  `ghb_do_scan(…, gboolean force)` said the same about GLib's `gboolean`. This is
  the situation the existing BSD and Win32 blocks already answer. `pthread_t`,
  `sem_t` and `gpointer` are deliberately excluded: they are integer- or
  pointer-shaped but name a live kernel object, and decoding one from fuzz bytes
  hands the target a fabricated handle. `gchar *` joins `char *` as a C string.
  Measured on fastfetch: 1 → 3 built+fuzzed.

  The scalar table also used to win over the tree unconditionally — the same
  hazard as the Win32 header pack redefining a Linux driver's own `CHAR`. A
  project that declares its own `key_t` struct would have had an int cast to it.
  A tree declaration that resolves to something real now wins.

- **A `java.io.File` parameter is a byte channel.** `parse(File)` is the classic
  Java entry point (`ImageIO.read(File)`, `new ZipFile(File)`) and every one of
  them skipped as an unsupported type, because the harness could only hand a
  target bytes it held in memory. It now writes the input to one temp file per
  process, truncated per iteration, and passes its `File`, `Path`, `URI` or
  `URL`. Output sinks (`OutputStream`, `Writer`, `PrintWriter`, `PrintStream`,
  `StringBuilder`) and `ClassLoader` also stopped blocking targets. Collections
  and fuzz-parsed URIs are still refused, with reasons.

- **`list targets` covers all sixteen lanes, not the five it was written for.**
  The command had its own five-variant language enum — Ada, C, C++, Java, Rust —
  written when there were five lanes and never revisited, so on a Go, Python,
  JS/TS, C#, Ruby, PHP, Perl, Lua, Fortran or COBOL tree it printed nothing at
  all. Across the sweep it listed 2.0M targets and every one was in those five,
  while `auto` discovered targets in all sixteen. The eleven are now deferred to
  `auto`'s discovery rather than given a second parser here, gated on a cheap
  extension scan so a C/C++/Ada/Java/Rust-only tree pays what it always did.

- **A JS/TS harness that cannot be prepared says so** (58 targets). The harness
  built — module loads, export resolves — and then died constructing the receiver
  for a `Class#method`, because the class wants an environment that is not here
  (gstack's `BrowseClient` looks for a live daemon port). The engine recorded a
  harness that ran zero inputs and the run said `built, no fuzz pass ran`, naming
  nothing. A third build gate now runs the launcher in a LOAD-ONLY mode and takes
  the driver's own error as the skip reason. Load-only rather than "run one
  input" because a finding halts the driver with a nonzero exit — gating on that
  would have skipped exactly the targets that crash.

- **Discovery on an amalgamated single header finishes.** simdjson's
  `singleheader/` took over 1500 seconds and was still going, where `list
  targets` over the same two files takes 145 — so the whole difference was work
  `auto` adds. Two loop-invariant computations were being redone inside
  per-function loops, and profiling named them (the obvious-looking quadratic was
  not the cost): `recipe_mining::for_source` handed back a CLONE of the whole
  recipe map on every cache hit — **133 of the preflight's 137 seconds** on one
  2,863-function file — and `cpp_class_is_default_constructible` re-parsed the
  entire include closure per opaque parameter, which its caller had already
  parsed once. The preflight on simdjson.h (10,894 functions) went from never
  finishing to **9.5 s**, and the whole directory from >1500 s to **218 s**.

- **A Go target under `internal/` is reachable** (8 targets, 3 repos). Go decides
  "outside the internal tree" from the IMPORT PATH, so a harness module named
  `govfuzzharness` was outside every project — and `internal/` is where a great
  deal of real Go code lives. The harness now declares itself a child of the
  module under test, satisfying the rule the way the project's own packages do.

- **A language PREVIEW feature is not an unbuildable tree** (11 targets, RxJava
  and spring-framework). javac refuses `var _ = …` — preview on 21, standard from
  22 — and names the flag it wants. It is asked for once now and carried through:
  javac refuses to READ preview class files without it, and so does the JVM that
  loads them.

- **The C# harness no longer duplicates attributes the target declares** (17
  targets, 4 Windows projects). The SDK synthesizes `[assembly: AssemblyTitle]`
  by default and a classic project keeps its own `Properties/AssemblyInfo.cs`
  declaring the same, so compiling those sources in gave `error CS0579`.

- **A `path =` in another table no longer answers for `[lib]`** (8 targets, fd).
  fd declares `[[bin]] path = "src/main.rs"`, so the binary-only crate's
  synthesized `[lib]` went out with no path of its own and cargo refused the
  manifest. Cargo's `error:` line is also a BANNER when it wraps — the diagnosis
  is in the `Caused by:` block, which is now carried.

- **A staged Ada C stub takes the header it includes with it** (12 targets, 2
  projects). `auto_stubs.c` opens with `#include "auto_types.h"`, and a quoted
  include resolves against the including file's own directory — so mirroring only
  the `.c` into the Ada source dir left the header behind and every staged stub
  died on `fatal error: auto_types.h: No such file or directory`. Measured on
  tsoding/eepers: 0 built+fuzzed and 5 failed builds, now 4 and 1.

- **The underscore is not part of the decoration-macro convention.** The ALL-CAPS
  visibility-macro rule anchored on one (`_API`, `_EXPORT`), so it missed JNI's
  `JNIEXPORT jint JNICALL …` — every Android or Java native library — and
  `JNIEXPORT` reached the harness as a type it could not construct offline.

- **A Go `/vN` module is required at `vN`, not `v0`.** The harness `go.mod`
  hardcoded `require <module> v0.0.0-incompatible`, which semantic import
  versioning makes illegal for a path ending `/vN` (N ≥ 2): Go rejects the file
  with `go: errors parsing go.mod` before any build, so every target in the
  project failed. 51 targets across 9 of the sweep's 40 Go repos — caddy,
  cli/cli, alist, etcd, moby, traefik, bubbletea, 3x-ui, CLIProxyAPI. `/v1` and
  unsuffixed paths keep the v0 spelling, which is what Go wants for a module that
  has not adopted the suffix.

  What this buys is that the REAL blocker becomes visible; it is not a fuzz-count
  claim. Measured on bubbletea, 7 targets moved off `failed_build` and the
  manufactured error is gone — and what they hit next is that the module wants a
  newer Go than the host has, which is an environment limit govfuzz reports
  honestly and cannot fix. Do not restate this as +51 fuzzed targets.

- **A line the interpreter echoed is not the diagnosis.** Node opens every
  module-load failure by echoing the failing statement from its own internals and
  underlining it with a caret; `throw error;` contains "error", so it won the
  first-line-containing-that-word match and **77 targets reported a line of
  Node's source, and nothing else, as their entire reason**. An echoed line (one
  followed by a caret underline) is now ineligible, and a line that NAMES a
  diagnostic is preferred over one that merely contains the word. Python, Lua,
  Perl and Ruby resolve to exactly the line they did before.

- **No Ada target could be built on GNAT 11 at all.** The harness build passed
  `-gnat2022` unconditionally, as "the latest supported standard, which accepts
  older code too". That switch arrived in GNAT 12; on GNAT 11 — Ubuntu 22.04's
  default and that of still-supported RHEL 9 derivatives — `gnat1` answers
  `invalid switch: -gnat2022` and the build dies before reading a line of Ada.
  The standard is now probed and lowered to `-gnat2012` when the compiler lacks
  the switch.

- **A compile flag that needs quoting is quoted, not refused.** A CMake
  version-comparison define is legitimate and its `>` would redirect if emitted
  bare into the recipe — `-DLLAMA_VERSIONS=>=3` (gpt4all),
  `-D_LIBCPP_HARDENING_MODE=..._DEBUG>` (btop) — which cost every target in both
  projects. The relaxation is for FLAGS only: a source path is also a make target
  and an include name lands in an `#include "..."` line, so both stay strict, and
  `$`, a single quote and a newline are still refused outright.

- **A non-code import no longer fails the whole TypeScript transpile.** esbuild
  has no loader for `import logo from "./logo.png"` or `"./Comp.vue"` and fails
  the entire bundle, skipping the target even though the fuzzed function never
  touches the asset (`.png` 5, `.svg` 5, `.yaml` 5, `.vue` 3).

- **A Go `context.Context` parameter is call context, not a refusal.** It carries
  no fuzz input, and one such parameter made the whole target undrivable. The
  harness passes `context.Background()` — never nil, which would panic the moment
  the callee touched `Done()`.

- **Two ways the blocker histogram destroyed its own key.** A path in the MIDDLE
  of a diagnostic was per-instance noise that never grouped — 176 of 1109
  distinct rows, 456 targets, were one-off rows for that alone; a rooted or
  extension-bearing path token now collapses to `PATH`, while prose keeps its
  slashes. And an apostrophe inside a word is a contraction, not a delimiter:
  Perl's most common failure opens "Can't locate Foo.pm in @INC", and reading
  that apostrophe as a quote destroyed the message on the lane where it fires
  most. GNAT's `Foo'` form and Ada attributes are unaffected.

## 0.2.21 - 2026-07-27

Reach release: the targets `--force` was supposed to rescue and did not.

- **`--force` now works outside C/C++/Ada.** The forced sweep's residual
  blockers showed 116 Go targets and 31 C# targets ending `unsupported_params`
  however hard you forced them — Go's undrivable count was identical between the
  forced and unforced arms, because nothing attempted it. Both lanes now have
  the C-family's best-effort driver:
  - **Go** drives an undrivable parameter as its type's zero value, qualifying
    the spelling into the harness package, and calls a method on an addressable
    zero receiver (not a nil pointer, which would panic on first field access).
    An unexported, generic, variadic, or inline-literal type is still refused
    rather than guessed.
  - **C#** allocates a receiver whose type has no accessible parameterless
    constructor without running one, via the runtime's own
    `GetUninitializedObject`, resolved by reflection so the shim compiles on any
    target framework. An abstract type or interface is still refused.
  - A target built on a fabricated value is recorded as such, so the report
    floors its findings to Low with the forced caveat and counts it separately —
    a forced nil-map panic never reads as a confirmed defect.

- **A function returning a struct by value can be stubbed.** Twenty raylib
  symbols in one clay harness stubbed fine and one did not, because it returns
  an aggregate by value and the stub generator had no way to name the type. It
  now constructs a zeroed return value where the type is complete (the
  header-backed path), which is exactly as neutral as the `return 0;` its
  siblings get. clay: 3 of 6 attempted targets fuzzed, now 4.

- **A configure-style `#error` guard no longer ends the build.** Sweeping what
  `--force` still cannot build, ten of 104 sampled unbuilt harnesses died on a
  header's own `#error` — libssh's "no strtoull function found", ImageMagick's
  "you should set MAGICKCORE_QUANTUM_DEPTH" — where nothing is missing from the
  tree at all and a real `./configure` would have defined the macro the guard
  tests. GovFuzz now reads the conditional that owns the `#error` and defines
  that macro, with the value the guard itself requires — preferring the outermost
  feature-test wrapper, so libssh's guard defines `HAVE_STRTOULL` and leaves the
  real libc function alone rather than taking the inner branch and aliasing
  `strtoull` to a symbol this host lacks. Undecidable guards (a comparison, a
  compound condition, an error that fires *because* a macro is defined) are
  refused rather than guessed. Measured on the two corpus projects that carry the
  class: the guard errors are gone from every build log and more targets reach
  the report-only floor (WindTerm 3 → 6, ImageMagick 1 → 4); neither converts a
  target to fuzzing inside a 90-second campaign, because what remains behind them
  is a different class.

- **`findings.csv` columns line up again.** The optional `scan_type`/`forced`
  columns are written before the stub-accounting block but their names were
  appended after it, so under `--force` or `--static-dynamic` every stub column
  carried its left neighbour's value and `forced` read out `linked_real`. With
  neither flag the header is unchanged.

- **A libc function is never defined away.** btop's build died inside glibc —
  `/usr/include/unistd.h:1091: error: expected identifier or '('` on its own
  declaration of `syscall` — because a vendored header calls `syscall()` from a
  `static inline` without including `<unistd.h>`, and the undeclared-call repair
  answered with `#define syscall`. That define is force-included ahead of every
  translation unit, so it erased the declaration too, in a file no repair can
  reach. Such names now route to their declaring header (`#include <unistd.h>`),
  and the neutral-macro fallback refuses outright for anything the C runtime
  owns. btop: 4 of 10 attempted targets built+fuzzed → 5, and zero unbuilt
  harnesses in the sweep.

- **A C++ free function no header declares gets declared.** The forward-
  declaration gate was "does the target have any includes at all", but a
  header-less `.cpp` still pulls in whatever headers the file includes — none of
  which need declare the target. The harness then called a name nothing had
  declared. It now searches those headers for an actual declarator, and strips
  export/constant-evaluation decoration macros (`JNIEXPORT jstring`,
  `utf8_constexpr14_impl int`) from the declaration it emits, so it cannot
  manufacture an `unknown type name` the target never had.

- **`--force` no longer empties the missing-dependency manifest.** Forcing
  degrades a residual failed build to a report-only static scan — the right
  floor — but a report-only outcome carries no diagnostics for the manifest to
  mine, and the degradation replaced them with a bare COUNT of residual errors.
  The dependency evidence went with them, so the run that most needs the manifest
  produced none: tmux, whose every target embeds libevent's `struct event` by
  value, reported "4 still blocking" unforced and **"No external dependencies
  were missing — the tree built against its own sources"** forced. The forced
  degradation now carries the unresolved type names across, and a regression test
  pins that forcing can never empty the manifest.

- **Macro templates and macro invocations are no longer discovered as targets.**
  Two shapes parse as function definitions but are not functions:
  - A body inside a backslash-continued `#define` — BSD `<sys/tree.h>`'s
    `RB_GENERATE_INSERT(name, type, field, cmp, attr)` defines a whole function
    whose return type is `attr struct type *`, where `attr`/`type`/`name` are
    macro PARAMETERS. The harness emitted `attr struct type * R = ...`, which
    clang rejects with "cannot combine with previous 'type-name' declaration
    specifier" and no repair can fix, because nothing is missing. tmux's
    compat/tree.h alone produced seven such dead targets — seven slots in the
    ranked cap that real functions should have had.
  - A multi-segment ALL-CAPS invocation at file scope — Linux's
    `TRACE_EVENT(mcu_cmd_info, TP_PROTO(...), ...)`, which parses as a function
    whose parameter *types* are the macro's arguments. Single-word ALL-CAPS names
    are kept, because BLAS/LAPACK really do export `DGEMM`.

  On lede this removed 139 pseudo-targets from the ranked list and gave the slots
  back to real functions.

- **The synthesized Win32 pack no longer redefines the tree's own typedefs.**
  Win32-style scalar names are not exclusive to Windows: lede's MediaTek mt7603
  Linux driver declares its own `typedef signed char CHAR;` and `union
  _LARGE_INTEGER`. GovFuzz force-included its `windows.h` placeholder over them
  and produced `typedef redefinition with different types ('signed char' vs
  'char')` — its own error. When the tree defines the name, the ordinary type
  repairs run instead.

- **A CamelCase export macro no longer leaks into the generated C harness.**
  `strip_type_decoration` recognised the ALL-CAPS convention (`WREN_API`,
  `STBIDEF`) but not the CamelCase one, so ImageMagick's `ModuleExport size_t f()`
  reached the harness as `extern ModuleExport size_t f(...)`: "unknown type name
  'ModuleExport'" plus an `expected ';'` cascade, on a line GovFuzz wrote itself.
  The same shape was fixed for C++ above; this is its C twin.

- **Getting started.** `docs/recommended-sweep.md` gives the one command to
  start from and what every flag buys; `govfuzz auto --help` prints the same
  command, and a distribution ships it as `RECOMMENDED-SWEEP.md`.

- **Tooling.** `benchmarks/campaign-2026-07-25/residual_errors.py` sweeps the
  corpus forced and histograms the actual compiler errors behind every harness
  that did not fuzz — the worklist that produced the `#error`-guard fix. It only
  counts harnesses GovFuzz gave up on: the repair loop reaches the link stage
  with symbols still undefined on its way to resolving them, so harvesting every
  harness (the first cut) ranked the loop working as designed as the largest
  defect class.

## 0.2.20 - 2026-07-24

- **More real legacy Ada/C/C++ targets reach the fuzzer.** A focused audit of
  the offline Ada/C/C++ fuzzing path fixed a set of defects, each of which
  silently prevented a class of real targets from being fuzzed:
  - Library-, aggregate-, and abstract-governed Ada projects now build. The
    synthesized build project no longer *extends* a library project (which GNAT
    rejects without `Library_Dir`, and which can't carry the harness main) or an
    aggregate (which can't be extended) — it builds a standalone project over the
    instrumented source overlay instead. Validated in a 20-project sweep against
    real library-project repos (AdaYaml, Ada-Crypto-Library, ada-toml).
  - GCC-instrumented C/C++ harnesses now record coverage. The coverage/cmplog
    shared-memory maps are opened unconditionally in the driver, not only on the
    clang `trace-pc-guard` path — a GCC (`trace-pc`) build previously left them
    NULL and fuzzed blind.
  - The framed fork-server no longer desyncs or deadlocks on inputs larger than
    the harness's 1 MiB buffer: the engine clamps each frame to that buffer.
  - UBSan-class faults (signed overflow, out-of-bounds index, shift, null deref)
    are detected on the default run — the builtin fuzz child now arms
    `UBSAN_OPTIONS`/`ASAN_OPTIONS` halt-on-error, matching the AFL path.
  - A translation unit that mixes old-style K&R and ANSI-prototyped functions
    keeps its ANSI parsers (the real targets), which were previously dropped;
    `list`/`scan` recover the correct K&R signatures too.
  - C++ rvalue-reference parameters (`T&&`) are moved into the call instead of
    being passed as an uncompilable lvalue.
  - `@response-file` compile-database arguments are expanded, preserving the
    `-I`/`-D` context they carried instead of dropping it.

- **Honest fuzz outcomes.** An `--engine afl++` run that executed zero inputs is
  recorded as built, not fuzzed. A native target that was entered and executed
  but produced zero coverage edges is flagged as having fuzzed blind. A legacy
  C++ target whose older-dialect build ties the default's error count now adopts
  the repairable older-dialect errors and converges instead of failing outright.

- **Dependencies.** Upgraded the Tera template engine to 2.x (with the
  corresponding harness-template syntax update) and refreshed the Cargo
  minor/patch set and pinned GitHub Actions.

## 0.2.19 - 2026-07-23

- **Legacy Ada/C/C++ zero-fuzz remediation.** Forty-seven discovery,
  ranking, generation, build-recovery, and execution-accounting issues found in
  a top-500 legacy-code sweep were investigated and covered by focused and
  end-to-end regressions. Fixes include exact Ada overload identity and
  dependency closure, merged reopened IDL modules, checked-in CORBA servants,
  C++ default/lifecycle construction, neutral `CORBA::Environment` handling,
  namespace-safe type resolution, legacy header preprocessing, and exact
  per-translation-unit compile contexts for original and repair-added sources.
  Directly included C++ implementation files are de-duplicated from that object
  graph, and generated C/C++ Makefiles explicitly select the complete build as
  their default goal. C++ standalone-header preflights now share the harness's
  standard-library path recovery and essential defensive prelude. Ada projects
  with obsolete runtime imports are overlaid without inheriting those imports,
  and generic-local result types are qualified through the generated instance.

- **Honest target execution and fallback evidence.** Successful campaigns now
  prove entry into the selected project endpoint rather than counting driver
  execution alone. Generation fallback chains, repairs, terminal stages, cache
  provenance, and stable structured failure categories survive into per-target
  checkpoints and final reports.

- **Durable and safe campaign resume.** `auto --resume` reloads atomically
  checkpointed completed targets from an unchanged campaign and retries only
  unfinished targets. Regenerable state is refreshed on normal reruns and
  incompatible upgrades while corpora and findings are preserved. The README
  now documents reboot/power-loss recovery and the target-level resume boundary.

- **Compact scrubbed bug reports.** The release includes
  `govfuzz-bug-report`, which creates one size-capped support report from a
  running or completed auto work directory. It reports structured decision,
  build, repair, and execution facts without source, harness or corpus content,
  paths, filenames, or project identifiers.

- **Full distribution is a permanent release artifact.** Every tagged release
  builds, installs, smokes, and publishes the all-in-one Linux
  `govfuzz-dist-<version>-x86_64-unknown-linux-gnu.tar.gz` with `install.sh`.
  The bundle now always contains `INSTALL.md`, `LICENSE`, `README.md`, and
  `RELEASE_NOTES.md`, enforced by packaging regressions and release-workflow
  archive checks.

## 0.2.18 - 2026-07-21

- **Restored all-in-one Linux installer bundle.** The release now publishes
  `govfuzz-dist-v0.2.18-x86_64-unknown-linux-gnu.tar.gz` with a bundled
  `install.sh`, CLI, daemon, both Linux preload shims, harness runtimes, signed
  content, and smoke fixture. The release workflow builds this bundle from the
  EL7-baseline artifacts and exercises an extracted install before publication.
  Separate component archives remain available for manual layouts; every one
  now includes `INSTALL.md` with exact checksum, extraction, co-location,
  optional-daemon, and environment-override commands.

- **Exact CLI archive validation.** The Linux and Windows release gates now
  select the exact `govfuzz` CLI archive instead of allowing the similarly
  named daemon archive to win an order-dependent wildcard match. This release
  completes publication of the self-contained harness-runtime packaging added
  in v0.2.17; the v0.2.17 tag did not publish after its gate correctly rejected
  the mistakenly selected daemon archive.

- **Task-based release asset guide.** The README, install, Windows, offline,
  and release-packaging guides now say exactly when to use the CLI, daemon,
  runtrace shim, compiler-interception shim, source archive, manifests, and
  checksum files. They distinguish installer-based and manual/archive installs,
  explain the effect of omitting optional components, and give an exact offline
  download pattern that cannot accidentally select the similarly named daemon.

- **ThreadSanitizer replay reliability.** Corpus replay now gives explicit TSan
  shadow-memory mapping failures a larger harness-wide bounded retry budget and
  retries transient unsymbolized reports, avoiding missed GF-556 findings under
  parallel sanitizer load without multiplying the bound across every corpus
  input. The live-runtime E2E also rechecks TSan availability at the point of
  failure instead of treating an ASLR/runtime outage as a govfuzz defect.

- **Clear RHEL 7 installation prerequisites.** The README now includes a
  copy-paste EL7 quick install. The v0.2.18 Unix CLI installer detects RHEL /
  CentOS 7 and explains that it installs only the CLI, prints the exact RHSCL
  LLVM 7 packages, and links the separate runtrace and compiler-interception
  shim installers instead of leaving a fresh host with an unexplained toolchain
  failure.

- **Current platform matrix.** Release compatibility now extends through RHEL
  10 and Ubuntu 26.04 LTS, while retaining RHEL 7/8/9 and Ubuntu 22.04/24.04.
  Native Windows coverage spans Windows 11 Enterprise 25H2, Windows 11
  Enterprise LTSC 2024 (24H2 codebase), and Windows Server 2019/2022/2025. CI
  exercises release binaries through scan, target discovery, native C harness
  compilation, and fuzzing instead of checking only startup.

- **Working Linux shim installers.** The v0.2.18 runtrace and compiler-
  interception shell installer assets were repaired in place after clean-host
  validation exposed cargo-dist 0.31 applying `chmod` to the final library path
  before moving the library out of its temporary directory. The release
  workflow now patches and gates both generated library installers so the
  failure cannot recur. Every Unix installer now also checks for the `xz`
  helper up front, and the RHEL setup commands install it explicitly; this
  replaces an opaque extraction failure on minimal RHEL images.

- **Platform installer and prerequisite diagnostics.** The v0.2.18 CLI and
  daemon PowerShell installer assets were updated in place so `irm ... | iex`
  also works in a non-interactive Windows Server 2019 OpenSSH session. Missing
  Windows C/C++ tools now recommend LLVM, VS 2022 Build Tools/Windows SDK, and
  GNU make instead of incorrectly printing an Ubuntu `apt-get` command. Linux
  C/C++ diagnostics now distinguish the RHEL 7 LLVM Toolset, RHEL 8+ `dnf`, and
  Ubuntu `apt-get` paths.

## 0.2.17 - 2026-07-21

- **Self-contained release harness runtimes.** Supersedes v0.2.16: the
  published CLI archives now carry all eleven language-runtime trees needed to
  generate and compile C/C++, Ada, Rust, Java, Python, Perl, C#, JavaScript /
  TypeScript, Ruby, Lua, PHP, COBOL, Fortran, and Go harnesses. Installer-only
  deployments securely materialize the same sources from the CLI's embedded
  copy, so a release binary never depends on the GitHub runner checkout path.
  Linux and Windows release jobs now inspect their completed archives and fail
  if any runtime is missing.

## 0.2.16 - 2026-07-21

- **Windows, Ubuntu, and RHEL release artifacts.** Releases now publish the
  `govfuzz` CLI and daemon for both `x86_64-pc-windows-msvc` and
  `x86_64-unknown-linux-gnu`, with native PowerShell and Unix shell installers.
  Windows Server 2022 CI tests and smokes the Windows executables. The Linux
  artifact is built at the GLIBC 2.17 baseline for Ubuntu and RHEL 7 through 9;
  Linux-only runtime and compiler-interception shims remain separate Linux
  assets.

- **Windows cargo-dist packaging.** The Linux-only runtrace shim now skips its
  GNU C hook compilation and linker version script when cargo-dist assembles a
  Windows release. Windows CI explicitly builds the shim package to keep this
  release-only path covered.

- **Native Windows C harness linking.** Generated harnesses and the external
  driver no longer emit competing COFF weak defaults for the Linux-only
  runtrace input hook. This fixes the `LNK1227` failure that previously stopped
  an otherwise valid MSVC/Clang harness before fuzzing.

- **UTF-8-safe C++ type qualification.** The C++ decoder no longer slices
  through a multibyte character when fuzzed or recovered type text places a
  non-ASCII scalar immediately before an identifier. This fixes the GF-210
  panic found by the repository's self-fuzzing PR gate.

- **Offline sanitizer replay reliability.** Capsule verification and direct
  sanitizer integration runners no longer inherit a distro-configured remote
  `DEBUGINFOD_URLS`. This prevents `llvm-symbolizer` from hanging indefinitely
  when the network or debuginfod service is unavailable; the ASan pool bridge
  regression also has a hard timeout.

- **RHEL 7 through RHEL 9 support and release compatibility.** GNU/Linux release
  artifacts now build in a pinned manylinux2014 / CentOS 7 userspace and pass an
  automated GLIBC 2.17 ABI plus preload-export gate instead of inheriting the
  newer Ubuntu runner ABI. The binary distribution installer auto-detects
  `dnf`/`yum`, maps selected lanes to RHEL package names, and installs available
  dependencies even when an optional supplemental package is absent. Dedicated
  RHEL-compatible CI and Proxmox validation cover the release build, package
  install, signed content, bundled C smoke target, and a real miniz run.

- **TypeScript fuzzing lane.** `govfuzz auto --languages typescript` discovers
  exported functions and public class methods in `.ts`/`.tsx` source (the
  name-extracting parser strips type annotations; interfaces, type aliases, and
  `private`/`protected`/`abstract` members are excluded), transpiles the target to
  CommonJS with esbuild, and fuzzes it with the same warm-Node framed driver, V8
  block coverage, dictionary, and command-injection detector as the JavaScript
  lane. Node + esbuild required (`npm i -g esbuild`); absent either, the lane skips
  cleanly. `.d.ts` declaration files are not fuzzed.

- **Self-fuzz dogfood CI.** A nightly `dogfood` workflow runs `govfuzz auto` on
  govfuzz's own C runtime decoders (the untrusted-input parsers every harness
  links), uploads SARIF + findings, and fails on a fuzz-confirmed crash — govfuzz
  fuzzing itself.

- **JS/TS runtime-load check.** A module that passes `node -c` (syntax) but whose
  `require('...')` cannot resolve at runtime — an npm dependency not installed
  (e.g. `qs` → `side-channel`) — previously built a harness that died at startup and
  fuzzed 0 inputs while being reported as "built". It now skips cleanly with an
  actionable reason (`… requires an npm dependency that is not installed; run
  npm install`). Applies to the transpiled TypeScript output too.

- **JavaScript/TypeScript prototype-pollution detector (GF-509 / CWE-1321).** The
  top JS injection class. The driver snapshots `Object.prototype`/`Array.prototype`
  and, after an input carrying a `__proto__`/`constructor`/`prototype` vector,
  reports a new own-property that appeared on them; complete `{"__proto__":{…}}`
  payloads are seeded into the dictionary so an unsafe `JSON.parse`+merge is
  reachable end-to-end. Verified: a recursive-merge vuln is found (GF-509) while a
  benign `JSON.parse` (which never pollutes) is not — 0 false positives.

- **JavaScript command-injection detector (GF-431 / CWE-78).** The JS lane runs
  without the LD_PRELOAD shim (managed runtime), so — like Jazzer.js's bug detectors
  — the driver hooks `child_process.exec`/`execSync` in JS and reports a
  taint-confirmed command injection when a shell-metacharacter-bearing substring of
  the fuzz input reaches the command (the input controls shell *syntax*, not just
  data). The command is never executed (a benign stub is returned). Verified:
  `execSync('convert ' + input)` is caught while a fixed command with metachar-laden
  input is not — 0 false positives.

- **Wider fuzzable surface for the C# and JavaScript lanes.** The C# lane now
  fuzzes methods with a `bool` sibling (driven to `false`) and drives an
  `offset`/`index`/`start` integer to `0` (not the buffer length, which threw), so
  `Parse(string, bool)` and `Read(byte[], int offset, int count)` shapes are covered.
  The JavaScript lane now discovers **static** methods of exported classes
  (`Class.parse`-style, no construction needed) in addition to instance methods.

- **Coverage depth for the C# and JavaScript lanes.** Three improvements from a
  post-merge dogfood sweep: (1) both lanes now **mine a magic-value dictionary**
  from the target's string/integer literals — the managed/interpreted drivers carry
  no CmpLog, so a single multi-byte comparison gate (`if (s == "OPENSESAME")`) was
  previously uncrackable; with the dictionary it is found (the libFuzzer-autodict /
  Jazzer-value-profile lever the other managed lanes already had). (2) The
  **JavaScript lane discovers public methods of exported classes** (`Class#method`),
  not just free functions — the driver `new`s a no-arg-constructible class and calls
  the method, covering class-based libraries. (3) The **JavaScript lane no longer
  runs under the LD_PRELOAD runtrace shim** (like the JVM/.NET lanes): Node's
  `stat()`→`open()` on every `require` is the same TOCTOU pattern that false-positived
  on the .NET host, so it is excluded.

- **JavaScript / Node.js fuzzing lane.** `govfuzz auto --languages javascript`
  discovers exported functions (CommonJS + ESM) taking a `Buffer`/`string`, and
  fuzzes them coverage-guided on govfuzz's own fork-server engine driving one warm
  Node process — no Jazzer.js, no jsfuzz, no libFuzzer, no `fuzz(data)` to
  hand-write. Coverage is **real V8 precise block coverage** (the inspector
  Profiler, no Babel/Istanbul source rewrite) folded per input — keyed on `(script,
  block span, taken/not-taken)` — into govfuzz's cumulative `GOVFUZZ_COV_SHM` edge
  bitmap, so the engine gets genuine branch feedback. An uncaught exception that is
  not input rejection hard-halts (exit 86) and maps to a GF rule + CWE (stack
  overflow → GF-207/CWE-674, resource `RangeError`/OOM → GF-209, `ReferenceError` /
  assertion / explicit `throw` → GF-210). `TypeError` (and `SyntaxError`/`URIError`/
  validating `RangeError`) are treated as input rejection — the untyped-lane policy
  the Python lane uses — since govfuzz synthesizes only the first argument; a
  first-argument name filter also keeps internal array/options helpers out of the
  fuzz set. Validated on a 30-project / 2,018-file campaign (express, lodash, axios,
  moment, validator.js, node-semver, marked, joi, …): 0 panics, 531 fuzzable
  functions discovered, 0 false positives; end-to-end it finds an
  uncontrolled-recursion crash with the V8 stack. The driver uses only Node
  built-ins (`inspector`, `fs`) — nothing linked into govfuzz. See
  [docs/site/javascript.md](docs/site/javascript.md).

- **C# / .NET fuzzing lane.** `govfuzz auto --languages csharp` discovers `public`
  methods taking a `byte[]`/`string`/`Stream`, builds the target with `dotnet`
  through a project reference, instruments its IL with
  [SharpFuzz](https://github.com/Metalnem/sharpfuzz) (`sharpfuzz <dll>`), and fuzzes
  it coverage-guided on govfuzz's own fork-server engine — no AFL, no libFuzzer, no
  `Fuzzer.Run` to hand-write. The driver `mmap`s govfuzz's `GOVFUZZ_COV_SHM` edge
  bitmap (64 KB = the AFL map size SharpFuzz targets) into
  `SharpFuzz.Common.Trace.SharedMem`, so the instrumented target writes coverage
  straight into govfuzz's cumulative map, and speaks the framed fork-server protocol
  to keep **one warm CLR** alive across all inputs. An uncaught exception that is not
  input rejection is a finding (exit 86), mapped to a GF rule + CWE by type (index
  OOB → GF-201/CWE-125, null-deref → GF-206/CWE-476, arithmetic → GF-205, OOM →
  GF-209, stack overflow → GF-207, else GF-210). Input-rejection exceptions
  (`ArgumentException`, `FormatException`, …) and the target namespace's own
  exceptions are suppressed. Like the JVM lane, it runs without the LD_PRELOAD shim
  (the .NET host's own startup I/O would otherwise trip the TOCTOU/open oracles).
  The target project reference is pinned to the best framework the installed SDK
  supports, so a library that multi-targets a newer preview TFM still builds.
  Validated on a 25-project / 69,608-file campaign (dotnet/runtime, roslyn, EF Core,
  Newtonsoft.Json, MessagePack, YamlDotNet, ImageSharp, …): 0 panics, 3,113 fuzzable
  methods discovered; end-to-end at ~6,900 exec/s on a warm CLR with real edge
  coverage and 0 shim false positives. SharpFuzz/SharpFuzz.Common are Apache-2.0 and
  link into the user harness, never into govfuzz. See
  [docs/site/csharp.md](docs/site/csharp.md).

- **Fortran fuzzing lane.** `govfuzz auto --languages fortran` discovers Fortran
  `subroutine`/`function` procedures with a `character` (byte-buffer) argument,
  compiles them with `gfortran -fsanitize=address
  -fsanitize-coverage=trace-pc,trace-cmp`, and fuzzes them coverage-guided on the C
  fork-server engine. AddressSanitizer is the memory oracle — a Fortran array/
  substring out-of-bounds is reported directly as a crash with the exact
  `.f90:line` and CWE (heap → CWE-122/787). The glue calls the routine via the
  gfortran C ABI (args by reference, a hidden length per character argument) with
  the primary buffer heap-allocated to the input size so a real OOB lands in ASan's
  redzone. Validated on a 20-project / 40,367-file campaign: 0 panics, 13,406
  fuzzable procedures discovered, 6,500+ exec/s, 0 false positives. See
  [docs/site/fortran.md](docs/site/fortran.md). libgfortran (LGPLv3 + GCC RLE) links
  into the user harness like the C runtime; gfortran is a subprocess only.

- **COBOL fuzzing lane — the first turnkey COBOL fuzzer.** `govfuzz auto
  --languages cobol` discovers COBOL programs (`PROGRAM-ID` with a fuzzable
  `LINKAGE` `PIC X` operand), translates them to C with GnuCOBOL (`cobc -C
  -debug -fec=all`; free/fixed format detected, copybook `-I` dirs collected),
  generates a driver that drives the full `USING` operand list (primary buffer +
  length + zeroed rest), and fuzzes on the C fork-server path (edge coverage,
  CmpLog, ASan). Two crash oracles — ASan for raw memory corruption and libcob
  `-fec=all` for COBOL-semantic violations — with each crash attributed to its
  `.cob:line` and CWE (out-of-bounds ref-mod → CWE-125, zero-divide → CWE-369,
  size overflow → CWE-190). The taint-confirmed sink oracles (command/SQL/path
  injection, CWE-78/89/22) apply too. Validated on a 23-project / 2925-file
  campaign: 0 panics, 30/38 build+fuzz, 0 false positives, 2 real
  command-injection findings. cobc is GPLv3 (subprocess-only); libcob is LGPLv3
  and links into the user harness like the GNAT runtime. See
  [docs/site/cobol.md](docs/site/cobol.md).

- **PR-native CI + GitHub Action.** New `govfuzz ci --changed-since <ref>` mode
  scopes a run to only the files a pull request changes (merge-base aware,
  reusing the discovery cache), with `--sarif` output, a compact `--ci-json`
  result, and a `--pr-gate {confirmed,all,never}` policy that by default fails
  only on a fuzz-confirmed finding. A composite action
  (`.github/actions/govfuzz-pr`) makes it one `uses:` line: it resolves the PR
  base, installs govfuzz, runs the scoped fuzz, uploads SARIF for inline
  code-scanning annotations, and posts a sticky PR summary comment. See
  [docs/site/ci.md](docs/site/ci.md). The git-diff helpers are factored into a
  shared module reused by `list-targets --changed-since`; non-scoped `ci`
  behavior is unchanged.
- **Two-compiler differential fuzzing in `auto`.** New `govfuzz auto
  --differential clang:gcc` rebuilds each C/C++ harness under both compilers via
  a portable `make diff` target and replays the fuzz corpus through both, flagging
  any input on which their exit/crash behavior diverges — a codegen- or
  UB-dependent bug one compiler exposes and the other hides — as a GF-301 finding
  in the normal report. Comparison is on exit status (govfuzz harnesses suppress
  target stdout); a failed second-compiler build logs and skips. The standalone
  `govfuzz differential` subcommand (arbitrary two-harness / metamorphic) is
  unchanged.

## v0.2.15 - 2026-07-10

- **First public release.** Hardened for public distribution: Dependabot version
  updates, GitHub Actions pinned to commit SHAs, least-privilege workflow
  permissions, and a security review that fixed a SQL-shim out-of-bounds read
  (counted `mysql_real_query`/`sqlite3_prepare*` buffers), an Ada-stub path
  traversal from untrusted compiler diagnostics, signal-unsafe shim locking, and
  two resource-exhaustion caps (IDL parser recursion, event-log allocation).
- **Cross-language static coverage sweep** closing per-language gaps found vs
  semgrep/gosec/spotbugs/cppcheck: `GF-551` Java JNDI injection (Log4Shell class,
  CWE-917; non-literal `Context.lookup`), `GF-552` Rust unsafe `transmute`
  (CWE-843), `GF-553` Rust `unwrap()`/`expect()` panic in library code (CWE-248,
  scoped to fallible boundaries to stay precise), `GF-554` C/C++ printf
  argument-type mismatch (CWE-686, high-confidence literal cases only). Broadened
  `GF-429` hardcoded-secret detection with a generic `NAME = "secret"` assignment
  pattern (language-agnostic, placeholder-guarded) and `GF-422` weak-crypto to
  cover DES/3DES/RC4/ECB/Blowfish/MD4 across C/Go/Rust/Python/Java (new Rust
  detector). All cross-checked against the competitor and verified 0 false
  positives on the 14-repo comparison corpus.
- **Static C/C++ now best-in-class outright.** Added the two bug classes cppcheck
  caught and govfuzz missed, as precise per-function intraprocedural scanners:
  `GF-549` dangling-lifetime return (returning the address/reference of a local;
  CWE-562) and `GF-550` resource leak (an allocation/handle never freed, closed,
  returned, or escaped; CWE-401/772). Cross-checked against cppcheck's
  `returnDanglingLifetime`/`memleak` — govfuzz fires on the same real defects with
  0 false positives on the corpus.

- **Best-in-class comparison + static/SBOM/SLOC improvements** (see
  `docs/site/comparison-2026-07.md`). New static rules: `GF-546` Python
  `try/except/pass` swallowed exception (CWE-703), `GF-547` unbounded
  `scanf`/`getwd` reads (CWE-120/676), `GF-548` cleartext `ws://` transport
  (CWE-319). Every static finding now carries its CWE and a `remediation` line in
  the JSON, Markdown, and SARIF (`help`/`helpUri`) outputs.
- **SBOM: lockfile ingestion + SPDX.** Reads `uv.lock` (and the existing
  lockfiles) for pinned/transitive components so CVE correlation works; adds an
  SPDX-2.3 JSON emitter (`--format spdx-json`) alongside CycloneDX/VEX.
- **`govfuzz sloc <PATH>...`** — a standalone, rayon-parallel SLOC counter (no SAST
  scan) that counts one or more roots in a single invocation; best-in-class on both
  accuracy and speed.
- **`auto --force` (alias `--force-fuzz`)** — force-fuzz mode: attempt every
  discovered C/C++/Ada function even when a parameter can't be driven or a
  type/symbol is undefined. Bypasses the pre-build skip gates, synthesizes
  best-effort drivers for opaque/function-pointer/unknown params, applies
  universal compiler-diagnostic-driven stubbing until the harness builds, and
  never hard-fails (a still-unbuildable target degrades to a report-only static
  scan). Findings from a forced/stub-heavy build are floored to Low confidence
  with a `forced` note and counted separately, since a forced crash may be a stub
  artifact rather than a real defect.
- **Win32/MFC + qualified-call recovery (no flag)** — the repair loop injects the
  synthesized `windows.h` typedefs (`BOOL`/`DWORD`/`PUCHAR`/…) for stray Win32
  names so such targets build+fuzz with real semantics; the C/C++ decoder drives
  Win32 pointer typedefs; and a namespaced free function gets a forward
  declaration even when an unrelated header (e.g. `StdAfx.h`) is auto-included,
  fixing `use of undeclared identifier`.
- **`findings.csv` overhaul** — weakness-describing messages, bare CWE numbers, a
  `remediation` column (replacing the meaningless `fix_location`), `source` +
  `data_flow` (source→sink from taint traces), an `entity` column (tainted
  variable/sink), blank `member_finding_ids` for singleton issues, and relative
  report-only (`F-RO-*`) paths.
- **`--static-dynamic`** adds a `scan_type` column to `findings.csv`
  (`static-dynamic` for a static-scan result, `dynamic` for a fuzzed result).
- Renamed the user-facing `report-only` outcome to `static-only`.

## v0.2.14 - 2026-07-08

- Added a `--sloc <FILE>` flag to `govfuzz static-scan` and `govfuzz auto` that
  writes an accurate per-language SLOC breakdown (LANGUAGE, FILES, TOTAL,
  COMMENTS, BLANKS, SLOC). Comment counting is language-aware (Ada `--`, C-family
  `//`/`/* */`, hash comments, Perl POD, Python docstrings) via the same stripper
  the rule engine uses, and the same dependency/build-tree pruning as the scan
  applies, so vendored/`node_modules`/`.venv` code is excluded. A `.json`
  extension emits JSON; anything else emits an aligned text table.

## v0.2.13 - 2026-07-08

- Added a Python static rule (`GF-545`, CWE-943) that flags a GraphQL operation
  document parsed via `gql()` from a dynamically-built string carrying GraphQL
  operation syntax. A literal document with request data bound through
  `variable_values` is the safe form and does not fire, mirroring the SQL rule.
- Fixed `govfuzz auto --external-tools` so the flag activates the external
  analyzers on its own: it now defaults to the `external-tools` license profile
  instead of the no-op `strict-permissive`, matching `static-scan --external-tools`
  (an explicit `GOVFUZZ_PROFILE` still wins). Previously the flag silently ran no
  analyzers unless `GOVFUZZ_PROFILE=external-tools` was also set.
- Expanded framework raw-HTML XSS coverage (`GF-512`) across Vue, Svelte, and
  Angular sinks, and stopped the static scanner from analyzing generated
  `compiled/` bundles (e.g. Next.js build output).
- Reworked the README for an outward-facing audience: dropped the internal Status
  section, added a concise "What it does" overview, and documented `auto --static`
  and `--external-tools` usage.

## v0.2.12 - 2026-07-07

- Added Python static rules for unsafe `tarfile` extraction without a safe filter
  (`GF-542`, CWE-22), Flask/Jinja request-data-as-template-source injection
  (`GF-543`, CWE-1336), and tainted values reaching a logging sink without CR/LF
  neutralization (`GF-544`, CWE-117).

## v0.2.11 - 2026-07-07

- Degrade C/C++ targets that reference an unsuppliable external class to a
  report-only static scan instead of a bare failed build: a placeholdered
  external class (e.g. MFC `CString`) whose rebuild fails with scalar-used-as-
  class errors, and a forward-declared type whose definition is not visible to
  the generated harness translation unit, now both fall back to "fuzz the
  source" with CWE-tagged findings.
- Overhauled `findings.csv` for static findings: added `rule_id` and a
  human-readable `message` column so a row says what the issue is, not just a
  CWE; blanked the redundant `harness_id` for static rows; surfaced the
  emit-time confidence instead of a flattened report-time value; and populated
  `sink_function` with the enclosing function name rather than the file name.
- Extended SBOM cataloging to list external COTS/OSS/GOTS software traced from
  C/C++ `#include` directives and Ada `with` clauses even without a dependency
  manifest, while excluding the project's own headers/packages and system or
  toolchain headers. `--sbom` now explains an empty result.
- Annotated the `auto` bug report so known, working-as-intended limitations
  (opaque-handle lifecycle skips, classes with no public constructor/factory)
  are tagged and not mistaken for reportable bugs.
- Made the SBOM golden test version-agnostic so it no longer breaks on each
  release version bump.

## v0.2.10 - 2026-07-07

- Re-cut the v0.2.9 release after GitHub rejected Artifact Attestations for the
  private Tarmo-Technologies organization/repository plan.
- Disabled GitHub Artifact Attestations in the generated release workflow and
  updated release documentation to describe checksum verification plus signed
  content-pack verification as the supported release integrity path.

## v0.2.9 - 2026-07-07

- Re-cut the v0.2.8 static-analysis release payload with the generated release
  matrix limited to the smoke-tested `x86_64-unknown-linux-gnu` target.
- Documented the supported binary release target and the Linux-only runtime
  preload package constraint.
- Guarded a Linux-only fuzz-runner `prctl` call so non-Linux source builds do
  not fail on that symbol.

## v0.2.8 - 2026-07-07

- Expanded `govfuzz static-scan` with broad framework, JavaScript, container,
  GitHub Actions, Django, Electron, and Qt WebEngine rule coverage.
- Added Qt WebEngine hardening detections for sandboxing, mixed content, local
  file/remote URL access, plugins, clipboard access, geolocation, unknown URL
  schemes, DNS prefetch, WebRTC local IP exposure, screen capture, canvas
  readback, and hyperlink auditing.
- Added Django deployment hardening detections for HTTPS redirect defaults,
  HSTS, proxy HTTPS state, referrer policy, nosniff, host allowlists,
  CSRF/session cookies, frame options, request-size limits, debug mode, and
  weak password hashers.
- Improved static-analysis release documentation, benchmark coverage for the
  Django HTTPS redirect rule, and release-flow guidance for `dist` tag planning.

## v0.2.7 - 2026-07-02

- Added `auto --static` whole-tree static scanning alongside fuzzing.
- Mapped static findings into sink/fix location reporting.
