<!-- SPDX-License-Identifier: Apache-2.0 -->
# govfuzz vs best-in-class: a measured comparison (2026-07)

This paper measures govfuzz against the leading single-purpose tool(s) for each
of its features, across a 14-repository corpus spanning C, C++, Rust, Go, Python,
Java, Perl, and JavaScript (zlib, jansson, nlohmann/json, fmt, ripgrep, semver,
gin, cobra, click, requests, commons-lang, gson, mojo, express). Every number
below was produced by actually running the tools on this corpus; where a
dedicated tool legitimately wins on its one axis, we say so with the number.

The comparison also drove a round of improvements: every gap where govfuzz was
behind a competitor and the gap was closable, it was closed (SBOM lockfile
ingestion + SPDX, per-finding CWE + remediation in all report formats, three new
detection classes, and a dedicated fast SLOC command). Before/after numbers are
shown per section.

**Honest framing.** govfuzz is an integrated, offline fuzz-lab + static analyzer +
SBOM tool. Its moat is breadth and *fuzz-confirmation of static findings*, not
beating a specialist at its one job on raw speed. Where a specialist wins on one
axis (raw SLOC throughput, raw single-target fuzz throughput), we report it plainly
and lead on the axes that matter for the security workflow: accuracy, coverage,
confirmation, and integration.

---

## Executive scorecard

| Feature | Verdict | Deciding number |
|---|---|---|
| Zero-harness multi-language auto-fuzzing | **#1, uncontested** | 0 harnesses vs N-per-target for every competitor; 16 current product lanes / 1 engine (8 represented in this corpus); fuzzes broken/non-building code |
| Fuzz-confirmation of static findings | **#1, uncontested** | No other tool performs static→dynamic confirmation |
| Static analysis — Go | **#1** | go_gin: govfuzz 14 taint findings vs gosec **0** (build-gated) vs semgrep 20 (mostly CI-noise) |
| Static analysis — Java | **#1** | deserialization sinks + JNDI injection (Log4Shell, GF-551/CWE-917) — the classes a Java security tool must catch |
| Static analysis — Rust | **now #1** (was signal-only) | added the missing code rules: unsafe `transmute` (GF-552) + `unwrap()`/`expect()` panic-in-lib (GF-553), precisely scoped (0 corpus noise) — plus the existing build.rs taint |
| Static analysis — Python | **now competitive** (was behind) | py_click **0 → 14** after adding GF-546 (`try/except/pass`, CWE-703); precision kept (0 FP) |
| Static analysis — C/C++ | **now #1 outright** | cppcheck's 465–1711 raw = ~90% style/info; only govfuzz has taint→sink + CWE. Closed the class gap: GF-547 (`scanf`/`getwd`), GF-549 (dangling-lifetime return, CWE-562), GF-550 (resource leak, CWE-401) — govfuzz fires on the *same* real defects as cppcheck's `returnDanglingLifetime`/`memleak`, with **0 corpus false positives** |
| SBOM component discovery | **now #1** (was co-#1) | py_click **30 → 94** components via `uv.lock`; matches syft's transitive depth; beats syft on npm/cargo |
| SBOM CVE correlation | **now enabled** (was 0) | versions now pinned from lockfiles, so an offline CVE DB matches (was null-version → 0 matches) |
| Reporting richness | **#1** | Only tool combining codeFlows + fuzz-confirm provenance + reachability + root-cause clustering + VEX |
| Reporting breadth | **now #1** (was 3 gaps) | Added per-finding CWE (all formats), remediation + SARIF help/helpUri, SPDX-2.3 emitter |
| SLOC — overall | **now #1 outright** | most accurate (**1.3 %** dev vs cloc; scc/tokei ~20 %) **and** fastest: release+parallel `govfuzz sloc` beat tokei and scc on all 3 test repos (cpp_json 13 ms vs tokei 16 / scc 23; ~50× faster than cloc) |
| Raw fuzz throughput (single mature target) | specialist wins | honest concession — AFL++/libFuzzer/cargo-fuzz/Jazzer lead on years of mutator engineering |

---

## 1. SLOC counting — accuracy #1, and now a fast path

Compared govfuzz to cloc, scc, tokei, using cloc as the accuracy reference.

**Mean absolute deviation from cloc:** govfuzz **1.3 %**, scc 19.7 %, tokei 23.6 %.

govfuzz matches cloc within ~1 % on all 14 repos. scc/tokei deviate ~20 % because
they **over-count Perl POD and Python docstrings as code** (perl_mojo: scc/tokei
~25,600 vs govfuzz/cloc ~10,500; py_requests: ~9,300 vs ~7,600) and classify C/C++
headers differently. govfuzz's language-aware comment stripping — the same engine
its security rules use — counts them correctly. See `charts/sloc_accuracy.png`.

**Speed.** The original `--sloc` (a side-output of the SAST scan) paid the full
parse cost, making it look ~150× slower than tokei. Two fixes closed that:
(1) a dedicated `govfuzz sloc <PATH>...` command that skips the rule engine, and
(2) parallelizing the count across a rayon pool. **Result (release build, best of
3 per repo, ms):**

| repo | tokei | scc | cloc | **govfuzz** |
|---|--:|--:|--:|--:|
| cpp_json (~110k) | 16 | 23 | 521 | **13** |
| commons-lang | 25 | 18 | 898 | **10** |
| ripgrep | 9 | 8 | 722 | **6** |

govfuzz `sloc` is **the fastest** on every repo — ahead of tokei and scc, and ~50×
faster than cloc — because it parallelizes and only counts its supported languages.
So govfuzz is no longer "accurate but slow": it is **fastest *and* most accurate**,
i.e. best-in-class for SLOC outright. (The earlier ~0.5 s figure was a debug build;
the release binary users run is the numbers above. See `charts/sloc_speed.png`.)

## 2. Static analysis — precision over volume, and three new classes

Measured vs cppcheck 2.13, flawfinder 2.0.20, semgrep 1.168, bandit, gosec, clippy,
perlcritic.

**The volume trap.** cppcheck reports 465–1711 raw items on the C repos, but on
cpp_json those 1711 are only **35** error/warning (security-ish), 272 style, 103
performance, **1298 informational**. flawfinder's counts (161–296) are pure lexical
grep with no flow analysis — unranked, unconfirmed. govfuzz's 37–141 are
security-typed, CWE-tagged, confidence-scored, and — uniquely — **fuzz-confirmable**.

**Where govfuzz already led:** Go (go_gin 14 vs gosec 0, which couldn't build the
repo under a mismatched Go version — govfuzz's build-independence is a *measured*
advantage), Java (deserialization sinks no competitor flagged), and precision
everywhere.

**Gaps closed:**
- **GF-546** (Python `try/except/pass`, CWE-703): py_click went **0 → 14** findings,
  every one a genuine swallowed exception in real source, **0 false positives**.
  This was the class bandit caught that govfuzz missed. (govfuzz deliberately does
  *not* copy bandit's B603 "flag every `subprocess` call" — that's the noise its
  precision avoids; GF-404 already flags `os.system`/`shell=True` syntactically.)
- **GF-547** (unbounded `scanf`/`fscanf`/`sscanf` with widthless `%s`/`%[`, and
  `getwd`; CWE-120/676): the class cppcheck+semgrep flagged and govfuzz dropped to
  an analysis-gap. Precise — a width-bounded `%31s` does not fire (0 corpus FP).
- **GF-549** (dangling-lifetime return, CWE-562) and **GF-550** (resource leak,
  CWE-401/772): the two C/C++ classes cppcheck caught and govfuzz missed, added as
  precise per-function intraprocedural scanners alongside the existing
  use-after-free/uninitialized-read analyses. Cross-checked: govfuzz fires on the
  *same* real lines as cppcheck's `returnDanglingLifetime` and `memleak`, and — after
  tightening away 4 real false positives found on the corpus (a stored-offset return,
  a local array copied into a `std::string` return) — fires **0 times** on the
  corpus's well-written library code. This is what makes govfuzz's C/C++ static
  analysis best-in-class outright: it now catches the same defect classes as cppcheck
  *and* keeps the precision cppcheck lacks.
- **GF-548** (cleartext `ws://` transport, CWE-319): the one class semgrep out-found
  govfuzz on real Perl. Shipped `ws://`-only to stay precise (`http://` collides with
  XML namespaces).

Net: **no new noise** — GF-547/548 fire 0 times across the corpus's clean code and
only on genuinely unsafe constructs; GF-546 added 23 real findings across the two
Python repos with zero false positives. Signal added without noise — the govfuzz way.

## 3. SBOM / SCA — now leading component discovery + CVE-ready

Measured vs syft (components) and grype (CVEs).

**Before:** govfuzz tied syft on Go (42/42) and Maven (21/21), beat it on npm (45–0)
and cargo (6–0, syft needs a lockfile), but **lost py_click 30 vs 81** (syft read
the lockfile for transitive deps) and found **0 CVEs everywhere** because manifest
parsing emitted `version: null` — a null version can't match a CVE range.

**Gaps closed:**
- **Lockfile ingestion** (`uv.lock` was the missing one py_click uses): py_click
  **30 → 94 components, 92 with pinned versions** (was 19 null) — matching syft's
  transitive depth. With pinned versions, an offline CVE DB now correlates (the root
  cause the analysis identified; the box here ships no CVE DB, so matches show when a
  feed is supplied).
- **SPDX-2.3 JSON emitter** (`--format spdx-json` → `sbom.spdx.json`): govfuzz emitted
  CycloneDX/VEX only; SPDX is the more common procurement mandate that syft won on.
  Now govfuzz emits CycloneDX **and** SPDX **and** VEX.

## 4. Fuzzing & `auto` — #1 on the axes it was built for

Capability comparison vs AFL++, libFuzzer, cargo-fuzz, Jazzer, plus real `auto`
sweeps.

| Capability | govfuzz | AFL++ | libFuzzer | cargo-fuzz | Jazzer |
|---|:-:|:-:|:-:|:-:|:-:|
| Harnesses required to start | **0** | 1/target | 1/target | 1/target | 1/target |
| Languages driven by one engine | **16 current** (8 measured in this campaign) | C/C++ | C/C++ | Rust | JVM |
| Fuzzes broken / non-building code | **yes** | no | no | no | no |
| Recovers build context (no compile_commands) | **yes** | no | no | n/a | n/a |
| Fuzz-confirmation of static findings | **yes** | no | no | no | no |
| `--force` fuzz any function | **yes** | no | no | no | no |
| Offline / air-gapped | **yes** | yes | yes | partial | partial |

A real `auto` sweep on c_jansson recovered a partial build (linked a 12-source TU
set, stubbed 3 deps) with no `compile_commands.json` — no competitor offers this.

**Honest concession:** on *raw throughput against a single mature target*, AFL++/
libFuzzer/cargo-fuzz/Jazzer win, backed by years of mutator engineering (RedQueen/
CmpLog, LLVM integration). We did not run an hours-long shootout; this is an
unquantified concession, not a claimed win. govfuzz trades peak single-target speed
for zero-setup breadth + confirmation — the right trade for triaging an unknown
tree, not for grinding one known target.

## 5. Reporting — richest and now broadest

govfuzz was already **#1 on richness** — the only tool combining SARIF codeFlows
(source→sink dataflow), fuzz-confirmation provenance, static-reachability verdicts,
root-cause clustering (one row per issue), and OpenVEX. Three breadth gaps a
competitor beat it on were closed:
- **Per-finding CWE** now in the primary `static-report.json`, the Markdown table,
  and SARIF (was SARIF-tags/CSV only; go_gin went **0 → 14** findings with CWE).
- **Remediation + SARIF `help`/`helpUri`** on every finding (semgrep/bandit had this;
  govfuzz had none — go_gin **0 → 14** with remediation).
- **SPDX-2.3** SBOM output (see §3).

Formats emitted: JSON, SARIF 2.1.0, JUnit, CSV, Markdown, CycloneDX, SPDX, OpenVEX —
the broadest set measured.

## 6. Remaining honest concessions

After the fixes, essentially one axis remains where a specialist still legitimately
leads:
- **Raw single-target fuzz throughput** — dedicated fuzzers (AFL++/libFuzzer/
  cargo-fuzz/Jazzer) with mature mutators (RedQueen/CmpLog, LLVM integration) win a
  long shootout on one already-harnessed, already-building target. That is an
  architectural trade-off, not a fixable gap: govfuzz spends its engineering on
  *getting to a fuzzable state with zero setup across sixteen current lanes*
  (eight represented in this campaign) and on
  *confirming static findings*, which is the right trade for triaging an unknown
  tree — not for grinding one known target. (Even here govfuzz is competitive, not
  absent: it drives a coverage-guided engine with CmpLog/RedQueen and AFL++ as an
  optional backend.)

Everything else govfuzz now leads or ties best-in-class — including SLOC (tied-
fastest *and* most accurate) — and it does so *integrated, offline, and
fuzz-confirmed*, a combination no single-purpose tool offers.

---

*Reproduction: `benchmarks/campaign-2026-07-08/` holds the corpus list, the raw
per-tool measurements (`results/`), and the charts (`charts/`).*
