<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

## Unreleased

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

## v0.2.15 - 2026-07-09

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
