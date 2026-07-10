<!-- SPDX-License-Identifier: Apache-2.0 -->
# Static-scanner CWE coverage matrix

What govfuzz's **static** analyzer (`govfuzz static-scan`, and `auto --static`)
detects, per language and CWE. This is a deliberately honest map: a checkmark
means there is implemented core-scanner coverage for that language/CWE pair, not
that the class is exhaustively covered. The curated precision benchmark remains
the release gate for representative rule behavior; broader framework and
configuration rules also ship with focused unit tests and real-project sweeps.

The differentiator is the column that no pure SAST tool has: **fuzz-confirmation**.
When `auto --static` runs, a static finding a fuzzer actually reaches at the same
site is upgraded to `fuzz_confirmed`; one inside a function fuzzing proved is not
attacker-reachable is downgraded to `lab_only`. A confirmed static finding is not
a maybe.

## Coverage by language

| CWE | Weakness | Ada | C | C++ | Go | Rust | Java | Python | Perl | JS/TS | Config/IaC |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| CWE-78 | OS command injection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | |
| CWE-79 | Cross-site scripting / raw HTML sink | | | | | | | | | ✅ | |
| CWE-89 | SQL injection | | | ✅ | ✅ | | ✅ | ✅ | | ✅ | |
| CWE-90 | LDAP injection | | | | | | ✅ | ✅ | | ✅ | |
| CWE-94 | Code injection (eval/exec) | | | | | | | ✅ | ✅ | ✅ | |
| CWE-117 | Log injection / log forging | | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | | |
| CWE-1333 | User-controlled regular expression | | | | | | | | | ✅ | |
| CWE-1336 | Server-side template injection | | | | | | | ✅ | | ✅ | |
| CWE-502 | Unsafe deserialization | | | | | | ✅ | ✅ | | ✅ | |
| CWE-601 | Open redirect | | | | ✅ | | ✅ | ✅ | | ✅ | |
| CWE-611 | XXE (untrusted XML -> unhardened parser) | | ✅ | ✅ | | | ✅ | ✅ | | ✅ | |
| CWE-915 | Mass assignment | | | | | | | | | ✅ | |
| CWE-943 | NoSQL injection | | | | | | | | | ✅ | |
| CWE-943 | GraphQL injection (dynamic `gql()` operation) | | | | | | | ✅ | | | |
| CWE-470 | Unsafe reflection (tainted class/module name) | | | | | | ✅ | ✅ | | | |
| CWE-789 | Uncontrolled allocation size (tainted alloc size) | | ✅ | ✅ | ✅ | ✅ | ✅ | | | | |
| CWE-918 | SSRF (attacker-controlled URL) | | | | ✅ | ✅ | ✅ | ✅ | | ✅ | ✅⁵ |
| CWE-295 | TLS verification disabled | | | | ✅ | ✅ | ✅ | ✅ | | ✅ | |
| CWE-319 | Cleartext/downgrade transport controls | | | ✅³ | | | | ✅⁴ | | ✅⁶ | |
| CWE-22 | Path traversal | ✅ | ✅ | ✅ | ✅ | | | ✅¹ | | ✅⁷ | |
| CWE-327 | Weak cryptography | | ✅ | ✅ | ✅ | | ✅ | ✅ | ✅ | ✅ | |
| CWE-338 | Insecure randomness (security context) | | ✅ | ✅ | ✅ | | ✅ | ✅ | ✅ | ✅ | |
| CWE-347 | Improper JWT signature verification | | | | | | ✅ | ✅ | | ✅ | |
| CWE-352 | CSRF protection disabled | | | | | | ✅ | ✅ | | ✅ | |
| CWE-693 | Protection mechanism disabled | | | ✅⁸ | | | | ✅ | | ✅⁸ | ✅⁸ |
| CWE-798 | Hardcoded secret (name heuristic + verified formats²) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| CWE-1004/614/1275 | Sensitive cookie flags | | | | ✅ | | ✅ | ✅ | | ✅ | |
| CWE-1021 | Clickjacking / frame protection disabled | | | | | | ✅ | ✅ | | ✅ | |
| CWE-1321 | Prototype pollution | | | | | | | | | ✅ | |
| CWE-120/787 | Unsafe buffer copy | | ✅ | ✅ | | | | | | | |
| CWE-134 | Uncontrolled format string | | ✅ | ✅ | | | | | | | |
| CWE-190 | Unchecked integer conversion | | ✅ | ✅ | | | | | | | |
| CWE-457 | Use of uninitialized variable | | ✅ | ✅ | | | | | | | |
| CWE-197 | Numeric truncation | | ✅ | ✅ | | | | | | | |
| CWE-416 | Use-after-free (static, intraprocedural) | | ✅ | ✅ | | | | | | | |
| CWE-415 | Double free (static, intraprocedural) | | ✅ | ✅ | | | | | | | |
| CWE-15 | External control of setting (env) | | ✅ | ✅ | | | | | | | |
| CWE-250/266/269/284/668 | Excess privilege / weak isolation | | | | | | | | | | ✅ |
| CWE-494/829 | Mutable or unverified build inputs | | | | | | | | | | ✅ |
| CWE-704 | Incorrect type conversion (Ada Unchecked_Conversion) | ✅ | | | | | | | | | |
| CWE-362 | Race condition (Ada tasking) | ✅ | | | | | | | | | |
| CWE-755 | Improper exception handling (broad Ada handler) | ✅ | | | | | | | | | |

¹ Python path traversal is covered by both the taint/oracle path (`open()` on a
non-literal path) and `GF-542`, which flags `tarfile.extract()`/`extractall()`
calls that omit a safe extraction filter.

² Hardcoded secrets have two layers: `GF-423` (a name heuristic — a
`password`/`token`/`api_key` lvalue assigned a literal, all languages) and
`GF-429` (**verified formats** — AWS `AKIA…`, GitHub `ghp_…`, GitLab, Google
`AIza…`, Stripe, npm, Slack, SendGrid tokens, and PEM `PRIVATE KEY` blocks that
carry actual key material). The format layer is near-zero false positive and
critical/high confidence — a match is almost certainly a live credential.

³ C++ transport coverage includes Qt WebEngine mixed-content settings that allow
active HTTP content inside HTTPS pages.

⁴ Python transport coverage includes Django deployment controls such as
`SECURE_SSL_REDIRECT` defaults and HSTS max-age settings.

⁵ Config/IaC SSRF coverage includes Kubernetes probe and lifecycle-hook `host`
fields that redirect kubelet-originated checks to explicit internal hosts.

⁶ JavaScript transport coverage includes Electron renderer mixed-content
settings.

⁷ JavaScript path traversal coverage includes server-side file responses, Node
filesystem reads, and archive-entry writes (`GF-510` and `GF-515`). Kubernetes
hostPath, hostPort, and volume exposure are tracked under the Config/IaC
isolation row because their catalog mappings are CWE-668.

⁸ Protection-mechanism coverage includes Qt WebEngine sandbox/plugin settings,
Electron renderer isolation, Docker Compose security profile disables, and
Django/Flask deployment controls.

## Framework and Embedded-Webview Rules

The release rule pack now includes focused configuration checks that commercial
SAST tools usually classify as framework or platform hardening:

- **Django**: proxy HTTPS state, `SECURE_CONTENT_TYPE_NOSNIFF`,
  `SECURE_SSL_REDIRECT`, referrer policy, HSTS, weak password hashers, frame
  options, CSRF/session-cookie security, host allowlists, request-size limits,
  and debug mode.
- **Python security APIs**: unsafe deserialization, weak cryptography, insecure
  randomness in secret-generation contexts, SSRF, disabled TLS verification,
  permissive CORS, JWT verification disables, server-side template injection,
  tarfile extraction without a safe filter, and request-data log forging.
- **Qt WebEngine and Qt desktop APIs**: mixed content, local-content remote URL access, sandbox
  disables, JavaScript clipboard access, insecure-origin geolocation, unknown
  URL scheme policy, DNS prefetch, WebRTC local IP exposure, screen capture,
  canvas readback, hyperlink auditing, local file URL access, and plugin
  support across C++/QML plus selected PyQt/PySide idioms; C++ `QProcess`
  single-string/native-argument launches and `QSqlQuery` concatenated SQL are
  covered as desktop Qt SAST sinks.
- **Electron and JavaScript web stacks**: renderer web-security toggles, context
  isolation, Node integration, insecure mixed content, session/JWT secrets,
  prototype pollution, NoSQL/SQL/LDAP/XPath/template injection, reflected XSS,
  path traversal, dynamic code execution, and unsafe deserialization.

**Inline suppression** is honored across every rule class: a `// govfuzz:ignore`,
`# nosec`, or `# nosemgrep` marker on a finding's line (or a standalone comment
directly above it) drops it; a scoped marker (`// govfuzz:ignore[GF-401,CWE-120]`)
drops only the listed rules/CWEs.

**Triage & remediation.** The report groups findings by **root cause** — a taint
flow keyed by (CWE, source, sink) collapses its N sink sites into one `issue`, so a
reviewer sees one row per defect. Each issue carries a composite **priority score**
(0–10 = exploitability × confidence × reachability; issues sort fix-first) and a
one-line **remediation** step. `--since <git-rev>` scans only files changed since a
revision — near-instant repeat-CI on a huge tree.

**Static reachability tier.** Every finding carries a `reachability` tier — the
honest, static analog of the "attacker-reachable" verdict the commercial tools
market. A taint flow is `source_reachable` by construction; a pattern finding is
`source_reachable` when its enclosing function is reached (over the call graph) from
an input source, `isolated` when the tree has input sources but none reach it, and
`unknown` otherwise. The tier feeds the priority score so a finding no attacker can
reach ranks below one on an input-influenced path — without over-claiming a dynamic
confirmation. When `auto --static` runs, fuzz-confirmation supersedes it.

**Durable finding identity.** Alongside the line-based `fingerprint`, every finding
carries a line-INDEPENDENT `identity` (rule + file + content key + a stable hash of
the normalized code). A finding that only *moves* — an unrelated edit shifts its
line — keeps the same identity, so a baseline still recognizes it instead of
resurfacing it as new. Fingerprint stays the primary baseline key for backward
compatibility; identity is the resilient fallback for cross-refactor issue tracking.

**Dependency (SCA) reachability.** For Go and Rust, a manifest dependency is promoted
on the SBOM **evidence ladder** to `source_observed` only when the source actually
imports it (a Go import path matching the module path; a Rust `use`/`extern crate`).
A dependency listed in `go.mod`/`Cargo.toml` but never imported stays merely
`resolved`, so the VEX ladder keeps its CVEs out of the execute path — the
govulncheck/Snyk "reachability" story at import granularity, offline.

**The interprocedural taint engine confirms multiple injection classes**, across
all eight languages, with sanitizer clearing, return-value summaries, branch-aware
guards, loop-carried closure, and field/container sensitivity — each superseding
the lower-confidence pattern heuristic at a confirmed site:

- **Command injection (CWE-78, `GF-304`)** — a source reaches `system` /
  `exec.Command` / `Runtime.exec` / `os.system` / backticks / …
- **Path traversal (CWE-22, `GF-405`)** — a source reaches a file-open (`fopen`,
  `os.Open`, `File::open`, `new File`, `open`, …). Naturally precise: it fires
  only when a *tainted* value is the path argument, so a literal-path open never
  trips. Python archive extraction adds `GF-542` for `tarfile.extract()` and
  `extractall()` calls that rely on no filter or the fully-trusted filter instead
  of `filter="data"`, `tarfile.data_filter`, or equivalent member validation.
- **SQL injection (CWE-89, `GF-419`)** — a source is *built into* a query
  (`db.Query`, `executeQuery`, `cursor.execute`, …). A parameterized query with a
  tainted **bound** argument is safe and does not fire (the sink requires
  concat/format evidence on the line).
- **GraphQL injection (CWE-943, `GF-545`)** — a GraphQL operation document is parsed
  via `gql()` from a dynamically-built string (concat / f-string / `.format(`) that
  carries GraphQL operation syntax (`query`/`mutation`/`subscription`). A literal
  document with request data bound through `variable_values` is safe and does not
  fire; the sink requires both the `gql()` parser call and dynamic-string evidence.
- **Log injection / log forging (CWE-117, `GF-544`)** — a source reaches a log
  message argument (`syslog`, `spdlog`, Go `log.Print*`, Rust `log::*!` /
  `tracing::*!`, Java logger APIs, Python `logging`/logger methods). Receiver-only
  taint and syslog/log-level arguments stay clean, so dependency-injected logger
  parameters and dynamic priorities do not create findings.
- **XXE (CWE-611, `GF-430`), LDAP injection (CWE-90, `GF-432`), unsafe reflection
  (CWE-470, `GF-434`)** — a tainted value reaches an XML parser, an LDAP filter, or
  a dynamic class/module load. Each fires only on a *tainted* argument (a literal
  parser input / filter / class name never trips), so precision matches the SQL
  model.
- **Uncontrolled allocation size (CWE-789, `GF-436`)** — a tainted value sizes a
  heap/stack allocation (`malloc`/`calloc`/`realloc`/`alloca`, `new T[]`, Go `make`,
  Rust `with_capacity`, Java `new byte[]`). This is the classic Coverity
  `TAINTED_SCALAR` → allocator finding; naturally precise, since a `sizeof`/constant
  allocation is never tainted.

Because these are taint flows — not line patterns — they cross function
boundaries, and `auto --static` can fuzz-confirm any of them. Each taint finding's
SARIF result carries the source→sink path as standard **`codeFlows`** (ordered
threadFlow steps with per-hop messages and code snippets), so GitHub code scanning
and IDEs render the dataflow visually — the answer to "why is this a vulnerability?"
without re-deriving the flow by hand.

**Taint sources are real input channels, not just parameter names.** A value read
from a recognized input-source API — `request.getParameter()` / `os.Getenv()` /
`input()` / `os.environ` / `std::env::var()` / `$ENV{…}` / `getenv()` — is
attacker-controlled and seeds taint even when no parameter name hints at it. That
is what finds bugs in real framework code (an HTTP handler, a CLI, an env-var
read), not just functions whose arguments happen to be named `userInput`.

The **CWE-338** row (insecure randomness) is deliberately *context-gated*: a weak
PRNG (`random.*`, `math/rand`, `java.util.Random`, C `rand`/`srand`, Perl `rand`)
is flagged only when the value it produces is a secret — the line names a
`token` / `key` / `nonce` / `salt` / `session` / `csrf` / `otp` / `credential`.
A blanket rule (bandit's `B311`, gosec's `G404`) flags *every* `random()`, most of
which are benign jitter, sampling, or test-data uses; govfuzz reports the
security-relevant subset and skips the crypto-secure sources (`secrets`,
`crypto/rand`, `SecureRandom`, `getrandom`, `urandom`) outright.

The **CWE-457 / CWE-197** rows for C/C++ come from an intraprocedural def-use
pass (uninitialized-variable read, narrowing numeric cast), not a line pattern —
it tracks a variable's declaration and definitions across a function body.

The **CWE-416 (use-after-free, `GF-437`) / CWE-415 (double-free, `GF-438`)** rows are
the *static, no-runtime* analogs of the AddressSanitizer-reported `GF-202`/`GF-204`
— because you cannot always fuzz. The same def-use machinery tracks a pointer that
is freed (`free`/`g_free`/`kfree`/`delete`) and then dereferenced (`*p`, `p->`,
`p[`) or freed again on the same straight-line path, with no reassignment or
NULL-out between. It is deliberately precision-first: the freed set is scoped by
brace depth (a guarded free never leaks past its `}`) and cleared at
switch-case / label / `goto` / `else` boundaries, and indexed frees (`free(a[i])`)
are not tracked — so freeing array elements and then the array is not a false
double-free. The cost is missing a cross-function or loop-carried use-after-free
(the safe direction); `auto` then fuzz-confirms what it can.

The Rust column is deliberately thin: clippy already covers most Rust lints well,
so govfuzz drives clippy (and gosec/Bandit/semgrep/GNATcheck) as a **subprocess
adapter** (`auto --external-tools`, license-gated) rather than reimplementing
their rule sets — their findings merge into the report and get fuzz-confirmed too.

## What govfuzz deliberately limits (and why)

An offline source scanner should not pretend to prove classes it cannot see
without a running web framework, a request lifecycle, or a rendered DOM. govfuzz
does implement focused, framework-specific checks where the source semantics are
clear, but it deliberately avoids generic claims that would inflate rule counts
with false positives:

- **Generic XSS beyond modeled sinks** — JavaScript/TypeScript raw HTML sinks
  (`GF-512`) are covered when request data reaches modeled Express/DOM/React/
  Vue/Svelte/Angular raw-HTML APIs without visible sanitization. govfuzz does not
  claim arbitrary rendered-DOM coverage for every framework/template engine
  because escaping semantics are framework- and context-specific.
- **Generic CSRF absence** — explicit CSRF disablement and unsafe framework
  configuration are covered for modeled stacks (`GF-446`). Proving that every
  state-changing route has a valid token/origin lifecycle still requires framework
  routing, middleware order, and often a live application.
- **CWE-613 (Insufficient session expiration)** — a runtime session-management
  property tied to a specific framework's session store and configuration; not a
  source pattern.

The broader forms are better served by a DAST tool with a live target. govfuzz's
remit is the offline source tree plus the fuzz-confirmation layer on top.

## Rule breadth without reimplementing it: external adapters

govfuzz's own rules are deliberately focused on the classes it can hold to a
precision number and fuzz-confirm. For the long tail — framework-specific XSS and
CSRF variants beyond the modeled stacks, plus the broader catalogs that
Fortify/Checkmarx/CodeQL ship — it *folds in* the tools that already have them
rather than reimplementing every framework rule. `static-scan
--external-tools` (and `auto --external-tools`) runs the operator's installed,
profile-allowed analyzers (**gosec / Bandit / semgrep / GNATcheck**) as
subprocesses — never linked — and normalizes their SARIF into
`<out>/external-findings.json`, carrying a CWE pulled from the result *or the rule
metadata* (where semgrep records it) or an adapter fallback (e.g. gosec `G203`,
Bandit `B701`/`B308` → CWE-79 XSS). This is breadth **without fuzzing**; under
`auto` these same findings additionally get fuzz-confirmed. The license profile
gates which tools run — `strict-permissive` runs none, so the default profile
never invokes a GPL tool.

## Extending coverage

The taint model (sinks, sources, sanitizers) is a declarative table in
`crates/static_analysis/src/taint_spec.rs` — adding a sink/source/sanitizer for a
language is a one-line edit. Pattern rules live in `scan_<lang>` in
`crates/static_analysis/src/lib.rs`, and every new rule must ship a labeled
`benchmarks/static/corpus/` case so it counts toward the published precision
number.
