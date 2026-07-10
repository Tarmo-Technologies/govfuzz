All numbers measured. Here are the findings.

## Python SAST comparison: govfuzz vs bandit vs semgrep

All three tools ran cleanly on both repos (no errors, no timeouts). Numbers are real, measured 2026-07-09.

### Raw finding counts

| Repo (SLOC) | Tool | Total | Severity mix | Categories (rule → count) |
|---|---|---|---|---|
| **py_click** (17,818) | bandit | **1325** | 1322 LOW / 3 MED | B101 assert 1292, B603 subprocess 10, B404 8, B110 try-except-pass 7, B311 rand 3, B108 tmp 3, B606/B607 1 |
| | semgrep (--config=auto) | **3** | 1 MED/1 ERR/1 WARN | uv-missing-dependency-cooldown 1, python36-Popen1 1, dangerous-globals-use 1 |
| | **govfuzz** | **0** | — | (24 analysis gaps: `unresolved_project_local_call`) |
| **py_requests** (7,575) | bandit | **708** | 581 LOW / 127 MED | B101 assert 579, B113 request-without-timeout 120, B301 pickle 7, B403 1, B105 hardcoded-pw 1 |
| | semgrep (--config=auto) | **3** | 3 WARN | insecure-hash-sha1 2, non-literal-import 1 |
| | **govfuzz** | **14** | 14 HIGH | GF-421 unsafe-deserialization 7, GF-426 TLS-verify-disabled 4, GF-427 SSRF (taint) 3 |

### Signal quality (the raw counts are misleading)

Bandit's totals are dominated by test-file noise. After excluding test files and `assert_used` (B101), the substantive bandit signal is **23 findings in py_click, 0 in py_requests**:
- **py_click**: 1290 of 1325 findings (97%) are in test files; 1292 are bare `assert`.
- **py_requests**: 692 of 708 (98%) are in test files; **every non-test finding is an assert or timeout** — 0 substantive non-test findings after filtering.

So bandit "wins by 700x" on raw count but that is almost entirely `assert` in tests plus `requests(...)` without a `timeout=` (a code-smell, not a vuln). Semgrep's auto ruleset is very quiet here (3/repo).

### govfuzz differentiators

- **Taint-traced, HIGH-severity vuln classes** none of the others surfaced on py_requests: GF-421 unsafe deserialization (pickle/marshal/yaml, CWE-502), GF-426 TLS cert/hostname verification disabled (CWE-295), GF-427 SSRF via tainted URL reaching an outbound HTTP request (CWE-918) — with a full `taint_trace` (assignment → project-local calls → sink), engine `govfuzz.static.taint.v1`. Bandit reports B301 (pickle *import/usage*, no dataflow) but never reaches SSRF or TLS-verify-disabled as taint findings. Semgrep's auto config missed all three classes on py_requests.
- **Deduped, non-noisy output**: 14 findings all HIGH, no test-assert flood — vs bandit's 708/1325 that a human must triage down to ~0–23.
- Emits SARIF/JSON/Markdown with baseline-diff (`new`/`unchanged`/`resolved`) and honest `analysis_gaps` (govfuzz *tells you* it couldn't resolve 24/36 project-local calls rather than silently dropping them).

### Verdict

**Mixed — govfuzz is NOT the raw-count leader, but it wins on substantive high-severity taint findings.**

- **py_requests: govfuzz wins** — 14 real HIGH taint findings (SSRF/deser/TLS) vs bandit's **0 substantive non-test findings** and semgrep's 3 (sha1/import). On the vuln that matters, govfuzz leads clearly.
- **py_click: govfuzz LOSES** — it reports **0** findings; semgrep gets 3, bandit gets 23 substantive (subprocess, try-except-pass, weak `random`). This is a real gap: govfuzz emitted 24 `unresolved_project_local_call` gaps and produced nothing. It has no rule for the `subprocess`/`try-except-pass`/`random.*`-for-security classes that bandit's B603/B110/B311 caught, so on a repo with no taint-reachable sink it goes silent.

### Concrete gap govfuzz should fix to lead

1. **py_click zero-finding miss** is the priority: add non-taint syntactic rules for the classes bandit caught and govfuzz has no equivalent for — `subprocess` without `shell=` review / partial-path exec (B603/B607, CWE-78/426), `try/except/pass` swallowing (B110, CWE-703), and non-crypto `random.*` used in a security context (B311, CWE-330). govfuzz already ships a weak-PRNG rule (GF-428) per memory — verify why it didn't fire on py_click's 3 `random` sites (likely context-gate too strict, or Python lane not wired to GF-428).
2. **Resolve `unresolved_project_local_call` gaps** (24 in click, 36 in requests): govfuzz's taint engine is dropping intra-project call edges it can't resolve, which both suppresses findings and inflates the gap count. Improving the Python decl-index / call resolution would let the taint lane reach sinks it currently can't, directly converting gaps into findings.

Net: keep the taint-finding lead (py_requests), but govfuzz cannot claim #1 on Python SAST until it stops returning 0 on a real 17k-SLOC repo where two competitors find issues.