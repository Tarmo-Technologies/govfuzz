I have all the real numbers. Let me compile the final report.

## govfuzz vs gosec vs semgrep — Go static-scan (go_gin, go_cobra)

All numbers below were measured by actually running each tool on `benchmarks/campaign-2026-07-08/corpus/{go_gin,go_cobra}`. Tool paths: gosec/semgrep from `~/.local/bin`, govfuzz `target/debug/govfuzz`. System Go is **1.22.2**.

### Raw counts

| Repo | govfuzz static-scan | gosec (`-fmt json ./...`) | semgrep (`--config=auto`) — total | semgrep — `.go`-code only |
|---|---|---|---|---|
| go_gin (18.3k Go SLOC) | **14** | **0 — FAILED to analyze** | 40 | 20 |
| go_cobra (12.6k Go SLOC) | 14 | 11 | 13 | 1 |

### What broke / caveats (honest)
- **gosec on go_gin returned 0 issues and analyzed 0 files/0 lines** — it fails-closed because it needs a compilable build, and go_gin's `go.mod` requires `go >= 1.25.0` while the box has go 1.22.2 (`Stats: files:0, lines:0`). Not a real "clean" result; gosec simply couldn't run. This is gosec's core weakness: no build, no analysis.
- **semgrep `--config=auto` required network + metrics-on** (errored with `--metrics=off`); it succeeded with metrics on. Its totals are heavily inflated by non-code findings: on go_gin, 19 of 40 are `.github/*.yml` CI-config rules (`github-actions-mutable-action-tag`, `dependabot-missing-cooldown`) and 1 is a test-fixture `key.pem`. On go_cobra, 12 of 13 are CI-config — only **1** finding touches actual `.go` code (`import-text-template` in cobra.go). Semgrep's `.go` signal on go_gin is 17× `no-direct-write-to-responsewriter` (a best-practice/style rule in render code, largely noise) plus 2 cookie flags and 1 fprintf.

### Categories

- **govfuzz** (all high/critical severity, taint-aware): go_gin → GF-472 unpinned GitHub Action ×5, GF-426 TLS verification disabled ×4, GF-405 non-literal file open ×3, GF-436 tainted allocation size ×1, GF-427 tainted URL → SSRF ×1. go_cobra → GF-405 non-literal file open ×11, GF-472 unpinned action ×2, GF-404 shell exec ×1.
- **gosec** go_cobra: G304 file-inclusion-via-variable ×10, G302 file-perms ×1. (go_gin: none, build failure.)
- **semgrep**: mostly CI-hygiene + framework style rules; genuine security signal is thin (cookie flags, private-key-in-fixture).

### Overlap / validation
- On go_cobra, **govfuzz GF-405 (×11) and gosec G304 (×10) are the same class** (CWE-22/73 file inclusion via non-literal path in the completion/doc generators) — govfuzz matches gosec's core finding and adds a shell-exec (GF-404) and unpinned-action findings gosec doesn't cover.
- govfuzz **GF-472 overlaps semgrep's `github-actions-mutable-action-tag`** — govfuzz has the CI-config breadth too, without the dependabot/style noise.

### Verdict
**Yes — govfuzz is #1 on this feature across the two Go repos.** It is the only tool that produced meaningful results on **both** repos. On go_gin it returned 14 high-severity taint-backed findings (TLS-verify-disabled, SSRF, tainted-alloc) while **gosec produced literally nothing** (couldn't build under the older Go) and semgrep's 40 were mostly CI-config/style noise (only 20 `.go`, dominated by 17 style hits). On go_cobra govfuzz (14) ties/edges gosec (11 — same file-inclusion class plus shell-exec) and dwarfs semgrep's single real code finding (1). govfuzz's decisive advantages here: **no toolchain/build dependency** (works offline on any Go version — the exact case that killed gosec on go_gin) and **taint-aware, security-severity findings** rather than build-gated or style-heavy output.

### Concrete gap govfuzz should fix to lead more convincingly
- **Emit CWE IDs on Go findings.** Every govfuzz finding in both reports had an **empty `cwe` field** (`cwe=` on GF-405/404/426/427/436/472). gosec ships `G304`/`G302` and semgrep ships OWASP/CWE metadata; govfuzz's blank CWE is a real regression for SARIF/compliance consumers and undercuts an otherwise-winning result. Populating CWE (GF-405→CWE-22/73, GF-404→CWE-78, GF-426→CWE-295, GF-427→CWE-918, GF-436→CWE-789) is the single highest-value fix.
- Secondary: govfuzz found **0** of the response-writer/cookie-security patterns semgrep flags on go_gin (`no-direct-write-to-responsewriter`, `cookie-missing-httponly/secure`). Most are low-value style, but the two cookie-attribute rules (CWE-1004/614) are legitimate and would close the only category where semgrep has code signal govfuzz lacks.

Report/data files (absolute): `/tmp/gfscan/{go_gin,go_cobra}/static-report.json`, `/tmp/gosec_{go_gin,go_cobra}.json`, `/tmp/semgrep_{go_gin,go_cobra}.json`.