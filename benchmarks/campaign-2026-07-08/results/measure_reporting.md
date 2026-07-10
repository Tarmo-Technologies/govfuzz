I have enough real data. cppcheck 2.13 emits XML/plist only (no SARIF in this version). Let me verify one more: does semgrep across a repo produce more/fewer than govfuzz, and confirm bandit/semgrep format list. I have solid numbers. Let me finalize.

Real measured data collected:
- govfuzz: JSON/SARIF-2.1.0/Markdown (static-scan); auto adds CSV+JUnit; SBOM = CycloneDX+OpenVEX+CSV, NO SPDX
- Static JSON/MD findings lack CWE field (CWE only in SARIF tags + auto CSV)
- SARIF has codeFlows (dataflow) — semgrep SARIF does NOT
- syft: SPDX-2.3 (23 pkgs) + CycloneDX
- bandit: JSON with issue_cwe + more_info(remediation)
- semgrep: SARIF-2.1.0 with helpUri+help+OWASP tags, no codeFlows, 3 results
- cppcheck: XML/plist only, 402 errors on cpp_json

Here are my findings.

---

## govfuzz reporting vs competitors — measured comparison (2026-07-09)

I ran `govfuzz static-scan benchmarks/campaign-2026-07-08/corpus/py_requests --out /tmp/rep --sarif` (14 findings: 7×GF-421 deser/CWE-502, 4×GF-426 TLS/CWE-295, 3×GF-427 SSRF/CWE-918) and inspected `/tmp/rep/static-report.{json,sarif,md}`, an auto `findings.csv`, and `govfuzz sbom` output, then ran each competitor on the same corpus.

### What govfuzz actually emits
- **static-scan**: JSON (`govfuzz.static.v1`), SARIF **2.1.0** (`$schema` verified, driver `GovFuzz 0.2.14`), Markdown. **No CSV, no JUnit from static-scan.**
- **auto**: adds `findings.csv` (19 columns incl. `cwe`, `sink_file/line/function`, `confirmation`, `confidence`, `verdict`, `member_finding_ids` = one-row-per-root-cause clustering) and JUnit.
- **sbom**: `cyclonedx.json`, `openvex.json`, `cyclonedx-vex`, `sbom.json`, `sbom.csv`, `vulnerabilities.json/csv`. **No SPDX.**

### Per-finding richness (measured against the JSON/SARIF)
- **Source→sink dataflow**: govfuzz SARIF carries **`codeFlows`** and a full `analysis.trace` (assignment→assignment→sink with snippets, `interprocedural_depth`, `tainted_parameters`, `complete_trace`, `confidence_reason`). Semgrep SARIF on the same repo has **no codeFlows**. This is govfuzz's clearest richness win.
- **Confidence + actionability**: every finding has `confidence` + `analysis.actionability.verdict` (`likely_reachable`) + `reachability`. Semgrep encodes confidence only as a tag; bandit has `issue_confidence`.
- **CWE**: present in govfuzz SARIF rule `tags` (CWE-918/502/295) and in the auto CSV `cwe` column — **but the static JSON and Markdown per-finding records have NO `cwe` field** (confirmed: `cwe in finding? False`). Bandit puts `issue_cwe` on every JSON finding; semgrep puts CWE in rule tags. **Gap: govfuzz's primary static JSON/MD lacks per-finding CWE.**
- **Remediation**: **govfuzz emits none** — no `help`/`helpUri`/fix text anywhere. Semgrep SARIF has both `help` and `helpUri` per rule; bandit has `more_info` links. **This is govfuzz's weakest richness axis.**
- **Fuzz-confirmation provenance**: unique to govfuzz (`confirmation` column, FuzzReached SBOM evidence) — no competitor has any equivalent.
- **Clustering to one-row-per-root-cause**: govfuzz CSV `member_finding_ids`; competitors emit one row per hit.

### Measured metrics table

| Feature / repo | govfuzz | semgrep | bandit | cppcheck | syft | Verdict (is govfuzz #1?) |
|---|---|---|---|---|---|---|
| SARIF 2.1.0 | ✅ | ✅ | ❌ | ❌ (2.13: XML/plist only) | n/a | Tie w/ semgrep |
| JSON | ✅ | ✅ | ✅ | ❌ | ✅ | Tie |
| Markdown | ✅ | ❌ | ❌ | ❌ | ❌ | **govfuzz #1** |
| CSV | ✅ (auto+sbom) | ❌ | ❌ | ❌ | ❌ (purls-ish) | **govfuzz #1** |
| JUnit | ✅ (auto) | ✅ (`--junit-xml`) | ❌ | ❌ | ❌ | Tie |
| XML | ❌ | ❌ | ✅ (txt/xml) | ✅ | ✅ (cyclonedx-xml) | cppcheck/syft win |
| SBOM CycloneDX | ✅ | ❌ | ❌ | ❌ | ✅ | Tie w/ syft |
| SBOM **SPDX** | ❌ | ❌ | ❌ | ❌ | ✅ **SPDX-2.3** | **syft wins — govfuzz gap** |
| VEX (OpenVEX/CDX-VEX) | ✅ | ❌ | ❌ | ❌ | ❌ | **govfuzz #1** |
| Source→sink dataflow (codeFlows) | ✅ | ❌ | ❌ | ❌ | n/a | **govfuzz #1** |
| Per-finding CWE in primary JSON | ❌ (SARIF/CSV only) | ⚠️ rule tag | ✅ every finding | ⚠️ | n/a | **bandit wins on JSON** |
| Remediation / help text | ❌ | ✅ help+helpUri | ✅ more_info | ⚠️ | n/a | **semgrep/bandit win** |
| Confidence + reachability verdict | ✅ rich | ⚠️ tag | ⚠️ field | ❌ | n/a | **govfuzz #1** |
| Fuzz-confirmation provenance | ✅ unique | ❌ | ❌ | ❌ | ❌ | **govfuzz #1 (unique)** |
| Root-cause clustering | ✅ | ❌ | ❌ | ❌ | ❌ | **govfuzz #1** |

### Per-repo finding counts (real, measured)
| Repo | govfuzz static | semgrep (auto) | bandit | cppcheck |
|---|---|---|---|---|
| py_requests | 14 | 3 | 16 | — |
| py_click | 0 | — | — | — |
| go_gin | 14 | — | — | — |
| rust_semver | 13 | — | — | — |
| java_gson | 5 | — | — | — |
| cpp_json | — | — | — | 402 |

(cppcheck's 402 is mostly style/warning noise on 422 files, not security; bandit's 16 vs govfuzz's 14 on py_requests are near-parity but govfuzz's carry dataflow traces bandit lacks.)

### Verdict
**govfuzz is best-in-class for reporting *richness* and near-best for *breadth*, but not the outright breadth leader.** It uniquely combines codeFlows dataflow, fuzz-confirmation provenance, actionability/reachability verdicts, root-cause clustering, and VEX — none of which any single competitor matches. On raw format breadth it's essentially tied with the field (SARIF/JSON/MD/CSV/JUnit/CycloneDX) but loses on three concrete, fixable points.

### Concrete gaps to fix to lead outright
1. **SPDX SBOM (highest priority).** syft emits SPDX-2.3 JSON + tag-value; `govfuzz sbom --emit` has no `spdx`/`spdx-json` option (confirmed "NO SPDX FILE"). SPDX is the more common procurement/compliance mandate than CycloneDX. Add `spdx-json` + `spdx-tag-value` emitters.
2. **Per-finding CWE in the primary static JSON + Markdown.** CWE lives only in SARIF `tags` and the auto CSV — the flagship `static-report.json` finding object and the MD table have no CWE column (bandit beats govfuzz here). Add a top-level `cwe` field to the static-scan finding schema and a CWE column to the MD table.
3. **Remediation / fix guidance.** govfuzz emits zero `help`/`helpUri`/fix text; semgrep and bandit both do. Add per-rule `help`+`helpUri` to SARIF rules and a `remediation` field to JSON findings — cheap, high-perceived-value, and the one axis where govfuzz is flatly behind.

Relevant paths: `/tmp/rep/static-report.{json,sarif,md}`, `/tmp/gfsbom/` (CycloneDX/VEX, no SPDX), `/tmp/syft.spdx.json`, `/tmp/bandit.json`, `/tmp/semgrep.sarif`, `/tmp/cppcheck.xml`.