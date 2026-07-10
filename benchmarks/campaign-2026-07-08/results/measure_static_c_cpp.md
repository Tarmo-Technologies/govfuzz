I have everything I need. Concrete gaps identified: govfuzz treats `scanf` as an unresolved-call analysis_gap rather than flagging it as a finding (semgrep + cppcheck both flag scanf/printf-format), and cppcheck's flow-sensitive engine finds classes govfuzz's heuristic lane doesn't (dangling-lifetime returns, printf arg-type mismatch, resource leaks). Final report below.

---

# govfuzz vs cppcheck / flawfinder / semgrep — C/C++ static scan (2026-07-09)

All numbers are real, measured on this box. Tools: cppcheck 2.13.0, flawfinder 2.0.20, semgrep 1.168.0, govfuzz `target/debug/govfuzz`. Corpus: `benchmarks/campaign-2026-07-08/corpus/{c_zlib,c_jansson,cpp_json,cpp_fmt}`.

## Metrics table (finding counts)

| Repo | govfuzz | cppcheck (raw `wc -l`) | cppcheck (real `<error>`) | flawfinder (task cmd `grep -c ':'`) | flawfinder (real hits) | semgrep (`results`) |
|---|---|---|---|---|---|---|
| c_zlib | 141 | 477 | 465 | 342 | 296 | 28 |
| c_jansson | 34 | 878 | 270 | 129 | 123 | 9 |
| cpp_json | 37 | 5360 | 1711 | 166 | 161 | 4 |
| cpp_fmt | 42 | 2834 | 859 | 232 | 227 | 7 |

Caveats on the raw counts (measured, not assumed):
- **cppcheck raw `wc -l` is badly inflated** by `information`/`checkers-report` lines. Real distinct `<error>` elements are far fewer, and of those most are non-security: e.g. cpp_json 1711 errors = only **35** `error`+`warning` (security-ish), 272 style, 103 performance, 1298 informational. c_zlib 465 = 25 security, 204 style, 234 info. cppcheck's actual memory-safety yield is a small fraction of the headline number.
- **flawfinder's `grep -c ':'` counts header/footer lines too**; real `[level]` hit lines are ~296/123/161/227. flawfinder is a pure lexical grep (every `strcpy`/`memcpy`/`sprintf` token) with no flow analysis, so its high counts are almost entirely unranked, unconfirmed noise.
- The earlier concurrent cppcheck run reported c_zlib=130 errors; that run was CPU-contended and timed out mid-scan. The clean 300s re-run gives **465** — the number in the table.

## What each tool actually finds (classes)

- **govfuzz**: security-typed findings with CWE + severity + confidence + remediation + dataflow. Clustered CWE distribution (issues view): CWE-120 unbounded-copy, CWE-22 path traversal (GF-405 path-controlled-open, its taint differentiator, 39 in zlib), CWE-134 format-string, CWE-190 int-overflow, CWE-457 uninit-use, CWE-787 OOB-write, CWE-494 unpinned CI action, CWE-829/415/362. Every finding carries `analysis.path.predicates` (guard conditions), `evidence` snippet, `actionability.verdict`, and `analysis_gaps` records unresolved interprocedural calls honestly. This is the differentiator: **taint/behavioral findings (GF-405 path-control, GF-401 unsafe-copy) that are fuzz-confirmable and CWE-tagged** — cppcheck/flawfinder/semgrep have no taint-to-sink path story here.
- **cppcheck**: flow-sensitive C/C++ engine. Its real security value (err/warn) in zlib: `uninitvar`, `returnDanglingLifetime`, `returnTempReference`, `autoVariables` (return address of local), `resourceLeak`, `invalidPrintfArgType`, `nullPointer`, `ctuOneDefinitionRuleViolation`. Low count but **genuine memory-safety classes govfuzz's heuristic lane does not emit** (dangling-lifetime, printf arg-type mismatch, resource leak).
- **flawfinder**: lexical only. High volume, zero flow, no confirmation. Not competitive on precision.
- **semgrep `--config=auto`**: on C/C++ it is almost entirely **non-code YAML/CI noise** — `github-actions-mutable-action-tag` (26/7/2/0), `dependabot-missing-cooldown`. Its only real C-code rules that fired: `insecure-use-scanf-fn` (2, c_zlib) and misfired Python rules on cpp_json (`direct-use-of-jinja2`). semgrep's registry has essentially no C/C++ memory-safety depth; it is not a serious C/C++ static competitor out of the box.

## Verdict

**Is govfuzz #1 on C/C++ static?** Not by raw count, and count is the wrong axis. By raw findings cppcheck "wins" (465–1711 vs govfuzz 37–141) and flawfinder is second — but those counts are dominated by style/informational/lexical noise (cppcheck: ~5–8% security; flawfinder: 100% unconfirmed). **On usable, CWE-tagged, taint-confirmable security findings govfuzz leads the field**: semgrep is effectively absent on C/C++ code (its top hits are CI-YAML), flawfinder has no flow, and cppcheck's security yield is a small, unranked slice with no CWE mapping or remediation. govfuzz is the only tool here that emits path-traversal/command-taint findings with dataflow predicates and fuzz-confirmability. **govfuzz is competitive and arguably #1 on precision/actionability; it is NOT #1 on raw volume (cppcheck wins volume ~3–45x, but ~90%+ of that volume is non-security).**

## Concrete gaps govfuzz should fix to lead outright

1. **`scanf`/`gets`-family unbounded-read is dropped to an analysis_gap, not a finding.** In c_zlib both semgrep (`insecure-use-scanf-fn`) and cppcheck flag `scanf("%1s",answer)` at `contrib/minizip/miniunz.c:392` and `minizip.c:343`; govfuzz records these two as `unresolved_project_local_call` gaps (`scanf` callee) and emits **0** scanf findings. Fix: add a lexical/AST rule (CWE-120/CWE-676) for unbounded `scanf`/`gets` reads so the gap becomes a finding — this is a class both competitors catch and govfuzz currently misses.
2. **printf/format arg-type mismatch (`invalidPrintfArgType`, 8 in zlib) and dangling-lifetime returns (`returnDanglingLifetime`/`returnTempReference`/`autoVariables`) are cppcheck-only classes.** govfuzz has format-string (CWE-134) for *untrusted* format arg but no printf **argument-type** checker and no return-of-local/temp-reference (CWE-562) rule. Adding these would close cppcheck's real-bug lead in one shot.
3. **Resource-leak (CWE-772) on `fopen`/`malloc` without matching close/free** — cppcheck's `resourceLeak` fires in zlib; govfuzz has no leak rule in the C lane. Worth a heuristic pass on the file-open sink it already tracks for GF-405.

Artifacts: govfuzz reports at `/tmp/gf_{repo}/static-report.json`; cppcheck XML at `/tmp/ccz.xml` (zlib) and `/tmp/cc_{jansson,cpp_json,cpp_fmt}.xml`; semgrep JSON at `/tmp/sg_{repo}.json`.