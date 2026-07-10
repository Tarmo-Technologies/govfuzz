<!-- SPDX-License-Identifier: Apache-2.0 -->
# GF-544 Log-Injection Sweep - 2026-07-07

This memo records the validation for `GF-544` (CWE-117 log injection / log
forging), added to the static taint engine.

## Scope

- Worktree: `sast-loop-log-injection-2026-07-07`
- Sweep root: `/tmp/govfuzz-sast-gf544-sweep-2026-07-07`
- Scanner: `target/debug/govfuzz static-scan <repo> --debug`
- Corpus: 50 shallow-cloned GitHub projects across Ada, C, C++, Rust, Go, Java,
  and Python source trees.

## Results

- Successful scans: 50 / 50
- Clone or scan failures: 0
- Total findings after FP fixes: 2869
- `GF-544` findings after FP fixes: 9
- Precision benchmark: 97 TP, 0 FP, 0 FN

The first sweep produced 20 `GF-544` findings. Manual triage identified and fixed
four noisy shapes:

- Plain string literals containing source words such as "Request" were parsed as
  tainted log message arguments.
- C++ benchmark logs of numeric CLI values such as `queue_size` and `iters` were
  treated as forgeable strings.
- Usage logs of `argv[0]` were reported.
- Log calls that pass a returned error object, and logs of parsed client/socket
  address scalars, were over-reported.

The final rescan removed those FPs. The remaining `GF-544` reports were in Log4j
examples/core text rendering, pip CacheControl URL logging, and a mitmproxy XSS
scanner example that logs reflected URL data; those are defensible source-to-log
flows for the current static rule.

## Commands

```sh
cargo fmt --check
cargo test -p finding_rules -p static_analysis --quiet
cargo test -p static_analysis --test precision_benchmark -- --nocapture
cargo build -p govfuzz --quiet
cargo run -p spdx_check -- check
```

The final 50-repo scan summary was written during validation at:

```text
/tmp/govfuzz-sast-gf544-sweep-2026-07-07/summary-final.json
```
