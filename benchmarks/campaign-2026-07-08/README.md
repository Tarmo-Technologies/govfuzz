<!-- SPDX-License-Identifier: Apache-2.0 -->
# govfuzz best-in-class comparison campaign (2026-07)

Real measurements of govfuzz vs the leading tool(s) for each feature, across a
14-repo multi-language corpus (C, C++, Rust, Go, Python, Java, Perl, JS). The
corpus is cloned locally and git-ignored; `results/` holds the measured numbers
and `charts/` the figures. Competitor tools: cloc/scc/tokei (SLOC),
cppcheck/flawfinder/semgrep/bandit/gosec/clippy/perlcritic (static),
syft/grype (SBOM), AFL++/libFuzzer/cargo-fuzz (fuzzing).

## SLOC accuracy (vs cloc reference)
Mean |deviation from cloc|: **govfuzz 1.3%**, scc 19.7%, tokei 23.6%.
govfuzz matches cloc (the accuracy gold standard) and beats scc/tokei, which
over-count Perl POD and Python docstrings. See `charts/sloc_accuracy.png`.
