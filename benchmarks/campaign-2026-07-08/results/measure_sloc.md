All measurements are real and complete. Here are my findings.

---

## SLOC Counting: govfuzz vs cloc / scc / tokei — Real Measured Results

I ran all four tools over the 14-repo corpus. Numbers below are **primary-language code lines**. For the four C/C++ repos I summed `C + C++ + C/C++ Header` for cloc/scc/tokei (govfuzz folds headers into `c`/`cpp`, so I summed govfuzz `c+cpp` to compare fairly). `gf Δ%` is govfuzz vs cloc (cloc is the accuracy anchor since it's the most conservative, comment-aware counter).

| repo | primary | cloc | scc | tokei | **govfuzz** | gf Δ vs cloc |
|---|---|---:|---:|---:|---:|---:|
| c_zlib | C | 30357 | 29923 | 29917 | **30368** | +0.0% |
| c_jansson | C | 14581 | 14720 | 14719 | **14581** | +0.0% |
| cpp_json | C++ | 109744 | 110974 | 110574 | **110071** | +0.3% |
| cpp_fmt | C++ | 45684 | 47413 | 47411 | **46173** | +1.1% |
| rust_ripgrep | Rust | 35402 | 37798 | 37935 | **36784** | +3.9% |
| rust_semver | Rust | 2160 | 2160 | 2160 | **2160** | +0.0% |
| go_gin | Go | 17317 | 18475 | 17868 | **18264** | +5.5% |
| go_cobra | Go | 12624 | 12897 | 12624 | **12624** | +0.0% |
| py_click | Python | 17506 | 20793 | 21399 | **17818** | +1.8% |
| py_requests | Python | 7729 | 9708 | 9256 | **7575** | −2.0% |
| java_commonslang | Java | 106409 | 106614 | 106614 | **106409** | +0.0% |
| java_gson | Java | 37430 | 37636 | 37731 | **37430** | +0.0% |
| perl_mojo | Perl | 10608 | 25647* | 25665* | **10446** | −1.5% |
| js_express | JavaScript | 15687 | 15878 | 15878 | **15756** | +0.4% |

\* scc and tokei **misclassify** Mojolicious `.pod`/`.t`/embedded template files as "Raku," ballooning the Perl count to ~25.6k (plus a separate 31.9k "Raku" row in scc). cloc and govfuzz both report ~10.5k honest Perl. This is a real correctness win for govfuzz on Perl.

### Speed (total wall over the whole corpus)

| tool | wall time | max RSS | invocation model |
|---|---:|---:|---|
| **tokei** | **0.09 s** | 15 MB | single whole-corpus run |
| **scc** | **0.11 s** | 63 MB | single whole-corpus run |
| cloc | 4.43 s | 118 MB | single whole-corpus run |
| **govfuzz** | **16.5 s** | — | 14 separate `static-scan` invocations |

Speed ranking: **tokei ≈ scc (both ~0.1 s) ≫ cloc (4.4 s) ≫ govfuzz (16.5 s)**. Caveat that keeps this honest: tokei/scc/cloc each ran once over the whole tree, while govfuzz ran 14 times (once per repo) because `--sloc` is a per-scan side output — and each govfuzz run is a full SAST parse+scan, not a dedicated line counter. Even normalized, govfuzz's per-repo counting is bundled inside heavier tree-sitter parsing, so it is **not** competitive on raw counting speed and never will be against purpose-built counters.

### Accuracy verdict

govfuzz is **highly accurate**: it agrees with cloc within ~5% on **all 14 repos** (worst case go_gin +5.5%, and there govfuzz sits *between* scc 18475 and tokei 17868 — cloc's 17317 is the low outlier, so govfuzz is arguably more correct than cloc there). On 8 of 14 repos govfuzz matches cloc within 0.0–0.5%. Where scc/tokei diverge upward (py_click +19%, py_requests +26%, ripgrep +7%), it's because they count Python docstrings and Rust `//!` doc comments as code; govfuzz's language-aware comment stripping tracks cloc's conservative counts. So on **fidelity to true code lines, govfuzz is essentially tied with cloc and cleaner than scc/tokei** (which over-count comments and misclassify Perl).

### Overall verdict: is govfuzz #1 on this feature?

**No — not on the headline "SLOC counter" metric.** For pure speed, **tokei and scc win decisively (~150× faster)**. govfuzz is #1 only on two narrow accuracy sub-points: (1) Perl classification correctness (scc/tokei are flat wrong, ~2.5× over-count), and (2) not counting docstrings/doc-comments as code (matches cloc, beats scc/tokei on Python/Rust fidelity).

govfuzz's **real differentiators** are contextual, not competitive-on-speed:
- **Language-aware comment counting** matching cloc-grade accuracy across 8 languages.
- **Dependency/build-tree pruning** — the same pruning as the security scan excludes `.venv`/`node_modules`/vendored code, which the others don't do by default.
- **Integrated in the security tool** — you get the SLOC breakdown "for free" as a side-effect of the SAST scan you were already running (findings-per-KLOC density, etc.), no second tool.

### Concrete gaps govfuzz should fix to lead

1. **Speed / invocation model.** Offer a standalone `govfuzz sloc <path>` (or `--sloc-only`) that skips the SAST parse and does a fast line-count pass, and support multi-root/whole-corpus counting in one invocation. Today you pay full scan cost (16.5 s) for numbers tokei produces in 0.09 s. This is the single biggest gap.
2. **Header attribution transparency.** govfuzz folds all `.h` into `c` even in a C++ repo (cpp_json shows `c: 44`, everything else `cpp`), which is defensible but makes apples-to-apples comparison require manual summing. Emitting an optional cloc-style `c_header`/`cpp_header` split (or documenting the fold) would remove the footgun.

If govfuzz shipped a dedicated fast SLOC path, its accuracy (already cloc-grade, and *better* than scc/tokei on Perl and comment handling) would make it a legitimate best-in-class counter. Today it's accurate-but-slow, so **tokei wins the feature outright on speed by ~150×**, with govfuzz winning only the correctness sub-battle.

Relevant files: `/tmp/gf/*_sloc.json` (govfuzz outputs), `/tmp/{cloc,scc,tokei}_time.txt` (timing captures).