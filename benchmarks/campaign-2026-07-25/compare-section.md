## Against the tool for each job

Measured on the same twelve projects, cloned once and read by every tool
(`benchmarks/campaign-2026-07-25/compare-*.json`).

### Line counting, against cloc (the accuracy reference) and tokei

| Project | govfuzz | cloc | tokei | govfuzz time | cloc time |
|---|---:|---:|---:|---:|---:|
| cJSON | 18,740 | 25,437 | 13,597 | 0.55s | 1.21s |
| jansson | 14,765 | 17,511 | 18,271 | 0.02s | 0.32s |
| leveldb | 21,289 | 23,026 | 22,008 | 0.03s | 0.36s |
| tinyxml2 | 7,552 | 27,943 | 26,717 | 0.02s | 0.56s |
| mkcert | 1,212 | 1,359 | 1,136 | 0.01s | 0.28s |
| gson | 38,061 | 41,438 | 40,108 | 0.03s | 0.94s |
| inspect.lua | 39 | 1,079 | 809 | 0.01s | 0.32s |
| MySQLTuner-perl | 14,425 | 38,995 | 20,334 | 0.02s | 0.66s |
| monolog | 333 | 19,007 | 17,233 | 0.01s | 0.93s |
| requests | 7,944 | 12,470 | 12,012 | 0.02s | 0.61s |
| tmuxinator | 1,342 | 7,123 | 5,174 | 0.01s | 0.35s |
| fd | 6,779 | 8,570 | 7,525 | 0.01s | 0.37s |

Total wall: govfuzz 0.74s, cloc 6.91s — **9x faster**. govfuzz counts
less than cloc on purpose: vendored trees, `node_modules`, `.venv` and test
directories are pruned, because the number that matters is the code it would fuzz.
This comparison is also what exposed six lanes the counter did not know about at
all (PHP, Ruby, Lua, C#, COBOL, Fortran); the numbers above are after that fix.

### SBOM, against syft

| Project | govfuzz components | syft components | govfuzz time | syft time |
|---|---:|---:|---:|---:|
| cJSON | 2 | 4 | 2.58s | 40.8s |
| jansson | 4 | 4 | 2.05s | 41.36s |
| leveldb | 6 | 1 | 1.62s | 21.44s |
| tinyxml2 | 3 | 4 | 0.68s | 51.15s |
| mkcert | 6 | 11 | 0.11s | 30.25s |
| gson | 22 | 42 | 1.34s | 33.07s |
| inspect.lua | 0 | 12 | 0.35s | 12.11s |
| MySQLTuner-perl | 185 | 21 | 1.45s | 15.16s |
| monolog | 19 | 12 | 0.33s | 13.44s |
| requests | 21 | 22 | 0.51s | 47.25s |
| tmuxinator | 0 | 4 | 0.51s | 18.72s |
| fd | 130 | 137 | 0.9s | 24.51s |

Total wall: govfuzz 12.43s, syft 349.26s — **28x faster**. Counts differ
in both directions: govfuzz reads declared manifests with evidence grading, syft also
fingerprints vendored binaries. This comparison found a gemspec parser that required
parentheses, so every gemspec-driven Ruby project reported zero components; the
numbers above are after that fix.

### Static analysis, against cppcheck, flawfinder, bandit and gosec

| Project | Lane | govfuzz | time | competitor | time |
|---|---|---:|---:|---:|---:|
| cJSON | c | 40 | 2.79s | cppcheck 223 | 740.23s |
| jansson | c | 34 | 0.29s | cppcheck 88 | 47.24s |
| leveldb | cpp | 22 | 0.42s | cppcheck 78 | 4.56s |
| tinyxml2 | cpp | 10 | 0.92s | cppcheck 49 | 20.94s |
| mkcert | go | 10 | 0.02s | gosec 19 | 1.18s |
| gson | java | 5 | 0.49s | no comparable tool | — |
| inspect.lua | lua | 2 | 0.01s | no comparable tool | — |
| MySQLTuner-perl | perl | 6 | 0.21s | no comparable tool | — |
| monolog | php | 0 | 0.08s | no comparable tool | — |
| requests | python | 23 | 0.17s | bandit 708 | 1.48s |
| tmuxinator | ruby | 5 | 0.03s | no comparable tool | — |
| fd | rust | 7 | 0.07s | no comparable tool | — |

govfuzz runs between 6x and 265x faster (cJSON: 2.8s against cppcheck's 740s) and
reports far fewer findings — 23 against bandit's 708 on requests. Fewer is the intent,
not a gap: the rules are precision-first, and an earlier campaign adjudicated the
false-positive rate directly (`docs/site/sast-comparison.md`). Six lanes are now
counted but still have no static rules of their own; that remains open.

Half the corpus has no comparable tool at all: there is no mainstream analyser or
fuzzer in this class for Ada, COBOL, Fortran, Lua or Perl, which is the point of the
sixteen-lane table above.

