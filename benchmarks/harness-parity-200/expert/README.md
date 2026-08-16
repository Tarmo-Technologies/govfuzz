# Independently designed expert harnesses

These drivers are deliberately project-level baselines, not edits of govfuzz's
generated output. Each targets the pinned revision in `expert-projects.tsv` and
uses the call shape an experienced fuzzing engineer would choose after reading
the code. They expose target-selection and protocol gaps that a same-function
comparison would hide: resource materialization, object construction, stateful
entrypoints, dependency setup, compiler descriptors, and expected rejection.

The files are meant to be copied into the named checkout and run with the normal
fuzzer for that ecosystem (libFuzzer, Jazzer, Go fuzzing, SharpFuzz, or a framed
stdin adapter). C and C++ additionally have the repository's 30-project blind
line-coverage comparison in `benchmarks/harness-parity-20`.
