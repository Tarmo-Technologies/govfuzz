<!-- SPDX-License-Identifier: Apache-2.0 -->

# Expanded Legacy Breakage Matrix - 2026-07-19

This campaign exercises GovFuzz discovery, build repair, and fuzz execution
against 53 pinned legacy C, C++, Ada, and mixed repositories. It is a hard
compatibility gate: unmodified controls and damaged copies must both reach the
selected real target with positive coverage. A clean failure is excluded from
the in-scope denominator only when pinned repository evidence and an exact
runtime failure signature both prove an unavailable external source,
generator, runtime, or cross-toolchain requirement.

## Scope and Reproduction

The catalog contains 57 exact Git revisions. The audited manifest selects 53
distinct repositories with a non-test, input-driven target and a
machine-checkable mutation. Four repositories (`cmdline`, `loki-lib`,
`luabind`, and `Signals`) have no suitable target/dependency pair and are not
part of the 53-case gate.

```sh
cargo build --release -p govfuzz
python3 scripts/validation/legacy-breakage-matrix.py \
  --manifest tests/fixtures/legacy_breakage_validation/expanded-manifest.toml \
  --materialized-root /tmp/govfuzz-legacy-campaign-2026-07-19/repos \
  --offline \
  --workspace /tmp/govfuzz-expanded-full-v49 \
  --jobs 3 \
  --json-out /tmp/govfuzz-expanded-full-v49-result.json \
  --markdown-out /tmp/govfuzz-expanded-full-v49-result.md
```

The matrix contains 12 Ada, 29 C, and 12 C++ scenarios:

| Mutation | Scenarios |
|---|---:|
| Missing dependency implementation | 19 |
| Missing direct header | 22 |
| Missing Ada spec | 6 |
| Missing Ada body | 6 |

Every scenario runs an unmodified control first, then makes a local shared Git
clone, deletes the proved artifact, verifies its absence, and runs GovFuzz
offline. A pass requires all of:

- the exact selected target and line report `built_and_fuzzed`;
- at least one execution and at least one coverage edge;
- at least one damaged-tree repair;
- no `fuzzed_stub_only` downgrade and no stub of the selected target.

The local Git clone matters: it lets GovFuzz restore exact deleted content from
the pinned object database without network access. A source archive without
that history can still use safe declaration/stub synthesis, but cannot in
general reconstruct arbitrary deleted implementation semantics.

## Results

The fresh run passed the 90% gate:

| Population | Clean controls | Damaged recovery |
|---|---:|---:|
| Raw 53 repositories | 47/53 (88.7%) | 48/53 (90.6%) |
| Verified external constraints | 6 | 6 |
| In-scope repositories | **47/47 (100%)** | **47/47 (100%)** |

The raw damaged numerator is 48 because the mutated TAMP case can substitute a
host `Interfaces` unit, while its unmodified embedded runtime still fails with
the verified cross-toolchain signature. This does not count as proof that the
original TAMP runtime is host-fuzzable.

All 47 in-scope controls and all 47 corresponding damaged copies executed the
selected target with nonzero coverage. Damaged copies performed 192 fuzz
executions and recorded 5,771 aggregate edges; controls performed 47 executions
and recorded 4,113 aggregate edges. The in-scope population is:

| Language | In scope | Clean pass | Damaged pass |
|---|---:|---:|---:|
| Ada | 7 | 7 | 7 |
| C | 29 | 29 | 29 |
| C++ | 11 | 11 | 11 |

| Mutation | In scope | Damaged pass |
|---|---:|---:|
| Missing Ada body | 6 | 6 |
| Missing Ada spec | 1 | 1 |
| Missing direct header | 22 | 22 |
| Missing dependency implementation | 18 | 18 |

## In-Scope Audit

The compact audit below records clean edges, damaged edges, damaged repair
rounds, and exact VCS-recovery actions for every in-scope repository.

| Scenario | Clean edges | Damaged edges | Rounds | VCS |
|---|---:|---:|---:|---:|
| `ada_crypto_missing_ada_spec` | 76 | 350 | 1 | 1 |
| `agpl_missing_ada_spec` | 62 | 113 | 1 | 1 |
| `beanstalkd_missing_direct_header` | 3 | 8 | 3 | 1 |
| `brotli_missing_dependency_impl` | 32 | 114 | 3 | 1 |
| `bzip2_missing_direct_header` | 24 | 40 | 4 | 1 |
| `c_ares_missing_direct_header` | 48 | 67 | 14 | 3 |
| `chocolate_doom_missing_dependency_impl` | 5 | 11 | 5 | 1 |
| `cjson_missing_direct_header` | 9 | 47 | 1 | 2 |
| `cparser_missing_dependency_impl` | 17 | 31 | 8 | 0 |
| `expat_missing_dependency_impl` | 94 | 139 | 3 | 0 |
| `fmt_missing_direct_header` | 20 | 41 | 2 | 2 |
| `gnatcoll_core_missing_ada_body` | 80 | 286 | 1 | 1 |
| `http_parser_missing_dependency_impl` | 3 | 9 | 1 | 1 |
| `jansson_missing_dependency_impl` | 26 | 44 | 5 | 1 |
| `jsoncpp_missing_direct_header` | 10 | 15 | 4 | 0 |
| `lacc_missing_dependency_impl` | 6 | 21 | 5 | 1 |
| `leveldb_missing_direct_header` | 10 | 34 | 1 | 1 |
| `libarchive_missing_dependency_impl` | 101 | 118 | 5 | 1 |
| `libevent_missing_dependency_impl` | 28 | 22 | 5 | 0 |
| `libffi_missing_dependency_implementation` | 30 | 59 | 3 | 1 |
| `libpng_missing_direct_header` | 15 | 79 | 3 | 1 |
| `libuv_missing_dependency_impl` | 9 | 26 | 1 | 1 |
| `libyaml_missing_direct_header` | 8 | 13 | 2 | 1 |
| `libzmq_missing_direct_header` | 7 | 19 | 2 | 1 |
| `lz4_missing_dependency_impl` | 28 | 36 | 2 | 1 |
| `memcached_missing_dependency_impl` | 6 | 19 | 1 | 1 |
| `mimalloc_missing_dependency_impl` | 717 | 427 | 2 | 1 |
| `minisat_missing_dependency_impl` | 3 | 9 | 1 | 1 |
| `mpc_missing_direct_header` | 198 | 247 | 1 | 2 |
| `ocarina_missing_ada_body` | 62 | 107 | 1 | 1 |
| `parse_args_missing_ada_spec` | 180 | 244 | 1 | 1 |
| `polyorb_hi_ada_missing_ada_spec` | 74 | 284 | 2 | 1 |
| `pugixml_missing_direct_header` | 17 | 39 | 1 | 1 |
| `rapidjson_missing_direct_header` | 3 | 8 | 2 | 2 |
| `redis_missing_dependency_impl` | 5 | 13 | 3 | 1 |
| `smhasher_missing_dependency_impl` | 8 | 24 | 1 | 1 |
| `thrift_missing_dependency_impl` | 5 | 11 | 1 | 1 |
| `tinyxml2_missing_direct_header` | 31 | 109 | 1 | 1 |
| `uncrustify_missing_dependency_impl` | 11 | 28 | 2 | 1 |
| `utf8proc_missing_direct_header` | 17 | 41 | 1 | 3 |
| `xmlada_missing_ada_body` | 1,933 | 1,981 | 6 | 1 |
| `xxhash_missing_direct_header` | 7 | 16 | 1 | 1 |
| `xz_missing_dependency_impl` | 10 | 29 | 4 | 1 |
| `yajl_missing_dependency_impl` | 5 | 9 | 2 | 1 |
| `yaml_cpp_missing_dependency_impl` | 59 | 217 | 2 | 1 |
| `zlib_missing_dependency_impl` | 5 | 10 | 1 | 1 |
| `zstd_missing_direct_header` | 6 | 13 | 1 | 1 |

## Verified External Constraints

An exclusion requires the manifest's exact file probes/absent paths and every
declared clean failure substring to match at runtime.

| Scenario | Constraint | Pinned evidence | Matched clean signature |
|---|---|---|---|
| Ada Drivers Library | ARM cross-toolchain | board GPR uses `arm-eabi` | `needs a matching GNAT cross toolchain` |
| Drake | version-matched GNAT runtime | master targets GCC 7 and asserts its integer model | `Long_Long_Integer is not largest type.` |
| GNATCOLL Bindings | external source dependency | zlib child requires absent `GNATCOLL.Coders` parent | `missing Ada symbol '.Coder_Interface'` |
| RE2 | external source dependency | CMake requires Abseil; `abseil-cpp` is absent | `undefined build-config macro 'ABSL_DCHECK'` |
| TAMP | ARM cross-toolchain/runtime | README pins GCC 4.6.1; GPR uses `arm-none-eabi-gnatmake` | `s-trasym.adb" must be compiled` |
| YAML-Ada | generated binding | source imports absent `C.yaml`; README requires `headmaster` | `missing Ada symbol 'yaml.yaml_mark_t'` |

Ocarina is not excluded: its generator is present in the pinned tree. The
low-closure `Charset.To_Lower(String)` control records 62 edges, and deleting
`charset.adb` is recovered from local Git in one round and records 107 edges.

## Repair-Round Default

The successful population is 95 samples: 47 controls plus 48 damaged runs.

| Cap | Successful samples covered |
|---:|---:|
| 6 | 91/95 (95.8%) |
| 8 | 93/95 (97.9%) |
| 12 | 94/95 (98.9%) |
| 16 | 95/95 (100%) |

Repair rounds have p50 1, p90 5, p95 6, p99 14, and maximum 14. The c-ares
control requires 12 rounds and its damaged copy requires 14, so the old
eight-round claim would lose valid targets. The default remains 16, providing
two rounds of measured headroom. No failed build exhausted the 16-round cap;
failed external cases stopped earlier when no new repair was available.

## Systemic Fixes

The campaign added or verified:

- exact, path-confined recovery of deleted tracked files and Ada bodies from a
  local Git object database, with repair provenance in `run.json`;
- C/C++ header, source-closure, type, callback, visibility-macro, static-member,
  stream, and legacy-language repairs;
- Ada package/spec/body indexing and preference for a recovered real body over
  an invented stub;
- isolation of generated runtimes from target-header libc macro redirects
  (c-ares redirected `getenv`, which previously disabled coverage);
- a control-first matrix gate with positive-coverage acceptance, raw and
  in-scope denominators, verified external constraints, and process-group
  timeout cleanup.

## Confidence Boundary

This result supports offline projects that contain their required source,
generated dependencies, compiler/runtime, and local Git history: every such
project in the pinned 53-repository population reached the selected real target
before and after destructive mutation. It does not claim that missing source
semantics, generated bindings, or a version/cross-matched compiler can be
recreated from no information. Those cases remain explicit, evidence-backed
failures rather than fabricated fuzz success.
