<!-- SPDX-License-Identifier: Apache-2.0 -->

# Legacy C, C++, and Ada Offline Validation - 2026-07-19

Campaign workspace: `/tmp/govfuzz-legacy-campaign-2026-07-19`

This campaign tested GovFuzz against 37 real GitHub repositories. Repositories
were cloned while online; every GovFuzz run after cloning used only the local
checkout and installed toolchains. No `--install-deps` or network-fetch step was
used for discovery, repair, compilation, or fuzz execution.

## Repositories

| Language | Repositories |
|---|---|
| Ada | `Ada-Crypto-Library@a9c201d586f3`, `agpl@c16703180a62`, `drake@4e4bdcd8b8e2`, `gnatcoll-core@96ae80611417`, `ocarina@9873d8b03542`, `parse_args@635f9e4f5318`, `polyorb-hi-ada@f956a4059f94`, `tamp@9fbc92482d7c`, `xmlada@0037f965a199`, `yaml-ada@0c93b15709ec` |
| C | `beanstalkd@25085c5f0900`, `chocolate-doom@353cf5001dfd`, `cparser@81330da3ee96`, `lacc@30839843daaf`, `libffi@46cb2e387105`, `memcached@2d51e364799b`, `redis@799e7c5c24ae`, `yajl@5e3a7856e643`, `cJSON@fb16e5cf3587`, `expat@551a88f87947`, `libarchive@e70bf490b8db`, `lz4@0774d05537f9`, `zlib@e3dc0a85b703` |
| C++ | `cmdline@e4cd007fb8f0`, `libzmq@ba63f0372701`, `loki-lib@7c29d87ecdec`, `luabind@cc743c37a7ff`, `minisat@37dc6c67e2af`, `Signals@17881fb92ec3`, `thrift@40d5a7ed9558`, `uncrustify@76b54da8c2b4`, `jsoncpp@edc01ab10f52`, `leveldb@7ee830d02b62`, `smhasher@07bb4de10a63`, `tinyxml2@8224e427b655` |
| Ada / C | `Ada_Drivers_Library@81c04806d267`, `gnatcoll-bindings@f6c420094905` |

Every repository produced at least one discovered target. This specifically
guards against the earlier failure mode where preprocessing, non-UTF-8 source,
old syntax, or directory pruning silently produced zero candidates.

## Executed Fuzz Proofs

The final release binary ran one fuzz-driven pass with 16 executions against
each representative target:

| Repository | Target | Language | Coverage edges | Outcome |
|---|---|---:|---:|---|
| Expat | `XML_Parse` | C | 158 | `built_and_fuzzed` |
| LevelDB | `leveldb::Hash` | C++ | 25 | `built_and_fuzzed` |
| Parse_Args | `add_option` | Ada | 1,422 | `built_and_fuzzed` |
| libarchive | `archive_read_open_memory2` | C | 81 | `built_and_fuzzed` |
| zlib | `uncompress` | C | 41 | `built_and_fuzzed` |
| YAJL | `yajl_tree_parse` | C | 92 | `built_and_fuzzed` |
| Loki | `Loki::Printf(const std::string &)` | C++ | 18 | `built_and_fuzzed` |
| PolyORB-HI-Ada | `is_data` | Ada | 83 | `built_and_fuzzed` |

Total: 128 executions, 1,920 coverage edges, zero findings, and zero
`fuzzed_stub_only` outcomes. Dependency-only matrices additionally built
targets from Ada-Crypto, AGPL, GNATCOLL Core, XMLAda, cJSON, LZ4, jsoncpp,
smhasher, tinyxml2, and the original C/C++ corpus.

## Gaps Found and Fixed

The campaign added regression coverage and implementation fixes for:

- non-UTF-8/Latin-1 source reads and preprocessing fallbacks;
- Ada callbacks, arrays, containers, streams, scalars, constructors, protected
  and task types, qualified type matching, and defaulted formals;
- Ada source-closure staging, platform-specific unit names, C glue, parallel
  build serialization, and sibling-repository isolation;
- Ada 2012 raise expressions versus nested raise statements;
- legacy C tentative definitions through `-fcommon`;
- callback/linkage macros, POSIX headers/types, feature-gated config headers,
  conditional typedefs, and safe declared-symbol prototypes;
- whole-library sibling-TU recovery without compiling textual `.c` includes,
  tests, benchmarks, or independent `contrib` projects;
- CMake target ownership, known variable expansion, generated config defines,
  deferred large source sets, and runtime-only shared-library rejection;
- old C++ dialect fallback, reserved literal suffixes, `std::FILE *`, and
  standard container/default-constructor decoding.

## External Boundaries

An offline fuzzing tool cannot reconstruct source semantics or a compiler that
is absent from the offline content pack. The campaign verified these boundaries
instead of hiding them behind fabricated success:

- `yaml-ada` requires a separately generated `C.yaml` Ada binding. Its
  README requires the external `headmaster` translator or pre-translated
  headers; neither is in the checkout.
- Ada Drivers Library's selected STM32 board project requires an `arm-eabi`
  GNAT cross-toolchain and matching board runtime.
- GNATCOLL Bindings' zlib child requires the `GNATCOLL.Coders` parent from a
  separate GNATCOLL source distribution.
- RE2's pinned build requires Abseil, while the offline checkout contains no
  `abseil-cpp` source tree.
- TAMP is an ARM cross-toolchain and replacement Ada RTS project. Its own
  instructions require `arm-none-eabi` GNAT plus a board RTS; host GNAT
  correctly rejects recompiling language-defined units.
- Drake is a replacement GNAT runtime with platform-specific runtime units, not
  a host library. It likewise requires the matching runtime/toolchain context.

Each exclusion is checked against pinned file/absence evidence and an exact
clean-control failure signature. Ocarina is not excluded: its `mknodes`
generator is present, and the expanded gate fuzzes `Charset.To_Lower` before
and after exact recovery of its deleted body.

These are content-pack/toolchain prerequisites, not harness-generation
failures. For a self-contained C, C++, Ada, or mixed source tree with its
matching compiler/runtime and generated dependency sources staged offline, this
matrix exercises discovery through real fuzz execution. Exact recovery of
deleted implementation semantics additionally requires local Git history; a
source archive cannot reconstruct arbitrary missing code from no information.

## Destructive Dependency Gate

The follow-up [legacy dependency breakage matrix](2026-07-19-legacy-breakage-matrix.md)
deleted required sources, headers, and Ada child-unit bodies from 13 pinned
projects. It passed 12/13 scenarios (92.3%) against a 90% hard gate while
requiring real-target fuzz execution, repair provenance, and no stub-only
downgrade.

The later [expanded 53-repository stress matrix](2026-07-19-expanded-legacy-breakage-matrix.md)
passes 47/47 in-scope clean controls and 47/47 corresponding damaged projects.
It also verifies six external/toolchain constraints and supplies the 95-sample
convergence distribution supporting the 16-round default.

## Regression Gates

The final tree passed:

- `cargo test --workspace --no-fail-fast`;
- `python3 scripts/validation/test_legacy_breakage_matrix.py`;
- `python3 scripts/validation/test_synthesize_legacy_breakage_manifest.py`;
- `cargo build --release -p govfuzz`;
- `cargo fmt --all -- --check` and `git diff --check`.
