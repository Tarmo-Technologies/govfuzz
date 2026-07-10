<!-- SPDX-License-Identifier: Apache-2.0 -->

# libFuzzer Adapter

The standalone libFuzzer adapter is intentionally deferred for Ada. GovFuzz can
define the adapter contract without shipping or requiring LLVM, libFuzzer, or an
Ada frontend in the strict-permissive core profile.

C and C++ are different: generated C/C++ harnesses already expose
`LLVMFuzzerTestOneInput`, and their Makefiles build sanitizer-instrumented
binaries (ASan/UBSan plus `trace-pc-guard` / `trace-cmp` coverage) with
`clang` / `clang++` — but they deliberately do not link libFuzzer's own `main`
(`-fsanitize=fuzzer`). `govfuzz fuzz` still defaults to the built-in
GovFuzz engine, which drives those binaries through a persistent framed
fork-server (single-input file mode as a fallback) and normalizes sanitizer
findings into GovFuzz reports. Running the generated `main` binary directly
drives that GovFuzz fork-server / single-input loop, not libFuzzer's own loop.

The planned adapter boundary is:

- user supplies a working LLVM/libFuzzer toolchain with a production-viable Ada
  frontend;
- generated harness behavior is exposed through `LLVMFuzzerTestOneInput`;
- testcase bytes are passed to the existing harness contract as stdin-equivalent
  bytes;
- adapter smoke tests skip when the host lacks that Ada/LLVM path, but the Rust
  crate still tests the contract and skip reason.

Until that Ada toolchain path exists, use the built-in engine as the supported
default for Ada. C/C++ users can also build an AFL++ target with
`govfuzz build --c-engine afl++` and run it with
`govfuzz fuzz --engine afl++` when AFL++ is installed.
