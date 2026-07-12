<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzzing Fortran with govfuzz

govfuzz fuzzes Fortran with **no harness to write** — point it at Fortran source
and it discovers fuzzable procedures, generates the harness, builds with gfortran,
and fuzzes, coverage-guided, with AddressSanitizer as the memory oracle.

```sh
govfuzz auto path/to/fortran --languages fortran
```

## How it works

A Fortran `subroutine`/`function` with a `character` (byte-buffer) dummy argument
is the fuzzable unit. govfuzz:

1. **Discovers** each procedure and its dummy-argument list, typed per argument
   (character buffer / integer / other), handling free-form continuation lines
   and `pure`/`recursive`/typed-`function` prefixes.
2. **Compiles** it with `gfortran -O1 -g -fsanitize=address
   -fsanitize-coverage=trace-pc,trace-cmp` — ASan instruments the Fortran for
   memory safety, and trace-pc/trace-cmp feed edge coverage + CmpLog.
3. **Generates a driver** (`LLVMFuzzerTestOneInput`) that calls the routine via
   the gfortran C ABI (`name_`, arguments by reference, a hidden `size_t` length
   appended per character argument). The primary buffer is **heap-allocated to the
   exact input size**, so a real out-of-bounds access — relative to the length the
   routine is told — lands in ASan's redzone instead of being hidden by a padded
   buffer. An integer length argument is set to the byte count.
4. **Fuzzes** it on govfuzz's C fork-server engine at native speed (thousands of
   executions/second), coverage-guided.

### Oracle

**AddressSanitizer** is the primary oracle: a Fortran array/substring out-of-bounds
read or write, or a bad pointer, is reported directly as a crash with the **exact
`.f90:line` and CWE** (heap-buffer-overflow → CWE-122/787, stack → CWE-121/125).
No exit-interposition is needed — an ASan abort is already a genuine crash the
engine classifies and attributes correctly.

The runtime-virtualisation shim's **taint-confirmed sink oracles** (command / SQL /
path injection) also apply, since the harness runs on govfuzz's C path.

## Where govfuzz stands vs the field

Fortran has **no turnkey fuzzer**. What exists is DIY — a scientist hand-writes a C
or Fortran driver, compiles with `gfortran -fsanitize=address`, and points AFL at
it — which govfuzz automates end to end (zero harness, auto-discovery, coverage +
CmpLog + taint oracles). On the static side, gfortran's own `-Wall`/`-fcheck`
warnings, and commercial linters (forcheck, fpt), flag candidate issues but don't
confirm them with real input. govfuzz is the only tool that **fuzz-confirms**
Fortran memory-safety defects and applies behavioral taint oracles.

## Validation (campaign)

A 20-project campaign over 40,367 real Fortran files (the most-starred Fortran
projects — LAPACK, CP2K, NWChem, FDS, neural-fortran, flibs, …):

- **0 govfuzz panics** across all 40,367 files — discovery is robust on massive,
  varied scientific Fortran.
- **13,406 fuzzable procedures discovered** (Fortran has a large character-argument
  surface — string handling, file paths, format processing).
- **Standalone free-form subroutines fuzz and find real bugs**: a heap out-of-bounds
  array access is caught as an ASan crash (GF-201, CWE-122/787) attributed to the
  exact `.f90:line`; benign procedures run at **6,500+ executions/second** with **0
  false positives**.

The campaign also surfaced the honest limits below: module-based library procedures
need their module context to compile standalone, and preprocessor include-fragment
"template" files (invalid Fortran identifiers) are skipped rather than mis-compiled.

## Requirements & licensing

- **gfortran** on the host — `apt-get install gfortran`. It is driven only as a
  subprocess; its `libgfortran` runtime (LGPLv3, GCC Runtime Library Exception)
  links into the *user's* harness like the C/GNAT runtime, never into govfuzz.
- `clang` + `make` for the C driver build.

## Limits (honest)

- The fuzzable surface is a `character` dummy argument. Procedures that take only
  numeric (`real`/`integer`) arrays, or read input via Fortran I/O (`READ`), are
  not discovered yet — a numeric-array driver is a planned enhancement.
- One procedure is fuzzed at a time; module `use` dependencies must compile
  standalone (most numerical modules do).
