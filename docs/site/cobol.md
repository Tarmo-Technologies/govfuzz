<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzzing COBOL with govfuzz

govfuzz is, as far as we can find, the **first turnkey COBOL fuzzer** — point it at
COBOL source and it discovers fuzzable programs, generates the harness, builds, and
fuzzes, with no test harness to write. It reuses govfuzz's mature C engine by
translating COBOL to C with GnuCOBOL.

```sh
govfuzz auto path/to/cobol --languages cobol
```

## How it works

A COBOL subprogram — a `PROGRAM-ID` with a `LINKAGE SECTION` driven by
`PROCEDURE DIVISION USING` — is the fuzzable unit. govfuzz:

1. **Discovers** each program and its `USING` operand list, typed per operand
   (byte buffer / numeric / group). A program is fuzzable when at least one
   operand is a `PIC X` byte buffer.
2. **Translates** it to C with `cobc -C -debug -fec=all` (GnuCOBOL). Free vs fixed
   source format is detected automatically, and every `.cpy` copybook directory in
   the project is added as a `cobc -I` search path so `COPY` statements resolve.
3. **Generates a driver** (`LLVMFuzzerTestOneInput`) that fills the primary
   `PIC X` / `PIC X ANY LENGTH` buffer from the fuzz bytes, sets a length operand
   to the byte count, and zeroes the rest — so a real multi-operand program
   (buffer + length + status) is driven correctly.
4. **Fuzzes** it on the existing C fork-server path: coverage-guided (edge
   coverage + CmpLog/RedQueen), ASan-instrumented, at native speed.

### Two crash oracles

- **ASan** on the generated C catches raw memory corruption.
- **libcob `-fec=all`** runtime checks catch COBOL-semantic violations —
  out-of-range reference-modification (`X(i:n)`), `OCCURS` subscript overflow,
  `SIZE ERROR`, divide-by-zero, invalid numeric data. govfuzz surfaces these as
  crashes and **attributes each to the exact `.cob:line` and CWE** (out-of-bounds
  → CWE-125, zero-divide → CWE-369, size overflow → CWE-190, …).

### Behavioral / taint oracles

Because the COBOL harness runs on govfuzz's C path, the runtime-virtualisation
shim's **taint-confirmed sink oracles apply to COBOL too**: a COBOL program that
passes fuzz-controlled data to a shell-exec (`CALL "SYSTEM"`), SQL, or file-open
sink is flagged as command injection (CWE-78), SQL injection (CWE-89), or path
control (CWE-22) — dynamically confirmed, not a static guess.

## Where govfuzz stands vs the field

There is **no dedicated COBOL fuzzer** in the field — no AFL/AFL++ COBOL mode, no
libFuzzer integration, no OSS-Fuzz COBOL targets. The state of practice is either:

- **Static analysis** (SonarSource COBOL, Micro Focus, IBM, Kiuwan): finds
  candidate defects but **cannot confirm** them — every result is an unproven
  maybe, and none exercises the program with real input.
- **Manual DIY**: hand-write a C driver, `cobc -C`, instrument, point AFL at it —
  what govfuzz automates end-to-end.

govfuzz is the only tool that **fuzz-confirms** COBOL defects (a real input that
trips a libcob/ASan check) and **dynamically confirms behavioral security issues**
(input reaching a shell/SQL/file sink) that static COBOL analyzers can only flag.

## Validation (campaign)

A 23-project campaign over 2925 real COBOL files (including CobolCraft — a full
GnuCOBOL Minecraft server — and several web/CLI COBOL projects):

- **0 govfuzz panics** across all 2925 files.
- **30 of 38** discovered fuzzable programs built and fuzzed (79%); the rest fail
  on mainframe-only features (embedded `EXEC SQL`/`CICS`) or copybooks outside the
  project tree.
- **0 false-positive crashes.** A failed dynamic `CALL` to a sibling program not
  linked into the single-program harness (`module 'X' not found`) is recognized as
  an environment artifact and never reported.
- **2 taint-confirmed command-injection findings (CWE-78)** in a real COBOL program
  that executes an input-derived shell command — the behavioral class no COBOL
  static tool confirms and no crash-only fuzzer would surface.

## Requirements & licensing

- **GnuCOBOL** (`cobc`) on the host — `apt-get install gnucobol`. cobc is GPLv3 and
  is driven **only as a subprocess** (same posture as FSF GNAT/GCC). Its `libcob`
  runtime is LGPLv3 and links into the *user's* generated harness (like the GNAT
  or GCC runtime), never into govfuzz — the strict-permissive core is unaffected.
- `clang` + `make` for the C harness build.

## Limits (honest)

- The primary fuzz surface is the `LINKAGE` `PIC X` buffer. Programs that read
  input only via `ACCEPT`/file `READ`, or take no `USING` byte buffer, aren't
  discovered yet.
- Multi-program projects fuzz one program at a time; a dynamic `CALL` to a sibling
  program is not resolved (the crash it would cause is suppressed, not fuzzed
  through). Linking sibling programs is a planned enhancement.
- Mainframe-specific COBOL (embedded `EXEC SQL`/`CICS`, IBM extensions GnuCOBOL
  doesn't accept) fails the `cobc` translation and is reported as build-failed.
