<!-- SPDX-License-Identifier: Apache-2.0 -->

# Symbolic Seed Generation

GovFuzz keeps symbolic-execution-assisted seed generation in the research-lab
boundary. The strict-permissive core does not embed solver libraries, compiler
front ends, or proprietary Ada analysis tools.

The current prototype is intentionally small:

- `fuzz_engine_builtin::generate_symbolic_seeds` lexes Ada source with the
  existing permissive parser stack;
- string literals found in `if`, `elsif`, `case`, or `when` guard regions become
  seed bytes;
- duplicate seed bytes are removed deterministically;
- `govfuzz fuzz --symbolic-seed-source <file.adb>` appends those generated seeds
  to the normal built-in engine seed list, so useful seeds enter the existing
  corpus and finding flow.

Candidate future integrations remain optional and out-of-process:

| Candidate | Boundary | Risk |
| --- | --- | --- |
| SMT solver fed by generated harness constraints | research-lab subprocess | Requires an Ada-to-constraints frontend before it is useful. |
| Compiler IR path from a user LLVM/Ada toolchain | optional adapter | No production-stable Ada/LLVM path is assumed today. |
| Libadalang-based path condition mining | research-lab only | Licensing and distribution boundary keeps it out of core. |
| GNATfuzz or vendor tools | forbidden for product core | Competes with GovFuzz goals and is not redistributable as a core dependency. |

This gives validation runs a concrete way to test guarded paths without changing
the product dependency policy.
