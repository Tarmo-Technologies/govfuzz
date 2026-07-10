<!-- SPDX-License-Identifier: Apache-2.0 -->

# Missing Dependency

Tiny M7 fixture: `src.adb` references `External_Lib.Process`, and M7 is
expected to synthesize the missing `External_Lib` stubs from compiler
diagnostics.
