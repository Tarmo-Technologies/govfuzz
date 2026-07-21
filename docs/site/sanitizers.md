<!-- SPDX-License-Identifier: Apache-2.0 -->

# Sanitizers

`govfuzz auto` and `govfuzz fuzz` arm the C/C++ sanitizer matrix via
`--sanitizers`. By default a native C/C++ harness builds with `-fsanitize=address,undefined`
(ASan + UBSan) plus the engine's coverage instrumentation. This page covers the
controls that make sanitizers usable on shared-memory / custom-allocator / RTOS
code, where stock ASan tends to drown a run in false positives.

`--sanitizers` governs the C/C++ matrix only. Ada uses source instrumentation
rather than LLVM sanitizers; Rust always builds with ASan + sancov via hardcoded
flags (not tunable through `--sanitizers`); Java runs in the JVM under govfuzz's
own bytecode coverage agent, where LLVM sanitizers do not apply; Python, Perl,
Ruby, Lua, and PHP use interpreter coverage plus exception/error oracles; C#
uses SharpFuzz IL coverage; JavaScript/TypeScript use V8 block coverage; and Go
uses atomic compiler coverage with a safe black-box fallback. COBOL and Fortran
have lane-owned ASan/coverage builds. None of those settings are selected by
the C/C++ `--sanitizers` matrix.

## `--sanitizers <set | none>`

- `--sanitizers asan,ubsan,lsan` — arm exactly this set. `asan,ubsan,lsan` are
  mutually compatible; `msan` and `tsan` are exclusive with those and each other
  (run them as separate campaigns).
- `--sanitizers none` — build each native C/C++ harness with the engine's
  coverage instrumentation but **no `-fsanitize=`** at all. You get
  coverage-guided, **crash-only** fuzzing (SIGSEGV / SIGABRT still caught) with
  **zero ASan/UBSan false positives**. This is the escape hatch for code that
  FP-storms under ASan — shared memory, custom allocators, partially instrumented
  RTOS builds — without paying the qemu-user cross-compile tax. `none` is
  standalone; combining it with a real sanitizer is rejected.

`--sanitizers` is inert on every lane except native C/C++. Ada uses source
instrumentation; Rust always applies ASan + sancov through lane-owned
`RUSTFLAGS`; Java and the managed/interpreted lanes use their coverage and
exception mechanisms; Go recovers panics and uses atomic compiler coverage;
COBOL and Fortran own their native build flags. Cross/emulated builds drop host
sanitizers because ASan's shadow memory does not survive qemu-user/wine. See
[Instrumentation](./instrumentation.md) for the complete sixteen-lane feedback
matrix and fallback behavior.

## Tuning, not disabling: `<SAN>_OPTIONS` passthrough

To tame the false-positive storm without giving up detection entirely, set the
sanitizer's own runtime options in the environment. govfuzz **merges** your
inherited `<SAN>_OPTIONS` with the keys it requires (`abort_on_error`,
`halt_on_error`, `detect_leaks`) — your keys are kept, govfuzz's go last so they
win (you cannot accidentally disable `abort_on_error`, which is what turns a
sanitizer report into a saved finding). Each sanitizer is merged independently, so
per-sanitizer suppressions land in the right variable:

```sh
ASAN_OPTIONS=verify_asan_link_order=0:detect_container_overflow=0:detect_odr_violation=0:allocator_may_return_null=1:suppressions=$PWD/asan.supp \
LSAN_OPTIONS=suppressions=$PWD/lsan.supp \
govfuzz auto path/to/src --sanitizers asan,ubsan,lsan
```

Common RTOS / partial-build false-positive killers:

- `verify_asan_link_order=0` — vendor libs not built with ASan.
- `detect_container_overflow=0` — partial instrumentation across the
  instrumented/uninstrumented boundary.
- `detect_odr_violation=0` — duplicate symbols in large firmware builds.
- `detect_stack_use_after_return=0` — RTOS cooperative context switches confuse
  ASan's fake stack.
- `suppressions=<file>` — silence a specific known-benign report.

## Custom allocators: the ASan poison bridge

Legacy / RTOS C rarely uses `malloc`; it carves a static `uint8_t pool[N]` and
hands out sub-regions from a custom allocator. ASan only tracks redzones around
its **own** allocations, so an overflow that stays inside the static pool (past
the logical allocation, but within the backing array) is a silent **false
negative**.

`c_runtime/govfuzz_asan.h` bridges a custom pool to ASan's manual poisoning
interface so those overflows become findings. Three calls, each a no-op when the
translation unit is not built with ASan (so the same source still compiles under
`--sanitizers none`, on the cross path, and in a normal build):

```c
#include "govfuzz_asan.h"

static unsigned char pool[4096];

void allocator_init(void) {
    govfuzz_asan_pool_init(pool, sizeof pool);   /* poison the whole pool once */
}

void *my_alloc(size_t n) {
    void *p = bump_from(pool, n);
    govfuzz_asan_on_alloc(p, n);                  /* unpoison the live slice */
    return p;
}

void my_free(void *p, size_t n) {
    govfuzz_asan_on_free(p, n);                   /* optional: re-arm UAF detection */
    /* ... return to pool ... */
}
```

After init + on-alloc, a read or write that runs off the end of an allocation
into still-poisoned pool memory is reported as a use-after-poison /
heap-buffer-overflow — the same coverage you would get from a malloc-based target.
Align pool sub-allocations to 8 bytes for exact detection (ASan's shadow
granularity is one byte per eight).

## Cooperative context switches: fiber annotations

RTOS cooperative schedulers switch stacks themselves (ucontext, custom
setjmp/longjmp, task switch). ASan's `detect_stack_use_after_return` fake stack
assumes one linear stack, so a switch can produce bogus `stack-use-after-return`
reports. Two options:

- **Blunt:** run with `ASAN_OPTIONS=detect_stack_use_after_return=0` (preserved by
  the env merge above). You lose use-after-return detection everywhere.
- **Accurate:** bracket each switch with `c_runtime/govfuzz_asan_fiber.h` so ASan
  follows it and keeps the check on. Describe each fiber (including the initial
  one) with a `govfuzz_fiber_t` holding its stack region, then:

```c
#include "govfuzz_asan_fiber.h"

govfuzz_fiber_t main_fiber = {0};                       /* learned on first entry */
govfuzz_fiber_t co_fiber = GOVFUZZ_FIBER_INIT(co_stack, sizeof co_stack);

/* main, switching to the coroutine */
govfuzz_fiber_before_switch(&main_fiber, &co_fiber);
swapcontext(&main_uc, &co_uc);
govfuzz_fiber_after_switch(&main_fiber, &co_fiber);

/* coroutine entry/resume — captures main's real stack region into main_fiber */
govfuzz_fiber_after_switch(&co_fiber, &main_fiber);
...
govfuzz_fiber_before_switch(&co_fiber, &main_fiber);    /* NULL `from` when exiting */
swapcontext(&co_uc, &main_uc);
```

The calls are no-ops without ASan, so the same source still builds under
`--sanitizers none`, on the cross path, and normally.

## When to use which

- **Default sweep:** omit `--sanitizers` — ASan + UBSan is the right baseline.
- **FP storm you want gone:** `--sanitizers none` (lose sub-crash detection, keep
  coverage + crashes), or keep ASan and tame it with `ASAN_OPTIONS` above.
- **Custom static-pool allocator:** keep ASan and wire `govfuzz_asan.h` so
  intra-pool overflows are caught.
- **Leaks:** `--sanitizers asan,ubsan,lsan`. **Uninitialized reads / races:**
  `--sanitizers msan` or `tsan` as separate campaigns.
