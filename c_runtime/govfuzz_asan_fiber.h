/* SPDX-License-Identifier: Apache-2.0 */
/*
 * govfuzz ASan fiber-switch annotations for cooperative context switches (#437).
 *
 * RTOS cooperative schedulers do their own stack switches (ucontext, custom
 * setjmp/longjmp, task switch). AddressSanitizer's `detect_stack_use_after_return`
 * fake-stack assumes ONE linear stack, so a task/coroutine switch makes it report
 * bogus `stack-use-after-return` on memory that simply lives on another task's
 * stack — a classic RTOS false-positive storm.
 *
 * Two ways to deal with it:
 *
 *   1. Blunt mitigation (no code change): run with
 *      `ASAN_OPTIONS=detect_stack_use_after_return=0`. govfuzz preserves operator
 *      `ASAN_OPTIONS` (see --sanitizers / the sanitizers doc), so this just works.
 *      You lose use-after-return detection everywhere.
 *
 *   2. Accurate fix (this header): tell ASan about each switch with
 *      `__sanitizer_{start,finish}_switch_fiber`, so it follows the switch and
 *      keeps use-after-return detection correct across fibers. Wrap your
 *      scheduler's switch primitive with the two calls below.
 *
 * Usage — describe each fiber (including the initial/main context) with a
 * `govfuzz_fiber_t` holding its stack region, then bracket every switch:
 *
 *     static char co_stack[64 * 1024];
 *     govfuzz_fiber_t main_fiber = {0};            // stack filled on first entry
 *     govfuzz_fiber_t co_fiber   = GOVFUZZ_FIBER_INIT(co_stack, sizeof co_stack);
 *
 *     // main, about to switch to the coroutine:
 *     govfuzz_fiber_before_switch(&main_fiber, &co_fiber);
 *     swapcontext(&main_uc, &co_uc);
 *     govfuzz_fiber_after_switch(&main_fiber, &co_fiber);   // back in main
 *
 *     // coroutine entry / resume point — capture where we came from (main's real
 *     // stack region is learned here on first entry, since main_fiber started 0):
 *     govfuzz_fiber_after_switch(&co_fiber, &main_fiber);
 *     ... work ...
 *     govfuzz_fiber_before_switch(&co_fiber, &main_fiber);
 *     swapcontext(&co_uc, &main_uc);
 *
 * `govfuzz_fiber_after_switch(self, came_from)` records the region of the fiber
 * we just left into `came_from` (pass NULL to ignore) — this is how the initial
 * fiber's real stack is discovered. When a fiber is exiting and will never be
 * resumed, pass NULL as `from` to `govfuzz_fiber_before_switch` so ASan discards
 * its fake stack.
 *
 * Every call is a NO-OP when the TU is not built with ASan, so the same source
 * compiles and runs unchanged in a normal build, on the cross path, and under
 * `--sanitizers none`. C89-compatible.
 */
#ifndef GOVFUZZ_ASAN_FIBER_H
#define GOVFUZZ_ASAN_FIBER_H

#include <stddef.h>

#if defined(__SANITIZE_ADDRESS__)
#define GOVFUZZ_ASAN_FIBER_ENABLED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define GOVFUZZ_ASAN_FIBER_ENABLED 1
#endif
#endif

/* Per-fiber state: its stack region plus ASan's saved fake-stack slot. */
typedef struct govfuzz_fiber {
    const void *stack_bottom; /* lowest address of this fiber's stack */
    size_t stack_size;
    void *fake_stack; /* ASan fake-stack save slot for THIS fiber */
} govfuzz_fiber_t;

#define GOVFUZZ_FIBER_INIT(stack_ptr, stack_bytes) \
    { (const void *)(stack_ptr), (size_t)(stack_bytes), (void *)0 }

#ifdef GOVFUZZ_ASAN_FIBER_ENABLED

void __sanitizer_start_switch_fiber(void **fake_stack_save, const void *bottom, size_t size);
void __sanitizer_finish_switch_fiber(void *fake_stack_save, const void **bottom_old,
                                     size_t *size_old);

#if defined(__GNUC__) || defined(__clang__)
#define GOVFUZZ_ASAN_FIBER_UNUSED __attribute__((unused))
#else
#define GOVFUZZ_ASAN_FIBER_UNUSED
#endif

/* Call right BEFORE switching from `from` to `to`. Pass `from == NULL` when the
 * current fiber is exiting and will not be resumed (ASan drops its fake stack). */
GOVFUZZ_ASAN_FIBER_UNUSED static void govfuzz_fiber_before_switch(govfuzz_fiber_t *from,
                                                                  const govfuzz_fiber_t *to) {
    __sanitizer_start_switch_fiber(from ? &from->fake_stack : (void **)0, to->stack_bottom,
                                   to->stack_size);
}

/* Call right AFTER arriving in fiber `self` (entry point or resume site).
 * `came_from` (optional) receives the stack region of the fiber we just switched
 * away from — that is how the initial/main fiber's real stack region is captured
 * on first entry, so later switches back to it pass the correct bottom/size. */
GOVFUZZ_ASAN_FIBER_UNUSED static void govfuzz_fiber_after_switch(govfuzz_fiber_t *self,
                                                                 govfuzz_fiber_t *came_from) {
    const void *prev_bottom = (const void *)0;
    size_t prev_size = 0;
    __sanitizer_finish_switch_fiber(self->fake_stack, &prev_bottom, &prev_size);
    if (came_from) {
        came_from->stack_bottom = prev_bottom;
        came_from->stack_size = prev_size;
    }
}

#else /* !GOVFUZZ_ASAN_FIBER_ENABLED */

#define govfuzz_fiber_before_switch(from, to) ((void)(from), (void)(to))
#define govfuzz_fiber_after_switch(self, came_from) ((void)(self), (void)(came_from))

#endif /* GOVFUZZ_ASAN_FIBER_ENABLED */

#endif /* GOVFUZZ_ASAN_FIBER_H */
