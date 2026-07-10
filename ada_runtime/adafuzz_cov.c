// SPDX-License-Identifier: Apache-2.0

/* Edge-coverage runtime for the Ada lane (#412).
 *
 * GNAT/GCC does NOT support `-fsanitize-coverage=trace-pc-guard` (the flag the
 * C/C++ driver uses); GCC 13.x rejects it with "valid arguments are: trace-cmp
 * trace-pc". The Ada target+harness are therefore instrumented with
 * `-fsanitize-coverage=trace-pc`, which emits a call to the parameterless
 * `__sanitizer_cov_trace_pc(void)` at every instrumented edge. This file DEFINES
 * that callback (plus a constructor that maps the GOVFUZZ_COV_SHM bitmap) so the
 * built-in engine gets per-edge feedback exactly like the C/C++ driver does.
 *
 * It is compiled by the AdaFuzz runtime project WITHOUT any
 * `-fsanitize-coverage` flag (`-g` only) so it is itself uninstrumented — if it
 * were instrumented, `__sanitizer_cov_trace_pc` would call into itself and
 * recurse. The unresolved `__sanitizer_cov_trace_pc` symbol referenced by the
 * instrumented Ada + binder objects pulls this archive member into the link.
 *
 * Bitmap indexing mirrors the C/C++ driver's GOVFUZZ_COV_BITS-sized MAP_SHARED
 * map (crates/cli/src/fuzz.rs:CoverageTracker and direct_harness.c.tera) so the
 * engine reader is unchanged: one byte per (hashed) edge, GOVFUZZ_COV_BITS bytes
 * total. trace-pc has no guard pointer, so the return-address PC is hashed into
 * the bitmap instead.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

/* MUST match GOVFUZZ_COV_BITS in crates/cli/src/fuzz.rs and
 * direct_harness.c.tera — the engine maps the same file at this size. */
#define GOVFUZZ_COV_BITS (1u << 16)

#if defined(__has_attribute)
#if __has_attribute(no_sanitize)
#define ADAFUZZ_NOCOV __attribute__((no_sanitize("coverage")))
#endif
#endif
#ifndef ADAFUZZ_NOCOV
#define ADAFUZZ_NOCOV
#endif

static unsigned char *adafuzz_cov_map = 0;

/* Map (or create+size) the GOVFUZZ_COV_SHM edge bitmap once at process start.
 * MAP_SHARED so coverage accumulates across the persistent fork-server process
 * and any per-spawn children, and so the engine reading the same file sees it.
 * No-op when GOVFUZZ_COV_SHM is unset (a plain run with no engine). */
ADAFUZZ_NOCOV __attribute__((constructor)) static void adafuzz_cov_open(void) {
    const char *p = getenv("GOVFUZZ_COV_SHM");
    if (!p || !*p) {
        return;
    }
    int fd = open(p, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        return;
    }
    if (ftruncate(fd, GOVFUZZ_COV_BITS) == 0) {
        void *m =
            mmap(0, GOVFUZZ_COV_BITS, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m != MAP_FAILED) {
            adafuzz_cov_map = (unsigned char *)m;
        }
    }
    close(fd);
}

/* trace-pc edge callback. GCC emits a parameterless call here at each edge; the
 * return address identifies the edge. Fold it into the bitmap with the same
 * scramble libFuzzer/AFL use for PC-table-less coverage so adjacent edges spread
 * across buckets. No-op until the bitmap is mapped. */
ADAFUZZ_NOCOV void __sanitizer_cov_trace_pc(void) {
    if (!adafuzz_cov_map) {
        return;
    }
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    adafuzz_cov_map[(pc ^ (pc >> 3)) & (GOVFUZZ_COV_BITS - 1)] = 1;
}
