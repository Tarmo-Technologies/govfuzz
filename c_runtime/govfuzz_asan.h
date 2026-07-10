/* SPDX-License-Identifier: Apache-2.0 */
/*
 * govfuzz custom-allocator ASan poison bridge (#436).
 *
 * Legacy / RTOS C rarely uses malloc; it carves a static `uint8_t pool[N]` and
 * hands out sub-regions from a custom allocator. AddressSanitizer only poisons
 * redzones around its OWN allocator's allocations, so a static pool looks like
 * one big valid region: intra-pool overflows go UNDETECTED (false negative).
 *
 * This header lets a harness teach ASan about a custom pool using ASan's manual
 * poisoning interface, turning those silent overflows into real findings:
 *
 *   1. At startup, poison the WHOLE pool   -> govfuzz_asan_pool_init(pool, sizeof pool)
 *   2. On each allocation of `n` bytes     -> govfuzz_asan_on_alloc(ptr, n)
 *   3. On each free of a region of `n`     -> govfuzz_asan_on_free(ptr, n)
 *
 * After (1)+(2), an access that runs past an allocation into still-poisoned pool
 * memory is reported as a use-after-poison / heap-buffer-overflow. Step (3) is
 * optional (re-arms use-after-free detection within the pool) and needs the freed
 * size — skip it if the allocator does not track sizes.
 *
 * Every macro/function is a NO-OP when the translation unit is not built with
 * ASan, so the same source compiles and runs unchanged in a normal build, on the
 * cross-compiled (qemu-user) path, and under `--sanitizers none`. C89-compatible
 * to match the rest of c_runtime (legacy targets).
 *
 * NOTE: ASan poison granularity is 8 bytes (one shadow byte per 8). Sub-8-byte
 * allocations from a pool share a shadow byte, so adjacent tiny allocations may
 * not catch a 1-byte overflow precisely — align pool sub-allocations to 8 bytes
 * for exact detection (the usual ASan custom-allocator guidance).
 */
#ifndef GOVFUZZ_ASAN_H
#define GOVFUZZ_ASAN_H

#include <stddef.h>

/* ASan detection: clang exposes __has_feature(address_sanitizer); gcc defines
 * __SANITIZE_ADDRESS__. */
#if defined(__SANITIZE_ADDRESS__)
#define GOVFUZZ_ASAN_ENABLED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define GOVFUZZ_ASAN_ENABLED 1
#endif
#endif

#ifdef GOVFUZZ_ASAN_ENABLED

/* Provided by the ASan runtime (declared here to stay header-only / C89). */
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);

#define GOVFUZZ_ASAN_POISON(addr, size) __asan_poison_memory_region((addr), (size))
#define GOVFUZZ_ASAN_UNPOISON(addr, size) __asan_unpoison_memory_region((addr), (size))

#else /* !GOVFUZZ_ASAN_ENABLED */

#define GOVFUZZ_ASAN_POISON(addr, size) ((void)(addr), (void)(size))
#define GOVFUZZ_ASAN_UNPOISON(addr, size) ((void)(addr), (void)(size))

#endif /* GOVFUZZ_ASAN_ENABLED */

/* Each helper is `static` so the header can be included by more than one TU
 * without multiple-definition link errors, and tagged unused (GCC/clang) so a TU
 * that calls only some of them does not warn under -Wall. */
#if defined(__GNUC__) || defined(__clang__)
#define GOVFUZZ_ASAN_UNUSED __attribute__((unused))
#else
#define GOVFUZZ_ASAN_UNUSED
#endif

/* Poison an entire custom memory pool at startup so any access to a not-yet-
 * allocated byte is flagged. Call once, before the allocator hands anything out. */
GOVFUZZ_ASAN_UNUSED static void govfuzz_asan_pool_init(void *base, size_t size) {
    GOVFUZZ_ASAN_POISON(base, size);
}

/* Mark `size` bytes at `ptr` as a live allocation (callable from the custom
 * allocator's success path). */
GOVFUZZ_ASAN_UNUSED static void govfuzz_asan_on_alloc(void *ptr, size_t size) {
    GOVFUZZ_ASAN_UNPOISON(ptr, size);
}

/* Re-poison a freed region so a later access is caught as use-after-free within
 * the pool. Needs the freed size; skip if the allocator does not track it. */
GOVFUZZ_ASAN_UNUSED static void govfuzz_asan_on_free(void *ptr, size_t size) {
    GOVFUZZ_ASAN_POISON(ptr, size);
}

#endif /* GOVFUZZ_ASAN_H */
