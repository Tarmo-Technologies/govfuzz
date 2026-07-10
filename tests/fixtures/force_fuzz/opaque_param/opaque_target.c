// SPDX-License-Identifier: Apache-2.0
// Force-fuzz Phase 2 fixture: a function whose only parameters are types the
// type-directed decoders REJECT — an opaque (incomplete) struct pointer and a
// function pointer. Without `--force` the target is `unsupported_params`; with
// `--force` the best-effort parameter drivers synthesize a compiling harness.

#include <stddef.h>

// Opaque handle: declared but never defined in any header the harness includes,
// so the normal decoders cannot synthesize it.
struct vendor_ctx;

typedef int (*vendor_cb)(int);

// The only fuzzable entry point. `ctx` is an opaque pointer; `cb` is a function
// pointer. Both are rejected by the default decoders.
int vendor_process(struct vendor_ctx *ctx, vendor_cb cb, size_t n) {
    // Deliberately trivial and safe: force mode only needs this to build + run.
    if (ctx == NULL) {
        return (int)n;
    }
    return cb ? cb((int)n) : 0;
}
