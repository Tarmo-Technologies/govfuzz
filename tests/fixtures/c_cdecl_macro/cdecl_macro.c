// SPDX-License-Identifier: Apache-2.0
//
// Regression fixture for a CALLING-CONVENTION macro in a function-pointer
// declarator (the cJSON `internal_hooks` pattern). `CDECL_MACRO` is `__stdcall`
// on Windows and EMPTY on Linux; the C parser cannot expand it, so the bare token
// sits in the CONV slot between the `(` and the `*name`:
// `RET (CDECL_MACRO *name)(args)`. The parser used to mistake it for the FIELD
// NAME, so the harness emitted `.CDECL_MACRO = <trampoline>` -> after the empty
// expansion `. = <trampoline>` -> `main.c: error: expected identifier`. The fix
// reads the name from the `*name` pointer declarator, so the field resolves to
// `deallocate` and the harness builds.
#include <stddef.h>

#if defined(_WIN32)
#  define CDECL_MACRO __stdcall
#else
#  define CDECL_MACRO /* nothing */
#endif

typedef struct my_hooks {
    void *(CDECL_MACRO *allocate)(size_t size);
    void (CDECL_MACRO *deallocate)(void *pointer);
    void *(CDECL_MACRO *reallocate)(void *pointer, size_t size);
} my_hooks;

// Takes the hooks struct by value, like cJSON's internal helpers that receive an
// `internal_hooks`. `static` so the harness #includes this source (making the
// struct a complete type) and CONSTRUCTS the value field-by-field — wiring each
// funcptr field to a trampoline. That only compiles if the field names resolved
// (`.deallocate = ...`, not the empty `. = ...` the convention macro produced).
static unsigned long use_hooks(my_hooks hooks, size_t n) {
    unsigned long h = (unsigned long)n;
    h = h * 31u + (unsigned long)(hooks.allocate != NULL);
    h = h * 31u + (unsigned long)(hooks.deallocate != NULL);
    h = h * 31u + (unsigned long)(hooks.reallocate != NULL);
    return h;
}
