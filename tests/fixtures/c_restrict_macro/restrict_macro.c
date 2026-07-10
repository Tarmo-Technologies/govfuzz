// SPDX-License-Identifier: Apache-2.0
//
// Regression fixture for a `restrict`-qualifier MACRO in a parameter signature
// (the xxHash `XXH_RESTRICT` pattern). `MYLIB_RESTRICT` is compiler-conditional
// and the C parser cannot expand it, so the bare token lands in the parameter
// QUALIFIER position — after the base type and `*`, immediately before the name.
// It must be recognised as a qualifier and stripped: emitting it as the decode
// variable name yields `redefinition of 'MYLIB_RESTRICT'` (multiple same-named
// params) or `expected identifier` once the macro expands to `restrict`.
#include <stddef.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define MYLIB_RESTRICT restrict
#else
#  define MYLIB_RESTRICT /* disable */
#endif

// Three parameters all carry the qualifier macro, mirroring
// `XXH3_accumulate_512(void* XXH_RESTRICT acc, const void* XXH_RESTRICT input,
//  const void* XXH_RESTRICT secret)`. The body never dereferences the buffers
// based on the fuzzed `len`, so the harness is a clean build+fuzz target whose
// point is the SIGNATURE, not a planted memory bug.
unsigned long mix_bytes(void* MYLIB_RESTRICT acc,
                        const void* MYLIB_RESTRICT input,
                        const void* MYLIB_RESTRICT secret,
                        size_t len) {
    unsigned long h = (unsigned long)len;
    h = h * 31u + (unsigned long)(acc != NULL);
    h = h * 31u + (unsigned long)(input != NULL);
    h = h * 31u + (unsigned long)(secret != NULL);
    return h;
}
