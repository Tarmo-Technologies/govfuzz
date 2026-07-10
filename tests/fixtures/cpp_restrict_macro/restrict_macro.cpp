// SPDX-License-Identifier: Apache-2.0
//
// C++ counterpart of the C restrict-macro regression fixture. xxHash's
// `xxhash.h` is frequently classified and compiled as C++, so the qualifier-macro
// gap surfaces through the C++ parser/codegen too: a `restrict`-qualifier MACRO
// (`MYLIB_RESTRICT`) in the parameter list must be recognised and stripped, never
// taken as the parameter name. Emitting the macro name as the decode variable
// yields `redefinition of 'MYLIB_RESTRICT'` (multiple same-named params) once the
// header that #defines the macro is included.
#include <cstddef>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define MYLIB_RESTRICT restrict
#elif defined(__GNUC__)
#  define MYLIB_RESTRICT __restrict
#else
#  define MYLIB_RESTRICT /* disable */
#endif

extern "C" unsigned long cpp_mix_bytes(void* MYLIB_RESTRICT acc,
                                       const void* MYLIB_RESTRICT input,
                                       const void* MYLIB_RESTRICT secret,
                                       std::size_t len) {
    unsigned long h = static_cast<unsigned long>(len);
    h = h * 31u + (acc != nullptr ? 1u : 0u);
    h = h * 31u + (input != nullptr ? 1u : 0u);
    h = h * 31u + (secret != nullptr ? 1u : 0u);
    return h;
}
