/* SPDX-License-Identifier: Apache-2.0 */
/* A configure-style feature-test guard whose dead end is a #error, in the
 * shape libssh's priv.h uses. Nothing is missing from this tree: a real
 * ./configure would have defined HAVE_STRTOULL, and offline govfuzz has to
 * supply it or the translation unit never compiles. */
#ifndef PRIV_H
#define PRIV_H
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_STRTOULL
# define proj_strtoull strtoull
#elif defined(HAVE___STRTOULL)
# define proj_strtoull __strtoull
#else
# error "no strtoull function found"
#endif

#endif
