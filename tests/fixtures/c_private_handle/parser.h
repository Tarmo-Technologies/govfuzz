/* SPDX-License-Identifier: Apache-2.0 */
#ifndef GOVFUZZ_C_PRIVATE_HANDLE_H
#define GOVFUZZ_C_PRIVATE_HANDLE_H

#include <stddef.h>

/* The handle is OPAQUE here: callers only ever see the forward declaration.
 * `struct pv_session` is defined in parser.c, beside the target — which is
 * exactly the shape antirez/ds4 has, and exactly what used to make the target
 * unfuzzable ("incomplete in the harness's included headers … cannot
 * stack-allocate it"). */
typedef struct pv_session pv_session;

int pv_session_scan(pv_session *s, const unsigned char *data, size_t len);

#endif
