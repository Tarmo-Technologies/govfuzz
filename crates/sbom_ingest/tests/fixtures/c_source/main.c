/* SPDX-License-Identifier: Apache-2.0 */
/* Fixture: a C source that includes a vendored zlib (version from header),
 * a system-only sqlite3 (no vendored header → version unknown), and an
 * unknown header (no KB entry → no component). */

#include <zlib.h>      /* vendored alongside → exact version extracted */
#include <sqlite3.h>   /* system-only → version unknown */
#include <stdio.h>     /* libc, not in KB */
#include "local_util.h" /* project-local, not in KB */
#include <madeup/nonexistent.h> /* unknown → no component */

int main(void) {
    return 0;
}
