/* SPDX-License-Identifier: Apache-2.0 */
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
void h(char *dst, const char *u) {
    strncpy(dst, u, 63); /* bounded */
    system("ls");        /* literal */
    perror("ERROR: system(make_cmd) failed"); /* api name in a string */
}
void safe_log_priority(int user_priority) {
    syslog(user_priority, "fixed");
}
/* Safe C idioms that must NOT trip GF-425 truncation: casting a char to
   unsigned char for array indexing, and casting a char-classification result. */
int index_by_char(const char *s, int *table) {
    int acc = 0;
    for (const char *p = s; *p; ++p) {
        acc += table[(unsigned char)*p];   /* array-index idiom, not truncation */
        acc += (char)toupper(*p);          /* char-func result, in range */
    }
    return acc;
}
