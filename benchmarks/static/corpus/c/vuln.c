/* SPDX-License-Identifier: Apache-2.0 */
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
void h(char *u, char *dst) {
    strcpy(dst, u);      /* EXPECT GF-401 */
    system(u);           /* EXPECT GF-404 */
}
void log_user(char *user_input) {
    syslog(LOG_WARNING, "%s", user_input); /* EXPECT GF-544 */
}
