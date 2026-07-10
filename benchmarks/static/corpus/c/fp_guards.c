/* SPDX-License-Identifier: Apache-2.0 */
/* Campaign 2026-07-03 regression guards: real-tree false-positive patterns that
   the GF-401 / GF-405 / GF-424 heuristics used to fire on. Lines WITHOUT an
   `EXPECT` annotation must produce NO finding; the positives keep recall. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct archive_string {
    char *s;
};
extern char *archive_strcpy(struct archive_string *, const char *);
extern char *archive_strcat(struct archive_string *, const char *);
extern void get_size(int *out);
extern int open(const char *, int);

/* GF-401: the SAFE bounded API `fgets` contains the substring `gets(`, and
   project-local wrappers contain `strcpy(`/`strcat(` — none may be flagged. */
void safe_string_apis(FILE *f, struct archive_string *s) {
    char buf[64];
    fgets(buf, sizeof buf, f);       /* safe: bounded read, not gets() */
    archive_strcpy(s, "literal");    /* safe: managed-string wrapper */
    archive_strcat(s, "more");       /* safe: managed-string wrapper */
}

/* GF-401 positive: a real strcpy of a runtime-length (variable) source. */
void copy_user(char *dst, const char *src) {
    strcpy(dst, src);                /* EXPECT GF-401 */
}

/* GF-405: a string-LITERAL path is author-chosen, never attacker-controlled;
   a typed parameter is a function DEFINITION, not a call site. */
FILE *safe_open_literal(void) {
    return fopen("config.txt", "r"); /* safe: constant path */
}
int open(const char *path, int flags); /* safe: prototype, not a call */

/* GF-405 positive: a non-literal path argument (variable) reaches open(). */
int open_user_file(const char *name) {
    return open(name, 0);            /* EXPECT GF-405 */
}

/* GF-424: a for-loop induction variable is defined by its init clause, and an
   address-of out-parameter is defined by the callee — neither is an
   uninitialized read despite appearing later on the same or a following line. */
int loop_sum(int n) {
    int i;
    int total = 0;
    for (i = 0; i < n; i++) {        /* safe: `i` defined by the for-init */
        total += i;
    }
    return total;
}
int read_size(void) {
    int size;
    get_size(&size);                 /* safe: &size is an out-parameter define */
    return size;
}

/* GF-422 (weak crypto) and GF-428 (weak PRNG in a secret context). A random()
   call with no security noun on the line is a benign use and stays unflagged. */
extern void MD5(const unsigned char *, unsigned long, unsigned char *);
void make_keys(unsigned char *out, unsigned long n) {
    MD5(out, n, out);                /* EXPECT GF-422 */
    unsigned int nonce = rand();     /* EXPECT GF-428 */
    int index = rand() % n;          /* safe: no security noun */
    (void) index;
}
