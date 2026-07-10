// SPDX-License-Identifier: Apache-2.0
// A small parser library. Each function carries ONE CWE. The memory + assertion
// CWEs are crash-detectable (any fuzzer finds them); the BEHAVIORAL CWEs are not
// crashes — only a taint/runtime-aware fuzzer (govfuzz) reports them, even when
// the competitor is handed a harness for the exact vulnerable function.
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

// CWE-121: stack-buffer-overflow write (ASan-detectable). [both find]
int parse_header(const unsigned char *d, size_t n) {
    if (n < 4) return 0;
    if (d[0]=='H' && d[1]=='D' && d[2]=='R') {
        char b[2];
        memset(b, 0, (size_t)(16 + (n & 0x1f)));   // OOB write
        return b[0];
    }
    return 1;
}

// CWE-617: reachable assertion / abort (crash). [both find]
int set_level(const unsigned char *d, size_t n) {
    if (n < 1) return 0;
    assert(d[0] < 200);                              // trips for d[0] >= 200
    return d[0];
}

// CWE-22: input bytes flow into a path passed to open() — NOT a crash. [govfuzz only]
int load_resource(const unsigned char *d, size_t n) {
    if (n < 2 || n >= 200) return -1;
    char p[256]; memcpy(p, d, n); p[n] = 0;
    int fd = open(p, O_RDONLY);                      // attacker-controlled path
    if (fd >= 0) close(fd);
    return 0;
}

// CWE-377: insecure temp file — O_CREAT without O_EXCL in a world-writable dir. [govfuzz only]
int write_temp(const unsigned char *d, size_t n) {
    if (n < 1) return -1;
    int fd = open("/tmp/gf_cwe_predictable", O_WRONLY | O_CREAT, 0644);  // no O_EXCL
    if (fd >= 0) { (void)write(fd, d, n > 16 ? 16 : n); close(fd); }
    return 0;
}

// CWE-522: reads a secret-like environment variable on an input-driven path. [govfuzz only]
int read_secret(const unsigned char *d, size_t n) {
    if (n < 1) return 0;
    if (d[0] == 'S') {
        const char *s = getenv("DATABASE_PASSWORD");  // sensitive env access
        return s ? 1 : 0;
    }
    return 0;
}
