/* SPDX-License-Identifier: Apache-2.0 */
/*
 * govfuzz native fork-server driver + edge-coverage / cmplog / value-profile
 * runtime, factored so a NON-C harness (a Rust staticlib exporting
 * `govfuzz_run_one`) can link the SAME persistent driver the C harness uses.
 *
 * This is a self-contained copy of the language-agnostic driver+runtime from
 * `harness_gen/src/templates/direct_harness.c.tera` (the default, non-AFL block):
 * it provides `main` (the persistent framed fork-server loop the builtin engine
 * drives via GOVFUZZ_FRAMED, plus an argv[1]-file per-spawn isolation path), the
 * SanitizerCoverage trace-pc-guard edge bitmap (GOVFUZZ_COV_SHM), AFL-style
 * hit-count buckets (GOVFUZZ_COV_CNT_SHM), the laf-intel comparison-progress map
 * (GOVFUZZ_CMP_PROGRESS_SHM), the RedQueen/cmplog operand ring (GOVFUZZ_CMP_SHM),
 * and the value-profile dictionary log (GOVFUZZ_VP_SHM). It declares — but does
 * NOT define — `govfuzz_run_one`, which the linked Rust staticlib provides.
 *
 * The marker string `GOVFUZZ_FRAMED` below is what the engine greps for in the
 * sibling source to decide a harness speaks the persistent fork-server protocol;
 * `rust_generate` copies this file to `main.c` beside the binary so the engine
 * drives the Rust harness exactly like a C driver harness (fork-server, coverage,
 * cmplog, value-profile — all the native machinery, no third-party fuzzer).
 *
 * Keep the SHM layouts (sizes, per-edge/site/record bytes) in lock-step with
 * direct_harness.c.tera and the readers in crates/cli/src/fuzz.rs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
/* Windows (mingw-w64) has no <unistd.h>/<sys/mman.h>. The shared coverage/cmplog
 * maps use Win32 file mapping; the framed-protocol pipe I/O uses the _-prefixed
 * CRT calls + _setmode for binary mode; windows.h supplies the vectored
 * exception handler that is govfuzz's crash detector here (no ASan on mingw). */
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#define GF_DEVNULL "NUL"
#define gf_read _read
#define gf_write _write
#define gf_dup _dup
#define gf_dup2 _dup2
#define gf_close _close
#define gf_open _open
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#define GF_DEVNULL "/dev/null"
#define gf_read read
#define gf_write write
#define gf_dup dup
#define gf_dup2 dup2
#define gf_close close
#define gf_open open
#endif

/* The Rust staticlib defines this; the driver only calls it. */
extern int govfuzz_run_one(const uint8_t *Data, size_t Size);

/* Auto-injected shim hook: republish the fuzz input to the runtrace shim so
 * fuzz-driven mode can route the current iteration's bytes into fake fds /
 * sockets / dlopen stubs. Weak so a build without the shim links cleanly. */
extern void govfuzz_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));

/* The coverage/cmplog runtime functions must NOT be instrumented themselves: a
 * compare inside a trace-cmp callback would re-enter it and recurse forever, and
 * self-edges would pollute the bitmap. GCC (incl. mingw) spells the opt-out
 * `no_sanitize_coverage`; clang spells it `no_sanitize("coverage")`. */
#if defined(__has_attribute)
#if defined(__clang__) && __has_attribute(no_sanitize)
#define GOVFUZZ_NOCOV __attribute__((no_sanitize("coverage")))
#elif __has_attribute(no_sanitize_coverage)
#define GOVFUZZ_NOCOV __attribute__((no_sanitize_coverage))
#elif __has_attribute(no_sanitize)
#define GOVFUZZ_NOCOV __attribute__((no_sanitize("coverage")))
#endif
#endif
#ifndef GOVFUZZ_NOCOV
#define GOVFUZZ_NOCOV
#endif

/* Map a shared, file-backed region of `size` bytes at `path`, or 0 on failure.
 * Both platforms back the map with a real file so the engine (a separate
 * process on the host; under wine the host sees the same file) reads the same
 * bytes. POSIX: open+ftruncate+mmap(MAP_SHARED). Windows: CreateFileMapping +
 * MapViewOfFile, which writes through to the backing file. */
GOVFUZZ_NOCOV static void *gf_map_shared(const char *path, size_t size) {
#ifdef _WIN32
    HANDLE fh = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return NULL;
    HANDLE mh = CreateFileMappingA(fh, NULL, PAGE_READWRITE,
                                   (DWORD)(((uint64_t)size) >> 32),
                                   (DWORD)(size & 0xffffffffu), NULL);
    CloseHandle(fh); /* the mapping object keeps the file alive */
    if (!mh) return NULL;
    /* Keep `mh` open for the process lifetime: the view stays valid and the OS
     * reclaims both at exit. */
    return MapViewOfFile(mh, FILE_MAP_ALL_ACCESS, 0, 0, size);
#else
    int fd = gf_open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return NULL;
    void *p = NULL;
    if (ftruncate(fd, (off_t)size) == 0) {
        void *m = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m != MAP_FAILED) p = m;
    }
    gf_close(fd);
    return p;
#endif
}

#ifdef _WIN32
/* mingw has no ASan, so a memory-safety bug surfaces only as a hardware fault.
 * A vectored exception handler converts a fatal exception (access violation,
 * stack overflow, …) into an immediate, distinctive exit so the engine running
 * the harness under wine detects a crash — instead of wine popping a debugger
 * dialog that blocks the fuzz loop. This is govfuzz's ASan substitute here. */
#define GOVFUZZ_WIN_CRASH_EXIT 0x39
GOVFUZZ_NOCOV static LONG CALLBACK govfuzz_win_veh(EXCEPTION_POINTERS *info) {
    DWORD code = info->ExceptionRecord->ExceptionCode;
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        fprintf(stderr, "GOVFUZZ_CRASH code=0x%lx\n", (unsigned long)code);
        fflush(stderr);
        TerminateProcess(GetCurrentProcess(), GOVFUZZ_WIN_CRASH_EXIT);
        return EXCEPTION_CONTINUE_SEARCH; /* unreachable */
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}
GOVFUZZ_NOCOV static void govfuzz_win_install_crash_handler(void) {
    AddVectoredExceptionHandler(1, govfuzz_win_veh);
}
#endif

/* Edge-coverage bitmap (#385): one presence bit per instrumented edge in a
 * MAP_SHARED region named by GOVFUZZ_COV_SHM, so coverage accumulates across
 * per-spawn children and within the persistent process. No-op when unset. */
#define GOVFUZZ_COV_BITS (1u << 16)
static unsigned char *govfuzz_cov_map = 0;
static uint32_t govfuzz_cov_next = 0;
GOVFUZZ_NOCOV static void govfuzz_cov_open(void) {
    if (govfuzz_cov_map) return;
    const char *p = getenv("GOVFUZZ_COV_SHM");
    if (!p || !*p) return;
    void *m = gf_map_shared(p, GOVFUZZ_COV_BITS);
    if (m) govfuzz_cov_map = (unsigned char *)m;
}
/* AFL-style per-exec hit-count buckets (#420): a SECOND map, GOVFUZZ_COV_CNT_SHM,
 * same size, one byte per edge; trace-pc-guard saturating-increments it so the
 * engine can bucket loop/recursion depth. No-op when unset. */
static unsigned char *govfuzz_cov_cnt_map = 0;
GOVFUZZ_NOCOV static void govfuzz_cov_cnt_open(void) {
    if (govfuzz_cov_cnt_map) return;
    const char *p = getenv("GOVFUZZ_COV_CNT_SHM");
    if (!p || !*p) return;
    void *m = gf_map_shared(p, GOVFUZZ_COV_BITS);
    if (m) govfuzz_cov_cnt_map = (unsigned char *)m;
}
/* laf-intel comparison-progress (#421): a THIRD map, GOVFUZZ_CMP_PROGRESS_SHM,
 * one byte per hashed compare site recording the MAX leading-byte match this
 * exec, so the engine can reward an input one byte closer to a multi-byte gate.
 * No-op when unset. */
#define GOVFUZZ_CMPP_BITS (1u << 16)
static unsigned char *govfuzz_cmpp_map = 0;
GOVFUZZ_NOCOV static void govfuzz_cmpp_open(void) {
    if (govfuzz_cmpp_map) return;
    const char *p = getenv("GOVFUZZ_CMP_PROGRESS_SHM");
    if (!p || !*p) return;
    void *m = gf_map_shared(p, GOVFUZZ_CMPP_BITS);
    if (m) govfuzz_cmpp_map = (unsigned char *)m;
}
GOVFUZZ_NOCOV static unsigned govfuzz_cmpp_slot(const void *ra) {
    uintptr_t rel = (uintptr_t)ra - (uintptr_t)&govfuzz_cmpp_open;
    return (unsigned)(rel * 2654435761u) & (GOVFUZZ_CMPP_BITS - 1);
}
GOVFUZZ_NOCOV static void govfuzz_cmpp_int(uint64_t a, uint64_t b, unsigned width, const void *ra) {
    unsigned m, i, slot;
    unsigned char p;
    if (!govfuzz_cmpp_map || a == b) return;
    if (width > 8) width = 8;
    m = 0;
    for (i = 0; i < width; i++) {
        if (((a >> (8 * i)) & 0xff) == ((b >> (8 * i)) & 0xff)) m++;
        else break;
    }
    if (m == 0) return;
    p = (unsigned char)(m > 7 ? 7 : m);
    slot = govfuzz_cmpp_slot(ra);
    if (govfuzz_cmpp_map[slot] < p) govfuzz_cmpp_map[slot] = p;
}
GOVFUZZ_NOCOV static void govfuzz_cmpp_buf(const unsigned char *s1, const unsigned char *s2,
                                           unsigned n, int result, const void *pc) {
    unsigned m = 0, slot;
    unsigned char p;
    if (!govfuzz_cmpp_map || result == 0) return;
    if (n > 8u) n = 8u;
    while (m < n && s1[m] == s2[m]) m++;
    if (m == 0) return;
    p = (unsigned char)(m > 7 ? 7 : m);
    slot = govfuzz_cmpp_slot(pc);
    if (govfuzz_cmpp_map[slot] < p) govfuzz_cmpp_map[slot] = p;
}

/* RedQueen/cmplog operand ring (#400) in GOVFUZZ_CMP_SHM. Layout MUST match
 * CmpShmReader in crates/cli/src/fuzz.rs:
 *   [u32 armed][u32 count] then GOVFUZZ_CMP_CAP records of
 *   [u8 len_a][u8 len_b][u8 a[OPMAX]][u8 b[OPMAX]]. */
#define GOVFUZZ_CMP_CAP 2048u
#define GOVFUZZ_CMP_OPMAX 32u
#define GOVFUZZ_CMP_REC (2u + 2u * GOVFUZZ_CMP_OPMAX)
#define GOVFUZZ_CMP_BYTES (8u + GOVFUZZ_CMP_CAP * GOVFUZZ_CMP_REC)
static unsigned char *govfuzz_cmp_map = 0;
GOVFUZZ_NOCOV static void govfuzz_cmp_open(void) {
    const char *p;
    if (govfuzz_cmp_map) return;
    p = getenv("GOVFUZZ_CMP_SHM");
    if (!p || !*p) return;
    void *m = gf_map_shared(p, GOVFUZZ_CMP_BYTES);
    if (m) govfuzz_cmp_map = (unsigned char *)m;
}
GOVFUZZ_NOCOV static int govfuzz_cmp_armed(void) {
    unsigned char *m = govfuzz_cmp_map;
    if (!m) return 0;
    return m[0] | m[1] | m[2] | m[3];
}
GOVFUZZ_NOCOV static void govfuzz_cmp_push(const unsigned char *a, unsigned la,
                                           const unsigned char *b, unsigned lb) {
    unsigned char *m = govfuzz_cmp_map;
    unsigned count, off, i;
    if (!m) return;
    if (la > GOVFUZZ_CMP_OPMAX) la = GOVFUZZ_CMP_OPMAX;
    if (lb > GOVFUZZ_CMP_OPMAX) lb = GOVFUZZ_CMP_OPMAX;
    count = (unsigned)m[4] | ((unsigned)m[5] << 8) | ((unsigned)m[6] << 16) | ((unsigned)m[7] << 24);
    if (count >= GOVFUZZ_CMP_CAP) return;
    off = 8u + count * GOVFUZZ_CMP_REC;
    m[off] = (unsigned char)la;
    m[off + 1] = (unsigned char)lb;
    for (i = 0; i < la; i++) m[off + 2u + i] = a[i];
    for (i = 0; i < lb; i++) m[off + 2u + GOVFUZZ_CMP_OPMAX + i] = b[i];
    count++;
    m[4] = (unsigned char)count;
    m[5] = (unsigned char)(count >> 8);
    m[6] = (unsigned char)(count >> 16);
    m[7] = (unsigned char)(count >> 24);
}
GOVFUZZ_NOCOV static void govfuzz_cmp_int(uint64_t a, uint64_t b, unsigned width) {
    unsigned char ab[8], bb[8];
    unsigned i;
    if (!govfuzz_cmp_armed()) return;
    if (a == b || a == 0 || b == 0) return;
    if (width > 8) width = 8;
    for (i = 0; i < width; i++) {
        ab[i] = (unsigned char)(a >> (8 * i));
        bb[i] = (unsigned char)(b >> (8 * i));
    }
    govfuzz_cmp_push(ab, width, bb, width);
}
GOVFUZZ_NOCOV static unsigned govfuzz_cmp_copy(unsigned char *dst, const unsigned char *src,
                                               unsigned maxlen, int stop_at_nul) {
    unsigned i;
    for (i = 0; i < maxlen; i++) {
        unsigned char c = src[i];
        if (stop_at_nul && c == 0) break;
        dst[i] = c;
    }
    return i;
}
GOVFUZZ_NOCOV static void govfuzz_cmp_buf(const unsigned char *s1, const unsigned char *s2,
                                          unsigned n, int stop_at_nul, int result) {
    unsigned char a[GOVFUZZ_CMP_OPMAX], b[GOVFUZZ_CMP_OPMAX];
    unsigned la, lb;
    if (!govfuzz_cmp_armed() || result == 0) return;
    if (n > GOVFUZZ_CMP_OPMAX) n = GOVFUZZ_CMP_OPMAX;
    la = govfuzz_cmp_copy(a, s1, n, stop_at_nul);
    lb = govfuzz_cmp_copy(b, s2, n, stop_at_nul);
    if (la == 0 && lb == 0) return;
    govfuzz_cmp_push(a, la, b, lb);
}

/* Value-profile token log (#398) in GOVFUZZ_VP_SHM:
 * [u32 cursor][ {u8 len}{len bytes} ... ], deduped in-process. */
#define GOVFUZZ_VP_BYTES (1u << 16)
static unsigned char *govfuzz_vp_map = 0;
static unsigned char govfuzz_vp_seen1[256];
static uint64_t govfuzz_vp_seenN[4096];
GOVFUZZ_NOCOV static void govfuzz_vp_open(void) {
    if (govfuzz_vp_map) return;
    const char *p = getenv("GOVFUZZ_VP_SHM");
    if (!p || !*p) return;
    void *m = gf_map_shared(p, GOVFUZZ_VP_BYTES);
    if (m) govfuzz_vp_map = (unsigned char *)m;
}
GOVFUZZ_NOCOV static void govfuzz_vp_add(const unsigned char *data, unsigned len) {
    if (!govfuzz_vp_map || len == 0 || len > 8) return;
    unsigned z = 1;
    for (unsigned i = 0; i < len; i++) if (data[i]) { z = 0; break; }
    if (z) return;
    if (len == 1) {
        if (govfuzz_vp_seen1[data[0]]) return;
        govfuzz_vp_seen1[data[0]] = 1;
    } else {
        uint64_t h = 1469598103934665603ull;
        for (unsigned i = 0; i < len; i++) { h ^= data[i]; h *= 1099511628211ull; }
        h ^= len;
        uint64_t slot = h & 4095u;
        if (govfuzz_vp_seenN[slot] == h) return;
        govfuzz_vp_seenN[slot] = h;
    }
    uint32_t *cursor = (uint32_t *)govfuzz_vp_map;
    uint32_t c = *cursor;
    if ((size_t)c + 1u + len + 4u > GOVFUZZ_VP_BYTES) return;
    unsigned char *w = govfuzz_vp_map + 4 + c;
    w[0] = (unsigned char)len;
    for (unsigned i = 0; i < len; i++) w[1 + i] = data[i];
    *cursor = c + 1 + len;
}

GOVFUZZ_NOCOV void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) return;
    for (uint32_t *x = start; x < stop; x++) *x = ++govfuzz_cov_next;
    govfuzz_cov_open();
    govfuzz_cov_cnt_open();
    govfuzz_cmp_open();
    govfuzz_cmpp_open();
}
GOVFUZZ_NOCOV void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (!*guard || !govfuzz_cov_map) return;
    govfuzz_cov_map[*guard & (GOVFUZZ_COV_BITS - 1)] = 1;
    if (govfuzz_cov_cnt_map && govfuzz_cov_cnt_map[*guard & (GOVFUZZ_COV_BITS - 1)] != 255)
        govfuzz_cov_cnt_map[*guard & (GOVFUZZ_COV_BITS - 1)]++;
}
#ifdef _WIN32
/* mingw-w64 gcc has no `trace-pc-guard`; the Windows build instruments with
 * `-fsanitize-coverage=trace-pc`, which calls this guard-less hook at each edge.
 * Hash the return address into the SAME bitmap the guard path fills so the
 * engine's coverage reader stays platform-agnostic. */
GOVFUZZ_NOCOV void __sanitizer_cov_trace_pc(void) {
    if (!govfuzz_cov_map) return;
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    uint32_t h = ((uint32_t)(pc * 2654435761u) >> 4) & (GOVFUZZ_COV_BITS - 1);
    govfuzz_cov_map[h] = 1;
    if (govfuzz_cov_cnt_map && govfuzz_cov_cnt_map[h] != 255)
        govfuzz_cov_cnt_map[h]++;
}
#endif
GOVFUZZ_NOCOV void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { govfuzz_cmp_int(a, b, 1); govfuzz_cmpp_int(a, b, 1, __builtin_return_address(0)); }
GOVFUZZ_NOCOV void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { govfuzz_cmp_int(a, b, 2); govfuzz_cmpp_int(a, b, 2, __builtin_return_address(0)); }
GOVFUZZ_NOCOV void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { govfuzz_cmp_int(a, b, 4); govfuzz_cmpp_int(a, b, 4, __builtin_return_address(0)); }
GOVFUZZ_NOCOV void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { govfuzz_cmp_int(a, b, 8); govfuzz_cmpp_int(a, b, 8, __builtin_return_address(0)); }
GOVFUZZ_NOCOV void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { govfuzz_vp_add(&a, 1); govfuzz_vp_add(&b, 1); govfuzz_cmp_int(a, b, 1); govfuzz_cmpp_int(a, b, 1, __builtin_return_address(0)); }
GOVFUZZ_NOCOV void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { govfuzz_vp_add((unsigned char *)&a, 2); govfuzz_vp_add((unsigned char *)&b, 2); govfuzz_cmp_int(a, b, 2); govfuzz_cmpp_int(a, b, 2, __builtin_return_address(0)); }
GOVFUZZ_NOCOV void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { govfuzz_vp_add((unsigned char *)&a, 4); govfuzz_vp_add((unsigned char *)&b, 4); govfuzz_cmp_int(a, b, 4); govfuzz_cmpp_int(a, b, 4, __builtin_return_address(0)); }
GOVFUZZ_NOCOV void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { govfuzz_vp_add((unsigned char *)&a, 8); govfuzz_vp_add((unsigned char *)&b, 8); govfuzz_cmp_int(a, b, 8); govfuzz_cmpp_int(a, b, 8, __builtin_return_address(0)); }
GOVFUZZ_NOCOV void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
    uint64_t n = cases[0], bits = cases[1];
    unsigned len = (unsigned)(bits / 8);
    uint64_t i;
    if (len < 1) len = 1;
    if (len > 8) len = 8;
    for (i = 0; i < n; i++) {
        uint64_t cv = cases[2 + i];
        govfuzz_vp_add((unsigned char *)&cv, len);
    }
    if (govfuzz_cmp_armed()) {
        for (i = 0; i < n && i < 64; i++) govfuzz_cmp_int(val, cases[2 + i], len);
    }
}
/* ASan's str/mem-cmp interceptors call these weak hooks (even without libFuzzer
 * linked), feeding multi-byte string/buffer gates into the RedQueen ring. */
GOVFUZZ_NOCOV void __sanitizer_weak_hook_memcmp(void *pc, const void *s1, const void *s2, size_t n, int result) {
    govfuzz_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, 0, result);
    govfuzz_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, result, pc);
}
GOVFUZZ_NOCOV void __sanitizer_weak_hook_strncmp(void *pc, const char *s1, const char *s2, size_t n, int result) {
    govfuzz_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, 1, result);
    govfuzz_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, result, pc);
}
GOVFUZZ_NOCOV void __sanitizer_weak_hook_strcmp(void *pc, const char *s1, const char *s2, int result) {
    govfuzz_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, GOVFUZZ_CMP_OPMAX, 1, result);
    govfuzz_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, GOVFUZZ_CMP_OPMAX, result, pc);
}
GOVFUZZ_NOCOV void __sanitizer_weak_hook_strncasecmp(void *pc, const char *s1, const char *s2, size_t n, int result) {
    govfuzz_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, 1, result);
    govfuzz_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, (unsigned)n, result, pc);
}
GOVFUZZ_NOCOV void __sanitizer_weak_hook_strcasecmp(void *pc, const char *s1, const char *s2, int result) {
    govfuzz_cmp_buf((const unsigned char *)s1, (const unsigned char *)s2, GOVFUZZ_CMP_OPMAX, 1, result);
    govfuzz_cmpp_buf((const unsigned char *)s1, (const unsigned char *)s2, GOVFUZZ_CMP_OPMAX, result, pc);
}

GOVFUZZ_NOCOV static void govfuzz_run_one_bytes(const uint8_t *data, size_t size) {
    if (govfuzz_shim_set_fuzz_input) govfuzz_shim_set_fuzz_input(data, size);
    govfuzz_run_one(data, size);
}
static void govfuzz_run_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) n = 0;
    rewind(f);
    uint8_t *b = (uint8_t *)malloc((size_t)(n ? n : 1));
    if (!b) { fclose(f); return; }
    size_t r = fread(b, 1, (size_t)n, f);
    fclose(f);
    govfuzz_run_one_bytes(b, r);
    free(b);
}
static int govfuzz_read_n(int fd, void *buf, size_t n) {
    size_t got = 0;
    unsigned char *b = (unsigned char *)buf;
    while (got < n) {
        int r = (int)gf_read(fd, b + got, (unsigned)(n - got));
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    return 1;
}
int main(int argc, char **argv) {
#ifdef _WIN32
    /* On Windows the trace-pc path has no guard-init to open the maps, so open
     * them here; and install the crash handler that makes a fault a detectable
     * exit under wine. */
    govfuzz_win_install_crash_handler();
    govfuzz_cov_open();
    govfuzz_cov_cnt_open();
    govfuzz_cmpp_open();
    govfuzz_cmp_open();
#endif
    govfuzz_vp_open();
    /* Persistent fork-server framed protocol (GOVFUZZ_FRAMED=1): write a ready
     * byte, then loop reading {u32 LE length, bytes} and replying one sync byte
     * per input. #427: redirect the target's stdout to /dev/null and write sync
     * bytes to the saved control fd so target output can't deadlock the pipe. */
    if (getenv("GOVFUZZ_FRAMED")) {
        int govfuzz_ctrl_fd = gf_dup(1);
        int govfuzz_devnull;
        unsigned char ready = 1;
        if (govfuzz_ctrl_fd < 0) return 1;
#ifdef _WIN32
        /* Binary mode: stop the CRT translating CRLF / treating 0x1A as EOF in
         * the framed {u32 len, bytes} protocol on stdin and the control fd. */
        _setmode(0, _O_BINARY);
        _setmode(govfuzz_ctrl_fd, _O_BINARY);
#endif
        govfuzz_devnull = gf_open(GF_DEVNULL, O_WRONLY);
        if (govfuzz_devnull >= 0) {
            gf_dup2(govfuzz_devnull, 1);
            if (govfuzz_devnull != 1) gf_close(govfuzz_devnull);
        }
        if (gf_write(govfuzz_ctrl_fd, &ready, 1) != 1) return 1;
        size_t cap = 1u << 20;
        uint8_t *buf = (uint8_t *)malloc(cap);
        if (!buf) return 1;
        for (;;) {
            uint32_t len;
            if (!govfuzz_read_n(0, &len, 4)) break;
            if ((size_t)len > cap) len = (uint32_t)cap;
            if (len && !govfuzz_read_n(0, buf, len)) break;
            govfuzz_run_one_bytes(buf, len);
            unsigned char sync = 1;
            if (gf_write(govfuzz_ctrl_fd, &sync, 1) != 1) break;
        }
        free(buf);
        return 0;
    }
    if (argc < 2) return 0;
    govfuzz_run_file(argv[1]);
    return 0;
}
