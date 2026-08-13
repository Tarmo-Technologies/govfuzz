/* SPDX-License-Identifier: Apache-2.0 */
#ifndef GOVFUZZ_DECODE_H
#define GOVFUZZ_DECODE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#ifndef inline
#if defined(_MSC_VER)
#define inline __inline
#else
#define inline __inline__
#endif
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gf_cursor {
    const uint8_t *data;
    size_t size;
    size_t pos;
} gf_cursor;

static inline gf_cursor gf_open(const uint8_t *data, size_t size) {
    /* Field assignment, not a compound initializer with runtime values: the
     * latter is a C99 extension that a strict C89 compiler (-std=c89 -ansi
     * -pedantic) rejects. M22: legacy C targets are recompiled with a modern
     * clang in -std=c89 mode, so the runtime must be genuinely C89-clean. */
    gf_cursor c;
    c.data = data;
    c.size = size;
    c.pos = 0;
    return c;
}

static inline size_t gf_remaining(const gf_cursor *c) {
    return c->size > c->pos ? c->size - c->pos : 0;
}

/* ---- op-program control channel -------------------------------------------
 *
 * A sequence harness needs two things from one input: an ordered program of
 * OPERATIONS, and the ARGUMENT bytes each operation consumes. Drawing both from
 * the same forward cursor makes the program byte-fragile — `gf_c_string`
 * consumes a 2-byte length prefix plus a payload, so a single length-changing
 * edit anywhere re-frames every downstream operation selector, and the engine's
 * structure-aware sequence mutator cannot describe the input at all.
 *
 * So the control channel is a CONTIGUOUS block reserved at the END of the
 * input, at a FIXED stride of one byte per slot — the same separation
 * libFuzzer's own FuzzedDataProvider makes, for the same reason:
 *
 *     [ argument data, forward ...... | count | slot_0 | slot_1 | ... ]
 *                                       ^ size - ctrl_len        ^ size - 1
 *
 * Each slot is GF_CTRL_SLOT bytes wide.
 *
 * A mutation in the argument region no longer re-frames a selector, so the op
 * program survives havoc, splice and cmplog edits that change length. Slot i
 * lives at `size - ctrl_len + 1 + i`: one byte per step, ASCENDING with step
 * order, which is what lets the engine describe the program as ordered,
 * non-overlapping byte spans.
 *
 * Reads past the front of the control region return 0, so a short input is a
 * short program rather than an out-of-bounds read. */
/* One selector byte plus a 4-byte value per operation slot — the encoding the
 * engine's bounded-value decoder understands. */
#define GF_CTRL_SLOT 5
/* One count byte, then one slot per possible step. */
#define GF_CTRL_LEN(max_steps) ((size_t)1 + (size_t)(max_steps) * GF_CTRL_SLOT)

/* Open a cursor over the ARGUMENT region only, so argument decoding can never
 * consume a control byte (which would make one byte mean two things and couple
 * an argument edit to a program edit). `ctrl_len` is 1 count byte plus one slot
 * per possible step. A too-short input yields an empty data region, which the
 * decoders already handle as "no bytes". */
static inline gf_cursor gf_open_data(const uint8_t *data, size_t size, size_t ctrl_len) {
    gf_cursor c;
    c.data = data;
    c.size = size > ctrl_len ? size - ctrl_len : 0;
    c.pos = 0;
    return c;
}

static inline size_t gf_ctrl_step_count(const uint8_t *data, size_t size, size_t max_steps) {
    size_t ctrl_len = GF_CTRL_LEN(max_steps);
    if (max_steps == 0 || size < ctrl_len) return 0;
    return (size_t)data[size - ctrl_len] % (max_steps + 1);
}

/* Decode one bounded control value, byte-for-byte the way the engine's
 * `decode_bounded_range` does. The two MUST agree: the engine describes these
 * slots to its structure-aware sequence mutator, and if the harness read them
 * by a different rule the mutator would be retargeting operations the harness
 * never selects.
 *
 * Slot layout is a selector byte plus a 4-byte little-endian value. A selector
 * divisible by 4 means "take a boundary value" (min, min+1, max-1, max, ...);
 * anything else means "take the 32-bit value, modulo the range". */
static inline uint32_t gf_ctrl_bounded(const uint8_t *data, size_t at, uint32_t min,
                                       uint32_t max) {
    uint8_t selector;
    uint32_t raw;
    if (max <= min) return min;
    selector = data[at];
    if (selector % 4 == 0) {
        switch (selector % 6) {
        case 0: raw = min; break;
        case 1: raw = min + 1; break;
        case 2: raw = max - 1; break;
        case 3: raw = max; break;
        case 4: raw = 0; break;
        default: raw = 0xffffffffu; break;
        }
        if (raw < min) raw = min;
        if (raw > max) raw = max;
        return raw;
    }
    raw = (uint32_t)data[at + 1]
        | ((uint32_t)data[at + 2] << 8)
        | ((uint32_t)data[at + 3] << 16)
        | ((uint32_t)data[at + 4] << 24);
    return min + raw % (max - min + 1);
}

static inline uint32_t gf_ctrl_op(const uint8_t *data, size_t size, size_t step,
                                  size_t max_steps, uint32_t op_count) {
    size_t ctrl_len = GF_CTRL_LEN(max_steps);
    size_t at;
    if (op_count == 0 || step >= max_steps || size < ctrl_len) return 0;
    at = size - ctrl_len + 1 + step * GF_CTRL_SLOT;
    return gf_ctrl_bounded(data, at, 0, op_count - 1);
}

static inline uint8_t gf_u8(gf_cursor *c) {
    if (gf_remaining(c) == 0) return 0;
    return c->data[c->pos++];
}

static inline int32_t gf_i32(gf_cursor *c) {
    uint32_t v = 0;
    int i;
    for (i = 0; i < 4 && gf_remaining(c) > 0; ++i) {
        v |= ((uint32_t)c->data[c->pos++]) << (i * 8);
    }
    return (int32_t)v;
}

static inline int64_t gf_i64(gf_cursor *c) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8 && gf_remaining(c) > 0; ++i) {
        v |= ((uint64_t)c->data[c->pos++]) << (i * 8);
    }
    return (int64_t)v;
}

static inline int32_t gf_bounded_i32(gf_cursor *c, int32_t lo, int32_t hi) {
    uint32_t range = (uint32_t)(hi - lo) + 1u;
    uint32_t raw = (uint32_t)gf_i32(c);
    if (hi <= lo) return lo;
    return lo + (int32_t)(raw % range);
}

static inline size_t gf_bounded_length(gf_cursor *c, size_t lo, size_t hi) {
    size_t range = (hi - lo) + 1;
    size_t raw = (size_t)gf_i64(c);
    if (hi <= lo) return lo;
    return lo + (raw % range);
}

/* Allocate a NUL-terminated heap buffer of up to `max` bytes. A 16-bit
 * little-endian length prefix is read first (clamped to [0, max] and to
 * remaining bytes) so that subsequent parameters still see fresh input. The
 * target always receives a valid (possibly empty) pointer. Caller frees with
 * free(). */
static inline char *gf_c_string(gf_cursor *c, size_t max) {
    uint16_t prefix = 0;
    size_t avail;
    size_t want;
    char *out;
    prefix |= (uint16_t)gf_u8(c);
    prefix |= ((uint16_t)gf_u8(c)) << 8;
    avail = gf_remaining(c);
    want = (size_t)prefix;
    if (want > max) want = max;
    if (want > avail) want = avail;
    out = (char *)malloc(want + 1);
    if (!out) return NULL;
    if (want > 0) memcpy(out, c->data + c->pos, want);
    out[want] = '\0';
    c->pos += want;
    return out;
}

/* Like gf_c_string, but the ALLOCATION is a fixed `cap` rather than a
 * fuzzer-chosen length.
 *
 * A WRITABLE `char *` parameter is an output (or in-out) buffer: the callee may
 * write into it, and the capacity it requires is stated only at the call site,
 * never in the signature. Sizing the allocation from the input therefore makes
 * any write into it a guaranteed heap overflow reported against the target.
 * Measured on libexpat's `getXMLCharset(const char *buf, char *charset)`, which
 * does `strcpy(charset, "us-ascii")` and whose only real caller declares
 * `char buf[CHARSET_MAX]`: a 1-byte fuzzer-chosen allocation made ASan fire on
 * correct library code.
 *
 * The CONTENT is still fuzz-driven — up to `cap` input bytes are copied — so an
 * in-out or plain input use loses nothing. Caller frees with free(). */
static inline char *gf_c_string_out(gf_cursor *c, size_t cap) {
    size_t avail;
    size_t want;
    char *out;
    out = (char *)malloc(cap + 1);
    if (!out) return NULL;
    memset(out, 0, cap + 1);
    avail = gf_remaining(c);
    want = avail < cap ? avail : cap;
    if (want > 0) memcpy(out, c->data + c->pos, want);
    c->pos += want;
    return out;
}

/* Like gf_c_string, but NEUTRALISES printf-style format specifiers by replacing
 * every '%' with a space. A variadic format function (log.c's
 * `log_log(..., const char *fmt, ...)`) takes a format string, but the harness
 * passes NO matching variadic arguments — so a '%s'/'%n' in a fuzzed format makes
 * vfprintf read a garbage vararg and crash. That is a harness format/argument
 * MISMATCH (the function is fine when called with matching args), not a target
 * bug; a %-free format calls it correctly. Used for parameters named fmt/format. */
static inline char *gf_c_format_string(gf_cursor *c, size_t max) {
    char *out = gf_c_string(c, max);
    if (out) {
        char *p;
        for (p = out; *p; ++p) {
            if (*p == '%') {
                *p = ' ';
            }
        }
    }
    return out;
}

/* Wide-char (wchar_t) analog of gf_c_string: a NUL-terminated heap wchar_t
 * buffer of up to `max` characters, decoded from the fuzz bytes (a 16-bit LE
 * length prefix, clamped to [0, max] and to the remaining whole wchar_t units).
 * For wide-string parameters (`const wchar_t *path`). Without this a wchar_t*
 * param decays to a pointer at a single non-NUL stack unit and the callee's
 * wcslen walks off the end (a harness false OOB). Caller frees with free(). */
static inline wchar_t *gf_wc_string(gf_cursor *c, size_t max) {
    uint16_t prefix = 0;
    size_t avail_chars;
    size_t want;
    size_t nbytes;
    wchar_t *out;
    prefix |= (uint16_t)gf_u8(c);
    prefix |= ((uint16_t)gf_u8(c)) << 8;
    want = (size_t)prefix;
    if (want > max) want = max;
    avail_chars = gf_remaining(c) / sizeof(wchar_t);
    if (want > avail_chars) want = avail_chars;
    out = (wchar_t *)malloc((want + 1) * sizeof(wchar_t));
    if (!out) return NULL;
    nbytes = want * sizeof(wchar_t);
    if (nbytes > 0) memcpy(out, c->data + c->pos, nbytes);
    out[want] = 0;
    c->pos += nbytes;
    return out;
}

/* Write `size` bytes of `data` to a fresh temp file and return its path (stored
 * in caller-owned `path_buf`, which MUST be at least `gf_tempfile_path_len`
 * bytes), or NULL on failure. For APIs that take a FILE PATH (not a FILE* or a
 * buffer) — the file's CONTENT is the fuzz input, mirroring `fmemopen` for FILE*.
 * The caller unlinks `path_buf` after the call. POSIX only; on platforms without
 * mkstemp the path-param falls back to an empty-string decoder upstream. */
#define gf_tempfile_path_len 20
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <unistd.h>
static inline const char *gf_make_tempfile(const uint8_t *data, size_t size, char *path_buf) {
    static const char tmpl[gf_tempfile_path_len] = "/tmp/gf_inXXXXXX";
    int fd;
    memcpy(path_buf, tmpl, sizeof(tmpl));
    fd = mkstemp(path_buf);
    if (fd < 0) return NULL;
    if (size) {
        ssize_t w = write(fd, data, size);
        (void)w;
    }
    close(fd);
    return path_buf;
}
#else
static inline const char *gf_make_tempfile(const uint8_t *data, size_t size, char *path_buf) {
    (void)data;
    (void)size;
    if (path_buf) path_buf[0] = '\0';
    return NULL;
}
#endif

/* Lend the rest of the input as a (ptr, size) span. Lifetime matches the
 * cursor's backing buffer (the libFuzzer input). No allocation. */
static inline void gf_data_slice(gf_cursor *c, const uint8_t **ptr, size_t *size) {
    *ptr = c->data + c->pos;
    *size = gf_remaining(c);
    c->pos = c->size;
}

#ifdef __cplusplus
}
#endif

#endif /* GOVFUZZ_DECODE_H */
