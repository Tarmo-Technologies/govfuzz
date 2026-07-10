// SPDX-License-Identifier: Apache-2.0

//! Cross-compilation target resolution for foreign-platform/arch candidates.
//!
//! `discovery` tags a candidate whose definition is guarded by a non-host
//! platform/arch conditional with a `foreign_guard` string — C/C++ `#ifdef`
//! macros (`_WIN32`, `_MSC_VER`, `__APPLE__`), Ada platform unit suffixes
//! (`win32`, `darwin`), or SIMD-arch backend dirs (`arm64`, `aarch64`, `neon`).
//! Rather than pre-skipping such a candidate, the attempt loop asks
//! [`resolve_cross_target`] whether this host carries a cross toolchain + an
//! emulator that can build and run it, and — when [`CrossTarget::available`]
//! holds — builds with the cross `CC`/`CXX` and runs the harness under the
//! resolved emulator (qemu-user, or wine).

use std::path::Path;

/// A resolved cross toolchain + emulator for a foreign-platform/arch candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossTarget {
    /// GNU target triple (e.g. `aarch64-linux-gnu`, `x86_64-w64-mingw32`).
    pub triple: String,
    /// Cross C compiler (e.g. `aarch64-linux-gnu-gcc`).
    pub cc: String,
    /// Cross C++ compiler (e.g. `aarch64-linux-gnu-g++`).
    pub cxx: String,
    /// How a cross-built harness is executed on this host.
    pub runner: CrossRunner,
}

/// How a cross-built harness is executed on this (foreign-arch/OS) host. Both
/// variants simply prefix the harness argv with an emulator executable, so the
/// fuzz runner treats them identically (reusing runner.rs `harness_runner`'s
/// qemu-user path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossRunner {
    /// qemu-user emulation for a foreign Linux architecture (`qemu-aarch64`).
    QemuUser { exe: String },
    /// Wine for a Windows (mingw) PE target. `wine` just prefixes argv.
    Wine { exe: String },
}

impl CrossRunner {
    /// The emulator executable that prefixes the harness argv.
    pub fn exe(&self) -> &str {
        match self {
            CrossRunner::QemuUser { exe } | CrossRunner::Wine { exe } => exe,
        }
    }
}

impl CrossTarget {
    /// True when both the cross compiler (`cc`) and the runner emulator are
    /// resolvable on `PATH`. The attempt loop only proceeds to cross-build+fuzz
    /// when this holds; otherwise it skips with an actionable "install X" reason
    /// built from [`CrossTarget::missing_tools`].
    pub fn available(&self) -> bool {
        self.missing_tools().is_empty()
    }

    /// The subset of `{cc, runner exe}` that is NOT on `PATH`, in declaration
    /// order. Empty iff [`CrossTarget::available`]. Drives the actionable skip
    /// reason naming exactly what to install.
    pub fn missing_tools(&self) -> Vec<&str> {
        [self.cc.as_str(), self.runner.exe()]
            .into_iter()
            .filter(|exe| !executable_on_path(exe))
            .collect()
    }

    /// One-line human description of the toolchain this target needs, used in
    /// the actionable skip reason (e.g. "aarch64-linux-gnu toolchain
    /// (aarch64-linux-gnu-gcc, aarch64-linux-gnu-g++) + qemu-aarch64").
    pub fn toolchain_hint(&self) -> String {
        format!(
            "{} toolchain ({}, {}) + {}",
            self.triple,
            self.cc,
            self.cxx,
            self.runner.exe()
        )
    }
}

/// Resolve a foreign-platform discovery guard to the cross toolchain govfuzz can
/// drive on this host, or `None` for an unmapped target. Matching is a
/// case-insensitive substring test because guards arrive from three sources
/// (preprocessor macros, Ada unit suffixes, and path components) in many forms.
/// Order matters: the 64-bit ARM check must precede the generic 32-bit `arm`
/// check, since `arm64` contains the substring `arm`.
pub fn resolve_cross_target(foreign_guard: &str) -> Option<CrossTarget> {
    let guard = foreign_guard.to_ascii_lowercase();
    // Windows: any Windows platform macro / unit tag → mingw-w64, run under wine.
    if contains_any(
        &guard,
        &["windows", "win32", "win64", "_win32", "_msc_ver", "mingw"],
    ) {
        return Some(CrossTarget {
            triple: "x86_64-w64-mingw32".to_owned(),
            cc: "x86_64-w64-mingw32-gcc".to_owned(),
            cxx: "x86_64-w64-mingw32-g++".to_owned(),
            runner: CrossRunner::Wine {
                exe: "wine".to_owned(),
            },
        });
    }
    // 64-bit ARM (incl. NEON SIMD backends) → aarch64 cross toolchain + qemu.
    if contains_any(&guard, &["arm64", "aarch64", "neon"]) {
        return Some(CrossTarget {
            triple: "aarch64-linux-gnu".to_owned(),
            cc: "aarch64-linux-gnu-gcc".to_owned(),
            cxx: "aarch64-linux-gnu-g++".to_owned(),
            runner: CrossRunner::QemuUser {
                exe: "qemu-aarch64".to_owned(),
            },
        });
    }
    // 32-bit ARM → armhf cross toolchain + qemu.
    if contains_any(&guard, &["armv7", "armhf", "arm"]) {
        return Some(CrossTarget {
            triple: "arm-linux-gnueabihf".to_owned(),
            cc: "arm-linux-gnueabihf-gcc".to_owned(),
            cxx: "arm-linux-gnueabihf-g++".to_owned(),
            runner: CrossRunner::QemuUser {
                exe: "qemu-arm".to_owned(),
            },
        });
    }
    None
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

/// A synthesized fake platform header (filename + content) written beside the
/// generated harness so the target's `#include <name>` resolves to our stub
/// instead of an absent real platform SDK header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthHeader {
    pub name: String,
    pub content: String,
}

/// The recipe for a STUB-ISOLATED native build of an OS-platform-guarded target
/// that this host cannot cross-compile/emulate faithfully. We compile the foreign
/// branch on the host by (1) `#define`-ing the platform guard macro so the code is
/// visible and (2) supplying fake platform headers/types so it type-checks; the
/// existing stub machinery fills in any leftover platform functions. Findings are
/// REDUCED-FIDELITY (the platform behavior is faked), which the report must flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformStub {
    /// Short platform label for the report (e.g. `windows`).
    pub platform: String,
    /// The guard macro to define so the foreign branch compiles (e.g. `_WIN32`).
    /// Defined to `1` so both `#ifdef GUARD` and `#if GUARD` forms are satisfied.
    pub define: String,
    /// Fake platform headers to drop beside the harness (resolved via the
    /// Makefile's existing `-I .`), so `#include <windows.h>` type-checks.
    pub headers: Vec<SynthHeader>,
}

/// Classify an OS-platform foreign guard to a [`PlatformStub`] recipe, or `None`
/// for guards that are NOT a stubable OS platform (CPU-arch/SIMD guards go through
/// [`resolve_cross_target`] instead, and unknown guards are skipped). Covers
/// Windows plus the RTOS/vendor platforms a Linux lab host cannot run faithfully —
/// VxWorks (`__vxworks`), Green Hills INTEGRITY (`__INTEGRITY`), QNX (`__QNX__`) —
/// for which a stub-isolated native build is the only practical strategy. The
/// match is case-insensitive substring, matching the forms `discovery` emits
/// (`_WIN32`/`_MSC_VER`/`mingw`, `__vxworks`/`__VXWORKS__`, Ada `*_vxworks` unit
/// tags, `__INTEGRITY`, `__QNX__`/`__QNXNTO__`).
pub fn foreign_platform_stub(guard: &str) -> Option<PlatformStub> {
    let g = guard.to_ascii_lowercase();
    if contains_any(
        &g,
        &["windows", "win32", "win64", "_win32", "_msc_ver", "mingw"],
    ) {
        return Some(PlatformStub {
            platform: "windows".to_owned(),
            define: "_WIN32".to_owned(),
            headers: vec![
                SynthHeader {
                    name: "windows.h".to_owned(),
                    content: WINDOWS_H_STUB.to_owned(),
                },
                SynthHeader {
                    name: "io.h".to_owned(),
                    content: IO_H_STUB.to_owned(),
                },
                SynthHeader {
                    name: "_govfuzz_crt_compat.h".to_owned(),
                    content: CRT_COMPAT_STUB.to_owned(),
                },
                // MFC/ATL surface (CString, CWnd, message-map macros). Force-
                // included AFTER windows.h so it sees BOOL/LPCTSTR. Supplied under
                // the two most common include spellings; other afx*/atl* includes
                // fall back to empty repair placeholders, and the content is
                // already force-included so CString resolves regardless.
                SynthHeader {
                    name: "afxwin.h".to_owned(),
                    content: MFC_STUB.to_owned(),
                },
                SynthHeader {
                    name: "atlstr.h".to_owned(),
                    content: MFC_STUB.to_owned(),
                },
            ],
        });
    }
    // RTOS / vendor platforms. We cannot run a VxWorks/INTEGRITY/QNX image on
    // this host, so the only practical lab strategy is a stub-isolated NATIVE
    // build: define the platform guard so the RTOS branch is visible and supply
    // fake platform headers so the algorithmic code (parsers, protocol/radar
    // signal processing) type-checks and fuzzes on the host with sanitizers. The
    // headers listed here are flat (force-included for their types); the repair
    // loop additionally supplies any RTOS header by `#include` spelling via
    // [`platform_header_stub`] (including subdir spellings like `sys/neutrino.h`).
    if contains_any(&g, &["vxworks"]) {
        return Some(PlatformStub {
            platform: "vxworks".to_owned(),
            define: "__vxworks".to_owned(),
            headers: vec![
                SynthHeader {
                    name: "vxWorks.h".to_owned(),
                    content: VXWORKS_H_STUB.to_owned(),
                },
                SynthHeader {
                    name: "taskLib.h".to_owned(),
                    content: TASKLIB_H_STUB.to_owned(),
                },
                SynthHeader {
                    name: "semLib.h".to_owned(),
                    content: SEMLIB_H_STUB.to_owned(),
                },
                SynthHeader {
                    name: "msgQLib.h".to_owned(),
                    content: MSGQLIB_H_STUB.to_owned(),
                },
            ],
        });
    }
    if contains_any(&g, &["integrity"]) {
        return Some(PlatformStub {
            platform: "integrity".to_owned(),
            define: "__INTEGRITY".to_owned(),
            headers: vec![SynthHeader {
                name: "INTEGRITY.h".to_owned(),
                content: INTEGRITY_H_STUB.to_owned(),
            }],
        });
    }
    if contains_any(&g, &["qnx", "neutrino"]) {
        return Some(PlatformStub {
            platform: "qnx".to_owned(),
            define: "__QNX__".to_owned(),
            // `sys/neutrino.h` is a subdir spelling; the repair loop places it at
            // the right path via `platform_header_stub`. The guard `define` alone
            // makes a `#ifdef __QNX__` branch visible.
            headers: Vec::new(),
        });
    }
    None
}

/// A self-contained fake `<windows.h>`: the common Win32 scalar/handle typedefs
/// and a few ubiquitous macros, mapped onto fixed-width host types. Enough to
/// type-check portable Win32 logic for fuzzing; the actual platform *behavior*
/// is NOT modeled (handles are inert `void *`), hence reduced-fidelity findings.
pub(crate) const WINDOWS_H_STUB: &str = r#"/* govfuzz synthesized fake <windows.h> — reduced-fidelity platform stub.
 * Maps the common Win32 type surface onto host fixed-width types so portable
 * Win32 logic type-checks for fuzzing. Platform behavior is NOT modeled. */
#ifndef GOVFUZZ_FAKE_WINDOWS_H
#define GOVFUZZ_FAKE_WINDOWS_H
#include <stdint.h>
#include <stddef.h>

typedef unsigned char       BYTE, BOOLEAN, UCHAR;
typedef char                CHAR;
typedef unsigned short      WORD, USHORT, WCHAR;
typedef short               SHORT;
typedef unsigned int        UINT, DWORD32, ULONG32;
typedef int                 INT, BOOL, WINBOOL;
typedef unsigned long       ULONG, DWORD;
typedef long                LONG;
typedef unsigned long long  ULONGLONG, DWORD64, QWORD;
typedef long long           LONGLONG, INT64;
typedef float               FLOAT;
typedef double              DOUBLE;
typedef void                VOID;

typedef void *              PVOID, *LPVOID, *HANDLE, *HMODULE, *HINSTANCE, *HWND,
                            *HKEY, *HLOCAL, *HGLOBAL, *HDC, *HBITMAP, *HMENU;
typedef const void *        PCVOID, *LPCVOID;
typedef CHAR *              PSTR, *LPSTR, *PCHAR;
typedef const CHAR *        PCSTR, *LPCSTR;
typedef WCHAR *             PWSTR, *LPWSTR, *PWCHAR;
typedef const WCHAR *       PCWSTR, *LPCWSTR;
typedef BYTE *              PBYTE, *LPBYTE;
typedef WORD *              PWORD, *LPWORD;
typedef DWORD *             PDWORD, *LPDWORD;
typedef BOOL *              PBOOL, *LPBOOL;
typedef UCHAR *             PUCHAR;
typedef CHAR                TCHAR;
typedef LPCSTR              LPCTSTR;
typedef LPSTR               LPTSTR;

typedef size_t              SIZE_T, ULONG_PTR, DWORD_PTR, UINT_PTR;
typedef ptrdiff_t           SSIZE_T, LONG_PTR, INT_PTR;
typedef UINT_PTR            WPARAM;
typedef LONG_PTR            LPARAM, LRESULT;

typedef union _LARGE_INTEGER { struct { DWORD LowPart; LONG HighPart; } u; LONGLONG QuadPart; } LARGE_INTEGER;
typedef union _ULARGE_INTEGER { struct { DWORD LowPart; DWORD HighPart; } u; ULONGLONG QuadPart; } ULARGE_INTEGER;

#ifndef WINAPI
#define WINAPI
#endif
#define APIENTRY
#define CALLBACK
#define WINAPIV
#define CONST const
#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif

/* File / memory-mapping flags the govfuzz driver's Windows input path passes. */
#ifndef GENERIC_READ
#define GENERIC_READ            0x80000000UL
#define GENERIC_WRITE           0x40000000UL
#define FILE_SHARE_READ         0x00000001UL
#define FILE_SHARE_WRITE        0x00000002UL
#define OPEN_ALWAYS             4
#define FILE_ATTRIBUTE_NORMAL   0x00000080UL
#define PAGE_READWRITE          0x04
#define FILE_MAP_ALL_ACCESS     0x000F001FUL
#endif

/* Structured-exception codes the driver's vectored handler switches on. REAL,
 * DISTINCT values — a single shared value (e.g. all 0) collapses the switch to
 * duplicate `case` labels, a hard compile error under modern clang. */
#ifndef EXCEPTION_ACCESS_VIOLATION
#define EXCEPTION_ACCESS_VIOLATION      0xC0000005UL
#define EXCEPTION_DATATYPE_MISALIGNMENT 0x80000002UL
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED 0xC000008CUL
#define EXCEPTION_ILLEGAL_INSTRUCTION   0xC000001DUL
#define EXCEPTION_INT_DIVIDE_BY_ZERO    0xC0000094UL
#define EXCEPTION_STACK_OVERFLOW        0xC00000FDUL
#define EXCEPTION_CONTINUE_SEARCH       0L
#endif

typedef struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    void *ExceptionAddress;
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;
typedef struct _CONTEXT { DWORD ContextFlags; } CONTEXT, *PCONTEXT;
typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT          ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
typedef LONG (CALLBACK *PVECTORED_EXCEPTION_HANDLER)(EXCEPTION_POINTERS *);

/* Inert definitions of the Win32 calls the driver makes — declared AND defined so
 * the driver compiles + links with no repair-loop stubbing. Behavior is NOT
 * modeled (handles are inert): file-mapping fails closed so the driver uses its
 * framed-fd input path, and the vectored-handler install is a no-op. Enough to
 * build + run the fuzz cascade on the host (reduced-fidelity, as the report flags).
 * `static inline` => internal linkage, no unused-function warning in TUs that
 * force-include this header without calling them (e.g. the target source). */
static inline HANDLE CreateFileA(LPCSTR path, DWORD access, DWORD share, void *sa,
                                 DWORD disp, DWORD flags, HANDLE tmpl) {
    (void)path; (void)access; (void)share; (void)sa; (void)disp; (void)flags; (void)tmpl;
    return INVALID_HANDLE_VALUE;
}
static inline HANDLE CreateFileMappingA(HANDLE file, void *sa, DWORD prot, DWORD hi,
                                        DWORD lo, LPCSTR name) {
    (void)file; (void)sa; (void)prot; (void)hi; (void)lo; (void)name;
    return (HANDLE)0;
}
static inline LPVOID MapViewOfFile(HANDLE map, DWORD access, DWORD hi, DWORD lo, SIZE_T n) {
    (void)map; (void)access; (void)hi; (void)lo; (void)n;
    return (LPVOID)0;
}
static inline BOOL CloseHandle(HANDLE h) { (void)h; return 1; }
static inline HANDLE GetCurrentProcess(void) { return INVALID_HANDLE_VALUE; }
static inline BOOL TerminateProcess(HANDLE proc, UINT code) { (void)proc; (void)code; return 1; }
static inline PVOID AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER h) {
    (void)first; (void)h; return (PVOID)0;
}

#endif /* GOVFUZZ_FAKE_WINDOWS_H */
"#;

/// A self-contained fake `<io.h>`: maps the MSVC CRT low-level I/O names the
/// driver's Windows branch uses (`_read`, `_dup`, `_setmode`, …) onto their POSIX
/// equivalents, so the host stub build links them to the real syscalls. `_setmode`
/// / `_O_BINARY` are no-ops on POSIX (no text-mode translation to undo).
const IO_H_STUB: &str = r#"/* govfuzz synthesized fake <io.h> — reduced-fidelity platform stub.
 * Maps the MSVC CRT low-level I/O names onto POSIX so the host build links. */
#ifndef GOVFUZZ_FAKE_IO_H
#define GOVFUZZ_FAKE_IO_H
#include <unistd.h>
#include <fcntl.h>
#define _read   read
#define _write  write
#define _close  close
#define _dup    dup
#define _dup2   dup2
#define _open   open
#ifndef _O_BINARY
#define _O_BINARY 0
#endif
#ifndef _setmode
#define _setmode(fd, mode) ((void)(fd), (void)(mode), 0)
#endif
#endif /* GOVFUZZ_FAKE_IO_H */
"#;

/// A self-contained CRT-compat header force-included into the StubIsolated host
/// build. MSVC spells a handful of standard functions with a leading underscore
/// (`_vsnprintf`, `_snprintf`, `_stricmp`, `_strdup`); they are declared by MSVC's
/// `<stdio.h>`/`<string.h>` but NOT glibc's, so a `#ifdef _WIN32` branch that calls
/// them (frozen's `cs_win_vsnprintf` → `_vsnprintf`) hits "call to undeclared
/// function" on the host. Alias each to the glibc spelling — token-for-token
/// equivalent signatures, so a plain `#define` carries the varargs through. The
/// MSVC truncation/NUL-termination edge cases differ, but StubIsolated findings are
/// already flagged reduced-fidelity. The header pulls in the glibc declarations so
/// the aliased names resolve even when the target source doesn't itself include
/// them. `_vscprintf` (needed length) maps to a `vsnprintf(NULL, 0, …)` probe.
const CRT_COMPAT_STUB: &str = r#"/* govfuzz synthesized MSVC CRT compat — reduced-fidelity platform stub.
 * Maps underscore-prefixed MSVC CRT names onto their glibc equivalents so a
 * `#ifdef _WIN32` branch built natively on the host compiles + links. */
#ifndef GOVFUZZ_FAKE_CRT_COMPAT_H
#define GOVFUZZ_FAKE_CRT_COMPAT_H
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
/* Each MSVC name maps to a `static inline` wrapper, NOT a bare `#define _x x`
 * alias, on purpose. A target may itself hijack the base name — frozen does
 * `#define vsnprintf cs_win_vsnprintf` and then calls `_vsnprintf` inside that
 * wrapper. A bare `#define _vsnprintf vsnprintf` would re-expand through the
 * target's macro to `cs_win_vsnprintf`, making the wrapper call ITSELF (infinite
 * recursion). The wrapper bodies are parsed HERE — force-included before the
 * target's `#define` — so their `vsnprintf`/`strcasecmp`/… bind to the REAL glibc
 * functions, and the `_x -> wrapper` macro can't be re-hijacked downstream.
 * MSVC truncation/NUL-termination edge cases differ slightly; StubIsolated
 * findings are already flagged reduced-fidelity. */
static inline int _gf_crt_vsnprintf(char *_s, size_t _n, const char *_f, va_list _a) {
    return vsnprintf(_s, _n, _f, _a);
}
static inline int _gf_crt_snprintf(char *_s, size_t _n, const char *_f, ...) {
    va_list _a; int _r;
    va_start(_a, _f); _r = vsnprintf(_s, _n, _f, _a); va_end(_a);
    return _r;
}
static inline int _gf_crt_vscprintf(const char *_f, va_list _a) {
    return vsnprintf((char *)0, (size_t)0, _f, _a);
}
static inline int _gf_crt_stricmp(const char *_a, const char *_b) {
    return strcasecmp(_a, _b);
}
static inline int _gf_crt_strnicmp(const char *_a, const char *_b, size_t _n) {
    return strncasecmp(_a, _b, _n);
}
static inline char *_gf_crt_strdup(const char *_s) { return strdup(_s); }
#define _vsnprintf _gf_crt_vsnprintf
#define _snprintf _gf_crt_snprintf
#define _vscprintf _gf_crt_vscprintf
#define _stricmp _gf_crt_stricmp
#define _strnicmp _gf_crt_strnicmp
#define _strdup _gf_crt_strdup
/* A real Windows toolchain always defines a compiler-identity macro (MSVC sets
 * _MSC_VER; mingw sets __GNUC__). With only _WIN32 forced and _MSC_VER absent,
 * a `#if defined(_WIN32) && _MSC_VER < 1700` ladder evaluates _MSC_VER as 0 and
 * takes the pre-VS2012 path — e.g. frozen's `typedef int bool;`, which collides
 * with glibc <stdbool.h> ("cannot combine with previous 'int'"). Claim a modern
 * MSVC (VS2015) so version ladders select their C99/standard branch, which is
 * also the most clang-compatible. Defined AFTER the glibc includes above so those
 * headers parse under their normal (non-MSVC) identity. */
#ifndef _MSC_VER
#define _MSC_VER 1900
#endif
/* Claiming _MSC_VER flips clang's <stddef.h> into its MSVC branch, where
 * __stddef_wchar_t.h does `typedef __WCHAR_TYPE__ wchar_t;` UNLESS the native
 * wchar_t type is advertised: the guard is
 *   #if !defined(__cplusplus) || (defined(_MSC_VER) && !_NATIVE_WCHAR_T_DEFINED)
 * In C++ `wchar_t` is a builtin keyword, so that typedef fails to compile with
 * "cannot combine with previous 'int' declaration specifier" the moment any
 * TU pulls <cstddef>/<cstdlib> (i.e. every C++ harness). Advertise the native
 * wchar_t (the MSVC `/Zc:wchar_t` default since VS2005) so the typedef branch
 * is skipped; also set _WCHAR_T_DEFINED so CRT headers don't re-typedef it. */
#ifndef _NATIVE_WCHAR_T_DEFINED
#define _NATIVE_WCHAR_T_DEFINED 1
#endif
#ifndef _WCHAR_T_DEFINED
#define _WCHAR_T_DEFINED 1
#endif
#endif /* GOVFUZZ_FAKE_CRT_COMPAT_H */
"#;

/// A reduced-fidelity MFC/ATL surface: enough of `CString`, the common window
/// classes, and the message-map/RTTI macros for portable MFC application logic
/// to type-check and fuzz on the host. `CString` is backed by `std::string`
/// (narrow only — wide strings are accepted but not modeled). This is
/// govfuzz-authored scaffolding, NOT Microsoft's headers, so nothing proprietary
/// is bundled. Force-included AFTER windows.h, so BOOL/LPCTSTR are visible; the
/// class definitions are `#ifdef __cplusplus`-guarded because the same stub is
/// force-included into C translation units too.
pub(crate) const MFC_STUB: &str = r#"/* govfuzz synthesized MFC/ATL compat — reduced-fidelity platform stub.
 * A minimal CString + window classes + message-map macros so portable MFC logic
 * type-checks for fuzzing. NOT Microsoft MFC headers; behavior is not modeled. */
#ifndef GOVFUZZ_FAKE_MFC_H
#define GOVFUZZ_FAKE_MFC_H

/* Message-map / RTTI / annotation macros expand to nothing (or a benign body)
 * so class declarations that use them still parse. Valid in both C and C++. */
#define DECLARE_MESSAGE_MAP()
#define BEGIN_MESSAGE_MAP(a, b)
#define END_MESSAGE_MAP()
#define DECLARE_DYNCREATE(a)
#define IMPLEMENT_DYNCREATE(a, b)
#define DECLARE_DYNAMIC(a)
#define IMPLEMENT_DYNAMIC(a, b)
#define DECLARE_SERIAL(a)
#define IMPLEMENT_SERIAL(a, b, c)
#define afx_msg
#ifndef AFX_MANAGE_STATE
#define AFX_MANAGE_STATE(a)
#endif

#ifdef __cplusplus
#include <string>
#include <cstdarg>
#include <cstdio>

class CString {
public:
    CString() {}
    CString(const char *s) : s_(s ? s : "") {}
    CString(const char *s, int n) : s_(s ? s : "", (s && n > 0) ? (unsigned)n : 0u) {}
    CString(const CString &o) : s_(o.s_) {}
    CString(const wchar_t *) {}          /* wide not modeled (reduced fidelity) */
    ~CString() {}
    int GetLength() const { return (int)s_.size(); }
    bool IsEmpty() const { return s_.empty(); }
    void Empty() { s_.clear(); }
    const char *GetString() const { return s_.c_str(); }
    operator const char *() const { return s_.c_str(); }
    char GetAt(int i) const { return (i >= 0 && (unsigned)i < s_.size()) ? s_[(unsigned)i] : 0; }
    char operator[](int i) const { return GetAt(i); }
    CString &operator=(const char *s) { s_ = s ? s : ""; return *this; }
    CString &operator=(const CString &o) { s_ = o.s_; return *this; }
    CString &operator+=(const CString &o) { s_ += o.s_; return *this; }
    CString &operator+=(const char *s) { if (s) s_ += s; return *this; }
    bool operator==(const CString &o) const { return s_ == o.s_; }
    bool operator!=(const CString &o) const { return s_ != o.s_; }
    int Compare(const char *s) const { return s_.compare(s ? s : ""); }
    void Format(const char *fmt, ...) {
        char buf[1024];
        va_list a; va_start(a, fmt);
        int n = vsnprintf(buf, sizeof buf, fmt ? fmt : "", a);
        va_end(a);
        s_.assign(buf, (n > 0 && (unsigned)n < sizeof buf) ? (unsigned)n : 0u);
    }
private:
    std::string s_;
};
typedef CString CStringA;
typedef CString CStringW;

class CObject { public: CObject() {} virtual ~CObject() {} };
class CWnd : public CObject { public: CWnd() {} virtual ~CWnd() {} };
class CDialog : public CWnd { public: CDialog() {} explicit CDialog(int) {} };
class CFrameWnd : public CWnd { public: CFrameWnd() {} };
class CView : public CWnd { public: CView() {} };
class CWinApp : public CObject { public: CWinApp() {} virtual ~CWinApp() {} };
class CDataExchange { public: CWnd *m_pDlgWnd; CDataExchange() : m_pDlgWnd(0) {} };
class CException : public CObject { public: CException() {} };

#endif /* __cplusplus */
#endif /* GOVFUZZ_FAKE_MFC_H */
"#;

/// Win32 typedef/macro names govfuzz can satisfy with real underlying types from
/// `WINDOWS_H_STUB`. Kept in sync with that stub by
/// `win32_and_mfc_name_sets_are_covered_by_the_stubs`.
pub(crate) fn win32_known_names() -> &'static [&'static str] {
    &[
        "BOOL",
        "DWORD",
        "BYTE",
        "WORD",
        "UINT",
        "PUCHAR",
        "LPBYTE",
        "LPVOID",
        "HANDLE",
        "HWND",
        "HINSTANCE",
        "LPCSTR",
        "LPSTR",
        "LPCTSTR",
        "TCHAR",
        "WCHAR",
        "ULONG",
        "LONG",
        "USHORT",
        "UCHAR",
    ]
}

pub(crate) fn is_win32_known_name(name: &str) -> bool {
    win32_known_names().contains(&name.trim())
}

/// True when `exe` is resolvable as an executable: a path with a separator is
/// checked as-is, a bare name is searched across `PATH` entries.
pub fn executable_on_path(exe: &str) -> bool {
    let path = Path::new(exe);
    if path.components().count() > 1 {
        return path.is_file();
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(exe).is_file()))
        .unwrap_or(false)
}

/// A rich fake for a recognized RTOS/vendor platform header, keyed by the
/// `#include` spelling's basename. Returned to the repair loop so a host build
/// that hits e.g. `vxWorks.h: file not found` gets a real type surface (STATUS,
/// SEM_ID, …) instead of an empty placeholder that cascades into a storm of
/// "unknown type" errors. This is the dominant path for *unguarded* RTOS code
/// (radar/avionics application code that simply `#include <vxWorks.h>` and is
/// built only by the vendor toolchain). Subdir spellings (`sys/neutrino.h`)
/// match on the basename; the repair loop places the file at the full path.
pub fn platform_header_stub(include_spelling: &str) -> Option<&'static str> {
    let base = Path::new(include_spelling)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(include_spelling)
        .to_ascii_lowercase();
    match base.as_str() {
        "vxworks.h" => Some(VXWORKS_H_STUB),
        "tasklib.h" => Some(TASKLIB_H_STUB),
        "semlib.h" => Some(SEMLIB_H_STUB),
        "msgqlib.h" => Some(MSGQLIB_H_STUB),
        "integrity.h" => Some(INTEGRITY_H_STUB),
        "neutrino.h" => Some(NEUTRINO_H_STUB),
        _ => None,
    }
}

/// Self-contained fake `<vxWorks.h>`: the base Wind River type surface mapped
/// onto host fixed-width types, plus the platform guard macros so guarded code is
/// visible. Behavior is NOT modeled (handles are inert) — reduced fidelity.
const VXWORKS_H_STUB: &str = r#"/* govfuzz synthesized fake <vxWorks.h> — reduced-fidelity RTOS stub. */
#ifndef GOVFUZZ_FAKE_VXWORKS_H
#define GOVFUZZ_FAKE_VXWORKS_H
#include <stdint.h>
#include <stddef.h>
#ifndef __vxworks
#define __vxworks 1
#endif
#ifndef __VXWORKS__
#define __VXWORKS__ 1
#endif

typedef int                 STATUS, BOOL;
typedef unsigned char       UCHAR, UINT8;
typedef unsigned short      USHORT, UINT16;
typedef unsigned int        UINT, UINT32, _Vx_usr_arg_t;
typedef unsigned long       ULONG;
typedef signed char         INT8;
typedef short               INT16;
typedef int                 INT32;
typedef unsigned long long  UINT64;
typedef long long           INT64;
typedef int                 (*FUNCPTR)(void);
typedef void                (*VOIDFUNCPTR)(void);
typedef void *              SEM_ID, *MSG_Q_ID, *WDOG_ID, *PART_ID;
typedef int                 TASK_ID, OBJ_ID;
typedef uintptr_t           Vx_ulong_t;

#ifndef OK
#define OK    0
#endif
#ifndef ERROR
#define ERROR (-1)
#endif
#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef NULL
#define NULL  ((void *)0)
#endif
#ifndef WAIT_FOREVER
#define WAIT_FOREVER (-1)
#endif
#ifndef NO_WAIT
#define NO_WAIT 0
#endif
#endif /* GOVFUZZ_FAKE_VXWORKS_H */
"#;

/// Fake `<taskLib.h>`: the common VxWorks task API as declarations (calls
/// type-check; govfuzz's stub machinery resolves the link).
const TASKLIB_H_STUB: &str = r#"/* govfuzz synthesized fake <taskLib.h> — reduced-fidelity RTOS stub. */
#ifndef GOVFUZZ_FAKE_TASKLIB_H
#define GOVFUZZ_FAKE_TASKLIB_H
#include "vxWorks.h"
TASK_ID taskSpawn(char *name, int priority, int options, int stackSize,
                  FUNCPTR entryPt, _Vx_usr_arg_t arg1, _Vx_usr_arg_t arg2,
                  _Vx_usr_arg_t arg3, _Vx_usr_arg_t arg4, _Vx_usr_arg_t arg5,
                  _Vx_usr_arg_t arg6, _Vx_usr_arg_t arg7, _Vx_usr_arg_t arg8,
                  _Vx_usr_arg_t arg9, _Vx_usr_arg_t arg10);
STATUS  taskDelete(TASK_ID tid);
STATUS  taskDelay(int ticks);
TASK_ID taskIdSelf(void);
STATUS  taskSuspend(TASK_ID tid);
STATUS  taskResume(TASK_ID tid);
#endif /* GOVFUZZ_FAKE_TASKLIB_H */
"#;

/// Fake `<semLib.h>`: VxWorks semaphore API + the option/timeout macros.
const SEMLIB_H_STUB: &str = r#"/* govfuzz synthesized fake <semLib.h> — reduced-fidelity RTOS stub. */
#ifndef GOVFUZZ_FAKE_SEMLIB_H
#define GOVFUZZ_FAKE_SEMLIB_H
#include "vxWorks.h"
#define SEM_Q_FIFO     0x0
#define SEM_Q_PRIORITY 0x1
#define SEM_EMPTY      0
#define SEM_FULL       1
SEM_ID semBCreate(int options, int initialState);
SEM_ID semMCreate(int options);
SEM_ID semCCreate(int options, int initialCount);
STATUS semTake(SEM_ID semId, int timeout);
STATUS semGive(SEM_ID semId);
STATUS semFlush(SEM_ID semId);
STATUS semDelete(SEM_ID semId);
#endif /* GOVFUZZ_FAKE_SEMLIB_H */
"#;

/// Fake `<msgQLib.h>`: VxWorks message-queue API + priority macros.
const MSGQLIB_H_STUB: &str = r#"/* govfuzz synthesized fake <msgQLib.h> — reduced-fidelity RTOS stub. */
#ifndef GOVFUZZ_FAKE_MSGQLIB_H
#define GOVFUZZ_FAKE_MSGQLIB_H
#include "vxWorks.h"
#define MSG_PRI_NORMAL 0
#define MSG_PRI_URGENT 1
MSG_Q_ID msgQCreate(int maxMsgs, int maxMsgLength, int options);
STATUS   msgQDelete(MSG_Q_ID msgQId);
STATUS   msgQSend(MSG_Q_ID msgQId, char *buffer, UINT nBytes, int timeout, int priority);
int      msgQReceive(MSG_Q_ID msgQId, char *buffer, UINT maxNBytes, int timeout);
#endif /* GOVFUZZ_FAKE_MSGQLIB_H */
"#;

/// Self-contained fake `<INTEGRITY.h>` (Green Hills INTEGRITY RTOS): the core
/// Error/Value/object type surface + the platform guard macro.
const INTEGRITY_H_STUB: &str = r#"/* govfuzz synthesized fake <INTEGRITY.h> — reduced-fidelity RTOS stub. */
#ifndef GOVFUZZ_FAKE_INTEGRITY_H
#define GOVFUZZ_FAKE_INTEGRITY_H
#include <stdint.h>
#include <stddef.h>
#ifndef __INTEGRITY
#define __INTEGRITY 1
#endif

typedef int            Error;
typedef unsigned int   Value;
typedef uintptr_t      Address;
typedef void *         Task, *Connection, *MessageQueue, *Semaphore, *Clock,
                      *IOObject, *Object, *ConnectionInfo;
typedef unsigned char  Boolean;

#ifndef Success
#define Success 0
#endif
#ifndef Failure
#define Failure 1
#endif
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif
#endif /* GOVFUZZ_FAKE_INTEGRITY_H */
"#;

/// Self-contained fake `<sys/neutrino.h>` (QNX Neutrino): the common kernel-call
/// type surface + the platform guard macros. Placed by the repair loop at
/// `sys/neutrino.h` so the angled include resolves.
const NEUTRINO_H_STUB: &str = r#"/* govfuzz synthesized fake <sys/neutrino.h> — reduced-fidelity RTOS stub. */
#ifndef GOVFUZZ_FAKE_NEUTRINO_H
#define GOVFUZZ_FAKE_NEUTRINO_H
#include <stdint.h>
#include <stddef.h>
#ifndef __QNX__
#define __QNX__ 1
#endif
#ifndef __QNXNTO__
#define __QNXNTO__ 1
#endif

typedef int            rcvid_t;
typedef int            coid_t;
typedef int            chid_t;
typedef unsigned       _Uint32t;
typedef unsigned long  _Uintptrt;

int ChannelCreate(unsigned flags);
int ChannelDestroy(int chid);
int ConnectAttach(_Uint32t nd, int pid, int chid, unsigned index, int flags);
int ConnectDetach(int coid);
long MsgSend(int coid, const void *smsg, size_t sbytes, void *rmsg, size_t rbytes);
int  MsgReceive(int chid, void *msg, size_t bytes, void *info);
int  MsgReply(int rcvid, long status, const void *msg, size_t bytes);
#endif /* GOVFUZZ_FAKE_NEUTRINO_H */
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win32_name_set_is_covered_by_the_stub() {
        // Whole-word match: `LONG` must not be satisfied by `ULONG`, nor `TCHAR`
        // by `LPCTSTR` — each advertised name must be defined in its own right.
        fn stub_defines_word(stub: &str, name: &str) -> bool {
            let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
            stub.match_indices(name).any(|(i, _)| {
                let before = stub[..i].chars().next_back();
                let after = stub[i + name.len()..].chars().next();
                before.is_none_or(|c| !is_ident(c)) && after.is_none_or(|c| !is_ident(c))
            })
        }
        for name in win32_known_names() {
            assert!(
                stub_defines_word(WINDOWS_H_STUB, name),
                "WINDOWS_H_STUB must define Win32 name `{name}` as a whole word"
            );
        }
        assert!(is_win32_known_name("BOOL"));
        assert!(is_win32_known_name("PUCHAR"));
        assert!(!is_win32_known_name("widget_t"));
        assert!(!is_win32_known_name("CString"));
    }

    #[test]
    fn resolves_windows_guards_to_mingw_wine() {
        // Covers the C/C++ macro forms and the Ada `__win32`-unit / mingw forms.
        for guard in ["windows", "win32", "win64", "_WIN32", "_MSC_VER", "mingw"] {
            let target = resolve_cross_target(guard).expect("windows guard resolves");
            assert_eq!(target.triple, "x86_64-w64-mingw32");
            assert_eq!(target.cc, "x86_64-w64-mingw32-gcc");
            assert_eq!(target.cxx, "x86_64-w64-mingw32-g++");
            assert_eq!(
                target.runner,
                CrossRunner::Wine {
                    exe: "wine".to_owned()
                }
            );
        }
    }

    #[test]
    fn resolves_aarch64_guards_to_qemu_aarch64() {
        // `arm64` must resolve here (64-bit), NOT to the 32-bit `arm` branch.
        for guard in ["arm64", "aarch64", "neon", "ARM64"] {
            let target = resolve_cross_target(guard).expect("aarch64 guard resolves");
            assert_eq!(target.triple, "aarch64-linux-gnu");
            assert_eq!(target.cc, "aarch64-linux-gnu-gcc");
            assert_eq!(target.cxx, "aarch64-linux-gnu-g++");
            assert_eq!(
                target.runner,
                CrossRunner::QemuUser {
                    exe: "qemu-aarch64".to_owned()
                }
            );
        }
    }

    #[test]
    fn resolves_arm_guards_to_qemu_arm() {
        for guard in ["arm", "armv7", "armhf"] {
            let target = resolve_cross_target(guard).expect("arm guard resolves");
            assert_eq!(target.triple, "arm-linux-gnueabihf");
            assert_eq!(target.cc, "arm-linux-gnueabihf-gcc");
            assert_eq!(target.cxx, "arm-linux-gnueabihf-g++");
            assert_eq!(
                target.runner,
                CrossRunner::QemuUser {
                    exe: "qemu-arm".to_owned()
                }
            );
        }
    }

    #[test]
    fn rtos_guards_become_stub_isolated_platforms() {
        // VxWorks: define the guard + supply the base + companion headers.
        for guard in ["__vxworks", "__VXWORKS__", "vxworks"] {
            let stub = foreign_platform_stub(guard).expect("vxworks guard stubs");
            assert_eq!(stub.platform, "vxworks");
            assert_eq!(stub.define, "__vxworks");
            assert!(stub.headers.iter().any(|h| h.name == "vxWorks.h"));
            assert!(stub.headers.iter().any(|h| h.name == "semLib.h"));
        }
        // RTOS guards are NOT cross-compiled/emulated (no qemu image) — they must
        // route to the stub-isolated native path, not resolve_cross_target.
        assert_eq!(resolve_cross_target("__vxworks"), None);
        let integ = foreign_platform_stub("__INTEGRITY").expect("integrity stubs");
        assert_eq!(integ.define, "__INTEGRITY");
        assert!(integ.headers.iter().any(|h| h.name == "INTEGRITY.h"));
        let qnx = foreign_platform_stub("__QNX__").expect("qnx stubs");
        assert_eq!(qnx.define, "__QNX__");
    }

    #[test]
    fn platform_header_stub_serves_rtos_headers_by_basename() {
        // Flat and subdir spellings both resolve by basename.
        let vx = platform_header_stub("vxWorks.h").expect("vxWorks.h");
        assert!(vx.contains("STATUS") && vx.contains("SEM_ID"));
        assert!(vx.contains("#define OK") && vx.contains("#define ERROR"));
        let neut = platform_header_stub("sys/neutrino.h").expect("sys/neutrino.h");
        assert!(neut.contains("MsgReceive") && neut.contains("__QNXNTO__"));
        let integ = platform_header_stub("INTEGRITY.h").expect("INTEGRITY.h");
        assert!(integ.contains("typedef int            Error"));
        // A non-RTOS header is not ours to synthesize.
        assert_eq!(platform_header_stub("stdio.h"), None);
        assert_eq!(platform_header_stub("my_project.h"), None);
    }

    #[test]
    fn unknown_guard_is_unmapped() {
        // Foreign targets we have no cross toolchain mapping for: macOS, and the
        // non-ARM/non-Windows architectures discovery can also tag.
        for guard in ["darwin", "macos", "__APPLE__", "ppc64", "riscv64", "s390x"] {
            assert_eq!(
                resolve_cross_target(guard),
                None,
                "{guard} should be unmapped"
            );
        }
    }

    #[test]
    fn available_reflects_path_lookup() {
        // `available()`/`missing_tools()` consult PATH. Use a shell that every
        // POSIX host has on PATH as the "present" sentinel and a junk name as
        // the "absent" one, so the test does not depend on a cross toolchain
        // being installed.
        assert!(executable_on_path("sh"));
        assert!(!executable_on_path("govfuzz-cross-no-such-tool-zzz"));

        let present = CrossTarget {
            triple: "t".to_owned(),
            cc: "sh".to_owned(),
            cxx: "sh".to_owned(),
            runner: CrossRunner::QemuUser {
                exe: "sh".to_owned(),
            },
        };
        assert!(present.available());
        assert!(present.missing_tools().is_empty());

        let absent = CrossTarget {
            cc: "govfuzz-cross-no-such-cc-zzz".to_owned(),
            runner: CrossRunner::Wine {
                exe: "govfuzz-cross-no-such-wine-zzz".to_owned(),
            },
            ..present.clone()
        };
        assert!(!absent.available());
        assert_eq!(absent.missing_tools().len(), 2);
    }

    #[test]
    fn windows_guards_map_to_a_platform_stub() {
        for guard in ["_WIN32", "windows", "win32", "win64", "_MSC_VER", "mingw"] {
            let stub = foreign_platform_stub(guard).expect("windows guard stubs");
            assert_eq!(stub.platform, "windows");
            assert_eq!(stub.define, "_WIN32");
            let header = stub.headers.iter().find(|h| h.name == "windows.h").unwrap();
            assert!(header.content.contains("typedef"));
            assert!(header.content.contains("HANDLE"));
            assert!(header.content.contains("DWORD"));
        }
    }

    #[test]
    fn windows_stub_supplies_an_mfc_cstring_surface() {
        // An MFC target (`#include <afxwin.h>`) needs CString + the window
        // classes + message-map macros defined, or every `undefined type
        // 'CString'` fails the build. The stub provides them under the common
        // afx*/atl* include spellings, C++-guarded so C TUs still parse.
        let stub = foreign_platform_stub("_WIN32").unwrap();
        for spelling in ["afxwin.h", "atlstr.h"] {
            let mfc = stub
                .headers
                .iter()
                .find(|h| h.name == spelling)
                .unwrap_or_else(|| panic!("MFC header {spelling} present"));
            assert!(mfc.content.contains("class CString"), "{spelling}");
            assert!(mfc.content.contains("CString(const char *s)"), "{spelling}");
            assert!(mfc.content.contains("#ifdef __cplusplus"), "{spelling}");
            assert!(
                mfc.content.contains("#define DECLARE_MESSAGE_MAP()"),
                "{spelling}"
            );
            assert!(mfc.content.contains("class CWnd"), "{spelling}");
        }
        // Force-included AFTER windows.h so CString's members can use Win32 types.
        let names: Vec<&str> = stub.headers.iter().map(|h| h.name.as_str()).collect();
        let win_pos = names.iter().position(|n| *n == "windows.h").unwrap();
        let mfc_pos = names.iter().position(|n| *n == "afxwin.h").unwrap();
        assert!(
            mfc_pos > win_pos,
            "MFC stub must follow windows.h: {names:?}"
        );
    }

    #[test]
    fn windows_stub_maps_msvc_crt_stdio_string_names_onto_glibc() {
        // MSVC spells several standard functions with a leading underscore
        // (`_vsnprintf`, `_snprintf`, `_stricmp`, `_strdup`). They are declared by
        // MSVC's <stdio.h>/<string.h>, NOT glibc's, so a `#ifdef _WIN32` branch that
        // calls them (frozen's `cs_win_vsnprintf` → `_vsnprintf`) fails to compile
        // under the StubIsolated host build ("call to undeclared function"). A
        // force-included CRT-compat header aliases them to the glibc spellings.
        let stub = foreign_platform_stub("_WIN32").unwrap();
        let crt = stub
            .headers
            .iter()
            .find(|h| h.name == "_govfuzz_crt_compat.h")
            .expect("CRT-compat header present");
        // Each MSVC name maps to a `static inline` wrapper (not a bare alias to the
        // glibc name) so a target that hijacks the base name can't turn the alias
        // into self-recursion.
        for (msvc, wrapper, glibc) in [
            ("_vsnprintf", "_gf_crt_vsnprintf", "vsnprintf"),
            ("_snprintf", "_gf_crt_snprintf", "vsnprintf"),
            ("_stricmp", "_gf_crt_stricmp", "strcasecmp"),
            ("_strnicmp", "_gf_crt_strnicmp", "strncasecmp"),
            ("_strdup", "_gf_crt_strdup", "strdup"),
        ] {
            assert!(
                crt.content.contains(&format!("#define {msvc} {wrapper}")),
                "expected `{msvc}` -> `{wrapper}` wrapper alias in:\n{}",
                crt.content
            );
            assert!(
                crt.content.contains(&format!("{wrapper}(")) && crt.content.contains(glibc),
                "wrapper `{wrapper}` should call glibc `{glibc}`:\n{}",
                crt.content
            );
        }
        // It must pull in the glibc headers so the aliased names are declared even
        // when the target source itself doesn't include them.
        assert!(crt.content.contains("#include <stdio.h>"));
        assert!(crt.content.contains("#include <string.h>"));
        // A real Windows toolchain always defines a compiler-identity macro. With
        // only `_WIN32` defined and `_MSC_VER` absent (→ 0 in `#if`), a `#if
        // defined(_WIN32) && _MSC_VER < 1700` ladder (frozen's pre-VS2012 branch:
        // `typedef int bool;`) is taken and collides with glibc's <stdbool.h>.
        // Assert a modern `_MSC_VER` so version ladders select the C99 branch.
        assert!(
            crt.content.contains("#define _MSC_VER 1900"),
            "modern _MSC_VER identity present:\n{}",
            crt.content
        );
        // Claiming `_MSC_VER` flips clang's <stddef.h> into its MSVC branch, which
        // re-typedefs `wchar_t` unless the native wchar_t type is advertised —
        // fatal in every C++ TU (wchar_t is a builtin keyword). The stub must
        // advertise native wchar_t so <cstddef>/<cstdlib> don't fail with
        // "cannot combine with previous 'int'".
        assert!(
            crt.content.contains("#define _NATIVE_WCHAR_T_DEFINED 1"),
            "native wchar_t must be advertised alongside the faux _MSC_VER:\n{}",
            crt.content
        );
        assert!(
            crt.content.contains("#define _WCHAR_T_DEFINED 1"),
            "_WCHAR_T_DEFINED must guard CRT wchar_t re-typedef:\n{}",
            crt.content
        );
    }

    #[test]
    fn crt_compat_header_compiles_and_resists_base_name_hijack() {
        // The header must (1) be valid C and (2) keep `_vsnprintf` bound to the real
        // glibc function even when the TU later hijacks `vsnprintf` (frozen's
        // `#define vsnprintf cs_win_vsnprintf`) — otherwise the wrapper recurses.
        if std::process::Command::new("clang")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping crt-compat compile: clang not on PATH");
            return;
        }
        let dir = std::env::temp_dir().join(format!("gf-crt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("_govfuzz_crt_compat.h"), CRT_COMPAT_STUB).unwrap();
        // A TU that force-includes the compat header, THEN hijacks `vsnprintf` the
        // way frozen does, then calls the MSVC underscore name inside its wrapper.
        let tu = "#include \"_govfuzz_crt_compat.h\"\n\
                  #define vsnprintf cs_win_vsnprintf\n\
                  int cs_win_vsnprintf(char *s, size_t n, const char *f, va_list a) {\n\
                  \x20 return _vsnprintf(s, n, f, a);\n\
                  }\n";
        let tu_path = dir.join("probe.c");
        std::fs::write(&tu_path, tu).unwrap();

        // (1) It compiles as valid C. Use clang's default mode (gnu) — the mode
        // govfuzz's generated Makefile actually builds with, where the POSIX
        // `strdup`/`strcasecmp` declarations the wrappers call are visible.
        let compile = std::process::Command::new("clang")
            .args(["-c", "-o"])
            .arg(dir.join("probe.o"))
            .arg("-I")
            .arg(&dir)
            .arg(&tu_path)
            .output()
            .expect("spawn clang");
        assert!(
            compile.status.success(),
            "crt-compat header must compile:\n{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        // (2) `_vsnprintf` resolves to the wrapper, NOT the hijacked base name — so
        // the wrapper calls the real glibc `vsnprintf`, never itself.
        let pre = std::process::Command::new("clang")
            .arg("-E")
            .arg("-I")
            .arg(&dir)
            .arg(&tu_path)
            .output()
            .expect("spawn clang -E");
        let expanded = String::from_utf8_lossy(&pre.stdout);
        let body = expanded
            .split("cs_win_vsnprintf(char *s")
            .nth(1)
            .unwrap_or("");
        assert!(
            body.contains("_gf_crt_vsnprintf(s, n, f, a)"),
            "_vsnprintf must expand to the wrapper, not recurse:\n{body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crt_compat_header_compiles_in_cpp_tu_with_cstddef() {
        // Regression: the faux `_MSC_VER 1900` (needed for version ladders) put
        // clang into its MSVC <stddef.h> branch, whose `typedef __WCHAR_TYPE__
        // wchar_t;` collides with the C++ builtin `wchar_t` keyword the instant a
        // C++ harness pulls <cstddef>/<cstdlib> — i.e. EVERY C++ target using the
        // win32/MFC stub failed to build with "cannot combine with previous 'int'".
        // The prior compile test only exercised a C TU, where wchar_t is a plain
        // typedef and the conflict can't arise. Advertising native wchar_t fixes it.
        if std::process::Command::new("clang++")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping crt-compat C++ compile: clang++ not on PATH");
            return;
        }
        let dir = std::env::temp_dir().join(format!("gf-crt-cpp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Toolchain probe: this box (and some CI images) ship a clang++ that can't
        // locate libstdc++/libc++ headers unaided. If a bare `#include <cstddef>`
        // won't compile, the toolchain isn't C++-ready — self-skip rather than
        // report a spurious failure (per repo convention on missing toolchains).
        let probe = dir.join("probe0.cpp");
        std::fs::write(&probe, "#include <cstddef>\nint d;\n").unwrap();
        let probe_ok = std::process::Command::new("clang++")
            .args(["-std=gnu++20", "-fsyntax-only"])
            .arg(&probe)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !probe_ok {
            eprintln!("skipping crt-compat C++ compile: clang++ can't find the C++ stdlib");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        std::fs::write(dir.join("_govfuzz_crt_compat.h"), CRT_COMPAT_STUB).unwrap();
        // Mirror the real harness build: force-include the compat header (as the
        // generated auto_cpp_includes.h does), then pull <cstddef> like main.cpp.
        let tu = dir.join("probe.cpp");
        std::fs::write(&tu, "#include <cstddef>\n#include <cstdlib>\nint d;\n").unwrap();
        let out = std::process::Command::new("clang++")
            .args(["-std=gnu++20", "-fsyntax-only", "-include"])
            .arg(dir.join("_govfuzz_crt_compat.h"))
            .arg(&tu)
            .output()
            .expect("spawn clang++");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("cannot combine with previous"),
            "crt-compat stub must not re-typedef the builtin wchar_t in a C++ TU:\n{stderr}"
        );
        assert!(
            out.status.success(),
            "crt-compat header must compile in a C++ TU:\n{stderr}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_windows_guards_have_no_platform_stub() {
        // Arch/SIMD guards go through cross-compile, not platform stubbing; other
        // OS/arch guards we don't model are simply unmapped here.
        for guard in [
            "aarch64", "arm64", "neon", "armhf", "ppc64", "riscv64", "darwin",
        ] {
            assert!(
                foreign_platform_stub(guard).is_none(),
                "{guard} must not platform-stub"
            );
        }
    }
}
