// SPDX-License-Identifier: Apache-2.0
//
// Regression fixture: a Win32/MFC C++ target using the Windows integer typedefs
// BOOL / DWORD / WORD as parameters. On an offline non-Windows lab <windows.h>
// is NOT in the scanned tree, so these typedefs have nothing to chase and used
// to resolve opaque -> the whole target was skipped ("needs lifecycle support
// (Phase C)"). Two fixes make this build+fuzz:
//   1. Win32 integer spellings are recognized as scalars (type_model).
//   2. The synthesized MSVC CRT-compat stub advertises native wchar_t, so the
//      faux _MSC_VER no longer makes clang re-typedef the builtin wchar_t and
//      break every C++ TU that pulls <cstddef> ("cannot combine with 'int'").
//
// The <afxwin.h> include routes govfuzz to its win32 (MFC/ATL) platform stub,
// which supplies BOOL/DWORD/WORD so the emitted decoder compiles.

#include <afxwin.h>

int process_flags(const BOOL validate, DWORD count, WORD port) {
    if (validate && count > 1000000u && port == 0x4141) {
        volatile int *p = 0;
        return *p; // deliberate crash on a specific decoded combination
    }
    return (int)(count ^ port);
}
