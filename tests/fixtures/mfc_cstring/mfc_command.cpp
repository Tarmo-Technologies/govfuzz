// SPDX-License-Identifier: Apache-2.0
// An MFC target: `#include <afxwin.h>` and a `const CString &` parameter. On an
// offline non-Windows lab CString is undefined, so this used to fail the build
// ("undefined type 'CString'"). govfuzz's MFC stub now defines CString and the
// C++ decoder drives the param from a fuzz string, so it builds+fuzzes.
#include <afxwin.h>

int process_command(const CString &cmd) {
    if (cmd.GetLength() >= 3 && cmd.GetAt(0) == 'Z' && cmd.GetAt(1) == 'X') {
        volatile int *p = 0;
        return *p; // crash only on a specific decoded command
    }
    return cmd.GetLength();
}
