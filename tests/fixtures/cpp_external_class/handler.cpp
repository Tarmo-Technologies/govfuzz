// SPDX-License-Identifier: Apache-2.0
// A C++ target whose parameter is an out-of-tree CLASS (`CString`) used with
// member-call syntax — but WITHOUT any MFC/ATL header include, so govfuzz's MFC
// stub never fires. The repair loop placeholder-synthesizes `CString` as an
// opaque scalar; the rebuild then fails with "called object type '...' is not a
// function" (a scalar can't be called like a class). That must degrade to a
// report-only static scan (the type is an external SDK class the offline lab
// can't supply), NOT a bare failed_build.
int process_command(const CString &cmd) {
    if (cmd.GetLength() >= 3 && cmd.GetAt(0) == 'Z') {
        volatile int *p = 0;
        return *p;
    }
    return cmd.GetLength();
}
