// SPDX-License-Identifier: Apache-2.0
// Legacy Windows shape: Win32 typedefs used without any Windows headers present.
BOOL parse_record(PUCHAR data, DWORD len) {
    if (len < 4) return 0;
    if (data[0] == 'G' && data[1] == 'F' && data[2] == 'U' && data[3] == 'Z') return 1;
    return 0;
}
