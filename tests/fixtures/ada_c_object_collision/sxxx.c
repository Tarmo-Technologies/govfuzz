// SPDX-License-Identifier: Apache-2.0
// Same stem as sxxx.adb -> both compile to sxxx.o, which gprbuild rejects.
// govfuzz drops this file via `for Excluded_Source_Files` so the Ada unit wins.
int sxxx_helper(int x) { return x + 1; }
