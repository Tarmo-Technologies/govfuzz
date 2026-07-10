# SPDX-License-Identifier: Apache-2.0
"""A tiny untrusted-input parser fixture for the govfuzz Python lane.

`parse_record` is the fuzzable public entry point. A crafted first byte drives an
unbounded recursion (CWE-674) through a private helper — a real robustness bug a
crash-only fuzzer would also find, reachable purely from the input bytes.
"""


def parse_record(data: bytes):
    if len(data) < 1:
        raise ValueError("empty record")  # input rejection, not a bug
    tag = data[0]
    if tag == 0x41:  # 'A' -> planted defect: unbounded recursion
        return _walk(data, 1)
    if tag == 0x42:  # 'B' -> normal structured parse
        return {"len": len(data), "body": data[1:]}
    raise ValueError("unknown tag")  # rejection


def _walk(data, depth):
    # Bug: the recursion never terminates (depth only grows).
    return _walk(data, depth + 1)
