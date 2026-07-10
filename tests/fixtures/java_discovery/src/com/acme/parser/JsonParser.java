// SPDX-License-Identifier: Apache-2.0
package com.acme.parser;

import java.io.InputStream;

/** A small parser surface used to exercise the M2.1a Java discovery lane. */
public class JsonParser {

    /** A byte-channel parse entry — the canonical attacker surface. */
    public static Object parse(byte[] data) {
        return decodeInternal(data, 0);
    }

    /** A security sink (deserialization) over a stream — must rank highly. */
    public static Object readValue(InputStream in) {
        return null;
    }

    /** A String byte channel. */
    public Object parseString(String text) {
        return null;
    }

    /** A getter — penalized, not the attack surface. */
    public String getName() {
        return "JsonParser";
    }

    /** Package-private helper — not reachable from another package, skipped. */
    static Object decodeInternal(byte[] data, int off) {
        return null;
    }

    /** Private helper — skipped. */
    private void reset() {
    }
}
