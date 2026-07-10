// SPDX-License-Identifier: Apache-2.0
package com.acme.parser;

/** An interface (abstract methods) + a concrete default, to prove abstract drop. */
public interface Codec {

    /** Abstract (no body) — not callable without an implementation, skipped. */
    Object decode(byte[] input);

    /** A concrete default method with a byte channel — discoverable (implicitly public). */
    default Object decodeOrNull(byte[] input) {
        return null;
    }
}
