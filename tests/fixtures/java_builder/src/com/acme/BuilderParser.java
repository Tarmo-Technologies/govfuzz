// SPDX-License-Identifier: Apache-2.0
package com.acme;

/**
 * A builder-only parser for the native Java receiver-synthesis test (#459). The
 * sole constructor is PRIVATE, so the instance method {@code parse(byte[])} is
 * reachable only by constructing the receiver through the fluent builder
 * ({@code BuilderParser.builder().build()}) — exactly the receiver govfuzz must
 * synthesise instead of skipping the target for "no no-arg constructor".
 *
 * The byte channel reaches an ArrayIndexOutOfBoundsException behind a single-byte
 * 'G' gate (GF-201), so a seeded 'G'-prefixed input trips it deterministically.
 */
public final class BuilderParser {
    private final int limit;

    private BuilderParser(int limit) {
        this.limit = limit;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private int limit;

        public Builder limit(int n) {
            this.limit = n;
            return this;
        }

        public BuilderParser build() {
            return new BuilderParser(this.limit);
        }
    }

    public void parse(byte[] data) {
        if (data.length < 2) {
            return;
        }
        if (data[0] == 'G') {
            // Reached only when the first byte is 'G': an out-of-bounds read, with
            // the receiver constructed through the builder above.
            int[] tiny = new int[this.limit + 1];
            int value = tiny[data.length];
            if (value == 0) {
                return;
            }
        }
    }
}
