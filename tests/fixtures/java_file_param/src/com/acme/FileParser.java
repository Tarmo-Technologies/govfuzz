// SPDX-License-Identifier: Apache-2.0
package com.acme;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * A parser whose only input is a {@code java.io.File} — the classic Java parse
 * entry point ({@code ImageIO.read(File)}, {@code new ZipFile(File)}). Before the
 * file channel existed this target skipped with "parameter #0 has an unsupported
 * type `File`", because the harness could only hand a target bytes it held in
 * memory.
 *
 * The planted ArrayIndexOutOfBoundsException (GF-201) sits behind a single-byte
 * 'G' gate, so it fires only if the fuzz bytes really reached the file the target
 * opened — which is exactly what this fixture is here to prove.
 */
public final class FileParser {
    public static int parse(File input) throws IOException {
        byte[] data = Files.readAllBytes(input.toPath());
        if (data.length < 2) {
            return 0;
        }
        if (data[0] == 'G') {
            int[] tiny = new int[1];
            return tiny[data.length];
        }
        return data.length;
    }
}
