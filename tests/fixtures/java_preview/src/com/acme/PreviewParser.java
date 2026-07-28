// SPDX-License-Identifier: Apache-2.0
package com.acme;

/**
 * A parser written against an unnamed variable (`_`), which is a language PREVIEW
 * on JDK 21 and standard only from 22. javac refuses it outright without
 * `--enable-preview --release <current>`, and the JVM then refuses to LOAD the
 * resulting class files without `--enable-preview` too — so this fixture fails at
 * BOTH stages unless the flag is carried all the way from the target compile,
 * through the harness compile, to the launcher.
 *
 * RxJava and spring-framework failed exactly this way in the 500-project sweep.
 *
 * The planted ArrayIndexOutOfBoundsException (GF-201) sits behind a single-byte
 * 'G' gate, so finding it proves the target actually ran.
 */
public final class PreviewParser {
    public static int parse(byte[] data) {
        // The preview feature this fixture exists for: an unnamed variable.
        var _ = data.length;
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
