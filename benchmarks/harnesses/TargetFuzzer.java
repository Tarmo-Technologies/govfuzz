// SPDX-License-Identifier: Apache-2.0
public class TargetFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        new com.acme.FrameParser().parse(data);
    }
}
