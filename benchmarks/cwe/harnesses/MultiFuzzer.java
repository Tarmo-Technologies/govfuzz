// SPDX-License-Identifier: Apache-2.0
public class MultiFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        new com.acme.MultiParser().parsePacket(data);   // one entry point harnessed
    }
}
