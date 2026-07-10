--  SPDX-License-Identifier: Apache-2.0
--  A fuzzable Ada unit whose stem (`sxxx`) matches a sibling C source (sxxx.c).
--  Both would produce `sxxx.o`, which gprbuild rejects ("... have the same object
--  file name"); govfuzz excludes the C file so the Ada harness builds.
package Sxxx is
   procedure Run (X : Integer);
end Sxxx;
