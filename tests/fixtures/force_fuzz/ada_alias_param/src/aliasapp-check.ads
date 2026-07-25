--  SPDX-License-Identifier: Apache-2.0
package Aliasapp.Check is

   --  Driveable target: one opaque param of the re-exported type plus real
   --  fuzzable bytes.
   function Score (Object : Handle; Input : String) return Integer;

end Aliasapp.Check;
