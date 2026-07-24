--  SPDX-License-Identifier: Apache-2.0
with Vendorlib;
package App is
   --  Fuzz target whose parameter type comes from a MISSING external library
   --  (Vendorlib.Handle). Under --force the library is stubbed AND the opaque
   --  handle parameter is default-initialized (bare-declared, qualified + with'd),
   --  while the String parameter is driven by real fuzz bytes.
   function Process (Doc : Vendorlib.Handle; Data : String) return Integer;
end App;
