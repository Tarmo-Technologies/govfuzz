--  SPDX-License-Identifier: Apache-2.0
with Core_Checks;
with Interfaces;

package body Line_Parser is

   function Parse_Line (Data : String) return Integer is
      use type Interfaces.Unsigned_32;
      Sum : constant Interfaces.Unsigned_32 := Core_Checks.Checksum (Data);
   begin
      return Integer (Sum mod 1000);
   end Parse_Line;

end Line_Parser;
