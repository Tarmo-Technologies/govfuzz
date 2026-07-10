--  SPDX-License-Identifier: Apache-2.0
package body Core_Checks is

   function Checksum (Data : String) return Interfaces.Unsigned_32 is
      use type Interfaces.Unsigned_32;
      Sum : Interfaces.Unsigned_32 := 0;
   begin
      for C of Data loop
         Sum := Sum + Interfaces.Unsigned_32 (Character'Pos (C));
      end loop;
      return Sum;
   end Checksum;

end Core_Checks;
