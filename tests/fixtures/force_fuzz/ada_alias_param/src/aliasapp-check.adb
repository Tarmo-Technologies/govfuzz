--  SPDX-License-Identifier: Apache-2.0
package body Aliasapp.Check is

   function Score (Object : Handle; Input : String) return Integer is
      Total : Integer := Input'Length;
   begin
      if Input'Length > 3 and then Input (Input'First) = 'Z' then
         Total := Total + Vendorx.Doc.Weight (Object);
      end if;
      return Total;
   end Score;

end Aliasapp.Check;
