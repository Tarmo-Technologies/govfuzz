--  SPDX-License-Identifier: Apache-2.0
package body Vendor_Lib is
   function Score (Data : String) return Integer is
   begin
      if Data'Length > 0 and then Data (Data'First) = 'V' then
         return Data'Length;
      end if;
      return 0;
   end Score;
end Vendor_Lib;
