--  SPDX-License-Identifier: Apache-2.0
package body Simple_Parser is
   function Parse (Data : String) return Integer is
   begin
      if Data'Length >= 3
        and then Data (Data'First) = 'A'
        and then Data (Data'First + 1) = 'D'
        and then Data (Data'First + 2) = 'A'
      then
         return 1;
      end if;
      return 0;
   end Parse;
end Simple_Parser;
