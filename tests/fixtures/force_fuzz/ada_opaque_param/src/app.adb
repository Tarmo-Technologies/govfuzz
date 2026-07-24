--  SPDX-License-Identifier: Apache-2.0
package body App is
   function Process (H : Handle; Data : String) return Integer is
   begin
      if Data'Length >= 2 and then Data (Data'First) = 'X' then
         return H.Tag + 1;
      end if;
      return H.Tag;
   end Process;
end App;
