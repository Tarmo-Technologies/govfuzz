--  SPDX-License-Identifier: Apache-2.0
package body Legacy is
   function Score (Data : String) return Integer is
   begin
      if Data'Length > 3 then
         return Overriding;
      end if;
      return 0;
   end Score;
end Legacy;
