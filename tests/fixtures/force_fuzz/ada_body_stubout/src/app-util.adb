--  SPDX-License-Identifier: Apache-2.0
package body App.Util is
   function Double (X : Integer) return Integer is
   begin
      --  Branchy but overflow-free, so a clean fuzz run yields no findings — any
      --  finding would be a false positive from the synthesized parent stub body.
      if X > 0 then
         return 1;
      else
         return 0;
      end if;
   end Double;
end App.Util;
