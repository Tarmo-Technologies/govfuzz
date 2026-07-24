--  SPDX-License-Identifier: Apache-2.0
with Vendorlib;
package body App is
   function Process (Doc : Vendorlib.Handle; Data : String) return Integer is
   begin
      if Data'Length > 0 then
         return Vendorlib.Value (Doc);
      end if;
      return 0;
   end Process;
end App;
