--  SPDX-License-Identifier: Apache-2.0
with Vendor_Lib;
package body Dep_Parser is
   function Check (Data : String) return Integer is
   begin
      return Vendor_Lib.Score (Data);
   end Check;
end Dep_Parser;
