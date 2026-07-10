--  SPDX-License-Identifier: Apache-2.0
package body Pkg is
   function Inflate (Data : String) return Integer is
   begin
      return Data'Length;
   end Inflate;
end Pkg;
