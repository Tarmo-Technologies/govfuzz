--  SPDX-License-Identifier: Apache-2.0

pragma Ada_95;

package body Pkg is
   function Parse (S : String) return Integer is
      Tmp : Integer;
   begin
      Tmp := Integer'Value (S);
      return Tmp;
   exception
      when Constraint_Error =>
         return 0;
   end Parse;
end Pkg;
