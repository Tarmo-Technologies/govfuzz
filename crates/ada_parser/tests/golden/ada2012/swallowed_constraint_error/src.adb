--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2012;

package body Parser_2012 is
   function Parse (S : String) return Integer is
   begin
      return Integer'Value (S);
   exception
      when Constraint_Error =>
         return 0;
   end Parse;
end Parser_2012;
