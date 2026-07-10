--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2005;

package body Parser_2005 is
   function Parse (S : String) return Integer is
   begin
      return Integer'Value (S);
   exception
      when Constraint_Error =>
         return 0;
   end Parse;
end Parser_2005;
