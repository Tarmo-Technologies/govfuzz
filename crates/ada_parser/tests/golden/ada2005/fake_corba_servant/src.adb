--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2005;

package body Bar_Impl is
   function Compute (S : String) return Integer is
   begin
      if S = "neg" then
         raise Foo.BadInput with "neg";
      end if;
      return 1;
   exception
      when Foo.BadInput =>
         return 0;
   end Compute;
end Bar_Impl;
