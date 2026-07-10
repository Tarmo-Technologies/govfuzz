--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2005;

with Foo;

package body Bar_Impl is
   function Object_Ref return CORBA.Object.Ref is
      Ref : CORBA.Object.Ref;
   begin
      return Ref;
   end Object_Ref;

   function Compute (Self : Servant; S : String) return Integer is
      pragma Unreferenced (Self);
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
