--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

procedure Use_Declare_Expression is
   Value : Integer := (declare X : constant Integer := 1; begin X);
begin
   if Value = 0 then
      raise Program_Error;
   end if;
end Use_Declare_Expression;
