--  SPDX-License-Identifier: Apache-2.0
package body Value_Pkg is

   function Create_Null return Value is
   begin
      return (Is_Set => False, Number => 0);
   end Create_Null;

   function Create_Boolean (Flag : Boolean) return Value is
   begin
      return (Is_Set => Flag, Number => 0);
   end Create_Boolean;

   function Get (Object : Value; Index : Positive) return Value is
   begin
      if Object.Is_Set and then Index > 1 then
         return (Is_Set => True, Number => Integer_Type (Index));
      end if;
      return Object;
   end Get;

end Value_Pkg;
