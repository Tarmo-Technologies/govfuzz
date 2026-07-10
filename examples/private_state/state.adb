--  SPDX-License-Identifier: Apache-2.0
pragma Ada_2012;

package body State is
   Values      : array (Positive range 1 .. 8) of Integer := (others => 0);
   Count       : Natural := 0;
   Ever_Pushed : Boolean := False;

   procedure Push (X : Integer) is
   begin
      Ever_Pushed := True;
      if Count < Values'Length then
         Count := Count + 1;
         Values (Count) := X;
      end if;
   end Push;

   procedure Pop is
   begin
      if Ever_Pushed then
         Count := Count - 1;
      end if;
   exception
      when Constraint_Error =>
         null;
   end Pop;

   function Top return Integer is
   begin
      if Count = 0 then
         return 0;
      end if;

      return Values (Count);
   end Top;
end State;
