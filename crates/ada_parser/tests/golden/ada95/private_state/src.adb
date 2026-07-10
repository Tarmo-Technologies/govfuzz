--  SPDX-License-Identifier: Apache-2.0

pragma Ada_95;

package body State is
   type Store is array (Positive range <>) of Integer;
   Data : Store (1 .. 4);
   Count : Natural := 0;

   procedure Push (X : Integer) is
   begin
      Count := Count + 1;
      Data (Count) := X;
   end Push;

   procedure Pop is
   begin
      if Count = 0 then
         raise Constraint_Error;
      end if;
      Count := Count - 1;
   end Pop;

   function Top return Integer is
   begin
      return Data (Count);
   end Top;
end State;
