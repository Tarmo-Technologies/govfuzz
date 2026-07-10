--  SPDX-License-Identifier: Apache-2.0
package body Bench is
   --  CONSTRAINT_ERROR: index out of range, past a 'P' gate.
   function Parse_Index (Data : String) return Integer is
      Table : array (1 .. 4) of Integer := (others => 0);
   begin
      if Data'Length < 2 or else Data (Data'First) /= 'P' then return 0; end if;
      return Table ((Data'Length mod 64) + 5);   --  out of range
   end Parse_Index;

   --  CONSTRAINT_ERROR: numeric range, past a 'V' gate.
   function Parse_Value (Data : String) return Integer is
      X : Integer := 0;
   begin
      if Data'Length < 2 or else Data (Data'First) /= 'V' then return 0; end if;
      X := Integer'Last;
      X := X + Character'Pos (Data (Data'First + 1));   --  overflow -> CONSTRAINT_ERROR
      return X;
   end Parse_Value;
end Bench;
