--  SPDX-License-Identifier: Apache-2.0
package body Bench is
   function Parse_Frame (Data : String) return Integer is
      Table : array (1 .. 4) of Integer := (others => 0);
   begin
      if Data'Length < 4 then
         return 0;
      end if;
      --  Reachable only past a one-character 'G' gate; then an index out of
      --  range raises CONSTRAINT_ERROR (the Ada analogue of a stack OOB).
      if Data (Data'First) = 'G' then
         declare
            Idx : constant Integer := (Data'Length mod 64) + 5;  --  > 4
         begin
            return Table (Idx);  --  index out of range -> CONSTRAINT_ERROR
         end;
      end if;
      return 1;
   end Parse_Frame;
end Bench;
