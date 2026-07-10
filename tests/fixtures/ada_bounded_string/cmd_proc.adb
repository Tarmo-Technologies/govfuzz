--  SPDX-License-Identifier: Apache-2.0
package body Cmd_Proc is
   procedure Process (Command : Str_Defs.Bounded_750_Type.Bounded_String) is
   begin
      if Str_Defs.Bounded_750_Type.Length (Command) >= 4
        and then Str_Defs.Bounded_750_Type.Element (Command, 1) = 'X'
        and then Str_Defs.Bounded_750_Type.Element (Command, 2) = 'Y'
      then
         raise Program_Error;  --  crash only on a specific decoded string
      end if;
   end Process;
end Cmd_Proc;
