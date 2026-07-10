--  SPDX-License-Identifier: Apache-2.0
--  A subprogram whose parameter is a cross-package bounded-string type
--  (`Str_Defs.Bounded_750_Type.Bounded_String`) — the shape that used to skip
--  with "named type ... has no synthesizable constructor".
with Str_Defs;
package Cmd_Proc is
   procedure Process (Command : Str_Defs.Bounded_750_Type.Bounded_String);
end Cmd_Proc;
