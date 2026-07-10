-- SPDX-License-Identifier: Apache-2.0
with Ada.Command_Line;
with GNAT.OS_Lib;

procedure Runtime_Config is
   Path : constant String := Ada.Command_Line.Argument (1);
begin
   GNAT.OS_Lib.Spawn (Path);
end Runtime_Config;
