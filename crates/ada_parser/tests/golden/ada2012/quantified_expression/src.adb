--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2012;

procedure Check_All is
   All_Positive : Boolean := (for all I in 1 .. 3 => I > 0);
begin
   if not All_Positive then
      raise Program_Error;
   end if;
end Check_All;
