--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2012;

procedure Recover is
   State : Integer := 0;
   Result : Integer := 0;
begin
   raise Constraint_Error;
exception
   when others =>
      Result := (case State is
         when 0 => 1,
         when others => 2);
end Recover;
