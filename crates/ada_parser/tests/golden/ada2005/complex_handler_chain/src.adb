--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2005;

procedure Chain is
begin
   raise Program_Error with "chain";
exception
   when Constraint_Error | Program_Error =>
      null;
   when others =>
      null;
end Chain;
