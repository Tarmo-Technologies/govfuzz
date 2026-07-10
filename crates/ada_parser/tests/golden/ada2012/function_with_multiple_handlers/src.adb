--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2012;

function Convert (S : String) return Integer is
begin
   return Integer'Value (S);
exception
   when Constraint_Error =>
      return -1;
   when Program_Error =>
      return -2;
end Convert;
