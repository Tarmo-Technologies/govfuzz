--  SPDX-License-Identifier: Apache-2.0

pragma Ada_95;

package body Service is
   procedure Work is
   begin
      null;
   exception
      when Program_Error =>
         null;
   end Work;
begin
   null;
exception
   when Constraint_Error =>
      null;
end Service;
