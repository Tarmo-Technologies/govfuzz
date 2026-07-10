--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;

package body Access_Param is

   procedure Process (N : Node_Ptr) is
   begin
      if N /= null then
         if N.Value < 0 then
            raise Constraint_Error;
         end if;
      end if;
   exception
      when Constraint_Error =>
         null;
   end Process;

end Access_Param;
