--  SPDX-License-Identifier: Apache-2.0
package body Matrix is
   procedure Consume (M : Covariance_Matrix_Type) is
   begin
      if M (1, 1) > 1.0e30 and then M (3, 3) < -1.0e30 then
         raise Program_Error;  --  crash only on a specific decoded matrix
      end if;
   end Consume;
end Matrix;
