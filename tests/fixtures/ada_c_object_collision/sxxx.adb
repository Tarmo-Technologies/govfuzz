--  SPDX-License-Identifier: Apache-2.0
package body Sxxx is
   procedure Run (X : Integer) is
   begin
      if X = 42 then
         raise Program_Error;
      end if;
   end Run;
end Sxxx;
