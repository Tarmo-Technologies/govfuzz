--  SPDX-License-Identifier: Apache-2.0
with Aux_Pkg;

package body Pkg is
   function Inflate (Data : String) return Integer is
   begin
      return Aux_Pkg.Score (Data'Length);
   end Inflate;
end Pkg;
