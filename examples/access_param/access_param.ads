--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;

package Access_Param is
   type Node is record
      Value : Integer;
   end record;

   type Node_Ptr is access all Node;

   procedure Process (N : Node_Ptr);
end Access_Param;
