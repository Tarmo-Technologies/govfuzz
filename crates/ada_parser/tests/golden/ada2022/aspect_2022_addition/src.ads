--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

package Modern_Aspects is
   type Payload is record
      Word : Integer;
   end record with Object_Size => 32;
end Modern_Aspects;
