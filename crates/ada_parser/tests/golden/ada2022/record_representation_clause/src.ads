--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

package Packed_Records is
   type Header is record
      Word : Integer;
   end record;

   for Header use record
      Word at 0 range 0 .. 31;
   end record;
end Packed_Records;
