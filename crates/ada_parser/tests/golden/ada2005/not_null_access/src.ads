--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2005;

package Accesses is
   type Target is tagged record
      Id : Integer;
   end record;
   type Target_Access is not null access Target;
end Accesses;
