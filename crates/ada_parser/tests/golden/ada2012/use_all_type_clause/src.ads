--  SPDX-License-Identifier: Apache-2.0

with Interfaces;
pragma Ada_2012;

package Use_All_Types is
   use all type Interfaces.Unsigned_32;
   procedure Touch;
end Use_All_Types;
