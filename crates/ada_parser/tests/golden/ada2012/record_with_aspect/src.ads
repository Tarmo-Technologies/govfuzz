--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2012;

package Packets is
   type Packet is record
      Length : Natural;
   end record with Pack;
end Packets;
