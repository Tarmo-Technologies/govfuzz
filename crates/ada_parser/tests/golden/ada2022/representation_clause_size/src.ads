--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

package Sized_Types is
   type Small is range 0 .. 255;
   for Small'Size use 8;
end Sized_Types;
