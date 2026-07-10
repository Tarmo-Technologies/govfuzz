--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

package Deriveds is
   type Root is range 0 .. 100;
   type Child is new Root;
end Deriveds;
