--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

package Images is
   type Item is record
      Value : Integer;
   end record;
   function Show return String is (Item'(Value => 1)'Image);
end Images;
