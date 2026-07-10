--  SPDX-License-Identifier: Apache-2.0

pragma Ada_95;

generic
   type Item is private;
package Box is
   procedure Put (X : Item);
end Box;
