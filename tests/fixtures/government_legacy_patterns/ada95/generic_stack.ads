-- SPDX-License-Identifier: Apache-2.0
pragma Ada_95;

generic
   type Element is private;
package Generic_Stack is
   procedure Push (Item : Element);
   function Count return Natural;
end Generic_Stack;
