--  SPDX-License-Identifier: Apache-2.0
--  An `Ada.Strings.Bounded.Generic_Bounded_Length` instance whose Bounded_String
--  type is used cross-package as a parameter. The AST does not model the
--  instantiation, so the decoder recognizes the standard `Bounded_String` leaf
--  and constructs values via the instance's `To_Bounded_String`.
with Ada.Strings.Bounded;
package Str_Defs is
   package Bounded_750_Type is new Ada.Strings.Bounded.Generic_Bounded_Length (750);
end Str_Defs;
