--  SPDX-License-Identifier: Apache-2.0
package Simple_Parser is
   --  Externally callable, byte-fillable: a hermetic Ada endpoint auto can build
   --  and fuzz WITHOUT external (Alire) dependencies, so the validation gate can
   --  prove real Ada target entry in normal CI (#104).
   function Parse (Data : String) return Integer;
end Simple_Parser;
