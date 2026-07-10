--  SPDX-License-Identifier: Apache-2.0
package Bench is
   --  Decodes a frame; raises CONSTRAINT_ERROR only past a 2-character magic.
   function Parse_Frame (Data : String) return Integer;
end Bench;
