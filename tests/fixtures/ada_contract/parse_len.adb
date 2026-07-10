--  SPDX-License-Identifier: Apache-2.0
package body Parse_Len is
   function Parsed_Length (Data : String) return Natural is
   begin
      return Data'Length + 1;  --  off-by-one the postcondition catches
   end Parsed_Length;
end Parse_Len;
