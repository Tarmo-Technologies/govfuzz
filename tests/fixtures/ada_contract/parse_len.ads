--  SPDX-License-Identifier: Apache-2.0
package Parse_Len is
   --  Contract: the parsed length never exceeds the input length. The body has an
   --  off-by-one bug (it returns Data'Length + 1), so the postcondition is violated
   --  on every call — the defect govfuzz surfaces as a contract violation (GF-557)
   --  once the Ada target is built with -gnata.
   function Parsed_Length (Data : String) return Natural
     with Post => Parsed_Length'Result <= Data'Length;
end Parse_Len;
