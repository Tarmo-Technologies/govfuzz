--  SPDX-License-Identifier: Apache-2.0
package Bench is
   function Parse_Index (Data : String) return Integer;   --  range / index error
   function Parse_Value (Data : String) return Integer;   --  numeric error
end Bench;
