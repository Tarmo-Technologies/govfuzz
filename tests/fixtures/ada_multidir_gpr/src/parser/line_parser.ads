--  SPDX-License-Identifier: Apache-2.0
--  The fuzz TARGET, living in `src/parser`. Its body depends on Core_Checks from
--  the sibling `src/core` Source_Dir, so the harness only builds once that dir is
--  pulled into the instrumented set.
package Line_Parser is
   function Parse_Line (Data : String) return Integer;
end Line_Parser;
