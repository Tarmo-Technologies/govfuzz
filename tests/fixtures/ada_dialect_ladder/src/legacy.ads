--  SPDX-License-Identifier: Apache-2.0
package Legacy is
   --  'Overriding' became a reserved word in Ada 2005; this is legal Ada 95, so
   --  the build must ladder down from -gnat2022 to -gnat95 to compile it.
   Overriding : constant Integer := 7;
   function Score (Data : String) return Integer;
end Legacy;
