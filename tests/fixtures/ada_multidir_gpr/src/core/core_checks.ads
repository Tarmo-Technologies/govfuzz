--  SPDX-License-Identifier: Apache-2.0
--  The dependency unit, living in the sibling `src/core` Source_Dir.
with Interfaces;

package Core_Checks is
   function Checksum (Data : String) return Interfaces.Unsigned_32;
end Core_Checks;
