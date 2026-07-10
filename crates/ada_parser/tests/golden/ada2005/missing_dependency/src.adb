--  SPDX-License-Identifier: Apache-2.0

with External_Lib;
pragma Ada_2005;

package body Uses_External is
   function Parse return Integer is
   begin
      return External_Lib.Value;
   end Parse;
end Uses_External;
