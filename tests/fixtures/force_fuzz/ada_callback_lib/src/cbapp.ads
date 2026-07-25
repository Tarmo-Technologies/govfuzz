--  SPDX-License-Identifier: Apache-2.0
package Cbapp is
   --  Driveable String target whose body passes a CALLBACK to an operation of a
   --  missing external library. The callback's own parameters are typed by that
   --  same library, which is what makes an access-to-subprogram stub possible:
   --  the stub declares those types itself, so naming them creates no circular
   --  unit dependency.
   function Total (Input : String) return Integer;
end Cbapp;
