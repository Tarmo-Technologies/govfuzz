--  SPDX-License-Identifier: Apache-2.0

pragma Ada_95;

with AdaFuzz.Probe;
with Ada.Exceptions;
package body Pkg is
   function Parse (S : String) return Integer is
      Tmp : Integer;
   begin
      AdaFuzz.Probe.Breadcrumb (1);
      Tmp := Integer'Value (S);
      AdaFuzz.Probe.Breadcrumb (2);
      return Tmp;
   exception
      when AdaFuzz_E : Constraint_Error =>
         AdaFuzz.Probe.On_Handler_Entry
           (Exception_Name    => "CONSTRAINT_ERROR",
            Exception_Message => Ada.Exceptions.Exception_Message (AdaFuzz_E),
            Handler_File      => "src.adb",
            Handler_Line      => 12,
            Last_Breadcrumb   => AdaFuzz.Probe.Last_Breadcrumb,
            Target_Id         => AdaFuzz.Probe.Current_Target,
            Testcase_Id       => AdaFuzz.Probe.Current_Testcase);
         return 0;
   end Parse;
end Pkg;
