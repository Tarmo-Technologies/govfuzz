--  SPDX-License-Identifier: Apache-2.0
with Genapp.Options;
package body Genapp is

   function To_Label (Value : String) return Label_Name is
   begin
      return Label_Name (Value);
   end To_Label;

   function To_Retries (Value : String) return Natural is
   begin
      return Value'Length;
   end To_Retries;

   function Score (Input : String) return Integer is
      Label   : constant Label_Name := Genapp.Options.Label.Get;
      Retries : constant Natural := Genapp.Options.Retries.Get;
      Total   : Integer := Input'Length + Retries;
   begin
      if Label'Length > 0 then
         Total := Total + 1;
      end if;
      return Total;
   end Score;

end Genapp;
