--  SPDX-License-Identifier: Apache-2.0
with Vendorcb;
package body Cbapp is

   function Total (Input : String) return Integer is
      Sum : Integer := 0;

      procedure Accumulate (Name  : Vendorcb.Field_Name;
                            Value : Vendorcb.Field_Value) is
      begin
         Sum := Sum + Vendorcb.Width (Value) + Vendorcb.Length (Name);
      end Accumulate;

      Doc : Vendorcb.Document := Vendorcb.Parse (Input);
   begin
      Vendorcb.Each_Field (Doc, Accumulate'Access);
      return Sum;
   end Total;

end Cbapp;
