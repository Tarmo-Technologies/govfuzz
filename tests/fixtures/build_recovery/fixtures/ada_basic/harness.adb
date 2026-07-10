--  SPDX-License-Identifier: Apache-2.0
with Ada.Text_IO;
with Pkg;

procedure Harness is
   Result : Integer;
begin
   Result := Pkg.Inflate ("");
   Ada.Text_IO.Put_Line (Result'Image);
end Harness;
