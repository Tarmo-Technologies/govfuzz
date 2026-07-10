--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

procedure Use_Target_Name is
   Count : Integer := 0;
begin
   Count := @ + 1;
end Use_Target_Name;
