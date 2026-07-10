--  SPDX-License-Identifier: Apache-2.0

pragma Ada_95;

procedure Outer is
   procedure Inner is
   begin
      null;
   end Inner;
begin
   Inner;
end Outer;
