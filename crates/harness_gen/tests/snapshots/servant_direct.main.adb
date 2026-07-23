--  generated_harnesses/H-M12/main.adb
--  SPDX-License-Identifier: Apache-2.0
pragma Ada_2012;
with Ada.Streams; use Ada.Streams;
with Ada.Exceptions;
with Interfaces; use Interfaces;
with AdaFuzz.Input;
with AdaFuzz.Decode;
with AdaFuzz.Probe;
with Bar_Impl;

procedure Main is
   use type Interfaces.Unsigned_64;

   Buf  : aliased Stream_Element_Array := (1 .. 1 * 1024 * 1024 => 0);
   Last : Stream_Element_Offset;
   TC   : AdaFuzz.Probe.Testcase_Id := 0;
begin
   loop
      AdaFuzz.Input.Load_From_Stdin (Buf, Last);
      exit when Last < Buf'First;
      TC := TC + 1;
      AdaFuzz.Probe.Begin_Testcase (TC);
      AdaFuzz.Probe.Set_Target (16#002B#);
      begin
      declare
         Cur : AdaFuzz.Decode.Cursor := AdaFuzz.Decode.Open (Buf'Unchecked_Access, Last);
         Server : Bar_Impl.Servant;
         S : String := AdaFuzz.Decode.Ada_String (Cur, 0, 1024);
      begin
         AdaFuzz.Probe.Target_Entry;
         declare
            Gf_Result : constant Integer := Bar_Impl.Compute (Server, S);
            pragma Unreferenced (Gf_Result);
         begin
            null;
         end;
      exception
         when AdaFuzz_E : others =>
            AdaFuzz.Probe.On_Top_Level_Catch
              (Ada.Exceptions.Exception_Name (AdaFuzz_E),
               Ada.Exceptions.Exception_Message (AdaFuzz_E));
      end;
      exception
         when others =>
            --  A parameter/receiver initializer raised in the declarative part
            --  (e.g. a decoder draw outside its subtype range); skip this input
            --  rather than crash the harness process.
            null;
      end;
      AdaFuzz.Probe.End_Testcase;
      AdaFuzz.Probe.Flush;
   end loop;
end Main;
