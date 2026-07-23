--  generated_harnesses/H-M9/main.adb
--  SPDX-License-Identifier: Apache-2.0
pragma Ada_2012;
with Ada.Streams; use Ada.Streams;
with Ada.Exceptions;
with Interfaces; use Interfaces;
with AdaFuzz.Input;
with AdaFuzz.Decode;
with AdaFuzz.Probe;
with State;

procedure Main is
   use type Interfaces.Unsigned_64;

   Max_Steps : constant Natural := 32;
   Buf       : aliased Stream_Element_Array := (1 .. 1 * 1024 * 1024 => 0);
   Last      : Stream_Element_Offset;
   TC        : AdaFuzz.Probe.Testcase_Id := 0;
begin
   loop
      AdaFuzz.Input.Load_From_Stdin (Buf, Last);
      exit when Last < Buf'First;
      TC := TC + 1;
      AdaFuzz.Probe.Begin_Testcase (TC);
      AdaFuzz.Probe.Set_Target (16#0007#);
      declare
         Cur        : AdaFuzz.Decode.Cursor := AdaFuzz.Decode.Open (Buf'Unchecked_Access, Last);
         Step_Count : constant Natural := AdaFuzz.Decode.Bounded_Length (Cur, 1, Max_Steps);
      begin
         for Step in 1 .. Step_Count loop
            declare
               Op : constant Natural := Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 2));
            begin
               case Op is
                  when 0 =>
                     begin
                     declare
                        X : Integer := Integer (AdaFuzz.Decode.I32 (Cur));
                     begin
                        AdaFuzz.Probe.Target_Entry;
                        State.Push (X);
                     exception
                        when AdaFuzz_E : others =>
                           AdaFuzz.Probe.On_Top_Level_Catch
                             (Ada.Exceptions.Exception_Name (AdaFuzz_E),
                              Ada.Exceptions.Exception_Message (AdaFuzz_E));
                     end;
                     exception
                        when others =>
                           --  A parameter initializer raised in the declarative
                           --  part; skip this step rather than report a spurious
                           --  finding and abort the rest of the sequence.
                           null;
                     end;
                  when 1 =>
                     begin
                     declare
                     begin
                        AdaFuzz.Probe.Target_Entry;
                        State.Pop;
                     exception
                        when AdaFuzz_E : others =>
                           AdaFuzz.Probe.On_Top_Level_Catch
                             (Ada.Exceptions.Exception_Name (AdaFuzz_E),
                              Ada.Exceptions.Exception_Message (AdaFuzz_E));
                     end;
                     exception
                        when others =>
                           --  A parameter initializer raised in the declarative
                           --  part; skip this step rather than report a spurious
                           --  finding and abort the rest of the sequence.
                           null;
                     end;
                  when 2 =>
                     begin
                     declare
                        R_Top : Integer;
                        pragma Unreferenced (R_Top);
                     begin
                        AdaFuzz.Probe.Target_Entry;
                        R_Top := State.Top;
                     exception
                        when AdaFuzz_E : others =>
                           AdaFuzz.Probe.On_Top_Level_Catch
                             (Ada.Exceptions.Exception_Name (AdaFuzz_E),
                              Ada.Exceptions.Exception_Message (AdaFuzz_E));
                     end;
                     exception
                        when others =>
                           --  A parameter initializer raised in the declarative
                           --  part; skip this step rather than report a spurious
                           --  finding and abort the rest of the sequence.
                           null;
                     end;
                  when others =>
                     null;
               end case;
            end;
         end loop;
      exception
         when AdaFuzz_E : others =>
            AdaFuzz.Probe.On_Top_Level_Catch
              (Ada.Exceptions.Exception_Name (AdaFuzz_E),
               Ada.Exceptions.Exception_Message (AdaFuzz_E));
      end;
      AdaFuzz.Probe.End_Testcase;
      AdaFuzz.Probe.Flush;
   end loop;
end Main;
