-- SPDX-License-Identifier: Apache-2.0

with Ada.Streams; use Ada.Streams;
with AdaFuzz.Input;
with Filesystem.Fat;

procedure Adl_Basename is
   Buffer : Stream_Element_Array (1 .. 1_048_576);
   Last   : Stream_Element_Offset;
begin
   loop
      AdaFuzz.Input.Load_From_Stdin (Buffer, Last);
      exit when Last < Buffer'First;
      declare
         Path : String (1 .. Natural (Last));
      begin
         for Index in Path'Range loop
            Path (Index) := Character'Val (Buffer (Stream_Element_Offset (Index)));
         end loop;
         declare
            Result : constant String := Filesystem.Fat.Basename (Path);
            pragma Unreferenced (Result);
         begin
            null;
         end;
      end;
   end loop;
end Adl_Basename;
