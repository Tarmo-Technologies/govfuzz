--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;
with Ada.Streams; use Ada.Streams;
package AdaFuzz.Input is
   procedure Load_From_Stdin (Buf : out Stream_Element_Array; Last : out Stream_Element_Offset);
   procedure Load_From_File  (Path : String; Buf : out Stream_Element_Array; Last : out Stream_Element_Offset);
   procedure Load_From_Shared_Memory (Buf : out Stream_Element_Array; Last : out Stream_Element_Offset);
end AdaFuzz.Input;
