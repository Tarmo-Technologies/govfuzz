--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;
with Ada.Streams;
with Interfaces; use Interfaces;
with System;

package body AdaFuzz.Probe is

   use Ada.Streams;

   Ring_Size : constant := 16;

   subtype Ring_Cursor is Natural range 0 .. Ring_Size - 1;
   type Ring is array (Ring_Cursor) of Crumb_Id;

   Tag_Begin    : constant Unsigned_8 := 1;
   Tag_End      : constant Unsigned_8 := 2;
   Tag_Crumb    : constant Unsigned_8 := 3;
   Tag_Target   : constant Unsigned_8 := 4;
   Tag_Handler  : constant Unsigned_8 := 5;
   Tag_Raise    : constant Unsigned_8 := 6;
   Tag_Mock     : constant Unsigned_8 := 7;
   Tag_TopLevel : constant Unsigned_8 := 8;

   Semihosting_File_Descriptor : constant Unsigned_32 := 2;

   procedure Semihosting_Write
     (File_Descriptor : Unsigned_32;
      Buffer_Address  : System.Address;
      Length          : Unsigned_32);
   pragma Import
     (C, Semihosting_Write, "adafuzz_semihosting_write");

   Crumbs  : Ring := (others => 0);
   Cursor  : Ring_Cursor := 0;
   Cur_Tgt : Target_Id := 0;
   Cur_TC  : Testcase_Id := 0;

   procedure Open_If_Needed is
   begin
      null;
   exception
      when others =>
         null;
   end Open_If_Needed;

   procedure Write_Raw (Buffer : Stream_Element_Array) is
   begin
      if Buffer'Length > 0 then
         Semihosting_Write
           (File_Descriptor => Semihosting_File_Descriptor,
            Buffer_Address  => Buffer (Buffer'First)'Address,
            Length          => Unsigned_32 (Buffer'Length));
      end if;
   exception
      when others =>
         null;
   end Write_Raw;

   procedure Write_U8_LE (Value : Unsigned_8) is
      Buffer : constant Stream_Element_Array (1 .. 1) :=
        (1 => Stream_Element (Value));
   begin
      Write_Raw (Buffer);
   exception
      when others =>
         null;
   end Write_U8_LE;

   procedure Write_U32_LE (Value : Unsigned_32) is
      Buffer : constant Stream_Element_Array (1 .. 4) :=
        (1 => Stream_Element (Value and 16#FF#),
         2 => Stream_Element (Shift_Right (Value, 8) and 16#FF#),
         3 => Stream_Element (Shift_Right (Value, 16) and 16#FF#),
         4 => Stream_Element (Shift_Right (Value, 24) and 16#FF#));
   begin
      Write_Raw (Buffer);
   exception
      when others =>
         null;
   end Write_U32_LE;

   procedure Write_U64_LE (Value : Unsigned_64) is
      Buffer : constant Stream_Element_Array (1 .. 8) :=
        (1 => Stream_Element (Value and 16#FF#),
         2 => Stream_Element (Shift_Right (Value, 8) and 16#FF#),
         3 => Stream_Element (Shift_Right (Value, 16) and 16#FF#),
         4 => Stream_Element (Shift_Right (Value, 24) and 16#FF#),
         5 => Stream_Element (Shift_Right (Value, 32) and 16#FF#),
         6 => Stream_Element (Shift_Right (Value, 40) and 16#FF#),
         7 => Stream_Element (Shift_Right (Value, 48) and 16#FF#),
         8 => Stream_Element (Shift_Right (Value, 56) and 16#FF#));
   begin
      Write_Raw (Buffer);
   exception
      when others =>
         null;
   end Write_U64_LE;

   procedure Write_String (Value : String) is
   begin
      Write_U32_LE (Unsigned_32 (Value'Length));

      if Value'Length > 0 then
         declare
            Buffer   : Stream_Element_Array
              (1 .. Stream_Element_Offset (Value'Length));
            Position : Stream_Element_Offset := 1;
         begin
            for Index in Value'Range loop
               Buffer (Position) :=
                 Stream_Element (Character'Pos (Value (Index)));
               Position := Position + 1;
            end loop;

            Write_Raw (Buffer);
         end;
      end if;
   exception
      when others =>
         null;
   end Write_String;

   procedure Write_Event (Tag : Unsigned_8) is
   begin
      Open_If_Needed;
      Write_U8_LE (Tag);
   exception
      when others =>
         null;
   end Write_Event;

   procedure Write_Event (Tag : Unsigned_8; U8 : Unsigned_8) is
   begin
      Open_If_Needed;
      Write_U8_LE (Tag);
      Write_U8_LE (U8);
   exception
      when others =>
         null;
   end Write_Event;

   procedure Write_Event (Tag : Unsigned_8; U32 : Unsigned_32) is
   begin
      Open_If_Needed;
      Write_U8_LE (Tag);
      Write_U32_LE (U32);
   exception
      when others =>
         null;
   end Write_Event;

   procedure Write_Event (Tag : Unsigned_8; U64 : Unsigned_64) is
   begin
      Open_If_Needed;
      Write_U8_LE (Tag);
      Write_U64_LE (U64);
   exception
      when others =>
         null;
   end Write_Event;

   procedure Write_Handler_Event
     (Exception_Name    : String;
      Exception_Message : String;
      Handler_File      : String;
      Handler_Line      : Natural;
      Last_Breadcrumb   : Crumb_Id;
      Target_Id         : AdaFuzz.Probe.Target_Id;
      Testcase_Id       : AdaFuzz.Probe.Testcase_Id) is
   begin
      Open_If_Needed;
      Write_U8_LE (Tag_Handler);
      Write_String (Exception_Name);
      Write_String (Exception_Message);
      Write_String (Handler_File);
      Write_U32_LE (Unsigned_32 (Handler_Line));
      Write_U32_LE (Unsigned_32 (Last_Breadcrumb));
      Write_U32_LE (Unsigned_32 (Target_Id));
      Write_U64_LE (Unsigned_64 (Testcase_Id));
   exception
      when others =>
         null;
   end Write_Handler_Event;

   procedure Write_Explicit_Raise_Event
     (Exception_Name : String;
      File           : String;
      Line           : Natural;
      Breadcrumb     : Crumb_Id) is
   begin
      Open_If_Needed;
      Write_U8_LE (Tag_Raise);
      Write_String (Exception_Name);
      Write_String (File);
      Write_U32_LE (Unsigned_32 (Line));
      Write_U32_LE (Unsigned_32 (Breadcrumb));
   exception
      when others =>
         null;
   end Write_Explicit_Raise_Event;

   procedure Write_Top_Level_Event
     (Exception_Name    : String;
      Exception_Message : String) is
   begin
      Open_If_Needed;
      Write_U8_LE (Tag_TopLevel);
      Write_String (Exception_Name);
      Write_String (Exception_Message);
      Write_U32_LE (Unsigned_32 (Last_Breadcrumb));
      Write_U32_LE (Unsigned_32 (Cur_Tgt));
      Write_U64_LE (Unsigned_64 (Cur_TC));
   exception
      when others =>
         null;
   end Write_Top_Level_Event;

   procedure Write_Mock_Event (Symbol : String) is
   begin
      Open_If_Needed;
      Write_U8_LE (Tag_Mock);
      Write_String (Symbol);
      Write_U32_LE (Unsigned_32 (Last_Breadcrumb));
      Write_U32_LE (Unsigned_32 (Cur_Tgt));
      Write_U64_LE (Unsigned_64 (Cur_TC));
   exception
      when others =>
         null;
   end Write_Mock_Event;

   procedure Begin_Testcase (TC : Testcase_Id) is
   begin
      Cur_TC := TC;
      Cursor := 0;
      Crumbs := (others => 0);
      Open_If_Needed;
      Write_Event (Tag => Tag_Begin, U64 => Unsigned_64 (TC));
   exception
      when others =>
         null;
   end Begin_Testcase;

   procedure End_Testcase (Result_Class : Interfaces.Unsigned_8 := 0) is
   begin
      Write_Event (Tag => Tag_End, U8 => Result_Class);
      Flush;
   exception
      when others =>
         null;
   end End_Testcase;

   procedure Set_Target (T : Target_Id) is
   begin
      Cur_Tgt := T;
      Write_Event (Tag => Tag_Target, U32 => Unsigned_32 (T));
   exception
      when others =>
         null;
   end Set_Target;

   procedure Flush is
   begin
      null;
   exception
      when others =>
         null;
   end Flush;

   procedure Breadcrumb (Id : Crumb_Id) is
   begin
      Crumbs (Cursor) := Id;
      Cursor := (Cursor + 1) mod Ring_Size;
      Write_Event (Tag => Tag_Crumb, U32 => Unsigned_32 (Id));
   exception
      when others =>
         null;
   end Breadcrumb;

   function Last_Breadcrumb return Crumb_Id is
   begin
      return Crumbs ((Cursor + Ring_Size - 1) mod Ring_Size);
   exception
      when others =>
         return 0;
   end Last_Breadcrumb;

   function Current_Target return Target_Id is
   begin
      return Cur_Tgt;
   exception
      when others =>
         return 0;
   end Current_Target;

   function Current_Testcase return Testcase_Id is
   begin
      return Cur_TC;
   exception
      when others =>
         return 0;
   end Current_Testcase;

   procedure On_Handler_Entry
     (Exception_Name    : String;
      Exception_Message : String;
      Handler_File      : String;
      Handler_Line      : Natural;
      Last_Breadcrumb   : Crumb_Id;
      Target_Id         : AdaFuzz.Probe.Target_Id;
      Testcase_Id       : AdaFuzz.Probe.Testcase_Id) is
   begin
      Write_Handler_Event
        (Exception_Name    => Exception_Name,
         Exception_Message => Exception_Message,
         Handler_File      => Handler_File,
         Handler_Line      => Handler_Line,
         Last_Breadcrumb   => Last_Breadcrumb,
         Target_Id         => Target_Id,
         Testcase_Id       => Testcase_Id);
   exception
      when others =>
         null;
   end On_Handler_Entry;

   procedure On_Explicit_Raise
     (Exception_Name : String;
      File           : String;
      Line           : Natural;
      Breadcrumb     : Crumb_Id) is
   begin
      Write_Explicit_Raise_Event
        (Exception_Name => Exception_Name,
         File           => File,
         Line           => Line,
         Breadcrumb     => Breadcrumb);
   exception
      when others =>
         null;
   end On_Explicit_Raise;

   procedure On_Top_Level_Catch
     (Exception_Name    : String;
      Exception_Message : String) is
   begin
      Write_Top_Level_Event
        (Exception_Name    => Exception_Name,
         Exception_Message => Exception_Message);
   exception
      when others =>
         null;
   end On_Top_Level_Catch;

   procedure Mock_Call (Symbol : String) is
   begin
      Write_Mock_Event (Symbol);
   exception
      when others =>
         null;
   end Mock_Call;

end AdaFuzz.Probe;
