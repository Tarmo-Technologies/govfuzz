--  SPDX-License-Identifier: Apache-2.0
pragma Ada_2012;
with Ada.Unchecked_Conversion;

package body AdaFuzz.Decode is

   function Open
     (Buf  : Stream_Element_Array_Ref;
      Last : Stream_Element_Offset) return Cursor is
   begin
      return
        (Data => Buf,
         Pos  => Buf.all'First,
         Last => Last);
   end Open;

   function Has_Data (C : Cursor) return Boolean is
   begin
      return C.Data /= null and then C.Last >= C.Data.all'First;
   end Has_Data;

   procedure Wrap_If_Needed (C : in out Cursor) is
   begin
      if Has_Data (C) and then C.Pos > C.Last then
         C.Pos := C.Data.all'First;
      end if;
   end Wrap_If_Needed;

   function U8 (C : in out Cursor) return Unsigned_8 is
      Value : Unsigned_8 := 0;
   begin
      if not Has_Data (C) then
         return 0;
      end if;

      Wrap_If_Needed (C);
      Value := Unsigned_8 (C.Data.all (C.Pos));
      C.Pos := C.Pos + 1;
      return Value;
   end U8;

   function U16 (C : in out Cursor) return Unsigned_16 is
      B0 : constant Unsigned_16 := Unsigned_16 (U8 (C));
      B1 : constant Unsigned_16 := Unsigned_16 (U8 (C));
   begin
      return B0 or Shift_Left (B1, 8);
   end U16;

   function U32 (C : in out Cursor) return Unsigned_32 is
      W0 : constant Unsigned_32 := Unsigned_32 (U16 (C));
      W1 : constant Unsigned_32 := Unsigned_32 (U16 (C));
   begin
      return W0 or Shift_Left (W1, 16);
   end U32;

   function U64 (C : in out Cursor) return Unsigned_64 is
      D0 : constant Unsigned_64 := Unsigned_64 (U32 (C));
      D1 : constant Unsigned_64 := Unsigned_64 (U32 (C));
   begin
      return D0 or Shift_Left (D1, 32);
   end U64;

   function To_I32 is new Ada.Unchecked_Conversion (Unsigned_32, Integer_32);
   function To_Long_Float is new Ada.Unchecked_Conversion (Unsigned_64, Long_Float);

   function I32 (C : in out Cursor) return Integer_32 is
   begin
      return To_I32 (U32 (C));
   end I32;

   function F64 (C : in out Cursor) return Long_Float is
   begin
      return To_Long_Float (U64 (C));
   end F64;

   function Bool (C : in out Cursor) return Boolean is
   begin
      return U8 (C) mod 2 = 1;
   end Bool;

   function Clamp (Value, Lo, Hi : Integer) return Integer is
   begin
      if Value < Lo then
         return Lo;
      elsif Value > Hi then
         return Hi;
      else
         return Value;
      end if;
   end Clamp;

   function Bounded_Range
     (C      : in out Cursor;
      Lo, Hi : Integer) return Integer is
      Selector : constant Unsigned_8 := U8 (C);
      Width    : Natural;
      Raw      : Unsigned_32;
   begin
      if Hi <= Lo then
         return Lo;
      end if;

      if Selector mod 4 = 0 then
         case Natural (Selector mod 6) is
            when 0 =>
               return Clamp (Lo, Lo, Hi);
            when 1 =>
               return Clamp (Lo + 1, Lo, Hi);
            when 2 =>
               return Clamp (Hi - 1, Lo, Hi);
            when 3 =>
               return Clamp (Hi, Lo, Hi);
            when 4 =>
               return Clamp (0, Lo, Hi);
            when others =>
               return Clamp (-1, Lo, Hi);
         end case;
      end if;

      Width := Natural (Hi - Lo + 1);
      Raw := U32 (C);
      return Lo + Integer (Raw mod Unsigned_32 (Width));
   end Bounded_Range;

   function Choose_Tag (C : in out Cursor; N : Positive) return Positive is
      Idx : constant Integer := Bounded_Range (C, 1, Integer (N));
   begin
      return Positive (Idx);
   end Choose_Tag;

   function Slot_Index (C : in out Cursor; Slot_Count : Natural) return Natural is
   begin
      if Slot_Count = 0 then
         return 0;
      end if;

      return Natural (Bounded_Range (C, 0, Integer (Slot_Count)));
   end Slot_Index;

   function Bounded_Length (C : in out Cursor; Min, Max : Natural) return Natural is
   begin
      return Natural (Bounded_Range (C, Integer (Min), Integer (Max)));
   end Bounded_Length;

   function Bytes
     (C        : in out Cursor;
      Min, Max : Natural) return Stream_Element_Array is
      Len    : constant Natural := Natural (Bounded_Range (C, Integer (Min), Integer (Max)));
      Result : Stream_Element_Array (1 .. Stream_Element_Offset (Len));
   begin
      for I in Result'Range loop
         Result (I) := Stream_Element (U8 (C));
      end loop;
      return Result;
   end Bytes;

   function Ada_String
     (C        : in out Cursor;
      Min, Max : Natural) return String is
      Len    : constant Natural := Natural (Bounded_Range (C, Integer (Min), Integer (Max)));
      Result : String (1 .. Len);
      Byte   : Unsigned_8;
   begin
      for I in Result'Range loop
         Byte := U8 (C);
         if Byte < 32 or else Byte > 126 then
            Result (I) := Character'Val (Integer (Byte mod 95) + 32);
         else
            Result (I) := Character'Val (Integer (Byte));
         end if;
      end loop;
      return Result;
   end Ada_String;

end AdaFuzz.Decode;
