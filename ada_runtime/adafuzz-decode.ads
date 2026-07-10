--  SPDX-License-Identifier: Apache-2.0
pragma Ada_2012;
with Ada.Streams; use Ada.Streams;
with Interfaces; use Interfaces;
package AdaFuzz.Decode is
   type Stream_Element_Array_Ref is access all Stream_Element_Array;
   type Cursor is private;
   function Open
     (Buf  : Stream_Element_Array_Ref;
      Last : Stream_Element_Offset) return Cursor;
   function U8  (C : in out Cursor) return Unsigned_8;
   function U16 (C : in out Cursor) return Unsigned_16;
   function U32 (C : in out Cursor) return Unsigned_32;
   function U64 (C : in out Cursor) return Unsigned_64;
   function I32 (C : in out Cursor) return Integer_32;
   function F64 (C : in out Cursor) return Long_Float;
   function Bool (C : in out Cursor) return Boolean;
   function Bounded_Range (C : in out Cursor; Lo, Hi : Integer) return Integer;
   function Choose_Tag (C : in out Cursor; N : Positive) return Positive;
   function Slot_Index (C : in out Cursor; Slot_Count : Natural) return Natural;
   function Bounded_Length (C : in out Cursor; Min, Max : Natural) return Natural;
   function Bytes (C : in out Cursor; Min, Max : Natural) return Stream_Element_Array;
   function Ada_String (C : in out Cursor; Min, Max : Natural) return String;
   --  Wide_String / Wide_Wide_String decoders only emitted at >=2005.
private
   type Cursor is record
      Data : Stream_Element_Array_Ref;
      Pos  : Stream_Element_Offset;
      Last : Stream_Element_Offset;
   end record;
end AdaFuzz.Decode;
