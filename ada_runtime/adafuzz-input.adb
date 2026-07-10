--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;
with Ada.Environment_Variables;
with Interfaces.C;
with System;

package body AdaFuzz.Input is

   --  Two input modes:
   --   * Raw (default): each spawn reads its single input as the whole of stdin.
   --     This is the legacy behaviour used by per-spawn fuzzing, replay,
   --     minimize and external tooling that feeds one input per process.
   --   * Framed (the fork-server, signalled by GOVFUZZ_FRAMED): stdin is a
   --     sequence of `u32`-LE-length + bytes frames read from a persistent fd;
   --     EOF (closed stdin) ends the loop. Before every read the harness writes
   --     one sync byte to stdout: the first is the "ready" handshake (the engine
   --     reads it, with a timeout, to confirm the harness speaks the protocol);
   --     each later one means the previous input finished, so the engine reads
   --     the events delta.
   Framed_Mode : constant Boolean :=
     Ada.Environment_Variables.Exists ("GOVFUZZ_FRAMED");
   Stdin_File : Ada.Streams.Stream_IO.File_Type;
   Stdin_Open : Boolean := False;

   procedure Open_Stdin is
   begin
      if not Stdin_Open then
         Ada.Streams.Stream_IO.Open
           (Stdin_File, Ada.Streams.Stream_IO.In_File, "/dev/stdin");
         Stdin_Open := True;
      end if;
   end Open_Stdin;

   --  Read exactly Count bytes into Target (Target'First ..). Returns how many
   --  were actually read; < Count means EOF (or a closed pipe).
   procedure Read_Exact
     (Count  : Stream_Element_Offset;
      Target : out Stream_Element_Array;
      Got    : out Stream_Element_Offset) is
      Last : Stream_Element_Offset;
   begin
      Got := 0;
      while Got < Count loop
         Ada.Streams.Stream_IO.Read
           (Stdin_File,
            Target (Target'First + Got .. Target'First + Count - 1),
            Last);
         exit when Last < Target'First + Got;  --  EOF / no progress
         Got := Last - Target'First + 1;
      end loop;
   exception
      when others =>
         null;
   end Read_Exact;

   --  #427: the framed sync channel is the harness's original stdout (the pipe
   --  the fork-server reads sync bytes from). An Ada target that writes to
   --  Standard_Output (Text_IO) would share that pipe; its output fills the
   --  buffer the engine drains only one sync byte per input from, blocking the
   --  harness on write() and deadlocking the fork-server. We dup fd 1 to a
   --  private control fd, redirect fd 1 to /dev/null (discarding the target's
   --  stdout), and write sync bytes only to the control fd.
   use type Interfaces.C.int;

   function C_Dup (Fd : Interfaces.C.int) return Interfaces.C.int;
   pragma Import (C, C_Dup, "dup");
   function C_Dup2
     (Old_Fd : Interfaces.C.int; New_Fd : Interfaces.C.int)
      return Interfaces.C.int;
   pragma Import (C, C_Dup2, "dup2");
   function C_Open
     (Path : Interfaces.C.char_array; Flags : Interfaces.C.int)
      return Interfaces.C.int;
   pragma Import (C, C_Open, "open");
   function C_Write
     (Fd    : Interfaces.C.int;
      Buf   : System.Address;
      Count : Interfaces.C.size_t)
      return Interfaces.C.long;
   pragma Import (C, C_Write, "write");
   procedure C_Close (Fd : Interfaces.C.int);
   pragma Import (C, C_Close, "close");

   O_WRONLY     : constant Interfaces.C.int := 1;
   Ctrl_Fd      : Interfaces.C.int := -1;
   Stdout_Setup : Boolean := False;

   procedure Ensure_Sync_Channel is
      Devnull : Interfaces.C.int;
      Result  : Interfaces.C.int;
      pragma Warnings (Off, Result);
   begin
      if Stdout_Setup then
         return;
      end if;
      Stdout_Setup := True;
      Ctrl_Fd := C_Dup (1);
      Devnull := C_Open (Interfaces.C.To_C ("/dev/null"), O_WRONLY);
      if Devnull >= 0 then
         Result := C_Dup2 (Devnull, 1);
         if Devnull /= 1 then
            C_Close (Devnull);
         end if;
      end if;
   exception
      when others =>
         null;
   end Ensure_Sync_Channel;

   procedure Write_Sync is
      Byte   : aliased Interfaces.C.unsigned_char := 10;
      Result : Interfaces.C.long;
      pragma Warnings (Off, Result);
   begin
      Ensure_Sync_Channel;
      if Ctrl_Fd >= 0 then
         Result := C_Write (Ctrl_Fd, Byte'Address, 1);
      else
         Ada.Text_IO.Put (Character'Val (10));
         Ada.Text_IO.Flush;
      end if;
   exception
      when others =>
         null;
   end Write_Sync;

   procedure Load_From_Stream
     (File : in out Ada.Streams.Stream_IO.File_Type;
      Buf  : out Stream_Element_Array;
      Last : out Stream_Element_Offset) is
   begin
      Ada.Streams.Stream_IO.Read (File, Buf, Last);
   exception
      when others =>
         Last := Buf'First - 1;
   end Load_From_Stream;

   procedure Load_From_Stdin
     (Buf  : out Stream_Element_Array;
      Last : out Stream_Element_Offset) is
      Len_Bytes : Stream_Element_Array (1 .. 4);
      Got       : Stream_Element_Offset;
      Length    : Stream_Element_Offset;
   begin
      if not Framed_Mode then
         --  Legacy raw mode: this process's single input is all of stdin.
         Load_From_File ("/dev/stdin", Buf, Last);
         return;
      end if;

      --  Framed mode: emit a sync byte before reading. The very first one is the
      --  "ready" handshake the fork-server engine waits for to confirm this
      --  harness speaks the framed protocol; later ones mean "the previous input
      --  finished".
      Write_Sync;

      Open_Stdin;
      Read_Exact (4, Len_Bytes, Got);
      if Got < 4 then
         Last := Buf'First - 1;  --  EOF: no more inputs
         return;
      end if;
      Length :=
        Stream_Element_Offset (Len_Bytes (1))
        + Stream_Element_Offset (Len_Bytes (2)) * 256
        + Stream_Element_Offset (Len_Bytes (3)) * 65536
        + Stream_Element_Offset (Len_Bytes (4)) * 16777216;
      if Length <= 0 then
         Last := Buf'First - 1;  --  empty input frame (degenerate; treat as none)
         return;
      end if;
      if Length > Buf'Length then
         Length := Buf'Length;  --  cap to the harness buffer
      end if;
      Read_Exact (Length, Buf, Got);
      Last := Buf'First + Got - 1;
   exception
      when others =>
         Last := Buf'First - 1;
   end Load_From_Stdin;

   procedure Load_From_File
     (Path : String;
      Buf  : out Stream_Element_Array;
      Last : out Stream_Element_Offset) is
      File : Ada.Streams.Stream_IO.File_Type;
   begin
      Ada.Streams.Stream_IO.Open
        (File => File,
         Mode => Ada.Streams.Stream_IO.In_File,
         Name => Path);
      Load_From_Stream (File, Buf, Last);
      if Ada.Streams.Stream_IO.Is_Open (File) then
         Ada.Streams.Stream_IO.Close (File);
      end if;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File) then
            Ada.Streams.Stream_IO.Close (File);
         end if;
         Last := Buf'First - 1;
   end Load_From_File;

   procedure Load_From_Shared_Memory
     (Buf  : out Stream_Element_Array;
      Last : out Stream_Element_Offset) is
   begin
      --  M3 stub; the AFL++ shared-memory adapter fills this in during M14.
      Last := Buf'First - 1;
   end Load_From_Shared_Memory;

end AdaFuzz.Input;
