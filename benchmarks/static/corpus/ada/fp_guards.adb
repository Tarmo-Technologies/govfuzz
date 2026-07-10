--  SPDX-License-Identifier: Apache-2.0
--  Campaign 2026-07-03 Ada regression guards. A `with`/`use` context clause is
--  an import, not a hazard site; `Selected`/`Selection` must not match the
--  `select` tasking keyword; a subprogram declaration is not a file-open call.
--  Lines without `EXPECT` must produce no finding.
with GNAT.OS_Lib;                     --  safe: import, not a spawn (GF-412)
with Ada.Unchecked_Deallocation;      --  safe: import, not a free site (GF-410)
with Ada.Unchecked_Conversion;        --  safe: import, not a conversion (GF-409)
use GNAT.OS_Lib;                      --  safe: use clause

package body Fp_Guards is

   --  GF-405: a subprogram DECLARATION is not a call site.
   function Open (Path : String) return File_Descriptor;

   procedure Run (User_Path : String; Cmd : String) is
      Selected : Integer := 0;        --  safe: not the `select` keyword (GF-411)
      Selection_Count : Integer := 1; --  safe: not the `select` keyword
      FD : File_Descriptor;
   begin
      Selected := Selection_Count;
      GNAT.OS_Lib.Spawn (Cmd);        --  EXPECT GF-304 (taint supersedes GF-412)
      FD := FS.Open (Path => User_Path); --  EXPECT GF-405
   end Run;

   --  GF-412 pattern positive: a spawn whose argument is a local constant is not
   --  taint-reachable, so the process-dependency pattern (not GF-304) fires.
   procedure Launch is
      Fixed : constant String := "ls -l";
   begin
      Trace.Detail ("Spawning: " & Fixed); --  safe: keyword only in a log string
      GNAT.OS_Lib.Spawn (Fixed);      --  EXPECT GF-412
   end Launch;                        --  safe: `end` terminator, not a call

   function Unchecked_Spawn (Cmd : String) return Integer; --  safe: declaration

   --  GF-410 / GF-409 positives: the instantiation IS the hazard site.
   procedure Free is new Ada.Unchecked_Deallocation (Object, Object_Access); --  EXPECT GF-410
   function Conv is new Ada.Unchecked_Conversion (Source, Target);           --  EXPECT GF-409

end Fp_Guards;
