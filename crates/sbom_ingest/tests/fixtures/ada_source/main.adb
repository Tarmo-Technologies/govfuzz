-- SPDX-License-Identifier: Apache-2.0
-- Fixture: an Ada body whose `with` clauses mix stdlib roots (skipped) with
-- third-party units (emitted as SourceObserved).
with Ada.Text_IO;        -- stdlib root → skipped
with Interfaces.C;       -- stdlib root → skipped
with System.Storage_Elements;  -- stdlib root → skipped
with GNAT.OS_Lib;        -- GNAT runtime → skipped
with Gnatcoll.Json;      -- third party → Gnatcoll
with Mylib.Core;         -- third party → Mylib

procedure Main is
begin
   null;
end Main;
