--  SPDX-License-Identifier: Apache-2.0
with Extlib.Gen;
package body App is
   --  Instantiates a generic package from a MISSING external library — this body
   --  cannot compile offline and cannot be stubbed as an external package (a
   --  generic instantiation stub is intractable). --force must replace THIS body.
   package Inst is new Extlib.Gen (Size => 4);
   function Root_Value return Integer is (Inst.Value);
end App;
