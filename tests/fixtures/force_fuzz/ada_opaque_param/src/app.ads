--  SPDX-License-Identifier: Apache-2.0
package App is
   --  An opaque handle the type-directed decoders reject (no constructor).
   type Handle is private;
   --  Target mixes an undriveable opaque handle with a driveable String: without
   --  --force the whole target is unsupported_params; with --force the handle is
   --  default-initialized (bare-declared) and the String receives real fuzz bytes.
   function Process (H : Handle; Data : String) return Integer;
private
   type Handle is record
      Tag : Integer := 0;
   end record;
end App;
