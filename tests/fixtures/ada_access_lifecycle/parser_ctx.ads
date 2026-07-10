--  SPDX-License-Identifier: Apache-2.0
--  An opaque-handle parsing API (zip-ada `Memory_Zipstream` shape): a private
--  context reached only through an access type, constructed by `Create` and
--  released by `Destroy`. A harness for `Parse`/`Checksum` must build the handle
--  via its lifecycle (`Ctx := Create; .. ; Destroy (Ctx);`) rather than pass null.
with Interfaces;

package Parser_Ctx is

   type Context is private;
   type Context_Access is access Context;

   --  Lifecycle: a nullary returning constructor and a one-handle destructor.
   function Create return Context_Access;
   procedure Destroy (Ctx : in out Context_Access);

   --  Fuzzable entry points that consume the handle.
   procedure Parse (Ctx : Context_Access; Data : String);
   function Checksum (Ctx : Context_Access) return Interfaces.Unsigned_32;

private

   type Context is record
      Sum   : Interfaces.Unsigned_32 := 0;
      Count : Natural                := 0;
   end record;

end Parser_Ctx;
