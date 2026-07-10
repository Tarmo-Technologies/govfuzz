--  SPDX-License-Identifier: Apache-2.0
with Ada.Unchecked_Deallocation;

package body Parser_Ctx is

   procedure Free is new Ada.Unchecked_Deallocation (Context, Context_Access);

   function Create return Context_Access is
   begin
      return new Context'(Sum => 0, Count => 0);
   end Create;

   procedure Destroy (Ctx : in out Context_Access) is
   begin
      if Ctx /= null then
         Free (Ctx);
      end if;
   end Destroy;

   procedure Parse (Ctx : Context_Access; Data : String) is
      use type Interfaces.Unsigned_32;
   begin
      if Ctx = null then
         return;
      end if;
      for C of Data loop
         Ctx.Sum   := Ctx.Sum + Interfaces.Unsigned_32 (Character'Pos (C));
         Ctx.Count := Ctx.Count + 1;
      end loop;
   end Parse;

   function Checksum (Ctx : Context_Access) return Interfaces.Unsigned_32 is
      use type Interfaces.Unsigned_32;
   begin
      if Ctx = null then
         return 0;
      end if;
      return Ctx.Sum xor Interfaces.Unsigned_32 (Ctx.Count);
   end Checksum;

end Parser_Ctx;
