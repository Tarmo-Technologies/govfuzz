--  SPDX-License-Identifier: Apache-2.0
with Vendorbig.Json;
with Vendorbig.Strings;
with Vendorbig.Errors;
package body Bigapp is

   function Process (Input : String) return Integer is
      Doc  : Vendorbig.Json.JSON_Value;
      Name : Vendorbig.Json.UTF8_String := "";
      Len  : Integer := 0;
   begin
      --  Exercises: string-arg function returning a stub type (Parse), a stub
      --  handle type (JSON_Value), a stub String subtype (UTF8_String), a bare
      --  enum-value constant (JSON_String_Type), a 2-arg call with a string
      --  literal (Get), a default-parameter-style call (Length), and a
      --  qualified exception handler (Parse_Error) — all across three missing
      --  packages that --force reconstructs into a compilable stub tree.
      Doc := Vendorbig.Json.Parse (Input);
      if Vendorbig.Json.Kind (Doc) = Vendorbig.Json.JSON_String_Type then
         Name := Vendorbig.Json.Get (Doc, "field");
         Len  := Vendorbig.Strings.Length (Name);
      end if;
      return Len;
   exception
      when Vendorbig.Errors.Parse_Error =>
         return -1;
   end Process;

end Bigapp;
