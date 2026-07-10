--  SPDX-License-Identifier: Apache-2.0
--  A generic package whose operations take a PRIVATE type declared inside the
--  generic, built only through constructor functions (`Create_Null`,
--  `Create_Boolean`) that also live in the generic (the json-ada `JSON.Types`
--  shape). The generic is synthesizable (its sole formal is a discrete `type`),
--  so the harness instantiates it. A harness for `Get` must therefore reach BOTH
--  the target AND the constructors that build its `Object` argument through the
--  instance, never through the uninstantiated generic package name — Ada rejects
--  `Value_Pkg.Create_Null` with "prefix must not be a generic package".
generic
   type Integer_Type is range <>;
package Value_Pkg is

   type Value is private;

   function Create_Null return Value;

   function Create_Boolean (Flag : Boolean) return Value;

   --  The fuzz target: its `Object` parameter is the private type above, so the
   --  decoder must synthesise it via the constructor functions.
   function Get (Object : Value; Index : Positive) return Value;

private

   type Value is record
      Is_Set : Boolean := False;
      Number : Integer_Type := 0;
   end record;

end Value_Pkg;
