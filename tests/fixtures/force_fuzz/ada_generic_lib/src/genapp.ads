--  SPDX-License-Identifier: Apache-2.0
package Genapp is

   --  An indefinite type: passed as a generic formal type actual, it forces the
   --  stub's `is private` formal to widen to `(<>) is private`.
   type Label_Name is new String;
   Empty_Label : constant Label_Name := "";

   function To_Label (Value : String) return Label_Name;
   function To_Retries (Value : String) return Natural;

   --  Driveable String target. Its body reads values back THROUGH both generic
   --  instances, which is what makes the shared stub entity formal-typed.
   function Score (Input : String) return Integer;

end Genapp;
