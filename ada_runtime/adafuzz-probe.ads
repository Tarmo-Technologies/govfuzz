--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;
with Interfaces;

package AdaFuzz.Probe is

   pragma Preelaborate;

   subtype Crumb_Id    is Interfaces.Unsigned_32;
   subtype Target_Id   is Interfaces.Unsigned_32;
   subtype Testcase_Id is Interfaces.Unsigned_64;

   procedure Begin_Testcase (TC : Testcase_Id);
   procedure End_Testcase   (Result_Class : Interfaces.Unsigned_8 := 0);
   procedure Set_Target     (T : Target_Id);
   procedure Target_Entry;
   procedure Flush;

   procedure Breadcrumb (Id : Crumb_Id);
   pragma Inline (Breadcrumb);

   function Last_Breadcrumb return Crumb_Id;
   function Current_Target  return Target_Id;
   function Current_Testcase return Testcase_Id;

   procedure On_Handler_Entry
     (Exception_Name    : String;
      Exception_Message : String;
      Handler_File      : String;
      Handler_Line      : Natural;
      Last_Breadcrumb   : Crumb_Id;
      Target_Id         : AdaFuzz.Probe.Target_Id;
      Testcase_Id       : AdaFuzz.Probe.Testcase_Id);

   procedure On_Explicit_Raise
     (Exception_Name : String;
      File           : String;
      Line           : Natural;
      Breadcrumb     : Crumb_Id);

   procedure On_Top_Level_Catch
     (Exception_Name    : String;
      Exception_Message : String);

   procedure Mock_Call (Symbol : String);

end AdaFuzz.Probe;
