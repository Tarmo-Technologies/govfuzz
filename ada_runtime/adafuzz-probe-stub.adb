--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;
with Ada.Command_Line;
with Interfaces; use Interfaces;

package body AdaFuzz.Probe is

   Ring_Size : constant := 16;

   subtype Ring_Cursor is Natural range 0 .. Ring_Size - 1;
   type Ring is array (Ring_Cursor) of Crumb_Id;

   Crumbs            : Ring := (others => 0);
   Cursor            : Ring_Cursor := 0;
   Cur_Tgt           : Target_Id := 0;
   Cur_TC            : Testcase_Id := 0;
   Exit_Result_Class : Interfaces.Unsigned_8 := 0;

   procedure Record_Result_Class (Result_Class : Interfaces.Unsigned_8) is
   begin
      if Result_Class > Exit_Result_Class then
         Exit_Result_Class := Result_Class;
      end if;
   exception
      when others =>
         null;
   end Record_Result_Class;

   procedure Apply_Exit_Status is
   begin
      Ada.Command_Line.Set_Exit_Status
        (Ada.Command_Line.Exit_Status (Exit_Result_Class));
   exception
      when others =>
         null;
   end Apply_Exit_Status;

   procedure Begin_Testcase (TC : Testcase_Id) is
   begin
      Cur_TC := TC;
      Cursor := 0;
      Crumbs := (others => 0);
   exception
      when others =>
         null;
   end Begin_Testcase;

   procedure End_Testcase (Result_Class : Interfaces.Unsigned_8 := 0) is
   begin
      Record_Result_Class (Result_Class);
      Apply_Exit_Status;
   exception
      when others =>
         null;
   end End_Testcase;

   procedure Set_Target (T : Target_Id) is
   begin
      Cur_Tgt := T;
   exception
      when others =>
         null;
   end Set_Target;

   procedure Target_Entry is
   begin
      null;
   end Target_Entry;

   procedure Flush is
   begin
      Apply_Exit_Status;
   exception
      when others =>
         null;
   end Flush;

   procedure Breadcrumb (Id : Crumb_Id) is
   begin
      Crumbs (Cursor) := Id;
      Cursor := (Cursor + 1) mod Ring_Size;
   exception
      when others =>
         null;
   end Breadcrumb;

   function Last_Breadcrumb return Crumb_Id is
   begin
      return Crumbs ((Cursor + Ring_Size - 1) mod Ring_Size);
   exception
      when others =>
         return 0;
   end Last_Breadcrumb;

   function Current_Target return Target_Id is
   begin
      return Cur_Tgt;
   exception
      when others =>
         return 0;
   end Current_Target;

   function Current_Testcase return Testcase_Id is
   begin
      return Cur_TC;
   exception
      when others =>
         return 0;
   end Current_Testcase;

   procedure On_Handler_Entry
     (Exception_Name    : String;
      Exception_Message : String;
      Handler_File      : String;
      Handler_Line      : Natural;
      Last_Breadcrumb   : Crumb_Id;
      Target_Id         : AdaFuzz.Probe.Target_Id;
      Testcase_Id       : AdaFuzz.Probe.Testcase_Id) is
      pragma Unreferenced
        (Exception_Name,
         Exception_Message,
         Handler_File,
         Handler_Line,
         Last_Breadcrumb,
         Target_Id,
         Testcase_Id);
   begin
      null;
   exception
      when others =>
         null;
   end On_Handler_Entry;

   procedure On_Explicit_Raise
     (Exception_Name : String;
      File           : String;
      Line           : Natural;
      Breadcrumb     : Crumb_Id) is
      pragma Unreferenced (Exception_Name, File, Line, Breadcrumb);
   begin
      null;
   exception
      when others =>
         null;
   end On_Explicit_Raise;

   procedure On_Top_Level_Catch
     (Exception_Name    : String;
      Exception_Message : String) is
      pragma Unreferenced (Exception_Name, Exception_Message);
   begin
      Record_Result_Class (1);
      Apply_Exit_Status;
   exception
      when others =>
         null;
   end On_Top_Level_Catch;

   procedure Mock_Call (Symbol : String) is
      pragma Unreferenced (Symbol);
   begin
      null;
   exception
      when others =>
         null;
   end Mock_Call;

end AdaFuzz.Probe;
