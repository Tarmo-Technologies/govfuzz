--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2005;

with CORBA;
with CORBA.Any;
with CORBA.Object;
with CORBA.TypeCode;
with Legacy.Control.Controller;
with Legacy.Telemetry;
with Legacy.Telemetry.Admin;
with Legacy.Telemetry.Monitor;
with Legacy.Telemetry.Monitor.Helper;
with Legacy.Telemetry.Monitor.Skel;
with Legacy.Telemetry.Monitor.Stub;
with Sequence_Of_Legacy_Telemetry_Reading_Bound_8;

package body Legacy_Client is
   use type Legacy.Telemetry.Status;

   procedure Touch is
      Monitor : Legacy.Telemetry.Monitor.Ref;
      Admin : Legacy.Telemetry.Admin.Ref;
      Obj : CORBA.Object.Ref;
      Samples : Sequence_Of_Legacy_Telemetry_Reading_Bound_8.Sequence;
      Any_Value : CORBA.Any.Value;
      Code : CORBA.TypeCode.Object := CORBA.Any.Get_Type (Any_Value);
      State : Legacy.Telemetry.Status := Legacy.Telemetry.Status_Ok;
   begin
      Legacy.Telemetry.Monitor.Skel.Dispatch (Monitor);
      Legacy.Telemetry.Monitor.Stub.Notify (State);
      Samples.Length := 0;
      Any_Value := Legacy.Telemetry.Monitor.Snapshot (Samples);

      CORBA.Any.Set_Type (Any_Value, Code);
      if CORBA.Object.Is_Nil (Obj)
         or else CORBA.TypeCode.Kind (Code) = CORBA.Tk_Null
      then
         Any_Value := Legacy.Telemetry.Monitor.Helper.To_Any (Monitor);
      end if;

      Code := CORBA.TypeCode.Content_Type (Code);
      if CORBA.TypeCode.Kind (Code) = CORBA.Tk_Null then
         null;
      end if;

      State := Legacy.Telemetry.Status_Warn;
      Legacy.Telemetry.Monitor.Stub.Notify (State);
      Legacy.Telemetry.Admin.Reset (Admin, 0);
      Legacy.Control.Controller.Apply ((Length => 0, Values => (1 => 0)));
   end Touch;
end Legacy_Client;
