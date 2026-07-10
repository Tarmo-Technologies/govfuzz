--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2005;

with CORBA.Object;
with PortableServer;

package Bar_Impl is
   type Servant is new PortableServer.Servant_Base with null record;

   function Object_Ref return CORBA.Object.Ref;
   function Compute (Self : Servant; S : String) return Integer;
end Bar_Impl;
