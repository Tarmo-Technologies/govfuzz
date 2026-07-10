--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2012;

package Models is
   type Base is abstract tagged record
      Id : Integer;
   end record;
   procedure Run (Self : in out Base) is abstract;
end Models;
