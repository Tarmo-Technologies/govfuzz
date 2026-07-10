--  SPDX-License-Identifier: Apache-2.0
pragma Ada_2012;

package State is
   procedure Push (X : Integer);
   procedure Pop;
   function Top return Integer;
end State;
