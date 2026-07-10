--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

package body Initializer_Raise is
begin
   raise Program_Error;
exception
   when others =>
      null;
end Initializer_Raise;
