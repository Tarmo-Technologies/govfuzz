--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2005;

package Interface_Types is
   type Worker is interface;
   procedure Execute (Self : in out Worker) is abstract;
end Interface_Types;
