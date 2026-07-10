--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2012;

package Jobs is
   procedure Submit;
   procedure Cancel;
   function Count return Natural;
end Jobs;
