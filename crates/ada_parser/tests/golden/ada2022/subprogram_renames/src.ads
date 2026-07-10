--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

package Renamed_Ops is
   procedure Original;
   procedure Alias renames Original;
end Renamed_Ops;
