--  SPDX-License-Identifier: Apache-2.0
--  A tiny in-tree "dependency" package. The offline-dependency scenario deletes
--  this unit's source to reproduce the real failure mode of legacy Ada projects
--  whose Alire/GPR dependencies cannot be resolved without network access.
package Vendor_Lib is
   function Score (Data : String) return Integer;
end Vendor_Lib;
