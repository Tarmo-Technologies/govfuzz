--  SPDX-License-Identifier: Apache-2.0
--  A target that depends on Vendor_Lib. It builds and fuzzes normally; when the
--  offline-dependency scenario removes Vendor_Lib, auto must categorize this as a
--  failed build that names the unresolved unit (not crash, not silently pass).
package Dep_Parser is
   function Check (Data : String) return Integer;
end Dep_Parser;
