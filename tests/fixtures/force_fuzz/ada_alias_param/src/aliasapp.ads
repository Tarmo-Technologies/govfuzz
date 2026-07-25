--  SPDX-License-Identifier: Apache-2.0
with Vendorx.Doc;
package Aliasapp is

   --  The project RE-EXPORTS a type of the missing library under its own name.
   --  A child unit then names it unqualified, so the harness must declare the
   --  parameter by a spelling it can actually see: `Aliasapp.Handle`, not the
   --  external `Vendorx.Doc.Handle` (which the harness has no `with` for).
   subtype Handle is Vendorx.Doc.Handle;

end Aliasapp;
