--  SPDX-License-Identifier: Apache-2.0
with Vendorbig.Json;
package Bigapp is
   --  Driveable String target; the body exercises a large, missing, multi-package
   --  external library (Vendorbig.*) that --force must reconstruct as stubs.
   function Process (Input : String) return Integer;
end Bigapp;
