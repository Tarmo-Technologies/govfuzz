--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2012;

package Cache is
   type Cache_Entry is private;
private
   type Cache_Entry is record
      Value : Integer;
   end record;
end Cache;
