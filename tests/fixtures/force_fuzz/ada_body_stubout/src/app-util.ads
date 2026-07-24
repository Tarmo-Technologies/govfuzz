--  SPDX-License-Identifier: Apache-2.0
package App.Util is
   --  Driveable Integer target. It needs nothing from the parent BODY, but
   --  compiling it drags in app.adb (the mandatory parent body).
   function Double (X : Integer) return Integer;
end App.Util;
