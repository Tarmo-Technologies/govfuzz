--  SPDX-License-Identifier: Apache-2.0
package App is
   --  Root spec declares a subprogram, so a body is MANDATORY and every child
   --  unit drags the (offline-unbuildable) parent body into its build.
   function Root_Value return Integer;
end App;
