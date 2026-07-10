--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

package Protected_Objects is
   protected type Gate is
      entry Lock;
      procedure Release;
   private
      Open : Boolean := True;
   end Gate;
end Protected_Objects;
