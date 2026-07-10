--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2022;

package Tasking is
   task type Worker is
      entry Start;
   end Worker;
end Tasking;
