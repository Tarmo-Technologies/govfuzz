--  SPDX-License-Identifier: Apache-2.0

pragma Ada_2005;

procedure Fail_With_Message is
begin
   raise Constraint_Error with "bad input";
end Fail_With_Message;
