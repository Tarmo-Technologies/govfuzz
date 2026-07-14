-- SPDX-License-Identifier: Apache-2.0
-- A tiny Lua parser fixture for the M3.10 native Lua lane end-to-end test. The
-- `parse_record` field divides by the digit count without guarding zero — a planted
-- integer divide-by-zero (Lua 5.4 errors on x//0) that fires on any digit-free input.
local M = {}
function M.parse_record(text)
  local digits = 0
  for _ in text:gmatch("[0-9]") do digits = digits + 1 end
  return 1000 // digits
end
return M
