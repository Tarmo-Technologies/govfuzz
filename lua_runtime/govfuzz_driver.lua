-- SPDX-License-Identifier: Apache-2.0
-- govfuzz Lua fork-server driver. A debug.sethook("l") line hook records edge
-- coverage into the shared GOVFUZZ_COV_SHM map. Speaks the GOVFUZZ_FRAMED protocol
-- (matches c_runtime/govfuzz_driver.c and the Ruby/Perl drivers): fd 1 control pipe,
-- fd 0 input pipe ({u32 LE len, bytes}). A finding errors -> stderr marker + exit 86
-- (no sync byte); an expected rejection (a bad-argument / index-nil error) is
-- swallowed. No third-party fuzzer.

local FINDING_HALT = 86
local TARGET_MODULE = os.getenv("GOVFUZZ_TARGET_MODULE") or ""

-- ---- Coverage: a debug.sethook("l") line hook folded into a 64KB edge bitmap. ----
local COV_BITS = 1 << 16
local COV_MASK = COV_BITS - 1
local cov = {}                                   -- sparse byte map: idx -> count
local dirty = {}                                 -- indices changed since last flush
local cov_prev = 0
local cov_prefix = os.getenv("GOVFUZZ_TRACE_PREFIX") or ""
local covered = {}
local covered_dumped = 0
local file_sized = false

local function fnv(str, line)
  local h = 0x811c9dc5
  for k = 1, #str do
    h = ((h ~ str:byte(k)) * 0x01000193) & 0xFFFFFFFF
  end
  h = ((h ~ (line & 0xFF)) * 0x01000193) & 0xFFFFFFFF
  h = ((h ~ ((line >> 8) & 0xFF)) * 0x01000193) & 0xFFFFFFFF
  return h & COV_MASK
end

local function line_hook(_, line)
  local info = debug.getinfo(2, "S")
  if not info then return end
  local src = info.source
  if src:sub(1, 1) == "@" then src = src:sub(2) end
  if cov_prefix ~= "" and src:sub(1, #cov_prefix) ~= cov_prefix then return end
  covered[src .. ":" .. line] = true
  local block = fnv(src, line)
  local idx = (cov_prev ~ block) & COV_MASK
  local v = cov[idx] or 0
  if v < 0xFF then
    cov[idx] = v + 1
    dirty[idx] = true
  end
  cov_prev = (block >> 1) & COV_MASK
end

local function reset_prev() cov_prev = 0 end

-- Write only the bytes that changed since the last flush into the shared 64KB edge
-- bitmap (the engine mmaps it read-only). The file is pre-sized to 64KB once; the
-- map is cumulative (counts only grow), so per-input dirty-writes suffice and avoid
-- rebuilding the whole image each exec.
local function flush_cov()
  local path = os.getenv("GOVFUZZ_COV_SHM")
  if not path or path == "" then return end
  local f = io.open(path, "r+b") or io.open(path, "wb")
  if not f then return end
  if not file_sized then
    f:seek("set", COV_BITS - 1)
    f:write("\0")
    file_sized = true
  end
  for idx in pairs(dirty) do
    f:seek("set", idx)
    f:write(string.char(cov[idx]))
    dirty[idx] = nil
  end
  f:close()
end

local function dump_covered()
  local path = os.getenv("GOVFUZZ_COVERED_LINES")
  if not path or path == "" then return end
  local n = 0
  for _ in pairs(covered) do n = n + 1 end
  if n == covered_dumped then return end
  local keys = {}
  for k in pairs(covered) do keys[#keys + 1] = k end
  table.sort(keys)
  local f = io.open(path .. ".tmp", "w")
  if not f then return end
  f:write(table.concat(keys, "\n"))
  f:close()
  os.rename(path .. ".tmp", path)
  covered_dumped = n
end

-- ---- Finding classification (FP-avoidant, like the Ruby/Python/Perl lanes). ----
-- Only high-confidence bug-class errors are findings; Lua's normal input-rejection
-- errors ("attempt to index a nil value", "bad argument", "attempt to call") are
-- suppressed. `msg` is the error value stringified.
local function bug_cwe(msg)
  msg = tostring(msg)
  local lower = msg:lower()
  -- A target-namespaced error object (rare in Lua) is a declared rejection.
  if TARGET_MODULE ~= "" and lower:find(TARGET_MODULE:lower(), 1, true) and lower:find("reject") then
    return nil
  end
  if lower:find("stack overflow", 1, true) then return "CWE-674" end
  if lower:find("not enough memory", 1, true) or lower:find("out of memory", 1, true) then
    return "CWE-789"
  end
  -- Lua 5.4 integer divide/modulo by zero: "attempt to perform 'n//0'" / "'n%%0'".
  if lower:find("'n//0'", 1, true) or lower:find("'n%%0'", 1, true)
      or lower:find("divide by zero", 1, true) then
    return "CWE-369"
  end
  if lower:find("assert", 1, true) or lower:find("unreachable", 1, true)
      or lower:find("invariant", 1, true) or lower:find("should not happen", 1, true) then
    return "CWE-617"
  end
  return nil -- generic Lua error = normal input rejection, suppressed
end

local control -- fd 1 handle, saved before stdout redirect

local function report_finding(cwe, msg)
  msg = tostring(msg):gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
  io.stderr:write("== govfuzz lua finding: " .. cwe .. ": " .. msg .. "\n")
  os.exit(FINDING_HALT)
end

local run_one -- the generated harness entry (dofile'd below)

local function run_input(data)
  reset_prev()
  local ok, err = pcall(run_one, data)
  if not ok then
    local cwe = bug_cwe(err)
    if cwe then report_finding(cwe, err) end
  end
end

local function read_exact(n)
  local buf = {}
  local got = 0
  while got < n do
    local chunk = io.stdin:read(n - got)
    if not chunk or #chunk == 0 then return nil end
    buf[#buf + 1] = chunk
    got = got + #chunk
  end
  return table.concat(buf)
end

-- ---- Load the target harness (returns govfuzz_run_one). ----
local harness = os.getenv("GOVFUZZ_HARNESS") or error("GOVFUZZ_HARNESS unset")
run_one = assert(dofile(harness), "harness did not return a run_one function")

debug.sethook(line_hook, "l")

if os.getenv("GOVFUZZ_FRAMED") then
  -- Save the control pipe (fd 1) then redirect stdout/print to /dev/null so the
  -- target's output can't corrupt the sync stream (#427).
  control = io.stdout
  control:setvbuf("no")
  local devnull = io.open("/dev/null", "w")
  if devnull then
    io.output(devnull)
    io.stdout = devnull
  end
  _G.print = function() end
  io.stdin:setvbuf("no")
  control:write("\1") -- ready byte
  local count = 0
  while true do
    local hdr = read_exact(4)
    if not hdr then break end
    local n = string.unpack("<I4", hdr)
    local data = n > 0 and read_exact(n) or ""
    if not data then break end
    run_input(data)
    flush_cov()
    control:write("\1") -- sync byte
    count = count + 1
    -- Exponentially spaced early checkpoints keep short campaigns from losing
    -- all line evidence before the old 512-input checkpoint.
    if (count & (count - 1)) == 0 or (count & 0x1FF) == 0 then dump_covered() end
  end
else
  local data
  local arg1 = arg and arg[1]
  if arg1 then
    local f = io.open(arg1, "rb")
    if f then data = f:read("a"); f:close() end
  end
  data = data or io.stdin:read("a") or ""
  run_input(data)
  flush_cov()
end
dump_covered()
