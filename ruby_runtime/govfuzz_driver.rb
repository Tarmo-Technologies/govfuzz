# SPDX-License-Identifier: Apache-2.0
# govfuzz Ruby fork-server driver. A TracePoint(:line) records edge coverage into the
# shared GOVFUZZ_COV_SHM map. Speaks the GOVFUZZ_FRAMED protocol (matches
# c_runtime/govfuzz_driver.c and the Perl driver): fd 1 control pipe, fd 0 input pipe
# ({u32 LE len, bytes}). A finding raises -> stderr marker + exit 86 (no sync byte);
# an expected rejection (input validation / a library's own exception class) is
# swallowed. No third-party fuzzer.

FINDING_HALT = 86
# The declared-rejection namespace: an exception whose class is defined in the
# target's own top module (e.g. Toml::ParseError) is that library's rejection, not a
# govfuzz finding (the Ada/Java/Perl "declared exception" principle).
TARGET_MODULE = ENV['GOVFUZZ_TARGET_MODULE'].to_s
EXPECTED = (ENV['GOVFUZZ_EXPECTED_EXCEPTIONS'] || '').split(',').reject(&:empty?)

# ---- Coverage: a TracePoint(:line) folded into a 64KB AFL-style edge bitmap. ----
COV_BITS = 1 << 16
COV_MASK = COV_BITS - 1
$cov_map = ("\0".b * COV_BITS)
$cov_prev = 0
$cov_prefix = ENV['GOVFUZZ_TRACE_PREFIX'].to_s
$covered = {}
$covered_dumped = 0

def gf_fnv(str, line)
  h = 0x811c9dc5
  str.each_byte { |c| h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF }
  h = ((h ^ (line & 0xFF)) * 0x01000193) & 0xFFFFFFFF
  h = ((h ^ ((line >> 8) & 0xFF)) * 0x01000193) & 0xFFFFFFFF
  h & COV_MASK
end

COV_TP = TracePoint.new(:line) do |tp|
  path = tp.path
  next if !$cov_prefix.empty? && !path.start_with?($cov_prefix)
  $covered["#{path}:#{tp.lineno}"] = true
  block = gf_fnv(path, tp.lineno)
  idx = ($cov_prev ^ block) & COV_MASK
  v = $cov_map.getbyte(idx)
  $cov_map.setbyte(idx, v + 1) if v < 0xFF
  $cov_prev = (block >> 1) & COV_MASK
end

def gf_reset_prev
  $cov_prev = 0
end

def gf_flush_cov
  path = ENV['GOVFUZZ_COV_SHM']
  return if path.nil? || path.empty?
  begin
    File.open(path, File::RDWR | File::CREAT) do |f|
      f.binmode
      f.seek(0)
      f.write($cov_map)
    end
  rescue StandardError
    # best-effort
  end
end

def gf_dump_covered
  path = ENV['GOVFUZZ_COVERED_LINES']
  return if path.nil? || path.empty?
  n = $covered.size
  return if n == $covered_dumped
  begin
    File.write("#{path}.tmp", $covered.keys.sort.join("\n"))
    File.rename("#{path}.tmp", path)
    $covered_dumped = n
  rescue StandardError
    # best-effort
  end
end

# ---- Finding classification (FP-avoidant, like the Python/Perl/JS lanes). ----
# Only high-confidence bug-class exceptions are findings; Ruby's normal input-
# rejection errors (ArgumentError/TypeError/KeyError/IndexError/NoMethodError/...) are
# suppressed. The behavioral/taint oracles (the shim) catch the security classes.
def gf_bug_cwe(err)
  case err
  when ZeroDivisionError then 'CWE-369'
  when SystemStackError then 'CWE-674' # unbounded recursion / stack exhaustion
  when NoMemoryError then 'CWE-789'    # uncontrolled memory allocation
  else
    msg = err.message.to_s
    if err.is_a?(RuntimeError) &&
       msg =~ /\b(assert(ion)?|invariant|unreachable|internal error|should (never|not) (happen|be reached|occur)|impossible|bug|corrupt)\b/i
      'CWE-617'
    end
  end
end

def gf_report_finding(cwe, msg)
  msg = msg.to_s.gsub(/\s+/, ' ').strip
  # Marker mirrors the Perl/Python/JVM drivers; the engine's parse_ruby_finding maps
  # the CWE token to a GF rule.
  $stderr.puts "== govfuzz ruby finding: #{cwe}: #{msg}"
  $stderr.flush
  exit(FINDING_HALT)
end

def gf_handle_error(err)
  cls = err.class.name.to_s
  # A blessed exception from the target's own module is a declared rejection.
  return if !TARGET_MODULE.empty? && cls.start_with?("#{TARGET_MODULE}::")
  return if EXPECTED.any? { |x| !x.empty? && err.message.to_s.include?(x) }
  cwe = gf_bug_cwe(err)
  gf_report_finding(cwe, "#{cls}: #{err.message}") if cwe
end

def gf_run_input(data)
  gf_reset_prev
  begin
    govfuzz_run_one(data)
  rescue SystemExit, SignalException
    raise
  rescue Exception => e
    gf_handle_error(e)
  end
end

def gf_read_exact(io, n)
  buf = ''.b
  while buf.bytesize < n
    chunk = io.read(n - buf.bytesize)
    return nil if chunk.nil? || chunk.empty?
    buf << chunk
  end
  buf
end

# ---- Load the target harness (defines govfuzz_run_one). ----
harness = ENV['GOVFUZZ_HARNESS'] or abort 'GOVFUZZ_HARNESS unset'
require harness

$stdin.binmode
COV_TP.enable

if ENV.key?('GOVFUZZ_FRAMED')
  # Save the control pipe (fd 1) then redirect $stdout to /dev/null so the target's
  # prints can't corrupt the sync stream (#427).
  ctl = $stdout.dup
  ctl.binmode
  ctl.sync = true
  $stdout.reopen(File.open(File::NULL, 'w'))
  ctl.write("\x01") # ready byte
  count = 0
  loop do
    hdr = gf_read_exact($stdin, 4)
    break if hdr.nil?
    n = hdr.unpack1('V')
    data = n > 0 ? gf_read_exact($stdin, n) : ''.b
    break if data.nil?
    gf_run_input(data)
    gf_flush_cov
    ctl.write("\x01") # sync byte
    count += 1
    gf_dump_covered if (count & 0x1FF).zero?
  end
else
  data =
    if ARGV[0] && File.file?(ARGV[0])
      File.binread(ARGV[0])
    else
      $stdin.read
    end
  gf_run_input(data || ''.b)
  gf_flush_cov
end
