<?php
// SPDX-License-Identifier: Apache-2.0
// govfuzz PHP fork-server driver. The pcov extension records per-line coverage into
// the shared GOVFUZZ_COV_SHM map. Speaks the GOVFUZZ_FRAMED protocol (matches
// c_runtime/govfuzz_driver.c and the Ruby/Lua/Perl drivers): fd 1 control pipe, fd 0
// input pipe ({u32 LE len, bytes}). A finding throws a bug-class Throwable -> stderr
// marker + exit 86 (no sync byte); an expected rejection (TypeError/ValueError, a
// library's own exception) is swallowed. No third-party fuzzer.

const FINDING_HALT = 86;
$TARGET_NS = getenv('GOVFUZZ_TARGET_NS') ?: '';

// ---- Coverage: pcov per-input line hits folded into a 64KB block bitmap. ----
const COV_BITS = 1 << 16;
const COV_MASK = COV_BITS - 1;
$cov = str_repeat("\0", COV_BITS);          // 64KB image (bytes only grow)
$cov_prefix = getenv('GOVFUZZ_TRACE_PREFIX') ?: '';
$covered = [];
$covered_dumped = 0;
$have_pcov = function_exists('\\pcov\\start');

function gf_fnv(string $s, int $line): int {
    $h = 0x811c9dc5;
    $n = strlen($s);
    for ($k = 0; $k < $n; $k++) {
        $h = (($h ^ ord($s[$k])) * 0x01000193) & 0xFFFFFFFF;
    }
    $h = (($h ^ ($line & 0xFF)) * 0x01000193) & 0xFFFFFFFF;
    $h = (($h ^ (($line >> 8) & 0xFF)) * 0x01000193) & 0xFFFFFFFF;
    return $h & COV_MASK;
}

function gf_fold_coverage(): void {
    global $cov, $cov_prefix, $covered, $have_pcov;
    if (!$have_pcov) return;
    $data = \pcov\collect();
    foreach ($data as $file => $lines) {
        if ($cov_prefix !== '' && strncmp($file, $cov_prefix, strlen($cov_prefix)) !== 0) {
            continue;
        }
        foreach ($lines as $line => $hit) {
            $covered["$file:$line"] = true;
            $idx = gf_fnv($file, (int)$line);
            $v = ord($cov[$idx]);
            if ($v < 0xFF) $cov[$idx] = chr($v + 1);
        }
    }
    \pcov\clear();
}

function gf_flush_cov(): void {
    global $cov;
    $path = getenv('GOVFUZZ_COV_SHM');
    if (!$path) return;
    $f = @fopen($path, 'cb');
    if (!$f) return;
    fseek($f, 0);
    fwrite($f, $cov);
    fclose($f);
}

function gf_dump_covered(): void {
    global $covered, $covered_dumped;
    $path = getenv('GOVFUZZ_COVERED_LINES');
    if (!$path) return;
    $n = count($covered);
    if ($n === $covered_dumped) return;
    $keys = array_keys($covered);
    sort($keys);
    if (@file_put_contents("$path.tmp", implode("\n", $keys)) !== false) {
        @rename("$path.tmp", $path);
        $covered_dumped = $n;
    }
}

// ---- Finding classification (FP-avoidant, like the Ruby/Lua/Perl lanes). ----
function gf_bug_cwe(Throwable $e): ?string {
    global $TARGET_NS;
    $cls = get_class($e);
    // A target-namespaced exception is that library's declared rejection.
    if ($TARGET_NS !== '' && strncmp($cls, $TARGET_NS, strlen($TARGET_NS)) === 0) {
        return null;
    }
    if ($e instanceof \DivisionByZeroError) return 'CWE-369';
    if ($e instanceof \AssertionError) return 'CWE-617';
    $msg = strtolower($e->getMessage());
    if (str_contains($msg, 'allowed memory size') || str_contains($msg, 'out of memory')) {
        return 'CWE-789';
    }
    if (str_contains($msg, 'maximum function nesting') || str_contains($msg, 'stack overflow')) {
        return 'CWE-674';
    }
    // TypeError / ValueError / ArgumentCountError / generic Exception = normal PHP
    // input rejection -> suppressed.
    return null;
}

function gf_report_finding(string $cwe, string $msg): void {
    $msg = trim(preg_replace('/\s+/', ' ', $msg));
    fwrite(STDERR, "== govfuzz php finding: $cwe: $msg\n");
    exit(FINDING_HALT);
}

$GF_RUN_ONE = null; // the generated harness entry

function gf_run_input(string $data): void {
    global $GF_RUN_ONE, $have_pcov;
    if ($have_pcov) \pcov\clear();
    ob_start();
    try {
        ($GF_RUN_ONE)($data);
    } catch (\Throwable $e) {
        ob_end_clean();
        gf_fold_coverage();
        $cwe = gf_bug_cwe($e);
        if ($cwe !== null) {
            gf_report_finding($cwe, get_class($e) . ': ' . $e->getMessage());
        }
        return;
    }
    ob_end_clean();
    gf_fold_coverage();
}

function gf_read_exact($stream, int $n): ?string {
    $buf = '';
    while (strlen($buf) < $n) {
        $chunk = fread($stream, $n - strlen($buf));
        if ($chunk === '' || $chunk === false) return null;
        $buf .= $chunk;
    }
    return $buf;
}

// ---- Load the target harness (returns govfuzz_run_one callable). ----
$harness = getenv('GOVFUZZ_HARNESS');
if (!$harness) {
    fwrite(STDERR, "GOVFUZZ_HARNESS unset\n");
    exit(1);
}
$GF_RUN_ONE = require $harness;
if (!is_callable($GF_RUN_ONE)) {
    fwrite(STDERR, "harness did not return a callable\n");
    exit(1);
}

if ($have_pcov) \pcov\start();

if (getenv('GOVFUZZ_FRAMED') !== false) {
    $control = STDOUT; // fd 1 — sync stream (target echo captured by ob_start per run)
    fwrite($control, "\x01"); // ready byte
    fflush($control);
    $count = 0;
    while (true) {
        $hdr = gf_read_exact(STDIN, 4);
        if ($hdr === null) break;
        $n = unpack('V', $hdr)[1];
        $data = $n > 0 ? gf_read_exact(STDIN, $n) : '';
        if ($data === null) break;
        gf_run_input($data);
        gf_flush_cov();
        fwrite($control, "\x01"); // sync byte
        fflush($control);
        $count++;
        // Exponentially spaced early checkpoints keep short campaigns from
        // losing all line evidence before the old 512-input checkpoint.
        if (($count & ($count - 1)) === 0 || ($count & 0x1FF) === 0) {
            gf_dump_covered();
        }
    }
} else {
    $data = '';
    if (isset($argv[1]) && is_file($argv[1])) {
        $data = file_get_contents($argv[1]);
    } else {
        $data = stream_get_contents(STDIN);
    }
    gf_run_input($data === false ? '' : $data);
    gf_flush_cov();
}
gf_dump_covered();
