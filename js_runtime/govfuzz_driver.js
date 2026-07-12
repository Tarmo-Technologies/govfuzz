// SPDX-License-Identifier: Apache-2.0
//
// govfuzz Node.js fork-server driver — the JavaScript analog of
// python_runtime/govfuzz_driver.py. Speaks the SAME GOVFUZZ_FRAMED protocol so the
// builtin engine drives a warm, long-lived V8 one input at a time (amortizing
// interpreter + require startup), exactly like a C/Rust fork-server binary — no
// Jazzer.js, no jsfuzz, no libFuzzer.
//
// Coverage: V8 precise block coverage via the inspector Profiler. With
// callCount:false the coverage is cumulative (each `takePreciseCoverage` returns
// every block executed since start), which matches govfuzz's cumulative AFL-style
// edge bitmap: per input we fold the covered blocks of the target's own scripts
// into a 64 KB map (GOVFUZZ_COV_BITS) and write it to the file-backed
// GOVFUZZ_COV_SHM (the engine maps the same file MAP_SHARED and counts non-zero
// bytes). node internals and the driver are excluded so the signal is the code
// under test.
//
// Protocol (must match the C driver):
//   1. Save the engine's control pipe (fd 1) to a private fd, then redirect fd 1
//      to /dev/null so the target's stdout can't corrupt the sync stream (#427).
//   2. Write one ready byte to the control fd.
//   3. Loop: read {u32 little-endian length, bytes} from fd 0, run the harness,
//      write one sync byte to the control fd.
// An uncaught FINDING halts the process (exit 86) with no sync byte, so the engine
// sees the death and re-isolates the input. An expected rejection (input
// validation) is swallowed — the input is just rejected.
//
// Without GOVFUZZ_FRAMED, argv[2] is a single input file to replay once (the
// engine's per-spawn crash-isolation path), else stdin is read.

'use strict';
const fs = require('fs');
const inspector = require('inspector');

const FINDING_HALT_CODE = 86;
const COV_BITS = 1 << 16; // matches GOVFUZZ_COV_BITS and the AFL map

// --- coverage state ---------------------------------------------------------
const covMap = new Uint8Array(COV_BITS);
let covFd = -1;
let session = null;
const targetHint = process.env.GOVFUZZ_JS_MODULE || '';

function covInit() {
  const path = process.env.GOVFUZZ_COV_SHM;
  if (path) {
    try {
      covFd = fs.openSync(path, 'r+');
    } catch (_) {
      try {
        covFd = fs.openSync(path, 'w+');
      } catch (_) {
        covFd = -1;
      }
    }
  }
  try {
    session = new inspector.Session();
    session.connect();
    session.post('Profiler.enable');
    // callCount:true + detailed:true => per-block execution counts (branch-level).
    // Each takePreciseCoverage returns the delta since the last take and resets the
    // counters, so folding count>0 blocks into the never-cleared covMap accumulates
    // cumulative edge coverage (with callCount:false V8 only reports function-level
    // coverage, which gives no branch feedback).
    session.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  } catch (_) {
    session = null;
  }
}

// Fold the target's covered blocks into the cumulative map (async: the inspector
// reply arrives on the event loop, which runs while we await).
function covFold() {
  if (!session) return Promise.resolve();
  return new Promise((resolve) => {
    session.post('Profiler.takePreciseCoverage', (err, res) => {
      if (!err && res && res.result) {
        for (const script of res.result) {
          const url = script.url || '';
          // Skip node internals, the driver, and anonymous eval scripts — keep
          // only the code under test so the map is meaningful.
          if (!url || url.startsWith('node:') || url.includes('govfuzz_driver')) continue;
          // Hash the URL (stable across takes; scriptId is not guaranteed to be)
          // into the block key so two scripts' identical offsets don't alias.
          let uh = 0;
          for (let k = 0; k < url.length; k++) uh = (Math.imul(uh, 31) + url.charCodeAt(k)) | 0;
          for (const fn of script.functions) {
            for (const r of fn.ranges) {
              // V8 detailed block coverage collapses *taken* contiguous blocks into
              // the parent range, so the branch-discriminating signal lives in the
              // *not-taken* (count==0) ranges. Fold EVERY range keyed on its span
              // plus a taken/not-taken bit: the set of (block, taken?) pairs is a
              // path signature that changes as different branches are exercised, so
              // the never-cleared covMap grows exactly when a new branch is reached.
              let h =
                Math.imul(uh, 0x9e3779b1) ^
                Math.imul(r.startOffset | 0, 0x85ebca6b) ^
                Math.imul(r.endOffset | 0, 0x27d4eb2f);
              if (r.count === 0) h ^= 0x5bd1e995;
              h = (h ^ (h >>> 15)) >>> 0;
              covMap[h % COV_BITS] = 1;
            }
          }
        }
      }
      if (covFd >= 0) {
        try {
          fs.writeSync(covFd, covMap, 0, COV_BITS, 0);
        } catch (_) {
          /* ignore */
        }
      }
      resolve();
    });
  });
}

// --- exception classification ----------------------------------------------
// Errors that are input *rejection* or our-fault, never a target bug — mirrors the
// Python driver's REJECTION_EXC. A dynamically-fed API rejects bad input with a
// SyntaxError (JSON.parse etc.), a URIError (bad %-escape), or a validating
// RangeError; suppressing them is the key to a low false-positive rate.
const EXPECTED = new Set(
  (process.env.GOVFUZZ_EXPECTED_EXCEPTIONS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
);

function classify(err) {
  // Returns { finding: bool, rule: 'GF-...' }.
  const name = err && err.name ? String(err.name) : '';
  const msg = err && err.message ? String(err.message) : String(err);
  if (EXPECTED.has(name)) return { finding: false };

  // Stack exhaustion (uncontrolled recursion) — a real defect (GF-207).
  if (name === 'RangeError' && /call stack/i.test(msg)) {
    return { finding: true, rule: 'GF-207' };
  }
  // Resource exhaustion: an input-driven huge allocation (GF-209).
  if (
    (name === 'RangeError' && /Invalid (array|typed array|string) length/i.test(msg)) ||
    /out of memory/i.test(msg)
  ) {
    return { finding: true, rule: 'GF-209' };
  }
  // Input validation / format / our-fault type — rejection, swallow. In an
  // untyped lane govfuzz synthesizes only the FIRST argument, so a `TypeError`
  // ("Cannot read properties of undefined", "x is not a function") is dominated by
  // us calling a function with a missing/typed later argument or the wrong first
  // shape — our fault, not a target defect. This mirrors the Python driver, which
  // suppresses the exact analogs (`TypeError`/`AttributeError`); a campaign over 30
  // npm libraries showed every `TypeError` was such an artifact. `SyntaxError`
  // (a JSON.parse-style reject), `URIError`, and a validating `RangeError` are the
  // API's intended input rejection.
  if (
    name === 'TypeError' ||
    name === 'SyntaxError' ||
    name === 'URIError' ||
    name === 'RangeError'
  ) {
    return { finding: false };
  }
  // ReferenceError (undefined variable), AssertionError, an explicit throw, a
  // custom Error — a reachable crash the target owns (GF-210). Real security /
  // null-deref classes are covered by the behavioral oracles, not this policy.
  return { finding: true, rule: 'GF-210' };
}

function reportFinding(err, rule) {
  const name = err && err.name ? String(err.name) : 'Error';
  const msg = (err && err.message ? String(err.message) : String(err)).replace(/[\r\n]+/g, ' ');
  // Marker mirrors the JVM/Python drivers; the engine's `parse_js_finding` reads
  // the pre-resolved GF rule token and maps it to a CWE.
  process.stderr.write(`== govfuzz js finding: ${rule}: ${name}: ${msg}\n`);
  if (err && err.stack) process.stderr.write(String(err.stack) + '\n');
}

let runOne = null;
// The bytes of the input currently being processed (latin1), for the sink taint
// check. Set per input before the target runs.
let currentInput = '';

// --- taint-confirmed sink detectors (the JS analog of govfuzz's native GF-431
// command-injection oracle) --------------------------------------------------
// Jazzer.js ships bug detectors; the govfuzz JS lane runs without the LD_PRELOAD
// shim (managed runtime), so the driver hooks the dangerous sinks in JS instead.
// A sink is a *finding* only when a shell-metacharacter-bearing substring of the
// current fuzz input reaches the command — i.e. the input controls shell syntax,
// not just data. The command is NEVER executed (that would let the fuzzer run
// arbitrary shell); a benign stub is returned so a non-injecting input continues.
const SHELL_META = /[;|`&><\n$()]/;

function inputControlsSink(sinkStr) {
  if (typeof sinkStr !== 'string' || currentInput.length < 2) return false;
  for (let i = 0; i < currentInput.length; i++) {
    if (!SHELL_META.test(currentInput[i])) continue;
    // Grow a window around the metacharacter and require it to appear verbatim in
    // the command — the fuzz bytes (incl. the metachar) flowed into the shell.
    const max = Math.min(24, currentInput.length - i);
    for (let len = 2; len <= max; len++) {
      const w = currentInput.substr(i, len);
      if (SHELL_META.test(w) && sinkStr.includes(w)) return true;
    }
  }
  return false;
}

function reportSink(rule, kind, sink, detail) {
  const d = String(detail).replace(/[\r\n]+/g, ' ').slice(0, 200);
  process.stderr.write(`== govfuzz js finding: ${rule}: ${kind}: ${sink}: ${d}\n`);
  try {
    fs.fsyncSync(2);
  } catch (_) {
    /* ignore */
  }
  process.exit(FINDING_HALT_CODE);
}

// Patch `child_process` exec/execSync so a fuzz-controlled shell command is
// detected (GF-431, CWE-78) and never run. Best-effort — absent child_process, or
// a target that never execs, this is inert.
function installSinkGuards() {
  let cp;
  try {
    cp = require('child_process');
  } catch (_) {
    return;
  }
  const guard = (sink, cmd) => {
    if (inputControlsSink(cmd)) {
      reportSink('GF-431', 'CommandInjection', sink, cmd);
    }
  };
  const emptyChild = () => {
    const { EventEmitter } = require('events');
    const child = new EventEmitter();
    const out = new EventEmitter();
    out.setEncoding = () => {};
    out.pipe = () => {};
    child.stdout = out;
    child.stderr = new EventEmitter();
    child.stdin = { write() {}, end() {} };
    child.kill = () => {};
    process.nextTick(() => child.emit('close', 0));
    return child;
  };
  if (typeof cp.execSync === 'function') {
    cp.execSync = (cmd) => {
      guard('execSync', cmd);
      return Buffer.from('');
    };
  }
  if (typeof cp.exec === 'function') {
    cp.exec = (cmd, ...rest) => {
      guard('exec', cmd);
      const cb = rest.find((a) => typeof a === 'function');
      if (cb) {
        process.nextTick(() => cb(null, '', ''));
      }
      return emptyChild();
    };
  }
}

function runInput(buf) {
  currentInput = buf.toString('latin1');
  try {
    runOne(buf);
  } catch (err) {
    const c = classify(err);
    if (c.finding) {
      reportFinding(err, c.rule);
      // Flush stderr then hard-halt so the engine re-isolates the input.
      try {
        fs.fsyncSync(2);
      } catch (_) {
        /* ignore */
      }
      process.exit(FINDING_HALT_CODE);
    }
    // else: expected rejection — swallow.
  }
}

// --- harness resolution -----------------------------------------------------
// The launcher sets GOVFUZZ_JS_MODULE (absolute path to the target) and
// GOVFUZZ_JS_EXPORT (the dotted export path, e.g. "parse" or "Foo.bar") and
// GOVFUZZ_JS_ARG ("buffer" | "string"). `runOne(buf)` decodes and calls it.
function loadRunOne() {
  const modPath = process.env.GOVFUZZ_JS_MODULE;
  const exportPath = process.env.GOVFUZZ_JS_EXPORT || '';
  const argKind = process.env.GOVFUZZ_JS_ARG || 'buffer';
  const mod = require(modPath);
  // A `ClassPath#method` export path means: resolve the class, `new` it (no-arg),
  // then call the instance method. `#method` (empty class part) = the module itself
  // is the class. Otherwise the export path is a plain dotted function path.
  const hash = exportPath.indexOf('#');
  let fn;
  let recv;
  if (hash >= 0) {
    const classPath = exportPath.slice(0, hash);
    const methodName = exportPath.slice(hash + 1);
    let cls = mod;
    for (const part of classPath.split('.').filter(Boolean)) {
      cls = cls[part];
    }
    if (typeof cls !== 'function') {
      throw new Error(`GOVFUZZ_JS_EXPORT class '${classPath}' not found in ${modPath}`);
    }
    recv = new cls();
    fn = recv[methodName];
  } else {
    fn = mod;
    recv = undefined;
    for (const part of exportPath.split('.').filter(Boolean)) {
      recv = fn;
      fn = fn[part];
    }
  }
  if (typeof fn !== 'function') {
    throw new Error(`GOVFUZZ_JS_EXPORT '${exportPath}' is not a function in ${modPath}`);
  }
  const bound = fn.bind(recv);
  if (argKind === 'string') {
    return (buf) => bound(buf.toString('utf8'));
  }
  return (buf) => bound(buf);
}

// --- framed protocol --------------------------------------------------------
function readExact(fd, n) {
  const out = Buffer.allocUnsafe(n);
  let got = 0;
  while (got < n) {
    let r;
    try {
      r = fs.readSync(fd, out, got, n - got, null);
    } catch (e) {
      if (e.code === 'EAGAIN') continue;
      return null;
    }
    if (r <= 0) return null;
    got += r;
  }
  return out;
}

function readU32(fd) {
  const b = readExact(fd, 4);
  if (!b) return -1;
  return b.readUInt32LE(0);
}

async function framedLoop() {
  const ctrl = setupControlFd();
  const one = Buffer.from([1]);
  fs.writeSync(ctrl, one, 0, 1, null); // ready byte
  while (true) {
    const n = readU32(0);
    if (n < 0) break;
    const data = n > 0 ? readExact(0, n) : Buffer.alloc(0);
    if (data === null) break;
    runInput(data);
    await covFold();
    fs.writeSync(ctrl, one, 0, 1, null); // sync byte
  }
}

// The engine reads sync bytes from the child's stdout (fd 1). Node has no dup2()
// to point fd 1 at /dev/null, so instead: (1) duplicate fd 1 via /proc/self/fd/1
// (a new fd to the SAME pipe) as the private control channel, and (2) silence the
// JS-level stdout so the target's console output can't corrupt the sync stream on
// fd 1 (#427). A target writing to fd 1 through a raw syscall is not intercepted,
// but pure-JS targets go through process.stdout / console.
function setupControlFd() {
  let ctrl;
  try {
    ctrl = fs.openSync('/proc/self/fd/1', 'w');
  } catch (_) {
    ctrl = 1; // best effort
  }
  const noop = () => true;
  process.stdout.write = noop;
  console.log = noop;
  console.info = noop;
  console.debug = noop;
  return ctrl;
}

function main() {
  covInit();
  installSinkGuards();
  runOne = loadRunOne();
  if (process.env.GOVFUZZ_FRAMED !== undefined) {
    framedLoop().then(() => process.exit(0));
    return;
  }
  // Per-spawn single-input replay: argv[2] is an input file, else read stdin.
  let input;
  const argFile = process.argv[2];
  if (argFile && fs.existsSync(argFile)) {
    input = fs.readFileSync(argFile);
  } else {
    try {
      input = fs.readFileSync(0);
    } catch (_) {
      input = Buffer.alloc(0);
    }
  }
  runInput(input);
  covFold().then(() => process.exit(0));
}

main();
