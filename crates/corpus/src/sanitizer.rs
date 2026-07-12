// SPDX-License-Identifier: Apache-2.0
//
// Parse AddressSanitizer / UndefinedBehaviorSanitizer / LeakSanitizer crash
// reports out of a harness's stderr and map them to GovFuzz rule ids.
//
// Used by the C/C++ fuzz path: when the libFuzzer harness exits non-zero,
// `parse_sanitizer_report` examines stderr, picks the most specific match
// from the existing rule catalog (GF-201..GF-208), and returns the top-5
// frames so the caller can attach them to the finding.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizerReport {
    pub sanitizer: Sanitizer,
    /// Short crash class string (e.g. `heap-buffer-overflow`,
    /// `signed-integer-overflow`).
    pub kind: String,
    pub rule_id: &'static str,
    /// Up to the top 5 frames the sanitizer printed, in order. Each frame
    /// is a `function` plus optional `file`:`line` from the sanitizer
    /// output - file/line are present when the binary was built with
    /// debug info (`-g`) so the SARIF emitter can attach a real
    /// `physicalLocation`.
    pub stack: Vec<StackFrame>,
    /// First line of the sanitizer error, useful as a `message`.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StackFrame {
    pub function: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sanitizer {
    AddressSanitizer,
    UndefinedBehaviorSanitizer,
    LeakSanitizer,
}

impl Sanitizer {
    pub fn as_str(self) -> &'static str {
        match self {
            Sanitizer::AddressSanitizer => "asan",
            Sanitizer::UndefinedBehaviorSanitizer => "ubsan",
            Sanitizer::LeakSanitizer => "lsan",
        }
    }
}

pub fn parse_sanitizer_report(stderr: &str) -> Option<SanitizerReport> {
    parse_asan(stderr)
        .or_else(|| parse_ubsan(stderr))
        .or_else(|| parse_lsan(stderr))
        // A Rust panic is the PRIMARY bug signal for the native Rust lane: a
        // bounds-check / unwrap / overflow / explicit panic aborts via SIGABRT,
        // which the C-oriented `is_input_rejection` would otherwise dismiss as an
        // assert/abort "rejection". Recognising the panic message here turns it
        // into a finding (like cargo-fuzz/Jazzer treat a panic). Only fires when
        // stderr actually contains a Rust panic, so the C/Ada lanes are unaffected.
        .or_else(|| parse_rust_panic(stderr))
        // A JVM finding is the PRIMARY bug signal for the native Java lane: the
        // govfuzz JVM driver prints a marker + the Java stack trace and hard-halts
        // with a non-zero EXIT (not a fatal signal), which the signal-oriented
        // `is_input_rejection` would otherwise dismiss. Recognising the marker here
        // turns an uncaught exception/Error into a finding (like Jazzer). Only
        // fires on the govfuzz marker, so the other lanes are unaffected.
        .or_else(|| parse_jvm_finding(stderr))
        // A Python finding is the PRIMARY bug signal for the native Python lane: the
        // govfuzz CPython driver prints `== govfuzz python finding: <Type>: <msg>` +
        // a traceback and hard-halts with a non-zero EXIT (not a fatal signal).
        // Recognising the marker here maps the exception type to a GF rule + CWE.
        // Only fires on the govfuzz marker, so the other lanes are unaffected.
        .or_else(|| parse_python_finding(stderr))
        // A Perl finding: the govfuzz Perl driver prints `== govfuzz perl finding:
        // <CWE>: <die message>` and hard-halts. The CWE token (computed driver-side
        // from the die message) selects the GF rule.
        .or_else(|| parse_perl_finding(stderr))
        // A Go finding: the govfuzz Go harness recovers a panic and prints
        // `== govfuzz go finding: <msg>` (or the runtime prints `panic:`/`fatal
        // error:` for an unrecoverable crash). The message selects the GF rule.
        .or_else(|| parse_go_panic(stderr))
        // A C# finding: the govfuzz .NET driver prints `== govfuzz csharp finding:
        // <exception type>: <msg>` and hard-halts (exit 86). The exception type
        // selects the GF rule + CWE, mirroring the JVM lane.
        .or_else(|| parse_csharp_finding(stderr))
        // A JS finding: the govfuzz Node driver prints `== govfuzz js finding:
        // <GF-rule>: <error name>: <msg>` and hard-halts (exit 86). The GF rule is
        // pre-resolved driver-side (the exception class → rule mapping is cleaner in
        // the driver where the Error object is live), so the parser reads it directly.
        .or_else(|| parse_js_finding(stderr))
}

/// Parse a govfuzz JavaScript finding out of stderr. The Node driver prints
/// `== govfuzz js finding: <GF-NNN>: <Error name>: <message>` followed by the V8
/// stack (`    at fn (file:line:col)`). The GF rule token is pre-resolved by the
/// driver (stack-exhaustion RangeError → GF-207, resource RangeError → GF-209, a
/// property-of-undefined TypeError → GF-206, else GF-210).
fn parse_js_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== govfuzz js finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    // `after` is `<GF-NNN>: <rest>`.
    let (rule_tok, rest) = match after.split_once(':') {
        Some((r, m)) => (r.trim(), m.trim()),
        None => (after, ""),
    };
    let rule_id = match rule_tok {
        "GF-201" => "GF-201",
        "GF-205" => "GF-205",
        "GF-206" => "GF-206",
        "GF-207" => "GF-207",
        "GF-209" => "GF-209",
        _ => "GF-210",
    };
    let kind = match rule_id {
        "GF-206" => "js-null-dereference",
        "GF-207" => "js-stack-overflow",
        "GF-209" => "js-out-of-memory",
        "GF-205" => "js-arithmetic",
        "GF-201" => "js-index-out-of-bounds",
        _ => "js-uncaught-exception",
    }
    .to_owned();

    let mut stack = parse_js_stack_frames(stderr);
    stack.truncate(5);

    Some(SanitizerReport {
        sanitizer: Sanitizer::AddressSanitizer,
        kind,
        rule_id,
        stack,
        message: format!("JS finding: {rest}"),
    })
}

/// Parse V8 stack frames: `    at fn (path:line:col)` or `    at path:line:col`.
/// The govfuzz driver frames are skipped so the top frame is the target's code.
fn parse_js_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for raw in stderr.lines() {
        let t = raw.trim_start();
        let Some(rest) = t.strip_prefix("at ") else {
            continue;
        };
        if rest.contains("govfuzz_driver") {
            continue;
        }
        // Extract `name (loc)` or bare `loc`.
        let (func, loc) = if let Some(open) = rest.rfind('(') {
            let close = rest.rfind(')').unwrap_or(rest.len());
            (
                rest[..open].trim().to_owned(),
                rest.get(open + 1..close).unwrap_or("").to_owned(),
            )
        } else {
            ("<anonymous>".to_owned(), rest.trim().to_owned())
        };
        // loc = path:line:col — split the trailing :line:col.
        let (file, line) = split_loc(&loc);
        frames.push(StackFrame {
            function: if func.is_empty() {
                "<anonymous>".to_owned()
            } else {
                func
            },
            file,
            line,
        });
    }
    frames
}

/// Split a V8 `path:line:col` location into `(file, line)`.
fn split_loc(loc: &str) -> (Option<String>, Option<u32>) {
    let bytes: Vec<&str> = loc.rsplitn(3, ':').collect();
    // rsplitn yields [col, line, path] reversed.
    if bytes.len() == 3 {
        let line = bytes[1].parse::<u32>().ok();
        let file = bytes[2].to_owned();
        (Some(file), line)
    } else if loc.is_empty() {
        (None, None)
    } else {
        (Some(loc.to_owned()), None)
    }
}

/// Parse a govfuzz C# finding out of stderr. The .NET driver prints
/// `== govfuzz csharp finding: <System.ExceptionType>: <message>` followed by the
/// managed stack trace (`   at Ns.Type.Method(...) in File.cs:line N`). The
/// exception type drives the rule id: an index OOB is the CWE-125/787 class
/// (GF-201); a divide-by-zero / overflow `DivideByZeroException` / `OverflowException`
/// / `ArithmeticException` maps to GF-205; `OutOfMemoryException` to GF-209;
/// `StackOverflowException` to the uncontrolled-recursion GF-207; a
/// `NullReferenceException` to the null-deref GF-206; everything else — a custom
/// exception, `InvalidOperationException`, an assertion — is a reachable-crash GF-210.
fn parse_csharp_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== govfuzz csharp finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    let (exc, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };
    // Leaf type name (drop the `System.` / target namespace prefix).
    let leaf = exc.rsplit('.').next().unwrap_or(exc);

    let (kind, rule_id) = if leaf.contains("IndexOutOfRange") || leaf.contains("IndexOutOfBounds") {
        ("csharp-index-out-of-bounds".to_owned(), "GF-201")
    } else if leaf == "DivideByZeroException"
        || leaf == "OverflowException"
        || leaf == "ArithmeticException"
        || leaf == "NotFiniteNumberException"
    {
        ("csharp-arithmetic".to_owned(), "GF-205")
    } else if leaf == "OutOfMemoryException" {
        ("csharp-out-of-memory".to_owned(), "GF-209")
    } else if leaf == "StackOverflowException" || leaf == "InsufficientExecutionStackException" {
        ("csharp-stack-overflow".to_owned(), "GF-207")
    } else if leaf == "NullReferenceException" {
        ("csharp-null-dereference".to_owned(), "GF-206")
    } else {
        // InvalidOperationException, custom exceptions, an explicit throw, ...
        ("csharp-uncaught-exception".to_owned(), "GF-210")
    };

    let mut stack = parse_csharp_stack_frames(stderr);
    stack.truncate(5);

    let message = if msg.is_empty() {
        format!("C# finding: {exc}")
    } else {
        format!("C# finding: {exc}: {msg}")
    };
    Some(SanitizerReport {
        sanitizer: Sanitizer::AddressSanitizer,
        kind,
        rule_id,
        stack,
        message,
    })
}

/// Parse managed stack frames from a .NET stack trace: `   at Ns.Type.Method(args)`
/// or `   at Ns.Type.Method(args) in /path/File.cs:line 42`. The `govfuzz`
/// driver/entry frames are skipped so the top frame is the target's own code.
fn parse_csharp_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for raw in stderr.lines() {
        let t = raw.trim_start();
        let Some(rest) = t.strip_prefix("at ") else {
            continue;
        };
        // Skip our own driver / entry shim frames.
        if rest.starts_with("Driver.") || rest.starts_with("Govfuzzgen.") {
            continue;
        }
        // Function = everything up to the first `(`.
        let func = rest.split('(').next().unwrap_or(rest).trim().to_owned();
        // Optional `in <file>:line N`.
        let (file, line) = if let Some(pos) = rest.find(" in ") {
            let loc = &rest[pos + 4..];
            if let Some(lpos) = loc.rfind(":line ") {
                let file = loc[..lpos].trim().to_owned();
                let line = loc[lpos + 6..].trim().parse::<u32>().ok();
                (Some(file), line)
            } else {
                (Some(loc.trim().to_owned()), None)
            }
        } else {
            (None, None)
        };
        if func.is_empty() {
            continue;
        }
        frames.push(StackFrame {
            function: func,
            file,
            line,
        });
    }
    frames
}

/// Parse a Go panic / fatal runtime error out of stderr. The govfuzz Go harness
/// recovers and prints `== govfuzz go finding: <msg>`; an unrecoverable crash leaves
/// the runtime's own `panic: <msg>` / `fatal error: <msg>`. The message drives the
/// rule id: index/slice OOB -> CWE-125 (GF-201); nil dereference -> CWE-476 (GF-204
/// — null-pointer class); integer divide-by-zero -> CWE-369 (GF-205); stack
/// exhaustion -> CWE-674 (GF-207); out-of-memory -> CWE-789 (GF-209); everything
/// else (an explicit panic / type assertion / map misuse) -> reachable-crash GF-210.
fn parse_go_panic(stderr: &str) -> Option<SanitizerReport> {
    let msg = stderr
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("== govfuzz go finding:")
                .map(str::trim)
        })
        .or_else(|| {
            stderr
                .lines()
                .find_map(|l| l.trim().strip_prefix("panic:").map(str::trim))
        })
        .or_else(|| {
            stderr
                .lines()
                .find_map(|l| l.trim().strip_prefix("fatal error:").map(str::trim))
        })?;
    let lower = msg.to_ascii_lowercase();
    let (kind, rule_id) = if lower.contains("index out of range")
        || lower.contains("slice bounds out of range")
    {
        ("go-index-out-of-bounds".to_owned(), "GF-201")
    } else if lower.contains("nil pointer dereference") || lower.contains("invalid memory address")
    {
        ("go-nil-dereference".to_owned(), "GF-206")
    } else if lower.contains("integer divide by zero") {
        ("go-arithmetic".to_owned(), "GF-205")
    } else if lower.contains("stack overflow") || lower.contains("goroutine stack exceeds") {
        ("go-stack-overflow".to_owned(), "GF-207")
    } else if lower.contains("out of memory") || lower.contains("makeslice: len out of range") {
        ("go-out-of-memory".to_owned(), "GF-209")
    } else {
        ("go-panic".to_owned(), "GF-210")
    };
    let mut stack = parse_go_stack_frames(stderr);
    stack.truncate(5);
    Some(SanitizerReport {
        sanitizer: Sanitizer::AddressSanitizer,
        kind,
        rule_id,
        stack,
        message: format!("Go panic: {msg}"),
    })
}

/// Parse Go goroutine-stack frames from `debug.Stack()` output. Each frame is two
/// lines: `pkg/path.Func(args)` then `\t<file>:<line> +0xNN`. Skip the runtime,
/// the govfuzz harness, and debug.Stack itself so the top frame is the target's
/// own code — that frame drives the cluster key (one row per crash site).
fn parse_go_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let lines: Vec<&str> = stderr.lines().collect();
    let mut frames = Vec::new();
    let mut i = 0;
    while i + 1 < lines.len() {
        let func_line = lines[i].trim_end();
        let loc_line = lines[i + 1];
        // A location line is indented and looks like `\t<file>:<line> +0x...`.
        let loc = loc_line.trim();
        let is_loc = loc_line.starts_with('\t') && loc.contains(':') && loc.contains(".go:");
        let is_func =
            func_line.contains('(') && !func_line.starts_with('\t') && !func_line.is_empty();
        if is_func && is_loc {
            let function = func_line
                .split('(')
                .next()
                .unwrap_or(func_line)
                .trim()
                .to_owned();
            // `<file>:<line> +0xNN`
            let loc_no_off = loc.split(" +").next().unwrap_or(loc);
            let (file, line) = match loc_no_off.rsplit_once(':') {
                Some((f, l)) => (Some(f.to_owned()), l.trim().parse::<u32>().ok()),
                None => (None, None),
            };
            let skip = function.starts_with("runtime")
                || function == "panic"
                || function.starts_with("runtime/debug")
                || function.contains("main.runOne")
                || function == "main.main"
                || function.contains("govfuzz_harness");
            if !skip {
                frames.push(StackFrame {
                    function,
                    file,
                    line,
                });
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    frames
}

/// Parse a govfuzz Perl finding out of stderr. The driver prints
/// `== govfuzz perl finding: <CWE-NNN>: <die message>` (the CWE pre-resolved from
/// the message: deep-recursion -> CWE-674/GF-207, out-of-memory -> CWE-789/GF-209,
/// division-by-zero -> CWE-369/GF-205, else an uncaught die -> CWE-248/GF-210).
fn parse_perl_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== govfuzz perl finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    let (cwe, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };
    let (kind, rule_id) = match cwe {
        "CWE-674" => ("perl-uncontrolled-recursion".to_owned(), "GF-207"),
        "CWE-789" => ("perl-out-of-memory".to_owned(), "GF-209"),
        "CWE-369" => ("perl-arithmetic".to_owned(), "GF-205"),
        _ => ("perl-uncaught-die".to_owned(), "GF-210"),
    };
    Some(SanitizerReport {
        sanitizer: Sanitizer::AddressSanitizer,
        kind,
        rule_id,
        stack: Vec::new(),
        message: if msg.is_empty() {
            "Perl finding".to_owned()
        } else {
            format!("Perl finding: {msg}")
        },
    })
}

/// Parse a govfuzz JVM finding out of stderr. The driver prints
/// `== govfuzz JVM finding: <exception class>: <message>` followed by the Java
/// stack trace (`\tat pkg.Class.method(File.java:line)`). The exception class
/// drives the rule id: an index/bounds exception is the CWE-125/787 OOB class
/// (GF-201); an `ArithmeticException` (divide by zero) maps to GF-205; an
/// `OutOfMemoryError` to GF-209; everything else — NPE, ClassCast, AssertionError,
/// StackOverflow, … — is a reachable-crash GF-210.
fn parse_jvm_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== govfuzz JVM finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    // `after` is `<class>: <message>` or just `<class>`.
    let (class, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };
    let class_leaf = class.rsplit('.').next().unwrap_or(class);

    // JVM class-loading / bytecode-verification / linkage errors are ENVIRONMENT
    // or INSTRUMENTATION artifacts, not target logic bugs: a coverage-instrumented
    // class whose stack-map frames weren't recomputed throws `ClassFormatError`
    // ("bad offset for Uninitialized" — snakeyaml emitted 15 identical ones), a
    // missing classpath entry throws `NoClassDefFoundError`, a version mismatch
    // `UnsupportedClassVersionError`. Raising a GF-210 finding for them manufactures
    // phantom crashes that have nothing to do with the code under test, so report
    // no finding (the underlying instrumentation/classpath issue is handled out of
    // band, not as a fuzzing result).
    if matches!(
        class_leaf,
        "ClassFormatError"
            | "VerifyError"
            | "UnsupportedClassVersionError"
            | "NoClassDefFoundError"
            | "ClassNotFoundException"
            | "LinkageError"
            | "BootstrapMethodError"
            | "IncompatibleClassChangeError"
    ) {
        return None;
    }

    let (kind, rule_id) = if class_leaf.contains("IndexOutOfBounds")
        || class_leaf.contains("ArrayIndexOutOfBounds")
        || class_leaf.contains("StringIndexOutOfBounds")
    {
        ("jvm-index-out-of-bounds".to_owned(), "GF-201")
    } else if class_leaf == "ArithmeticException" {
        ("jvm-arithmetic".to_owned(), "GF-205")
    } else if class_leaf == "OutOfMemoryError" {
        ("jvm-out-of-memory".to_owned(), "GF-209")
    } else {
        // NullPointerException, ClassCastException, NegativeArraySizeException,
        // AssertionError, StackOverflowError, an explicit throw, …
        ("jvm-uncaught-throwable".to_owned(), "GF-210")
    };

    let mut stack = parse_java_stack_frames(stderr);
    stack.truncate(5);

    let message = if msg.is_empty() {
        format!("JVM finding: {class}")
    } else {
        format!("JVM finding: {class}: {msg}")
    };
    Some(SanitizerReport {
        // The crash-channel tag; AddressSanitizer keeps a memory-safety exception
        // (OOB) in the right bucket. `kind`/`rule_id` carry the JVM classification.
        sanitizer: Sanitizer::AddressSanitizer,
        kind,
        rule_id,
        stack,
        message,
    })
}

/// Parse a govfuzz Python finding out of stderr. The CPython driver prints
/// `== govfuzz python finding: <ExcType>: <message>` followed by the standard
/// traceback (`  File "x.py", line N, in func`). The exception type drives the
/// rule id: `IndexError` is the CWE-125/787 OOB class (GF-201); a divide-by-zero /
/// overflow `ZeroDivisionError`/`OverflowError`/`FloatingPointError` maps to GF-205;
/// `MemoryError` to GF-209; `RecursionError` to the uncontrolled-recursion GF-207;
/// everything else — KeyError, AttributeError, AssertionError, SystemError, a custom
/// exception — is a reachable-crash GF-210. CWE flows from the rule catalog.
fn parse_python_finding(stderr: &str) -> Option<SanitizerReport> {
    const MARKER: &str = "== govfuzz python finding:";
    let line = stderr.lines().find(|l| l.contains(MARKER))?;
    let after = line.split(MARKER).nth(1).unwrap_or("").trim();
    let (exc, msg) = match after.split_once(':') {
        Some((c, m)) => (c.trim(), m.trim()),
        None => (after, ""),
    };

    let (kind, rule_id) = match exc {
        "IndexError" => ("python-index-out-of-bounds".to_owned(), "GF-201"),
        "ZeroDivisionError" | "OverflowError" | "FloatingPointError" => {
            ("python-arithmetic".to_owned(), "GF-205")
        }
        "MemoryError" => ("python-out-of-memory".to_owned(), "GF-209"),
        "RecursionError" => ("python-uncontrolled-recursion".to_owned(), "GF-207"),
        // KeyError, AttributeError, AssertionError, SystemError, custom errors, ...
        _ => ("python-uncaught-exception".to_owned(), "GF-210"),
    };

    let mut stack = parse_python_stack_frames(stderr);
    stack.truncate(5);

    let message = if msg.is_empty() {
        format!("Python finding: {exc}")
    } else {
        format!("Python finding: {exc}: {msg}")
    };
    Some(SanitizerReport {
        sanitizer: Sanitizer::AddressSanitizer,
        kind,
        rule_id,
        stack,
        message,
    })
}

/// Parse CPython traceback frames (`  File "x.py", line N, in func`), skipping the
/// govfuzz driver/harness/coverage frames so the top frame is the target's code.
fn parse_python_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for raw in stderr.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("File \"") else {
            continue;
        };
        let Some(end_quote) = rest.find('"') else {
            continue;
        };
        let file = &rest[..end_quote];
        // `, line N, in func`
        let tail = &rest[end_quote + 1..];
        let line_no = tail
            .split("line ")
            .nth(1)
            .and_then(|s| s.split([',', ' ']).next())
            .and_then(|s| s.trim().parse::<u32>().ok());
        let function = tail
            .split(" in ")
            .nth(1)
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
        if file.ends_with("govfuzz_driver.py")
            || file.ends_with("govfuzz_cov.py")
            || file.ends_with("harness.py")
        {
            continue;
        }
        frames.push(StackFrame {
            function,
            file: Some(file.to_owned()),
            line: line_no,
        });
    }
    frames
}

/// Parse Java stack frames (`\tat pkg.Class.method(File.java:line)`).
fn parse_java_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for raw in stderr.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("at ") else {
            continue;
        };
        // rest = `pkg.Class.method(File.java:line)` (or `(Native Method)`).
        let Some(paren) = rest.find('(') else {
            continue;
        };
        let function = rest[..paren].trim().to_owned();
        let loc = &rest[paren + 1..];
        let loc = loc.trim_end_matches(')');
        let (file, line_no) = match loc.rsplit_once(':') {
            Some((f, l)) => (Some(f.to_owned()), l.parse::<u32>().ok()),
            None => (None, None),
        };
        // Skip the JDK reflection + govfuzz driver frames so the top frame is the
        // target's own code.
        if function.starts_with("java.")
            || function.starts_with("jdk.")
            || function.starts_with("com.govfuzz.")
        {
            continue;
        }
        frames.push(StackFrame {
            function,
            file,
            line: line_no,
        });
    }
    frames
}

/// Parse a Rust panic out of stderr. A panic line looks like
/// `thread '<unnamed>' (12345) panicked at <file>:<line>:<col>:` followed by the
/// panic message on the next line. The message drives the rule id (an OOB index
/// or slice-range panic is the same CWE-125/787 class as an ASan OOB; an
/// arithmetic-overflow panic maps to GF-205; everything else — `unwrap` on
/// `None`/`Err`, an explicit `panic!`, `assert!` — is a reachable-crash GF-210).
fn parse_rust_panic(stderr: &str) -> Option<SanitizerReport> {
    let lines: Vec<&str> = stderr.lines().collect();
    let idx = lines
        .iter()
        .position(|l| l.contains("panicked at") && l.contains("thread '"))
        // Also accept a bare `panicked at` (some panic hooks omit the thread).
        .or_else(|| {
            lines
                .iter()
                .position(|l| l.trim_start().starts_with("panicked at"))
        })?;
    let panic_line = lines[idx];
    // The human message is usually the next non-empty line.
    let msg = lines
        .get(idx + 1)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    let lower = msg.to_ascii_lowercase();
    let (kind, rule_id) = if lower.contains("index out of bounds")
        || lower.contains("range end index")
        || lower.contains("range start index")
        || lower.contains("slice index")
        || lower.contains("out of range for slice")
    {
        ("rust-panic-index-out-of-bounds".to_owned(), "GF-201")
    } else if lower.contains("overflow")
        || lower.contains("divide by zero")
        || lower.contains("remainder with a divisor of zero")
    {
        ("rust-panic-arithmetic".to_owned(), "GF-205")
    } else {
        // unwrap/expect on None/Err, explicit panic!, assert!, unreachable!, etc.
        ("rust-panic".to_owned(), "GF-210")
    };

    // Capture the panic site (`<file>:<line>:<col>`) as the top frame so the
    // finding gets a real physicalLocation.
    let site = panic_line.split("panicked at").nth(1).map(str::trim);
    let mut stack = Vec::new();
    if let Some(site) = site {
        let loc = site.trim_end_matches(':');
        let (file, line) = parse_file_line(loc);
        if file.is_some() {
            stack.push(StackFrame {
                function: "<rust panic>".to_owned(),
                file,
                line,
            });
        }
    }
    // Append any backtrace frames the runtime printed.
    stack.extend(parse_stack_frames(stderr));
    stack.truncate(5);

    let message = if msg.is_empty() {
        panic_line.trim().to_owned()
    } else {
        format!("Rust panic: {msg}")
    };
    Some(SanitizerReport {
        // A Rust panic is not literally an ASan finding, but the corpus model's
        // `Sanitizer` enum is the crash-channel tag; AddressSanitizer is the
        // closest existing variant and keeps the finding in the memory-safety
        // bucket. The `kind`/`rule_id` carry the real Rust classification.
        sanitizer: Sanitizer::AddressSanitizer,
        kind,
        rule_id,
        stack,
        message,
    })
}

fn parse_asan(stderr: &str) -> Option<SanitizerReport> {
    let needle = "ERROR: AddressSanitizer:";
    let pos = stderr.find(needle)?;
    let rest = &stderr[pos..];
    let line = rest.lines().next()?;
    let after_marker = line[needle.len()..].trim_start();
    // Real ASan double-free output is "attempting double-free on 0x... in thread
    // T0:" (and "attempting free on address which was not malloc()-ed"): strip the
    // leading "attempting " so the kind token is the real class (`double-free` /
    // `free`), not `attempting`. The hyphenated `attempting-double-free` arm below
    // never matched — ASan emits a space, not a hyphen (#37).
    let after_marker = after_marker
        .strip_prefix("attempting ")
        .unwrap_or(after_marker);
    let kind = after_marker.split_whitespace().next()?.to_owned();
    let rule_id = match kind.as_str() {
        "heap-buffer-overflow" => "GF-201",
        "heap-use-after-free" | "use-after-free" => "GF-202",
        // Spatial stack errors (a fixed on-stack buffer overrun) — CWE-121.
        "stack-buffer-overflow" | "stack-buffer-underflow" | "dynamic-stack-buffer-overflow" => {
            "GF-203"
        }
        // Temporal stack errors (a stale/expired stack pointer) are a DISTINCT
        // weakness — CWE-825/562, not the spatial CWE-121 — so route them to their
        // own rule instead of lumping them into GF-203 (#29).
        "stack-use-after-return" | "stack-use-after-scope" => "GF-211",
        // "double-free" (was "attempting double-free") and "free on address which
        // was not malloc()-ed" (kind token "free") are both the free-of-invalid-
        // pointer class — CWE-415 (#37).
        "double-free" | "free" => "GF-204",
        // ASan reports null deref as "SEGV on unknown address". Match the
        // common variant explicitly so we don't lose the signal.
        "SEGV" if line.contains("0x000000000000") => "GF-206",
        "SEGV" => "GF-206",
        // Global / static buffers and intra-object are all "OOB writes/reads"
        // at the rule-catalog level - one heuristic, same CWE-787.
        "global-buffer-overflow"
        | "container-overflow"
        | "intra-object-overflow"
        | "negative-size-param" => "GF-201",
        // Mismatched allocator/deallocator (new/delete vs malloc/free) - same
        // exploitability class as double-free for the rule catalog.
        "alloc-dealloc-mismatch" | "new-delete-type-mismatch" | "bad-free" => "GF-204",
        _ => "GF-201",
    };
    // Enrich the message with the access kind — an OOB READ (info disclosure /
    // DoS) vs WRITE (memory corruption / potential RCE) drives severity and is on
    // a SEPARATE line of the report ("READ of size 4 at 0x...", "WRITE of size 8
    // at 0x..."). For a SEGV the direction is instead on the "The signal is caused
    // by a READ/WRITE memory access." line, which carries the `==NN==` PID prefix
    // so it can't be anchored with `starts_with` (#30). Keep just the kind, drop
    // the noisy address.
    let access = rest.lines().take(12).find_map(|l| {
        let t = l.trim_start();
        if t.starts_with("READ of size") || t.starts_with("WRITE of size") {
            return Some(t.split(" at ").next().unwrap_or(t).trim().to_owned());
        }
        if let Some(pos) = l.find("The signal is caused by a ") {
            let word = l[pos + "The signal is caused by a ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or("");
            if word == "READ" || word == "WRITE" {
                return Some(format!("{word} memory access"));
            }
        }
        None
    });
    let message = match access {
        Some(a) => format!("{line} ({a})"),
        None => line.to_owned(),
    };
    Some(SanitizerReport {
        sanitizer: Sanitizer::AddressSanitizer,
        kind,
        rule_id,
        stack: parse_stack_frames(rest),
        message,
    })
}

fn parse_ubsan(stderr: &str) -> Option<SanitizerReport> {
    // UBSan prints a single line per error in the form:
    // `<file>:<line>:<col>: runtime error: <message>`
    let line = stderr
        .lines()
        .find(|line| line.contains("runtime error:"))?;
    let after = line.split("runtime error:").nth(1)?.trim();

    let (kind, rule_id) = if after.starts_with("signed integer overflow")
        || after.starts_with("unsigned integer overflow")
        || after.contains("cannot be represented in type")
    {
        ("signed-integer-overflow".to_owned(), "GF-205")
    } else if after.starts_with("load of null pointer")
        || after.starts_with("store to null pointer")
        || after.starts_with("member access within null pointer")
        || after.starts_with("reference binding to null pointer")
    {
        ("null-pointer-dereference".to_owned(), "GF-206")
    } else if after.starts_with("index ") && after.contains("out of bounds") {
        ("out-of-bounds-access".to_owned(), "GF-201")
    } else if after.starts_with("division by zero") {
        ("division-by-zero".to_owned(), "GF-205")
    } else {
        return None;
    };

    Some(SanitizerReport {
        sanitizer: Sanitizer::UndefinedBehaviorSanitizer,
        kind,
        rule_id,
        stack: parse_stack_frames(stderr),
        message: line.to_owned(),
    })
}

fn parse_lsan(stderr: &str) -> Option<SanitizerReport> {
    let line = stderr.lines().find(|line| {
        line.contains("ERROR: LeakSanitizer:")
            || line.contains("LeakSanitizer: detected memory leaks")
    })?;
    Some(SanitizerReport {
        sanitizer: Sanitizer::LeakSanitizer,
        kind: "memory-leak".to_owned(),
        rule_id: "GF-208",
        stack: parse_stack_frames(stderr),
        message: line.to_owned(),
    })
}

const MAX_SANITIZER_FRAMES: usize = 16;

fn parse_stack_frames(stderr: &str) -> Vec<StackFrame> {
    let mut frames: Vec<StackFrame> = Vec::new();
    for line in stderr.lines() {
        let trimmed = line.trim_start();
        // ASan/UBSan format:
        //   "    #0 0x... in <symbol> /path/file.c:LINE[:COL]"
        //   "    #0 0x... in <demangled C++ name with spaces> /path/file.c:LINE"
        //   "    #0 0x... in <symbol> (module+0xab)"   (unresolved)
        let Some(rest) = trimmed.strip_prefix('#') else {
            continue;
        };
        let Some(in_pos) = rest.find(" in ") else {
            continue;
        };
        let after = &rest[in_pos + 4..].trim_end();
        let (function, file, line) = split_function_and_location(after);
        let function = function.to_owned();
        if function.is_empty() {
            continue;
        }
        let frame = StackFrame {
            function,
            file,
            line,
        };
        if frames.contains(&frame) || frames.len() >= MAX_SANITIZER_FRAMES {
            continue;
        }
        frames.push(frame);
    }
    frames
}

/// Pull a `(function, file, line)` triple out of the substring that
/// follows `" in "` on a sanitizer stack line. C++ demangled names
/// contain spaces (`std::vector<int>::push_back(int const&)`), so we
/// can't simply tokenize on whitespace. Instead, scan the trailing
/// token: if it looks like `path:LINE` (or `path:LINE:COL`), it's a
/// source location; if it's wrapped in `(...)` it's an unresolved
/// `(module+0xoffset)` and we drop it; otherwise the entire string
/// is the function name.
fn split_function_and_location(after: &str) -> (&str, Option<String>, Option<u32>) {
    // First check whether the last whitespace-separated token is a
    // source location (`path:LINE[:COL]`); if so, peel it off. Then
    // strip any number of trailing `(...)` annotations (module+offset,
    // `(BuildId: ...)`, etc.) so the function name doesn't get
    // contaminated with toolchain decoration.
    let mut cursor = after.trim();
    let mut file_opt: Option<String> = None;
    let mut line_opt: Option<u32> = None;
    if let Some(last_ws) = cursor.rfind(char::is_whitespace) {
        let tail = cursor[last_ws..].trim_start();
        if !tail.starts_with('(') {
            let (file, line) = parse_file_line(tail);
            if file.is_some() {
                cursor = cursor[..last_ws].trim_end();
                file_opt = file;
                line_opt = line;
            }
        }
    }
    // Strip trailing `(...)` chunks. Each chunk may itself contain
    // whitespace (BuildId blobs do), so we scan from the end matching
    // balanced parens.
    loop {
        let trimmed = cursor.trim_end();
        if !trimmed.ends_with(')') {
            cursor = trimmed;
            break;
        }
        // Find matching opening paren by scanning backwards.
        let bytes = trimmed.as_bytes();
        let mut depth = 0_i32;
        let mut open_idx: Option<usize> = None;
        for (i, b) in bytes.iter().enumerate().rev() {
            match b {
                b')' => depth += 1,
                b'(' => {
                    depth -= 1;
                    if depth == 0 {
                        open_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(open) = open_idx else {
            cursor = trimmed;
            break;
        };
        // Only strip if the chunk is preceded by whitespace - otherwise
        // it's part of a C++ name like `foo(int)` and we keep it.
        let preceding = &trimmed[..open];
        if !preceding.ends_with(char::is_whitespace) {
            cursor = trimmed;
            break;
        }
        cursor = preceding.trim_end();
    }
    (cursor, file_opt, line_opt)
}

/// Parse the trailing `/path/file.c:42[:7]` token from a sanitizer frame.
/// Returns `(None, None)` when the symbol was unresolved (eg. stripped
/// binary printed `function+0xab` instead of a file:line tuple).
/// Examples handled:
///   /src/a.c:42       -> (Some(a.c), Some(42))
///   /src/a.c:42:7     -> (Some(a.c), Some(42))  // column dropped
///   stripped+0xab     -> (None, None)
fn parse_file_line(token: &str) -> (Option<String>, Option<u32>) {
    if token.is_empty() || token.starts_with('+') || token.starts_with('(') {
        return (None, None);
    }
    let Some(last_colon) = token.rfind(':') else {
        return (None, None);
    };
    let (head, tail) = token.split_at(last_colon);
    let tail_value = &tail[1..];
    let Ok(last_num) = tail_value.parse::<u32>() else {
        return (None, None);
    };
    if head.is_empty() {
        return (None, None);
    }
    // The trailing number is either the line (`file.c:42`) or the column
    // when there are two colons (`file.c:42:7`). Probe the segment before
    // the last colon: if that's also numeric, the trailing value was the
    // column and the real line is the inner number.
    if let Some(mid_colon) = head.rfind(':') {
        let (head_inner, mid) = head.split_at(mid_colon);
        if let Ok(line) = mid[1..].parse::<u32>() {
            return (Some(head_inner.to_owned()), Some(line));
        }
    }
    (Some(head.to_owned()), Some(last_num))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_asan_heap_buffer_overflow_maps_to_gf201_and_captures_frames() {
        let stderr = "\
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead
    #0 0x4ff in target_parse /src/parse.c:42
    #1 0x500 in LLVMFuzzerTestOneInput /tmp/main.c:9
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-201");
        assert_eq!(r.kind, "heap-buffer-overflow");
        assert_eq!(r.sanitizer, Sanitizer::AddressSanitizer);
        assert_eq!(r.stack.len(), 2);
        assert_eq!(r.stack[0].function, "target_parse");
        assert_eq!(r.stack[0].file.as_deref(), Some("/src/parse.c"));
        assert_eq!(r.stack[0].line, Some(42));
        assert!(r.message.contains("heap-buffer-overflow"));
    }

    #[test]
    fn parse_lsan_keeps_deep_rust_harness_frames() {
        let stderr = "\
==1234==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 6 byte(s) in 1 object(s) allocated from:
    #0 0x100 in malloc (/tmp/h/main+0x100)
    #1 0x101 in <alloc::raw_vec::RawVecInner>::try_allocate_in (/tmp/h/main+0x101)
    #2 0x102 in <alloc::raw_vec::RawVecInner>::with_capacity_in /rust/library/alloc/src/raw_vec/mod.rs:434:15
    #3 0x103 in <alloc::raw_vec::RawVec<u8>>::with_capacity_in /rust/library/alloc/src/raw_vec/mod.rs:177:20
    #4 0x104 in <alloc::vec::Vec<u8>>::with_capacity_in /rust/library/alloc/src/vec/mod.rs:977:20
    #5 0x105 in <u8 as <[_]>::to_vec_in::ConvertVec>::to_vec::<alloc::alloc::Global> /rust/library/alloc/src/slice.rs:448:29
    #6 0x106 in <[u8]>::to_vec /rust/library/alloc/src/slice.rs:376:14
    #7 0x107 in <str as alloc::borrow::ToOwned>::to_owned /rust/library/alloc/src/str.rs:251:62
    #8 0x108 in <alloc::borrow::Cow<str>>::into_owned /rust/library/alloc/src/borrow.rs:333:44
    #9 0x109 in <rust_runtime::Cursor>::string /workspace/crates/rust_runtime/src/lib.rs:171:39
    #10 0x10a in govfuzz_run_one /tmp/h/rust_harness/src/lib.rs:17:30
    #11 0x10b in govfuzz_run_one_bytes /tmp/h/main.c:406:5
    #12 0x10c in main /tmp/h/main.c:481:5
SUMMARY: AddressSanitizer: 6 byte(s) leaked in 1 allocation(s).
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-208");
        assert!(
            r.stack
                .iter()
                .any(|frame| frame.function == "govfuzz_run_one"),
            "deep harness frame must be retained: {:?}",
            r.stack
        );
    }

    #[test]
    fn jvm_finding_aioobe_maps_to_gf201_and_skips_driver_frames() {
        let stderr = "\
== govfuzz JVM finding: java.lang.ArrayIndexOutOfBoundsException: Index 8 out of bounds for length 1
java.lang.ArrayIndexOutOfBoundsException: Index 8 out of bounds for length 1
\tat com.acme.Magic.parse(Magic.java:30)
\tat govfuzzgen.Harness.govfuzzRunOne(Harness.java:10)
\tat java.base/jdk.internal.reflect.DirectMethodHandleAccessor.invoke(DirectMethodHandleAccessor.java:103)
\tat com.govfuzz.Driver.runInput(Driver.java:93)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-201");
        assert_eq!(r.kind, "jvm-index-out-of-bounds");
        // The target's own frame is the top frame; JDK/govfuzz frames are skipped.
        assert_eq!(r.stack[0].function, "com.acme.Magic.parse");
        assert_eq!(r.stack[0].file.as_deref(), Some("Magic.java"));
        assert_eq!(r.stack[0].line, Some(30));
        assert!(r.message.contains("ArrayIndexOutOfBoundsException"));
    }

    #[test]
    fn jvm_finding_npe_maps_to_gf210() {
        let stderr = "== govfuzz JVM finding: java.lang.NullPointerException\n\
                      \tat com.acme.P.parse(P.java:5)\n";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-210");
        assert_eq!(r.kind, "jvm-uncaught-throwable");
    }

    #[test]
    fn non_jvm_stderr_is_not_a_jvm_finding() {
        assert!(parse_sanitizer_report("just some normal output\n").is_none());
    }

    #[test]
    fn python_finding_recursion_maps_to_gf207_and_skips_driver_frames() {
        let stderr =
            "== govfuzz python finding: RecursionError: maximum recursion depth exceeded\n\
                      Traceback (most recent call last):\n\
                      \x20 File \"/w/govfuzz_driver.py\", line 99, in _run_input\n\
                      \x20 File \"/w/govfuzzgen/harness.py\", line 11, in govfuzz_run_one\n\
                      \x20 File \"/proj/recordparser.py\", line 18, in parse_record\n\
                      \x20 File \"/proj/recordparser.py\", line 22, in _walk\n";
        let r = parse_sanitizer_report(stderr).expect("python finding");
        assert_eq!(r.rule_id, "GF-207");
        assert_eq!(r.kind, "python-uncontrolled-recursion");
        // Driver + harness frames are skipped; the top frame is the target's code.
        assert_eq!(r.stack[0].function, "parse_record");
        assert_eq!(r.stack[0].file.as_deref(), Some("/proj/recordparser.py"));
        assert_eq!(r.stack[0].line, Some(18));
    }

    #[test]
    fn python_finding_index_and_arithmetic_and_generic_map_correctly() {
        let idx = "== govfuzz python finding: IndexError: list index out of range\n";
        assert_eq!(parse_sanitizer_report(idx).unwrap().rule_id, "GF-201");
        let zde = "== govfuzz python finding: ZeroDivisionError: division by zero\n";
        assert_eq!(parse_sanitizer_report(zde).unwrap().rule_id, "GF-205");
        let oom = "== govfuzz python finding: MemoryError: \n";
        assert_eq!(parse_sanitizer_report(oom).unwrap().rule_id, "GF-209");
        let key = "== govfuzz python finding: KeyError: 'x'\n";
        assert_eq!(parse_sanitizer_report(key).unwrap().rule_id, "GF-210");
    }

    #[test]
    fn csharp_finding_maps_types_and_parses_stack() {
        let stderr = "== govfuzz csharp finding: System.IndexOutOfRangeException: Index was outside the bounds of the array.\n\
                      \x20  at Govfuzzgen.GovfuzzEntry.Run(Byte[] data)\n\
                      \x20  at Acme.Parsing.JsonReader.Parse(Byte[] data) in /proj/JsonReader.cs:line 42\n\
                      \x20  at Acme.Parsing.JsonReader.Scan(Byte[] data) in /proj/JsonReader.cs:line 51\n";
        let r = parse_sanitizer_report(stderr).expect("csharp finding");
        assert_eq!(r.rule_id, "GF-201");
        assert_eq!(r.kind, "csharp-index-out-of-bounds");
        // The Govfuzzgen entry frame is skipped; the top frame is the target's code.
        assert_eq!(r.stack[0].function, "Acme.Parsing.JsonReader.Parse");
        assert_eq!(r.stack[0].file.as_deref(), Some("/proj/JsonReader.cs"));
        assert_eq!(r.stack[0].line, Some(42));
    }

    #[test]
    fn csharp_finding_type_rule_mapping() {
        let nre = "== govfuzz csharp finding: System.NullReferenceException: \n";
        assert_eq!(parse_sanitizer_report(nre).unwrap().rule_id, "GF-206");
        let dz = "== govfuzz csharp finding: System.DivideByZeroException: div by zero\n";
        assert_eq!(parse_sanitizer_report(dz).unwrap().rule_id, "GF-205");
        let oom = "== govfuzz csharp finding: System.OutOfMemoryException: \n";
        assert_eq!(parse_sanitizer_report(oom).unwrap().rule_id, "GF-209");
        let custom = "== govfuzz csharp finding: Acme.ParseException: bad token\n";
        assert_eq!(parse_sanitizer_report(custom).unwrap().rule_id, "GF-210");
    }

    #[test]
    fn js_finding_reads_rule_and_stack() {
        let stderr = "== govfuzz js finding: GF-206: TypeError: Cannot read properties of undefined (reading 'x')\n\
                      \x20   at parse (/proj/parser.js:42:13)\n\
                      \x20   at Object.<anonymous> (/w/govfuzz_driver.js:99:5)\n\
                      \x20   at walk (/proj/parser.js:51:7)\n";
        let r = parse_sanitizer_report(stderr).expect("js finding");
        assert_eq!(r.rule_id, "GF-206");
        assert_eq!(r.kind, "js-null-dereference");
        // The driver frame is skipped; the top frame is the target's code.
        assert_eq!(r.stack[0].function, "parse");
        assert_eq!(r.stack[0].file.as_deref(), Some("/proj/parser.js"));
        assert_eq!(r.stack[0].line, Some(42));
    }

    #[test]
    fn js_finding_rule_mapping() {
        let so = "== govfuzz js finding: GF-207: RangeError: Maximum call stack size exceeded\n";
        assert_eq!(parse_sanitizer_report(so).unwrap().rule_id, "GF-207");
        let oom = "== govfuzz js finding: GF-209: RangeError: Invalid array length\n";
        assert_eq!(parse_sanitizer_report(oom).unwrap().rule_id, "GF-209");
        let gen = "== govfuzz js finding: GF-210: Error: boom\n";
        assert_eq!(parse_sanitizer_report(gen).unwrap().rule_id, "GF-210");
    }

    #[test]
    fn non_python_stderr_is_not_a_python_finding() {
        assert!(parse_python_finding("regular traceback-free output\n").is_none());
    }

    #[test]
    fn go_panic_maps_message_to_rule_and_skips_runtime_frames() {
        let stderr = "== govfuzz go finding: runtime error: index out of range [5] with length 1\n\
                      goroutine 1 [running]:\n\
                      runtime/debug.Stack()\n\
                      \t/usr/local/go/src/runtime/debug/stack.go:24 +0x5e\n\
                      main.runOne.func1()\n\
                      \t/w/govfuzz_harness.go:40 +0x4c\n\
                      panic({0x4a0,0xc1})\n\
                      \t/usr/local/go/src/runtime/panic.go:770 +0x132\n\
                      example/recordparser.ParseRecord({0x0,0x1,0x1})\n\
                      \t/proj/recordparser/parser.go:17 +0x1d0\n";
        let r = parse_sanitizer_report(stderr).expect("go finding");
        assert_eq!(r.rule_id, "GF-201");
        assert_eq!(r.kind, "go-index-out-of-bounds");
        assert_eq!(r.stack[0].function, "example/recordparser.ParseRecord");
        assert_eq!(
            r.stack[0].file.as_deref(),
            Some("/proj/recordparser/parser.go")
        );
        assert_eq!(r.stack[0].line, Some(17));
    }

    #[test]
    fn go_panic_classes() {
        let nil = "panic: runtime error: invalid memory address or nil pointer dereference\n";
        assert_eq!(parse_sanitizer_report(nil).unwrap().rule_id, "GF-206");
        let div = "panic: runtime error: integer divide by zero\n";
        assert_eq!(parse_sanitizer_report(div).unwrap().rule_id, "GF-205");
        let other = "panic: assertion failed\n";
        assert_eq!(parse_sanitizer_report(other).unwrap().rule_id, "GF-210");
        assert!(parse_go_panic("ordinary program output\n").is_none());
    }

    #[test]
    fn perl_finding_maps_cwe_token_to_rule() {
        let div = "== govfuzz perl finding: CWE-369: Illegal division by zero\n";
        assert_eq!(parse_sanitizer_report(div).unwrap().rule_id, "GF-205");
        let rec = "== govfuzz perl finding: CWE-674: Deep recursion\n";
        assert_eq!(parse_sanitizer_report(rec).unwrap().rule_id, "GF-207");
        let oom = "== govfuzz perl finding: CWE-789: Out of memory\n";
        assert_eq!(parse_sanitizer_report(oom).unwrap().rule_id, "GF-209");
        let assert_die = "== govfuzz perl finding: CWE-617: panic: invariant\n";
        assert_eq!(
            parse_sanitizer_report(assert_die).unwrap().rule_id,
            "GF-210"
        );
        assert!(parse_perl_finding("Use of uninitialized value\n").is_none());
    }

    #[test]
    fn jvm_class_loading_errors_are_not_findings() {
        // ClassFormatError / VerifyError / NoClassDefFoundError are instrumentation
        // or classpath artifacts, not target bugs (snakeyaml emitted 15 identical
        // ClassFormatError "bad offset for Uninitialized" from coverage-instrumented
        // bytecode). They must NOT raise a GF-210 finding.
        for class in [
            "java.lang.ClassFormatError",
            "java.lang.VerifyError",
            "java.lang.NoClassDefFoundError",
            "java.lang.UnsupportedClassVersionError",
            "java.lang.LinkageError",
        ] {
            let stderr = format!(
                "== govfuzz JVM finding: {class}: StackMapTable format error\n\
                 \tat org.yaml.snakeyaml.Yaml.load(Yaml.java:437)\n"
            );
            assert!(
                parse_sanitizer_report(&stderr).is_none(),
                "{class} must not be a finding"
            );
        }
        // A real target exception still IS a finding (regression guard).
        let real = "== govfuzz JVM finding: java.lang.NullPointerException\n\
                    \tat com.acme.P.parse(P.java:5)\n";
        assert!(parse_sanitizer_report(real).is_some());
    }

    #[test]
    fn rust_panic_index_oob_maps_to_gf201_with_site() {
        let stderr = "\
thread '<unnamed>' (3064726) panicked at /src/lib.rs:37:50:
index out of bounds: the len is 6 but the index is 6
note: run with `RUST_BACKTRACE=1` to display a backtrace
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-201");
        assert_eq!(r.kind, "rust-panic-index-out-of-bounds");
        assert!(r.message.contains("index out of bounds"), "{}", r.message);
        // The panic site is the top frame.
        assert_eq!(r.stack[0].file.as_deref(), Some("/src/lib.rs"));
        assert_eq!(r.stack[0].line, Some(37));
    }

    #[test]
    fn rust_panic_arithmetic_overflow_maps_to_gf205() {
        let stderr = "\
thread 'main' panicked at src/math.rs:9:5:
attempt to add with overflow
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-205");
        assert_eq!(r.kind, "rust-panic-arithmetic");
    }

    #[test]
    fn rust_panic_unwrap_is_generic_gf210() {
        let stderr = "\
thread '<unnamed>' panicked at src/lib.rs:3:14:
called `Option::unwrap()` on a `None` value
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-210");
        assert_eq!(r.kind, "rust-panic");
        assert!(r.message.contains("unwrap"));
    }

    #[test]
    fn non_rust_stderr_is_not_a_rust_panic() {
        // A plain C assert/abort must NOT be misread as a Rust panic.
        assert!(parse_sanitizer_report("Assertion failed: x > 0\n").is_none());
        assert!(parse_sanitizer_report("some unrelated output\n").is_none());
    }

    #[test]
    fn parse_ubsan_frame_with_column_suffix_keeps_line() {
        let stderr = "\
t.c:1:1: runtime error: signed integer overflow: 2 + 2147483647
    #0 0x123 in overflow_caller /tmp/t.c:7:9
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(r.stack[0].function, "overflow_caller");
        assert_eq!(r.stack[0].file.as_deref(), Some("/tmp/t.c"));
        assert_eq!(r.stack[0].line, Some(7));
    }

    #[test]
    fn parse_stack_frame_with_no_debug_info_keeps_function_only() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-use-after-free on 0xdead
    #0 0x456 in stripped_symbol+0xab
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(r.stack[0].function, "stripped_symbol+0xab");
        assert!(r.stack[0].file.is_none());
        assert!(r.stack[0].line.is_none());
    }

    #[test]
    fn parse_stack_frame_module_offset_token_is_not_a_file() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x4ff in __asan_memcpy (/tmp/build/main+0xfec85)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(r.stack[0].function, "__asan_memcpy");
        assert!(r.stack[0].file.is_none(), "module+offset is not a file");
        assert!(r.stack[0].line.is_none());
    }

    #[test]
    fn parse_stack_frame_strips_trailing_buildid_blob() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x4ff in __asan_memcpy (/tmp/main+0xfec85) (BuildId: b103ed1874b0142af3dadc0fd902cf79b6af9fa8)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(r.stack[0].function, "__asan_memcpy");
    }

    #[test]
    fn parse_stack_frame_preserves_cpp_paren_arglist_in_function() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x4ff in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/usr/bin/main+0x4cca4)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        // Trailing (module+offset) is dropped; the C++ arg list, which
        // is part of the function name with no preceding whitespace,
        // stays attached.
        assert_eq!(
            r.stack[0].function,
            "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)"
        );
    }

    #[test]
    fn parse_stack_frame_handles_demangled_cpp_name_with_spaces() {
        let stderr = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x4ff in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/usr/bin/main+0x4cca4)
";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.stack.len(), 1);
        assert_eq!(
            r.stack[0].function,
            "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)"
        );
        assert!(r.stack[0].file.is_none());
    }

    #[test]
    fn parse_asan_uaf_maps_to_gf202() {
        let stderr = "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x...";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "GF-202");
    }

    #[test]
    fn parse_asan_double_free_maps_to_gf204() {
        // Real ASan emits "attempting double-free on 0x... in thread T0:" (a
        // SPACE, not a hyphen); the leading "attempting " must be stripped so the
        // kind is "double-free" -> GF-204, not "attempting" -> GF-201 (#37).
        let stderr = "==1==ERROR: AddressSanitizer: attempting double-free on 0x602000000010 in thread T0:\n    #0 0x4ff in free /a.c:1\n";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-204");
        assert_eq!(r.kind, "double-free");
    }

    #[test]
    fn parse_asan_attempting_free_on_non_malloc_maps_to_gf204() {
        // "attempting free on address which was not malloc()-ed" — the kind token
        // after stripping "attempting " is "free"; classify as the invalid-free
        // class GF-204, not the GF-201 OOB fallback (#37).
        let stderr = "==1==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x7ff in thread T0\n";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-204");
        assert_eq!(r.kind, "free");
    }

    #[test]
    fn parse_asan_stack_overflow_maps_to_gf203() {
        let stderr = "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xbad";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "GF-203");
    }

    #[test]
    fn parse_ubsan_signed_overflow_maps_to_gf205() {
        let stderr = "source.c:10:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-205");
        assert_eq!(r.kind, "signed-integer-overflow");
    }

    #[test]
    fn parse_ubsan_oob_index_maps_to_gf201() {
        let stderr = "t.c:7:9: runtime error: index 88 out of bounds for type 'char[4]'";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-201");
        assert_eq!(r.kind, "out-of-bounds-access");
    }

    #[test]
    fn parse_ubsan_null_deref_maps_to_gf206() {
        let stderr = "t.c:5:1: runtime error: load of null pointer of type 'int'";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "GF-206");
    }

    #[test]
    fn parse_lsan_memory_leak_maps_to_gf208() {
        let stderr =
            "=================================================================\n==1==ERROR: LeakSanitizer: detected memory leaks\n";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-208");
        assert_eq!(r.sanitizer, Sanitizer::LeakSanitizer);
    }

    #[test]
    fn parse_asan_stack_use_after_return_maps_to_gf211_temporal() {
        // A temporal stack error (stale stack pointer) is the CWE-825/562 class,
        // NOT the spatial stack-buffer-overflow GF-203/CWE-121 (#29).
        let stderr = "==1==ERROR: AddressSanitizer: stack-use-after-return on address 0x7ff...";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-211");
        assert_eq!(r.kind, "stack-use-after-return");
    }

    #[test]
    fn parse_asan_stack_use_after_scope_maps_to_gf211_temporal() {
        let stderr = "==1==ERROR: AddressSanitizer: stack-use-after-scope on address 0x7ff...";
        let r = parse_sanitizer_report(stderr).unwrap();
        assert_eq!(r.rule_id, "GF-211");
        assert_eq!(r.kind, "stack-use-after-scope");
    }

    #[test]
    fn parse_asan_spatial_stack_overflow_stays_gf203() {
        // A genuine spatial stack-buffer-overflow must NOT be reclassified to the
        // temporal rule — its signal stays loud as GF-203/CWE-121 (#29 guard).
        let stderr = "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xbad";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "GF-203");
    }

    #[test]
    fn parse_asan_segv_captures_read_write_direction_line() {
        // A SEGV states its access direction on a separate "==NN==The signal is
        // caused by a READ/WRITE memory access." line; it must be folded into the
        // message so the CWE layer can tell an OOB read from a write (#30).
        let read = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010 (pc 0x55 bp 0x0 sp 0x0 T0)\n\
                    ==1==The signal is caused by a READ memory access.\n    #0 0x55 in deref /a.c:7\n";
        let m = parse_sanitizer_report(read).unwrap().message;
        assert!(m.contains("READ memory access"), "got: {m}");
        let write = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000001234 (pc 0x55 bp 0x0 sp 0x0 T0)\n\
                     ==1==The signal is caused by a WRITE memory access.\n";
        assert!(parse_sanitizer_report(write)
            .unwrap()
            .message
            .contains("WRITE memory access"));
    }

    #[test]
    fn parse_asan_global_buffer_overflow_maps_to_gf201() {
        let stderr = "==1==ERROR: AddressSanitizer: global-buffer-overflow on address 0xdead";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "GF-201");
    }

    #[test]
    fn parse_asan_negative_size_param_maps_to_gf201() {
        let stderr = "==1==ERROR: AddressSanitizer: negative-size-param: (size=-1)";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "GF-201");
    }

    #[test]
    fn parse_asan_alloc_dealloc_mismatch_maps_to_gf204() {
        let stderr = "==1==ERROR: AddressSanitizer: alloc-dealloc-mismatch (operator new vs free)";
        assert_eq!(parse_sanitizer_report(stderr).unwrap().rule_id, "GF-204");
    }

    #[test]
    fn parse_asan_captures_access_kind_read_vs_write_in_message() {
        // READ vs WRITE drives severity (info-disclosure vs memory corruption) and
        // is on a separate line; it must be folded into the report message.
        let write =
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50 at pc 0x6\n\
                     WRITE of size 8 at 0x50 thread T0\n    #0 0x6 in f /a.c:1\n";
        let m = parse_sanitizer_report(write).unwrap().message;
        assert!(m.contains("WRITE of size 8"), "got: {m}");
        assert!(
            !m.contains(" at 0x"),
            "noisy address dropped from access, got: {m}"
        );
        let read = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50 at pc 0x6\n\
                    READ of size 4 at 0x50 thread T0\n";
        assert!(parse_sanitizer_report(read)
            .unwrap()
            .message
            .contains("READ of size 4"));
        // No access line -> message is just the error line (unchanged behavior).
        let none = "==1==ERROR: AddressSanitizer: stack-use-after-return on address 0x7f";
        assert!(!parse_sanitizer_report(none)
            .unwrap()
            .message
            .contains("of size"));
    }

    #[test]
    fn parse_returns_none_for_clean_output() {
        assert!(parse_sanitizer_report("clean run, no errors").is_none());
    }

    #[test]
    fn parse_stack_frames_deduplicates_repeats_and_keeps_deeper_frames() {
        let stderr = "\
ERROR: AddressSanitizer: heap-buffer-overflow on 0x0
    #0 0x1 in a /a.c:1
    #1 0x2 in b /a.c:2
    #2 0x3 in c /a.c:3
    #3 0x4 in d /a.c:4
    #4 0x5 in e /a.c:5
    #5 0x6 in f /a.c:6
    #6 0x7 in a /a.c:1
";
        let r = parse_sanitizer_report(stderr).unwrap();
        let names: Vec<&str> = r.stack.iter().map(|f| f.function.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d", "e", "f"]);
    }
}
