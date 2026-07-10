// SPDX-License-Identifier: Apache-2.0

//! Declarative taint specifications (M23 Phase 2, #486).
//!
//! One auditable table of the taint model's *data* — the command-execution
//! **sinks**, the parameter-name **source** markers, and the **sanitizer** markers
//! that clear taint — per language, instead of hardcoded per-language `match` arms
//! scattered through the engine. Adding a sink/source/sanitizer for a language is
//! now a one-line table edit, and the whole model is reviewable in one place.
//!
//! All matching is case-insensitive: the engine lowercases the line/needles so a
//! single spec covers `GNAT.OS_Lib.Spawn`, `ProcessBuilder(`, `os.system(`, etc.
//! (Kept as compile-time Rust `const` data rather than a runtime TOML file: govfuzz
//! runs offline over untrusted trees, so a table baked into the binary avoids a
//! parse/error surface and a file dependency while staying just as declarative.)

/// A taint sink pattern for one language, tagged with the rule it graduates a
/// tainted flow to. The engine now confirms more than command injection: a
/// source-like value reaching a file-open is path traversal, a SQL builder is SQL
/// injection, etc. — each interprocedural and fuzz-confirmable.
pub(crate) struct TaintSink {
    /// Substring that marks the sink call on a line (matched case-insensitively).
    pub needle: &'static str,
    /// Sink name recorded in the taint trace / finding.
    pub display: &'static str,
    /// Extra substrings, ANY of which must ALSO appear on the line (empty =
    /// unconditional). Gates like Java `.exec` needing a `Runtime` receiver or
    /// Python `subprocess` needing `shell=True`.
    pub requires_any: &'static [&'static str],
    /// The finding rule this sink graduates a tainted flow to (GF-304 command,
    /// GF-405 path, GF-419 SQL); its CWE (used to dedup the pattern hit at the same
    /// site) comes from the `finding_rules` catalog.
    pub rule_id: &'static str,
    /// SQL sinks require concat/format evidence on the line (a bound-parameter
    /// query with a tainted argument is safe), so we only fire when the tainted
    /// value is built INTO the query, not passed as a parameter.
    pub needs_dynamic_string: bool,
    /// A LIST-form command builder (`exec.Command(prog, args…)`, `Command::new`,
    /// `ProcessBuilder`): a tainted ARGUMENT is passed to a fixed program, which is
    /// NOT command injection — only a tainted PROGRAM (first arg) or an explicit
    /// shell (`sh -c`) is. String-form sinks (`system(str)`, `os.system`,
    /// `Runtime.exec`) tokenize/interpret the whole string, so any tainted use is a
    /// finding (`false`).
    pub list_form: bool,
}

const fn cmd(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-304",
        needs_dynamic_string: false,
        list_form: false,
    }
}

/// A list-form command builder (tainted *argument* to a fixed program is safe).
const fn cmd_list(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-304",
        needs_dynamic_string: false,
        list_form: true,
    }
}

const fn cmd_gated(
    needle: &'static str,
    display: &'static str,
    requires_any: &'static [&'static str],
) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any,
        rule_id: "GF-304",
        needs_dynamic_string: false,
        list_form: false,
    }
}

const fn path(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-405",
        needs_dynamic_string: false,
        list_form: false,
    }
}

const fn sql(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-419",
        needs_dynamic_string: true,
        list_form: false,
    }
}

/// A server-side HTTP-request sink (SSRF, GF-427): a tainted URL reaching it lets
/// an attacker steer the server's outbound request.
const fn ssrf(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-427",
        needs_dynamic_string: false,
        list_form: false,
    }
}

/// Open redirect (CWE-601): a tainted destination reaches a server-side redirect
/// API, letting an attacker choose where the legitimate site sends a user.
const fn redirect(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-442",
        needs_dynamic_string: false,
        list_form: false,
    }
}

/// XXE (CWE-611): a tainted value reaches an XML parser. `requires_any` gates on a
/// risky-parser marker where the needle alone is ambiguous (Java `.parse(`).
const fn xxe(
    needle: &'static str,
    display: &'static str,
    requires_any: &'static [&'static str],
) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any,
        rule_id: "GF-430",
        needs_dynamic_string: false,
        list_form: false,
    }
}

/// LDAP injection (CWE-90): a tainted value built INTO a directory query — same
/// dynamic-string gate as SQL (a bound/escaped filter is safe).
const fn ldap(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-432",
        needs_dynamic_string: true,
        list_form: false,
    }
}

/// Unsafe reflection (CWE-470): a tainted class/method/attribute name drives
/// dynamic loading or invocation.
const fn reflect(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-434",
        needs_dynamic_string: false,
        list_form: false,
    }
}

/// Dynamic code evaluation (CWE-94): a tainted string reaches a script/expression
/// evaluator (JVM `ScriptEngine.eval`, `GroovyShell.evaluate`) and is executed as
/// code. `requires_any` gates on a script-engine/groovy marker so an unrelated
/// `.eval(`/`.evaluate(` on a plain object does not trip.
const fn code_eval(
    needle: &'static str,
    display: &'static str,
    requires_any: &'static [&'static str],
) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any,
        rule_id: "GF-420",
        needs_dynamic_string: false,
        list_form: false,
    }
}

/// Uncontrolled allocation size (CWE-789): a tainted value drives the size of a
/// heap/stack allocation. An attacker-controlled size is a memory-exhaustion DoS on
/// its own and, combined with an integer overflow on the size expression, yields an
/// undersized buffer. This is the classic Coverity `TAINTED_SCALAR` → allocator
/// finding. Naturally precise like `path`: it fires only when the size argument is
/// actually tainted, so a `sizeof`/constant allocation never trips.
const fn alloc(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-436",
        needs_dynamic_string: false,
        list_form: false,
    }
}

/// Log injection / log forging (CWE-117): an attacker-controlled value reaches a
/// log message argument without CR/LF neutralization. Receiver-gated forms avoid
/// treating arbitrary `.info(...)` helpers as logging APIs.
const fn log(needle: &'static str, display: &'static str) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any: &[],
        rule_id: "GF-544",
        needs_dynamic_string: false,
        list_form: false,
    }
}

const fn log_gated(
    needle: &'static str,
    display: &'static str,
    requires_any: &'static [&'static str],
) -> TaintSink {
    TaintSink {
        needle,
        display,
        requires_any,
        rule_id: "GF-544",
        needs_dynamic_string: false,
        list_form: false,
    }
}

/// Per-language taint sinks, most-specific needle first (so `exec.CommandContext`
/// wins over `exec.Command`, `ProcessBuilder` over `.exec`). Grouped command →
/// path → SQL. Path sinks are naturally precise: the engine only fires when a
/// TAINTED value is the argument, so a literal-path open never trips.
pub(crate) struct LangCommandSinks {
    pub language: &'static str,
    pub sinks: &'static [TaintSink],
}

pub(crate) const COMMAND_SINKS: &[LangCommandSinks] = &[
    LangCommandSinks {
        language: "ada",
        sinks: &[
            cmd("gnat.os_lib.spawn", "GNAT.OS_Lib.Spawn"),
            cmd(
                "gnat.expect.non_blocking_spawn",
                "GNAT.Expect.Non_Blocking_Spawn",
            ),
            // File opens with a tainted path (CWE-22). Needles are `.`-prefixed
            // (matched verbatim as a qualified call) because the package qualifier
            // in real Ada precedes them with a `.` (`Ada.Streams.Stream_IO.Open`),
            // which the bare-identifier word-boundary rule would otherwise reject.
            // They also omit the trailing paren, since Ada permits `Open (F, ...)`.
            path(".text_io.open", "Ada.Text_IO.Open"),
            path(".text_io.create", "Ada.Text_IO.Create"),
            path(".stream_io.open", "Ada.Streams.Stream_IO.Open"),
            path(".stream_io.create", "Ada.Streams.Stream_IO.Create"),
            path(".sequential_io.open", "Ada.Sequential_IO.Open"),
            path(".sequential_io.create", "Ada.Sequential_IO.Create"),
            path(".direct_io.open", "Ada.Direct_IO.Open"),
            path(".direct_io.create", "Ada.Direct_IO.Create"),
        ],
    },
    LangCommandSinks {
        language: "c",
        sinks: &[
            cmd("std::system(", "system"),
            cmd("system(", "system"),
            path("fopen(", "fopen"),
            path("freopen(", "freopen"),
            path("open(", "open"),
            xxe("xmlreadmemory(", "xmlReadMemory", &[]),
            xxe("xmlreadfile(", "xmlReadFile", &[]),
            xxe("xmlparsememory(", "xmlParseMemory", &[]),
            xxe("xmlparsefile(", "xmlParseFile", &[]),
            xxe("xmlctxtreadmemory(", "xmlCtxtReadMemory", &[]),
            alloc("malloc(", "malloc"),
            alloc("calloc(", "calloc"),
            alloc("realloc(", "realloc"),
            alloc("alloca(", "alloca"),
            log("syslog(", "syslog"),
        ],
    },
    LangCommandSinks {
        language: "cpp",
        sinks: &[
            cmd(".startcommand(", "QProcess::startCommand"),
            cmd("->startcommand(", "QProcess::startCommand"),
            cmd_list("qprocess::startdetached(", "QProcess::startDetached"),
            cmd_list("qprocess::execute(", "QProcess::execute"),
            cmd("std::system(", "system"),
            cmd("system(", "system"),
            path("fopen(", "fopen"),
            path("ifstream(", "ifstream"),
            path("ofstream(", "ofstream"),
            sql(".exec(", "QSqlQuery::exec"),
            sql("->exec(", "QSqlQuery::exec"),
            sql("qsqlquery ", "QSqlQuery"),
            xxe("xmlreadmemory(", "xmlReadMemory", &[]),
            xxe("xmlreadfile(", "xmlReadFile", &[]),
            xxe("xmlparsememory(", "xmlParseMemory", &[]),
            xxe("xmlparsefile(", "xmlParseFile", &[]),
            alloc("malloc(", "malloc"),
            alloc("calloc(", "calloc"),
            alloc("realloc(", "realloc"),
            alloc("alloca(", "alloca"),
            log("syslog(", "syslog"),
            log("spdlog::critical(", "spdlog::critical"),
            log("spdlog::error(", "spdlog::error"),
            log("spdlog::warn(", "spdlog::warn"),
            log("spdlog::info(", "spdlog::info"),
            log("spdlog::debug(", "spdlog::debug"),
            log("spdlog::trace(", "spdlog::trace"),
        ],
    },
    LangCommandSinks {
        language: "go",
        sinks: &[
            cmd_list("exec.commandcontext(", "exec.CommandContext"),
            cmd_list("exec.command(", "exec.Command"),
            path("os.open(", "os.Open"),
            path("os.openfile(", "os.OpenFile"),
            path("os.readfile(", "os.ReadFile"),
            path("ioutil.readfile(", "ioutil.ReadFile"),
            path("os.create(", "os.Create"),
            sql(".query(", "db.Query"),
            sql(".queryrow(", "db.QueryRow"),
            sql(".exec(", "db.Exec"),
            ssrf("http.get(", "http.Get"),
            ssrf("http.post(", "http.Post"),
            ssrf("http.newrequest(", "http.NewRequest"),
            redirect("http.redirect(", "http.Redirect"),
            alloc("make([", "make"),
            log("log.fatalln(", "log.Fatalln"),
            log("log.fatalf(", "log.Fatalf"),
            log("log.fatal(", "log.Fatal"),
            log("log.panicln(", "log.Panicln"),
            log("log.panicf(", "log.Panicf"),
            log("log.panic(", "log.Panic"),
            log("log.println(", "log.Println"),
            log("log.printf(", "log.Printf"),
            log("log.print(", "log.Print"),
            log("logger.println(", "logger.Println"),
            log("logger.printf(", "logger.Printf"),
            log("logger.print(", "logger.Print"),
        ],
    },
    LangCommandSinks {
        language: "rust",
        sinks: &[
            cmd_list("command::new(", "Command::new"),
            path("file::open(", "File::open"),
            path("file::create(", "File::create"),
            path("fs::read(", "fs::read"),
            path("fs::read_to_string(", "fs::read_to_string"),
            ssrf("reqwest::get(", "reqwest::get"),
            ssrf("reqwest::blocking::get(", "reqwest::blocking::get"),
            alloc("with_capacity(", "with_capacity"),
            log("tracing::error!(", "tracing::error!"),
            log("tracing::warn!(", "tracing::warn!"),
            log("tracing::info!(", "tracing::info!"),
            log("tracing::debug!(", "tracing::debug!"),
            log("tracing::trace!(", "tracing::trace!"),
            log("log::error!(", "log::error!"),
            log("log::warn!(", "log::warn!"),
            log("log::info!(", "log::info!"),
            log("log::debug!(", "log::debug!"),
            log("log::trace!(", "log::trace!"),
        ],
    },
    LangCommandSinks {
        language: "java",
        sinks: &[
            cmd_list("processbuilder(", "ProcessBuilder"),
            cmd_gated(".exec(", "Runtime.exec", &["runtime", "getruntime"]),
            alloc("new byte[", "new byte[]"),
            alloc("new char[", "new char[]"),
            alloc("new int[", "new int[]"),
            alloc("new long[", "new long[]"),
            path("new file(", "new File"),
            path("new fileinputstream(", "new FileInputStream"),
            path("new fileoutputstream(", "new FileOutputStream"),
            path("paths.get(", "Paths.get"),
            sql(".executequery(", "executeQuery"),
            sql(".executeupdate(", "executeUpdate"),
            ssrf(".openconnection(", "URL.openConnection"),
            ssrf("httpget(", "HttpGet"),
            ssrf("httppost(", "HttpPost"),
            redirect(".sendredirect(", "HttpServletResponse.sendRedirect"),
            redirect("redirectview(", "RedirectView"),
            // XXE: a `.parse(` gated on a risky XML parser (no secure-processing).
            xxe(
                ".parse(",
                "XML parser",
                &[
                    "documentbuilder",
                    "saxparser",
                    "xmlreader",
                    "saxbuilder",
                    "unmarshaller",
                ],
            ),
            xxe(".unmarshal(", "Unmarshaller.unmarshal", &["unmarshaller"]),
            ldap(".search(", "DirContext.search"),
            // Only sinks whose PRIMARY argument IS the loaded name — a tainted flow
            // there is genuine CWE-470. `.getMethod(`/`getattr` were dropped: their
            // name arg is usually a literal (the tainted RECEIVER trips them) and
            // `.getMethod(` collides with the HTTP `request.getMethod()`.
            reflect("class.forname(", "Class.forName"),
            reflect(".loadclass(", "ClassLoader.loadClass"),
            // Dynamic code evaluation (CWE-94). `.eval(` is generic, so gate on a
            // script-engine marker; `.evaluate(` on a Groovy marker. A tainted string
            // reaching either is executed as code.
            code_eval(
                ".eval(",
                "ScriptEngine.eval",
                &["engine", "script", "nashorn", "graal"],
            ),
            code_eval(
                ".evaluate(",
                "GroovyShell.evaluate",
                &["groovyshell", "groovy"],
            ),
            log("logger.trace(", "logger.trace"),
            log("logger.debug(", "logger.debug"),
            log("logger.info(", "logger.info"),
            log("logger.warn(", "logger.warn"),
            log("logger.warning(", "logger.warning"),
            log("logger.error(", "logger.error"),
            log("logger.fatal(", "logger.fatal"),
            log("logger.log(", "logger.log"),
            log("log.trace(", "LOG.trace"),
            log("log.debug(", "LOG.debug"),
            log("log.info(", "LOG.info"),
            log("log.warn(", "LOG.warn"),
            log("log.warning(", "LOG.warning"),
            log("log.error(", "LOG.error"),
            log("log.fatal(", "LOG.fatal"),
            log("log.log(", "LOG.log"),
        ],
    },
    LangCommandSinks {
        language: "python",
        sinks: &[
            cmd("os.system(", "os.system"),
            cmd("os.popen(", "os.popen"),
            cmd_gated("subprocess.", "subprocess", &["shell=true"]),
            path("open(", "open"),
            path("os.open(", "os.open"),
            sql(".execute(", "cursor.execute"),
            sql(".executemany(", "cursor.executemany"),
            ssrf("requests.get(", "requests.get"),
            ssrf("requests.post(", "requests.post"),
            ssrf("requests.request(", "requests.request"),
            ssrf("urlopen(", "urlopen"),
            ssrf("httpx.get(", "httpx.get"),
            redirect("redirect(", "redirect"),
            redirect("httpresponseredirect(", "HttpResponseRedirect"),
            redirect("redirectresponse(", "RedirectResponse"),
            // XXE: stdlib/lxml XML parsers (defusedxml is the safe alternative).
            xxe("etree.parse(", "etree.parse", &[]),
            xxe("etree.fromstring(", "etree.fromstring", &[]),
            xxe("minidom.parse(", "minidom.parse", &[]),
            xxe("minidom.parsestring(", "minidom.parseString", &[]),
            xxe("sax.parse(", "sax.parse", &[]),
            xxe("sax.parsestring(", "sax.parseString", &[]),
            ldap(".search_s(", "ldap.search_s"),
            ldap(".search_ext_s(", "ldap.search_ext_s"),
            // import_module/__import__ take the module NAME as their argument, so a
            // tainted flow is real CWE-470. getattr/setattr were dropped: the
            // attribute name is almost always a literal (the tainted OBJECT trips
            // them) — a 200+ false-positive flood on real code.
            reflect("importlib.import_module(", "importlib.import_module"),
            reflect("__import__(", "__import__"),
            log("logging.critical(", "logging.critical"),
            log("logging.exception(", "logging.exception"),
            log("logging.warning(", "logging.warning"),
            log("logging.error(", "logging.error"),
            log("logging.debug(", "logging.debug"),
            log("logging.info(", "logging.info"),
            log("logging.warn(", "logging.warn"),
            log("logging.log(", "logging.log"),
            log_gated(
                ".critical(",
                "logger.critical",
                &["logger", "log.", "_log", "audit"],
            ),
            log_gated(
                ".exception(",
                "logger.exception",
                &["logger", "log.", "_log", "audit"],
            ),
            log_gated(
                ".warning(",
                "logger.warning",
                &["logger", "log.", "_log", "audit"],
            ),
            log_gated(
                ".error(",
                "logger.error",
                &["logger", "log.", "_log", "audit"],
            ),
            log_gated(
                ".debug(",
                "logger.debug",
                &["logger", "log.", "_log", "audit"],
            ),
            log_gated(
                ".info(",
                "logger.info",
                &["logger", "log.", "_log", "audit"],
            ),
            log_gated(
                ".warn(",
                "logger.warn",
                &["logger", "log.", "_log", "audit"],
            ),
            log_gated(".log(", "logger.log", &["logger", "log.", "_log", "audit"]),
        ],
    },
    LangCommandSinks {
        language: "perl",
        sinks: &[
            cmd("`", "backticks"),
            cmd("system(", "system"),
            cmd("system ", "system"),
            cmd("exec(", "exec"),
            cmd("exec ", "exec"),
            cmd("qx(", "qx"),
            cmd("qx{", "qx"),
            cmd("qx/", "qx"),
            path("open(", "open"),
            path("sysopen(", "sysopen"),
        ],
    },
];

/// Parameter-name substrings (case-insensitive) that mark a fuzzable/attacker
/// source. A parameter whose name contains any of these seeds taint.
///
/// Deliberately does NOT include `path` (nor `file`/`name`): a parameter named
/// `path` is a file path, but almost never *attacker-controlled* — it comes from
/// config, a constant, or a validated caller. Treating every `open(path)` /
/// `fs::read(path)` as path traversal is the classic FP flood that makes naive
/// taint tools unusable (a campaign scan of real repos produced ~100 such FPs from
/// this one marker). Genuinely attacker-controlled paths arrive via a strong
/// marker below (`user_path`, `request`, `input`) or a source API, and still fire.
pub(crate) const SOURCE_PARAM_MARKERS: &[&str] = &["input", "argv", "request", "user", "query"];

/// Per-language input-SOURCE API substrings (case-insensitive). A value assigned
/// from one of these — a request parameter, an environment variable, a CLI arg,
/// stdin — is attacker-controlled, so it seeds taint even when no parameter name
/// hints at it. This lifts the taint model from "name looks like input" to "value
/// comes from a real input channel" — the difference between a toy and a scanner
/// that finds real bugs in framework code.
pub(crate) struct LangSourceApis {
    pub language: &'static str,
    pub apis: &'static [&'static str],
}

pub(crate) const SOURCE_APIS: &[LangSourceApis] = &[
    LangSourceApis {
        language: "c",
        apis: &["getenv(", "scanf(", "fgets(", "fscanf(", "gets("],
    },
    LangSourceApis {
        language: "cpp",
        apis: &["getenv(", "scanf(", "fgets(", "std::getline(", "getline("],
    },
    LangSourceApis {
        language: "go",
        apis: &[
            "os.getenv(",
            ".formvalue(",
            ".postformvalue(",
            ".query().get(",
            "flag.string(",
            "flag.arg(",
            "r.header.get(",
            ".url.query(",
            "bufio.newreader(stdin",
        ],
    },
    LangSourceApis {
        language: "rust",
        apis: &[
            "env::var(",
            "env::var_os(",
            "env::args(",
            ".read_line(",
            "std::env::var(",
            "std::env::args(",
        ],
    },
    LangSourceApis {
        language: "java",
        apis: &[
            ".getparameter(",
            "system.getenv(",
            ".getheader(",
            ".readline(",
            ".nextline(",
            ".getquerystring(",
            "system.getproperty(",
        ],
    },
    LangSourceApis {
        language: "python",
        apis: &[
            "input(",
            "sys.argv",
            "os.environ",
            "os.getenv(",
            "request.args",
            "request.form",
            "request.form(",
            "request.values",
            "request.get.get(",
            "request.post.get(",
            "request.meta.get(",
            "request.headers.get(",
            "request.cookies.get(",
            "request.query_params.get(",
            "request.path_params.get(",
            "request.scope.get(",
            "request.get_host(",
            "request.get_full_path(",
            "request.body(",
            "request.json(",
            "request.get_json(",
            "request.cookies",
        ],
    },
    LangSourceApis {
        language: "perl",
        apis: &["$env{", "<stdin>", "param(", "$argv", "->param("],
    },
    LangSourceApis {
        language: "ada",
        apis: &[
            "command_line.argument",
            "environment_variables.value",
            "get_line",
        ],
    },
];

/// Whether `line` reads from a recognized input-source API for `language`
/// (case-insensitive), so a value it produces is attacker-controlled.
pub(crate) fn line_has_source_api(line: &str, language: &str) -> bool {
    let folded = line.to_ascii_lowercase();
    SOURCE_APIS
        .iter()
        .find(|s| s.language == language)
        .is_some_and(|spec| spec.apis.iter().any(|api| folded.contains(api)))
}

/// Substrings on an assignment right-hand side (case-insensitive) that clear taint
/// — a value produced by one of these is treated as sanitized. Covers explicit
/// project sanitizers plus the language-standard shell-argument quoters.
pub(crate) const SANITIZER_MARKERS: &[&str] = &[
    "sanitize(",
    "sanitize_",
    "escaped_",
    "escape_shell",
    "shell_quote",
    "validated_",
    "validate(",
    "get_redirect_url(",
    // Language-standard shell-argument quoting (clears command-injection taint):
    "shlex.quote(", // Python 3
    "shlex_quote(",
    "quote_plus(",  // urllib
    "pipes.quote(", // Python 2
    "shellescape",  // Perl String::ShellQuote / shell-quote
    "shell_escape",
    // Library summaries (#6): a value ENCODED to an alphanumeric/percent form, or
    // regex-escaped / converted to a number, can carry no shell/path/SQL
    // metacharacter, so it universally sanitizes the injection sinks the engine
    // checks. Only distinctive, unambiguous names — NOT `html.escape` (which
    // leaves shell metacharacters intact and would cause a false negative).
    "base64.b64encode(",
    "base64.encodebytes(",
    "base64.encodetostring(", // Go encoding/base64
    "base64.urlsafe_b64encode(",
    "hex.encodetostring(", // Go encoding/hex
    "binascii.hexlify(",
    "url.queryescape(", // Go net/url
    "url.pathescape(",
    "re.escape(",        // Python regex escaping
    "regexp.quotemeta(", // Go
    "preg_quote(",       // Perl/PHP
    "strconv.itoa(",     // Go int -> string (numeric, injection-safe)
];

/// The taint sink matched on `line` for `language`. Case-insensitive; returns the
/// first matching sink (most-specific first). The caller uses `sink.needle` to
/// locate the column and `sink.rule_id`/`cwe` to emit the right finding.
pub(crate) fn matched_taint_sink(line: &str, language: &str) -> Option<&'static TaintSink> {
    let folded = line.to_ascii_lowercase();
    let spec = COMMAND_SINKS.iter().find(|s| s.language == language)?;
    spec.sinks.iter().find(|candidate| {
        needle_present(line, &folded, candidate.needle)
            && (candidate.requires_any.is_empty()
                || candidate
                    .requires_any
                    .iter()
                    .any(|needle| folded.contains(needle)))
    })
}

/// Whether `needle` occurs in `folded` as a real call, not a substring of a longer
/// name or a method on a receiver. A needle that starts with an identifier char (a
/// BARE function like `open(`/`system(`) must sit at a word boundary — the char
/// before it must not be an identifier char or `.` — so `path.open()` (pathlib
/// method) and `mysystem()` do NOT match the builtin `open(`/`system(` sinks. A
/// needle that already starts with `.` / a qualifier (`.exec(`, `os.system(`,
/// `exec.command(`) is matched verbatim (those ARE method/qualified calls).
fn needle_present(line: &str, folded: &str, needle: &str) -> bool {
    let starts_bare = needle
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    if !starts_bare {
        return folded
            .match_indices(needle)
            .any(|(index, _)| byte_index_is_code(line, index));
    }
    folded.match_indices(needle).any(|(index, _)| {
        if !byte_index_is_code(line, index) {
            return false;
        }
        folded[..index]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
    })
}

fn byte_index_is_code(line: &str, index: usize) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_backslash = false;
    for (i, byte) in line.bytes().enumerate() {
        if i >= index {
            break;
        }
        if !in_double && byte == b'\'' && !prev_backslash {
            in_single = !in_single;
        } else if !in_single && byte == b'"' && !prev_backslash {
            in_double = !in_double;
        }
        prev_backslash = byte == b'\\' && !prev_backslash;
    }
    !in_single && !in_double
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every interprocedural-taint language has a command-sink spec (a missing
    /// entry silently drops that lane's GF-304 detection).
    #[test]
    fn every_taint_language_has_a_spec() {
        for language in ["ada", "c", "cpp", "go", "rust", "java", "python", "perl"] {
            assert!(
                COMMAND_SINKS.iter().any(|s| s.language == language),
                "no command-sink spec for {language}"
            );
        }
    }

    /// Sink needles are lowercase (matching is case-insensitive over a folded line);
    /// a mixed-case needle would never match.
    #[test]
    fn sink_needles_are_lowercase() {
        for spec in COMMAND_SINKS {
            for candidate in spec.sinks {
                assert_eq!(
                    candidate.needle,
                    candidate.needle.to_ascii_lowercase(),
                    "{}: needle {:?} must be lowercase",
                    spec.language,
                    candidate.needle
                );
                for gate in candidate.requires_any {
                    assert_eq!(
                        *gate,
                        gate.to_ascii_lowercase(),
                        "{}: gate {gate:?} must be lowercase",
                        spec.language
                    );
                }
            }
        }
    }

    /// Case-insensitive matching + the gate semantics (Java `.exec` needs Runtime;
    /// Python `subprocess` needs shell=True), and each sink's rule class.
    #[test]
    fn matches_case_insensitively_and_honors_gates() {
        let sink = matched_taint_sink("Runtime.getRuntime().exec(x)", "java").unwrap();
        assert_eq!((sink.display, sink.rule_id), ("Runtime.exec", "GF-304"));
        // `.exec(` without a Runtime receiver (e.g. a JDBC statement) is not a sink.
        assert!(matched_taint_sink("stmt.exec(sql)", "java").is_none());
        // subprocess needs shell=True.
        assert_eq!(
            matched_taint_sink("subprocess.run(x, shell=True)", "python")
                .unwrap()
                .display,
            "subprocess"
        );
        assert!(matched_taint_sink("subprocess.run([x])", "python").is_none());
        // Most-specific needle wins.
        assert_eq!(
            matched_taint_sink("exec.CommandContext(ctx, x)", "go")
                .unwrap()
                .display,
            "exec.CommandContext"
        );
    }

    /// Multi-class sinks (#486 best-in-class): path-open and SQL sinks carry their
    /// own rule class alongside command injection.
    #[test]
    fn multi_class_sinks_carry_their_rule() {
        assert_eq!(
            matched_taint_sink("os.Open(p)", "go").unwrap().rule_id,
            "GF-405"
        );
        let sql = matched_taint_sink("stmt.executeQuery(q)", "java").unwrap();
        assert_eq!((sql.rule_id, sql.needs_dynamic_string), ("GF-419", true));
    }

    /// A bare-function sink (`open(`) matches the builtin at a word boundary but
    /// NOT a method (`path.open(`) or a longer name (`myopen(`); a method/qualified
    /// sink (`.query(`, `os.system(`) matches verbatim.
    #[test]
    fn bare_sinks_require_a_word_boundary() {
        // Builtin open -> path sink; pathlib method + longer name -> not.
        assert!(matched_taint_sink("open(p)", "python").is_some());
        assert!(matched_taint_sink("path.open(p)", "python").is_none());
        assert!(matched_taint_sink("reopen(p)", "python").is_none());
        // Method/qualified sinks still match as before.
        assert!(matched_taint_sink("cursor.execute(\"...\" + q)", "python").is_some());
    }

    /// Input-source APIs are recognized case-insensitively per language.
    #[test]
    fn source_apis_recognized_per_language() {
        assert!(line_has_source_api("c := os.Getenv(\"X\")", "go"));
        assert!(line_has_source_api(
            "String p = req.getParameter(\"q\")",
            "java"
        ));
        assert!(line_has_source_api("cmd = os.environ['X']", "python"));
        assert!(line_has_source_api("let v = std::env::var(\"X\")", "rust"));
        // A plain local assignment is not a source.
        assert!(!line_has_source_api("x = y + 1", "go"));
    }
}
