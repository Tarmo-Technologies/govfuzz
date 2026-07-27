// SPDX-License-Identifier: Apache-2.0

//! Generate a govfuzz-native Java fuzzing harness: a tiny class exposing
//!
//! ```ignore
//! public static void govfuzzRunOne(byte[] govfuzzInput) { ... }
//! ```
//!
//! which decodes the raw fuzz bytes into typed arguments via the dependency-free
//! `com.govfuzz.GovfuzzData` cursor (the JVM analog of `rust_runtime::Cursor`) and
//! calls the target. Compiled against the target's classpath and run by
//! `com.govfuzz.Driver` under govfuzz's own JVM coverage agent, the engine drives
//! it over the persistent `GOVFUZZ_FRAMED` fork-server protocol — no Jazzer.
//!
//! Locals are declared with `var` so the harness needs no target-specific imports
//! (the decode expressions are fully qualified). The exception/noise policy lives
//! in the Driver (runtime class inspection), so the harness has no try/catch.

use java_parser::{JavaMethod, JavaTypeModel};

/// The fixed package + class the harness is emitted into.
pub const HARNESS_PACKAGE: &str = "govfuzzgen";
pub const HARNESS_CLASS: &str = "Harness";

/// Inputs to Java harness generation for a direct (single-method) target.
#[derive(Debug, Clone)]
pub struct GenerateJavaDirectArgs {
    /// Source-form fully-qualified class to call, e.g. `com.acme.JsonParser`.
    pub target_class: String,
    /// The target method/constructor signature, from `java_parser`.
    pub target: JavaMethod,
    /// For an INSTANCE method, the receiver-construction expression (e.g.
    /// `new com.acme.JsonParser()`) resolved from a no-arg constructor; the harness
    /// does `var recv = <receiver>; recv.method(args)`. `None` for a static method
    /// or constructor, or when no no-arg constructor is reachable (the instance
    /// method is then rejected).
    pub receiver: Option<String>,
    /// Fully-qualified names of `enum` types declared in the scanned tree (from
    /// `java_parser::parse_java_enum_types`). An enum-typed parameter is decoded as
    /// a fuzz-byte-indexed `values()` pick instead of being rejected. Empty when no
    /// enum is in scope.
    pub enum_types: Vec<String>,
    /// Models of the custom (class/enum) types that appear as the target's
    /// parameters, resolved from their declarations across the scanned tree (from
    /// `java_parser::parse_java_type_models`). When a parameter is neither a scalar
    /// nor a known byte channel, the generator synthesises a *default* instance from
    /// the matching model (`CSVFormat.DEFAULT`, `new Cfg()`, a no-arg factory,
    /// `Enum.values()[0]`) so a config-object parameter stops blocking the target.
    /// Empty when the target has no such parameter.
    pub param_types: Vec<JavaTypeModel>,
    /// True when the target's own class is an `abstract class` / `interface`
    /// (resolved by `java_parser::parse_java_abstract_types`). The generator must
    /// then NEVER emit `new <class>(...)` — a CONSTRUCTOR target of an abstract type
    /// is rejected as a clean skip (javac: "<T> is abstract; cannot be
    /// instantiated"). An instance method is already gated upstream: its `receiver`
    /// is resolved to a factory/builder or left `None` for an abstract receiver.
    pub target_class_is_abstract: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedJavaHarness {
    /// The harness `.java` source.
    pub harness_java: String,
    /// The harness's fully-qualified class name, e.g. `govfuzzgen.Harness`.
    pub harness_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaGenerateError {
    pub reason: String,
}

impl std::fmt::Display for JavaGenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Generate a harness for a static method or a constructor. An instance method
/// (needs a constructed receiver) and an abstract method are rejected — a clean
/// skip, mirroring the Rust lane's `&self`/generic rejection.
pub fn generate_java_direct_harness(
    args: &GenerateJavaDirectArgs,
) -> Result<GeneratedJavaHarness, JavaGenerateError> {
    let t = &args.target;
    if t.is_abstract {
        return Err(JavaGenerateError {
            reason: format!(
                "Java target '{}' is abstract (no body); not auto-harnessable",
                t.name
            ),
        });
    }
    // A CONSTRUCTOR of an abstract class / interface can't be `new`'d: emitting
    // `new <class>(...)` is javac error "<class> is abstract; cannot be
    // instantiated". Skip cleanly instead of generating an uncompilable harness.
    if t.is_constructor && args.target_class_is_abstract {
        return Err(JavaGenerateError {
            reason: format!(
                "Java target '{}' constructs the abstract class/interface '{}', which \
                 cannot be instantiated; not auto-harnessable",
                t.name, args.target_class
            ),
        });
    }
    if !t.is_static && !t.is_constructor && args.receiver.is_none() {
        return Err(JavaGenerateError {
            reason: format!(
                "Java target '{}' is an instance method and no no-arg constructor was \
                 found to build a receiver; not auto-harnessable",
                t.name
            ),
        });
    }

    // The LAST byte-channel parameter consumes the rest of the input; the others
    // take a length-bounded slice so they don't all claim the whole buffer.
    let rest_idx = t
        .params
        .iter()
        .enumerate()
        .rev()
        .find(|(_, p)| is_byte_channel(&p.ty))
        .map(|(i, _)| i);

    let mut decls = Vec::new();
    let mut call_args = Vec::new();
    for (i, p) in t.params.iter().enumerate() {
        // An enum-typed parameter decodes as a fuzz-byte-indexed `values()` pick
        // (referenced by FQN so it resolves regardless of imports); otherwise fall
        // back to the type-based decoder.
        // A JDK decode mapping resolves by LEAF name (`File`, `Path`, `Writer`),
        // which is not exclusive to the JDK: a tree that declares its own `Path`
        // — `android.graphics.Path` is the common one — would get a
        // `java.nio.file.Path` expression and fail to COMPILE, turning a clean
        // skip into a failed build. When the scanned tree owns the name, its own
        // model wins.
        let tree_owns_the_name = type_model_for(&p.ty, &args.param_types).is_some();
        let expr = if let Some(fqn) = enum_fqn_for(&p.ty, &args.enum_types) {
            format!("{fqn}.values()[Math.floorMod(c.consumeInt(), {fqn}.values().length)]")
        } else if let Some(e) = (!tree_owns_the_name)
            .then(|| decode_expr(&p.ty, Some(i) == rest_idx))
            .flatten()
        {
            e
        } else if let Some(e) = custom_type_expr(&p.ty, &args.param_types) {
            // A custom class/enum config parameter: synthesise a fixed default
            // instance so the target's real fuzzable params still get driven.
            e
        } else {
            return Err(JavaGenerateError {
                reason: format!(
                    "Java target '{}' parameter #{i} has an unsupported type `{}`",
                    t.name, p.ty
                ),
            });
        };
        decls.push(format!("        var a{i} = {expr};"));
        call_args.push(format!("a{i}"));
    }

    let arglist = call_args.join(", ");
    let call = if t.is_constructor {
        format!("new {}({arglist})", args.target_class)
    } else if t.is_static {
        format!("{}.{}({arglist})", args.target_class, t.name)
    } else {
        // Instance method: construct a receiver via the resolved no-arg ctor, then
        // call on it. `receiver` is guaranteed Some here (checked above).
        let recv = args.receiver.as_deref().unwrap_or("null");
        format!(
            "var govfuzzRecv = {recv}; govfuzzRecv.{}({arglist})",
            t.name
        )
    };

    let harness_java = render_harness(&decls, &call);
    Ok(GeneratedJavaHarness {
        harness_java,
        harness_class: format!("{HARNESS_PACKAGE}.{HARNESS_CLASS}"),
    })
}

fn render_harness(decls: &[String], call: &str) -> String {
    let body = if decls.is_empty() {
        format!("        {call};\n")
    } else {
        format!("{}\n        {call};\n", decls.join("\n"))
    };
    let helpers = if body.contains(TEMP_FILE_CALL) {
        TEMP_FILE_HELPER
    } else {
        ""
    };
    format!(
        "// SPDX-License-Identifier: Apache-2.0\n\
         // GENERATED by govfuzz harness_gen::java_generate. Do not edit.\n\
         package {HARNESS_PACKAGE};\n\
         \n\
         public final class {HARNESS_CLASS} {{\n\
         {helpers}\
         \x20   /** Decode-and-call entry the govfuzz JVM driver invokes per input.\n\
         \x20    *  Declares `throws Throwable` so a target's CHECKED exceptions\n\
         \x20    *  (IOException, ParseException, DecoderException, …) compile and\n\
         \x20    *  propagate to the Driver, which applies the finding/noise policy. */\n\
         \x20   public static void govfuzzRunOne(byte[] govfuzzInput) throws Throwable {{\n\
         \x20       com.govfuzz.GovfuzzData c = new com.govfuzz.GovfuzzData(govfuzzInput);\n\
         {body}\
         \x20   }}\n\
         }}\n"
    )
}

/// Erase generic arguments (`Class<?>[]` -> `Class[]`, `List<String>` -> `List`)
/// by dropping everything between balanced angle brackets.
fn strip_java_generics(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0i32;
    for ch in s.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = (depth - 1).max(0),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

/// If parameter type `ty` names a known enum, the enum's fully-qualified name to
/// decode against. Matches a written type — simple (`Status`), qualified
/// (`com.acme.Status`), or generic-bounded — against each enum FQN by leaf name,
/// so a same-package simple reference still resolves to the FQN the harness emits.
fn enum_fqn_for<'a>(ty: &str, enum_types: &'a [String]) -> Option<&'a str> {
    let bare = strip_java_generics(&ty.replace(' ', ""));
    // Arrays/varargs and obvious non-class spellings aren't enum values.
    if bare.contains(['[', '<', '>']) {
        return None;
    }
    let leaf = bare.rsplit('.').next().unwrap_or(&bare);
    enum_types.iter().find_map(|fqn| {
        let fqn_leaf = fqn.rsplit('.').next().unwrap_or(fqn);
        // Exact FQN match, or a leaf match when the param is written unqualified.
        if fqn == &bare || (!bare.contains('.') && fqn_leaf == leaf) {
            Some(fqn.as_str())
        } else {
            None
        }
    })
}

/// Synthesise a *default* instance expression for a custom (class/enum) parameter
/// type `ty`, from the matching declaration model (F8). Returns `None` when no
/// model matches or none of the construction strategies apply, so the caller keeps
/// the existing clean skip. The strategies, in priority order:
///   1. **enum**            -> `T.values()[0]` (deterministic first constant)
///   2. **static final T**  -> `T.DEFAULT` (or the first such constant)
///   3. **no-arg ctor**     -> `new T()`
///   4. **no-arg factory**  -> `T.create()` / `T.getDefault()` / …
///
/// Every emitted expression is a fixed, non-fuzzed config object — its job is to
/// UNBLOCK the target so the real fuzzable params get driven (mirrors the Rust
/// `&T`-via-`Default` lane).
fn custom_type_expr(ty: &str, models: &[JavaTypeModel]) -> Option<String> {
    construct_from_model(type_model_for(ty, models)?)
}

/// The model whose type matches the written parameter type `ty` (by exact FQN, or
/// by leaf name when `ty` is written unqualified). Mirrors [`enum_fqn_for`]'s
/// matching; arrays/generics-only spellings don't match a constructible type.
fn type_model_for<'a>(ty: &str, models: &'a [JavaTypeModel]) -> Option<&'a JavaTypeModel> {
    let bare = strip_java_generics(&ty.replace(' ', ""));
    if bare.contains(['[', '<', '>']) {
        return None;
    }
    let leaf = bare.rsplit('.').next().unwrap_or(&bare);
    models.iter().find(|m| {
        let fqn_leaf = m.fqn.rsplit('.').next().unwrap_or(&m.fqn);
        m.fqn == bare || (!bare.contains('.') && fqn_leaf == leaf)
    })
}

/// Pick a construction expression for a resolved type model, or `None` when no
/// strategy applies (the parameter then keeps skipping).
fn construct_from_model(m: &JavaTypeModel) -> Option<String> {
    let fqn = &m.fqn;
    // 1. Enum: deterministic first constant.
    if m.is_enum {
        return Some(format!("{fqn}.values()[0]"));
    }
    // 2. Public `static final T` field — the immutable-config idiom. Prefer a
    //    `DEFAULT` constant, else the first declared one (deterministic).
    if let Some(c) = m
        .self_constants
        .iter()
        .find(|c| c.as_str() == "DEFAULT")
        .or_else(|| m.self_constants.first())
    {
        return Some(format!("{fqn}.{c}"));
    }
    // 3. Public no-arg constructor.
    if m.has_public_no_arg_ctor {
        return Some(format!("new {fqn}()"));
    }
    // 4. Public static no-arg factory returning T. Prefer a conventional name,
    //    else the first declared (deterministic).
    if let Some(f) = pick_factory(&m.no_arg_self_factories) {
        return Some(format!("{fqn}.{f}()"));
    }
    None
}

/// Choose a no-arg factory by a stable preference, falling back to source order.
fn pick_factory(factories: &[String]) -> Option<&str> {
    const PREFERRED: &[&str] = &[
        "getDefault",
        "defaultInstance",
        "getInstance",
        "newInstance",
        "create",
        "of",
        "valueOf",
        "from",
    ];
    for name in PREFERRED {
        if let Some(f) = factories.iter().find(|f| f.as_str() == *name) {
            return Some(f.as_str());
        }
    }
    factories.first().map(String::as_str)
}

/// The decode expression for a Java parameter type. `is_rest` true means this is
/// the chosen rest channel (consumes the remaining bytes); false means a
/// length-bounded read. `None` for an unsupported type.
fn decode_expr(ty: &str, is_rest: bool) -> Option<String> {
    let t = ty.replace(' ', "");
    if t == "byte[]" {
        return Some(if is_rest {
            "c.consumeRemainingAsBytes()".to_owned()
        } else {
            "c.consumeBytes(64)".to_owned()
        });
    }
    if t == "char[]" {
        // A char[] byte channel (e.g. Hex.decodeHex(char[])): decode the bytes as
        // a UTF-8 string, then to chars.
        return Some(if is_rest {
            "c.consumeRemainingAsString().toCharArray()".to_owned()
        } else {
            "c.consumeString(64).toCharArray()".to_owned()
        });
    }
    // Reflection array params (`MethodUtils.invokeExactMethod(Object, String,
    // Object[], Class<?>[])`): a single-element array drives the API. Generics are
    // stripped so the array-creation type is raw (`new Class[]{...}` is legal,
    // `new Class<?>[]{...}` is not).
    let t_no_generics = strip_java_generics(&t);
    if let Some(elem) = t_no_generics.strip_suffix("[]") {
        let elem_leaf = elem.rsplit('.').next().unwrap_or(elem);
        match elem_leaf {
            "Object" => {
                return Some(
                    "new Object[]{ (c.consumeBoolean() ? (Object) c.consumeString(64) : \
                     (Object) java.lang.Integer.valueOf(c.consumeInt())) }"
                        .to_owned(),
                )
            }
            "Class" => return Some("new Class[]{ String.class }".to_owned()),
            "String" | "CharSequence" => {
                return Some("new String[]{ c.consumeString(64) }".to_owned())
            }
            _ => {} // other element types fall through to the unsupported path
        }
    }
    // Strip generic args (`Class<T>` -> `Class`, `java.lang.Class<?>` -> `Class`)
    // before resolving the leaf type name.
    let base = t.split('<').next().unwrap_or(&t);
    let leaf = base.rsplit('.').next().unwrap_or(base);
    let expr = match leaf {
        "String" | "CharSequence" => {
            if is_rest {
                "c.consumeRemainingAsString()"
            } else {
                "c.consumeString(64)"
            }
        }
        // A `java.lang.Object` param: pick a concrete value by a fuzz byte
        // (String / byte[] / Integer) so reflection/deserialization APIs like
        // `MethodUtils.invokeExactMethod(Object, ...)` become drivable.
        "Object" => {
            if is_rest {
                "(c.consumeBoolean() ? (Object) c.consumeRemainingAsString() : \
                 (c.consumeBoolean() ? (Object) c.consumeRemainingAsBytes() : \
                 (Object) java.lang.Integer.valueOf(c.consumeInt())))"
            } else {
                "(c.consumeBoolean() ? (Object) c.consumeString(64) : \
                 (c.consumeBoolean() ? (Object) c.consumeBytes(64) : \
                 (Object) java.lang.Integer.valueOf(c.consumeInt())))"
            }
        }
        // A `Class<T>` reflection/deserialization-target param: the generic type
        // can't be instantiated, so pass a safe concrete class literal. Satisfies
        // APIs like `fromJson(json, Class<T>)` without needing the real type.
        "Class" => "String.class",
        // `java.text.ParsePosition`: a mutable index carrier seeded from a fuzz int.
        "ParsePosition" => "new java.text.ParsePosition(c.consumeInt())",
        "InputStream" | "DataInputStream" => {
            "new java.io.ByteArrayInputStream(c.consumeRemainingAsBytes())"
        }
        "ByteBuffer" => "java.nio.ByteBuffer.wrap(c.consumeRemainingAsBytes())",
        // A file-shaped parameter is the classic Java parse entry point
        // (`ImageIO.read(File)`, `CSVParser.parse(File, …)`, `new ZipFile(File)`)
        // and it IS a byte channel — the fuzz bytes just reach the target through
        // the filesystem. One temp file is reused for the life of the process and
        // rewritten per input; see `TEMP_FILE_HELPER`. A `file:` URI/URL is the
        // same channel for APIs that load by locator, and never touches a network.
        "File" => return Some(temp_file_expr(is_rest, "")),
        "Path" if base == "java.nio.file.Path" => {
            return Some(temp_file_expr(is_rest, ".toPath()"))
        }
        "URI" => return Some(temp_file_expr(is_rest, ".toURI()")),
        "URL" => return Some(temp_file_expr(is_rest, ".toURI().toURL()")),
        // Output sinks carry nothing INTO the target, so a fresh empty one is
        // always a correct argument — and refusing them blocked otherwise
        // fuzzable formatters and serializers on a parameter that cannot
        // influence the result.
        "OutputStream" | "ByteArrayOutputStream" => "new java.io.ByteArrayOutputStream()",
        "PrintStream" => "new java.io.PrintStream(new java.io.ByteArrayOutputStream())",
        "Writer" | "StringWriter" => "new java.io.StringWriter()",
        "PrintWriter" => "new java.io.PrintWriter(new java.io.StringWriter())",
        "Appendable" | "StringBuilder" | "StringBuffer" => "new StringBuilder()",
        // Reflection and resource-loading APIs take the loader that already has
        // the target on its classpath — which is the harness's own.
        "ClassLoader" => "Thread.currentThread().getContextClassLoader()",
        // Common JDK config types: a safe, conservative default so APIs that take
        // them (e.g. `CSVParser.parse(File, Charset, CSVFormat)`) become fuzzable.
        "Charset" => "java.nio.charset.StandardCharsets.UTF_8",
        "Locale" => "java.util.Locale.ROOT",
        "TimeZone" => "java.util.TimeZone.getTimeZone(\"UTC\")",
        "Reader" | "InputStreamReader" | "BufferedReader" => {
            "new java.io.InputStreamReader(new java.io.ByteArrayInputStream(\
             c.consumeRemainingAsBytes()), java.nio.charset.StandardCharsets.UTF_8)"
        }
        "int" | "Integer" => "c.consumeInt()",
        "long" | "Long" => "c.consumeLong()",
        "short" | "Short" => "c.consumeShort()",
        "byte" | "Byte" => "c.consumeByte()",
        "boolean" | "Boolean" => "c.consumeBoolean()",
        "char" | "Character" => "c.consumeChar()",
        "double" | "Double" => "c.consumeDouble()",
        "float" | "Float" => "c.consumeFloat()",
        _ => return None,
    };
    Some(expr.to_owned())
}

/// The call that materializes this input as a file, with `suffix` converting the
/// resulting `File` to whatever the parameter actually wants.
fn temp_file_expr(is_rest: bool, suffix: &str) -> String {
    let bytes = if is_rest {
        "c.consumeRemainingAsBytes()"
    } else {
        "c.consumeBytes(4096)"
    };
    format!("govfuzzFileOf({bytes}){suffix}")
}

/// The name the file-channel decode expressions call. Emitted into the harness
/// only when something references it, so an unused private method never appears.
const TEMP_FILE_CALL: &str = "govfuzzFileOf(";

/// A per-PROCESS temp file, rewritten for each input.
///
/// A fresh file per execution would leave one behind per iteration — millions
/// over a campaign — so the file is created once and truncated on every write.
/// `deleteOnExit` covers the ordinary end of the run, and a persistent-mode fuzz
/// process reuses the same path for its whole life.
const TEMP_FILE_HELPER: &str = concat!(
    "\x20   /** Materialize this input as a file so a File/Path/URI parameter is a\n",
    "\x20    *  real byte channel. One file per process, truncated per input. */\n",
    "\x20   private static java.io.File govfuzzTempFile;\n",
    "\x20   private static java.io.File govfuzzFileOf(byte[] bytes) throws java.io.IOException {\n",
    "\x20       if (govfuzzTempFile == null) {\n",
    "\x20           govfuzzTempFile = java.io.File.createTempFile(\"govfuzz-input\", \".bin\");\n",
    "\x20           govfuzzTempFile.deleteOnExit();\n",
    "\x20       }\n",
    "\x20       try (java.io.FileOutputStream out = new java.io.FileOutputStream(govfuzzTempFile)) {\n",
    "\x20           out.write(bytes);\n",
    "\x20       }\n",
    "\x20       return govfuzzTempFile;\n",
    "\x20   }\n",
);

/// Public, bounded (non-rest) decode expression for a single parameter type, or
/// `None` for a reference type the cursor can't synthesise. The CLI Java lane
/// uses this to fabricate constructor/factory arguments when synthesising a
/// receiver (#459); a `None` is its cue to pass `null`.
pub fn decode_param_expr(ty: &str) -> Option<String> {
    decode_expr(ty, false)
}

/// Whether a parameter type is an attacker byte channel (so it should win the rest
/// channel). Mirrors `target_rank::java_rank::is_byte_channel_type` but also counts
/// scalar-less byte sources.
fn is_byte_channel(ty: &str) -> bool {
    let t = ty.replace(' ', "");
    if t == "byte[]" || t == "char[]" {
        return true;
    }
    let leaf = t.rsplit('.').next().unwrap_or(&t);
    matches!(
        leaf,
        "String"
            | "CharSequence"
            | "ByteBuffer"
            | "InputStream"
            | "DataInputStream"
            | "Reader"
            | "InputStreamReader"
            | "BufferedReader"
            // The file channel carries the input just as directly as a stream —
            // it must be able to win the rest channel, or a `parse(File)` target
            // would only ever see a bounded prefix.
            | "File"
            | "URI"
            | "URL"
    ) || t == "java.nio.file.Path"
}

#[cfg(test)]
mod tests {
    use super::*;
    use java_parser::{JavaParam, JavaVisibility};

    #[test]
    fn a_file_parameter_is_a_byte_channel_backed_by_one_reused_temp_file() {
        // A File param takes the rest channel, like any other byte channel.
        assert!(is_byte_channel("java.io.File"));
        assert_eq!(
            decode_expr("java.io.File", true).as_deref(),
            Some("govfuzzFileOf(c.consumeRemainingAsBytes())")
        );
        // …and the locator forms reach the same file without a network.
        assert_eq!(
            decode_expr("java.net.URI", true).as_deref(),
            Some("govfuzzFileOf(c.consumeRemainingAsBytes()).toURI()")
        );
        assert_eq!(
            decode_expr("java.nio.file.Path", false).as_deref(),
            Some("govfuzzFileOf(c.consumeBytes(4096)).toPath()")
        );
        // `Path` is only the JDK one when it says so: a tree's own `Path`
        // (android.graphics.Path is the common one) must not be handed a file.
        assert_eq!(decode_expr("Path", false), None);

        // The helper appears exactly when something calls it — and creates ONE
        // file for the process, not one per execution.
        let harness = render_harness(
            &["        var a0 = govfuzzFileOf(c.consumeRemainingAsBytes());".to_owned()],
            "com.acme.P.parse(a0)",
        );
        assert!(harness.contains("createTempFile"), "{harness}");
        assert!(harness.contains("deleteOnExit"), "{harness}");
        assert!(
            harness.contains("if (govfuzzTempFile == null)"),
            "the file must be created once, not per input: {harness}"
        );
        // An unrelated harness carries no dead helper.
        let plain = render_harness(
            &["        var a0 = c.consumeRemainingAsBytes();".to_owned()],
            "com.acme.P.parse(a0)",
        );
        assert!(!plain.contains("govfuzzFileOf"), "{plain}");
    }

    #[test]
    fn an_output_sink_parameter_stops_blocking_the_target() {
        // A sink carries nothing INTO the target, so a fresh empty one is always
        // a correct argument — and is not a byte channel competing for the rest.
        for (ty, expected) in [
            (
                "java.io.OutputStream",
                "new java.io.ByteArrayOutputStream()",
            ),
            ("Writer", "new java.io.StringWriter()"),
            (
                "java.io.PrintWriter",
                "new java.io.PrintWriter(new java.io.StringWriter())",
            ),
            ("StringBuilder", "new StringBuilder()"),
            (
                "ClassLoader",
                "Thread.currentThread().getContextClassLoader()",
            ),
        ] {
            assert_eq!(decode_expr(ty, true).as_deref(), Some(expected), "{ty}");
            assert!(!is_byte_channel(ty), "{ty} must not claim the rest channel");
        }
    }

    /// A JDK mapping resolves by LEAF name, which the JDK does not own. When the
    /// scanned tree declares the name itself, its own model must win — otherwise
    /// the harness emits a `java.nio.file.Path` for an `android.graphics.Path`
    /// and a clean skip becomes a build failure.
    #[test]
    fn a_tree_declared_type_wins_over_a_same_named_jdk_mapping() {
        let target = JavaMethod {
            name: "draw".to_owned(),
            params: vec![java_parser::JavaParam {
                name: "p".to_owned(),
                ty: "Path".to_owned(),
            }],
            is_static: true,
            is_constructor: false,
            is_abstract: false,
            ..Default::default()
        };
        let args = GenerateJavaDirectArgs {
            target_class: "com.acme.Canvas".to_owned(),
            target,
            receiver: None,
            enum_types: Vec::new(),
            param_types: vec![JavaTypeModel {
                fqn: "android.graphics.Path".to_owned(),
                has_public_no_arg_ctor: true,
                ..Default::default()
            }],
            target_class_is_abstract: false,
        };
        let out = generate_java_direct_harness(&args).expect("tree-owned Path is constructible");
        assert!(
            out.harness_java.contains("new android.graphics.Path()"),
            "the tree's own type must be constructed: {}",
            out.harness_java
        );
        assert!(
            !out.harness_java.contains("govfuzzFileOf"),
            "the JDK file channel must not hijack a same-named project type: {}",
            out.harness_java
        );
    }

    #[test]
    fn decode_expr_synthesizes_object_class_and_parseposition() {
        // Object: a fuzz-byte-chosen concrete value cast to Object.
        let obj = decode_expr("java.lang.Object", true).expect("Object is supported");
        assert!(obj.contains("(Object)"), "{obj}");
        assert!(obj.contains("consumeRemainingAsString"), "{obj}");
        // Class<T> (generics stripped): a safe concrete class literal.
        assert_eq!(
            decode_expr("Class<T>", false).as_deref(),
            Some("String.class")
        );
        assert_eq!(
            decode_expr("java.lang.Class<?>", false).as_deref(),
            Some("String.class")
        );
        // ParsePosition: a fresh instance seeded from a fuzz int.
        assert_eq!(
            decode_expr("java.text.ParsePosition", false).as_deref(),
            Some("new java.text.ParsePosition(c.consumeInt())")
        );
        // Reflection array params: a single-element raw array (generics stripped).
        assert_eq!(
            decode_expr("Object[]", false)
                .as_deref()
                .map(|s| s.starts_with("new Object[]{")),
            Some(true)
        );
        assert_eq!(
            decode_expr("Class<?>[]", false).as_deref(),
            Some("new Class[]{ String.class }")
        );
    }

    fn method(name: &str, params: &[(&str, &str)], is_static: bool, is_ctor: bool) -> JavaMethod {
        JavaMethod {
            name: name.to_owned(),
            line: 1,
            return_type: None,
            params: params
                .iter()
                .map(|(n, t)| JavaParam {
                    name: (*n).to_owned(),
                    ty: (*t).to_owned(),
                })
                .collect(),
            is_static,
            visibility: JavaVisibility::Public,
            enclosing_public: true,
            package: Some("com.acme".to_owned()),
            class_path: vec!["JsonParser".to_owned()],
            is_constructor: is_ctor,
            is_abstract: false,
            is_fuzz_entry: false,
            throws: Vec::new(),
        }
    }

    fn gen(target_class: &str, m: JavaMethod) -> Result<GeneratedJavaHarness, JavaGenerateError> {
        generate_java_direct_harness(&GenerateJavaDirectArgs {
            target_class: target_class.to_owned(),
            target: m,
            receiver: None,
            enum_types: Vec::new(),
            param_types: Vec::new(),
            target_class_is_abstract: false,
        })
    }

    fn gen_with_enums(
        target_class: &str,
        m: JavaMethod,
        enum_types: &[&str],
    ) -> Result<GeneratedJavaHarness, JavaGenerateError> {
        generate_java_direct_harness(&GenerateJavaDirectArgs {
            target_class: target_class.to_owned(),
            target: m,
            receiver: None,
            enum_types: enum_types.iter().map(|s| (*s).to_owned()).collect(),
            param_types: Vec::new(),
            target_class_is_abstract: false,
        })
    }

    fn gen_with_models(
        target_class: &str,
        m: JavaMethod,
        param_types: Vec<JavaTypeModel>,
    ) -> Result<GeneratedJavaHarness, JavaGenerateError> {
        generate_java_direct_harness(&GenerateJavaDirectArgs {
            target_class: target_class.to_owned(),
            target: m,
            receiver: None,
            enum_types: Vec::new(),
            param_types,
            target_class_is_abstract: false,
        })
    }

    fn gen_recv(
        target_class: &str,
        m: JavaMethod,
        receiver: &str,
    ) -> Result<GeneratedJavaHarness, JavaGenerateError> {
        generate_java_direct_harness(&GenerateJavaDirectArgs {
            target_class: target_class.to_owned(),
            target: m,
            receiver: Some(receiver.to_owned()),
            enum_types: Vec::new(),
            param_types: Vec::new(),
            target_class_is_abstract: false,
        })
    }

    fn gen_ctor_abstract(
        target_class: &str,
        m: JavaMethod,
    ) -> Result<GeneratedJavaHarness, JavaGenerateError> {
        generate_java_direct_harness(&GenerateJavaDirectArgs {
            target_class: target_class.to_owned(),
            target: m,
            receiver: None,
            enum_types: Vec::new(),
            param_types: Vec::new(),
            target_class_is_abstract: true,
        })
    }

    #[test]
    fn enum_param_decodes_as_values_index() {
        // A param whose type is a known enum (matched by leaf name when written
        // unqualified) decodes as a fuzz-indexed `values()` pick, by FQN.
        let h = gen_with_enums(
            "com.acme.Api",
            method("setState", &[("s", "Status"), ("d", "byte[]")], true, false),
            &["com.acme.Status"],
        )
        .unwrap();
        assert!(
            h.harness_java.contains(
                "com.acme.Status.values()[Math.floorMod(c.consumeInt(), \
                 com.acme.Status.values().length)]"
            ),
            "{}",
            h.harness_java
        );
        // A non-enum type with no matching FQN still rejects.
        assert!(gen_with_enums(
            "com.acme.Api",
            method("run", &[("w", "Widget")], true, false),
            &["com.acme.Status"],
        )
        .is_err());
    }

    #[test]
    fn static_byte_array_target_calls_with_rest_bytes() {
        let h = gen(
            "com.acme.JsonParser",
            method("parse", &[("d", "byte[]")], true, false),
        )
        .unwrap();
        assert!(h
            .harness_java
            .contains("public static void govfuzzRunOne(byte[] govfuzzInput)"));
        assert!(h
            .harness_java
            .contains("var a0 = c.consumeRemainingAsBytes();"));
        assert!(h.harness_java.contains("com.acme.JsonParser.parse(a0);"));
        assert_eq!(h.harness_class, "govfuzzgen.Harness");
    }

    #[test]
    fn constructor_uses_new() {
        let h = gen(
            "com.acme.JsonParser",
            method("JsonParser", &[("d", "byte[]")], false, true),
        )
        .unwrap();
        assert!(h.harness_java.contains("new com.acme.JsonParser(a0);"));
    }

    #[test]
    fn string_param_consumes_remaining_string() {
        let h = gen(
            "com.acme.P",
            method("parse", &[("s", "String")], true, false),
        )
        .unwrap();
        assert!(h
            .harness_java
            .contains("var a0 = c.consumeRemainingAsString();"));
        assert!(h.harness_java.contains("com.acme.P.parse(a0);"));
    }

    #[test]
    fn qualified_inputstream_param_wraps_bytes() {
        let h = gen(
            "com.acme.P",
            method("readValue", &[("in", "java.io.InputStream")], true, false),
        )
        .unwrap();
        assert!(h.harness_java.contains("new java.io.ByteArrayInputStream("));
    }

    #[test]
    fn mixed_params_only_last_byte_channel_takes_rest() {
        let h = gen(
            "com.acme.P",
            method(
                "f",
                &[("a", "byte[]"), ("n", "int"), ("b", "String")],
                true,
                false,
            ),
        )
        .unwrap();
        // a0 (byte[]) is bounded; a1 is an int; a2 (the last byte channel) takes rest.
        assert!(
            h.harness_java.contains("var a0 = c.consumeBytes(64);"),
            "{}",
            h.harness_java
        );
        assert!(h.harness_java.contains("var a1 = c.consumeInt();"));
        assert!(h
            .harness_java
            .contains("var a2 = c.consumeRemainingAsString();"));
        assert!(h.harness_java.contains("com.acme.P.f(a0, a1, a2);"));
    }

    #[test]
    fn instance_method_without_receiver_is_rejected() {
        let err = gen(
            "com.acme.P",
            method("decode", &[("d", "byte[]")], false, false),
        )
        .unwrap_err();
        assert!(err.reason.contains("instance method"), "{}", err.reason);
    }

    #[test]
    fn instance_method_with_receiver_constructs_and_calls() {
        let h = gen_recv(
            "com.acme.P",
            method("decode", &[("d", "byte[]")], false, false),
            "new com.acme.P()",
        )
        .unwrap();
        assert!(
            h.harness_java
                .contains("var govfuzzRecv = new com.acme.P();"),
            "{}",
            h.harness_java
        );
        assert!(
            h.harness_java.contains("govfuzzRecv.decode(a0)"),
            "{}",
            h.harness_java
        );
    }

    #[test]
    fn abstract_method_is_rejected() {
        let mut m = method("decode", &[("d", "byte[]")], false, false);
        m.is_abstract = true;
        let err = gen("com.acme.P", m).unwrap_err();
        assert!(err.reason.contains("abstract"), "{}", err.reason);
    }

    #[test]
    fn constructor_of_abstract_class_is_rejected_not_newed() {
        // GAP 1 (campaign: commons-validator): a CONSTRUCTOR target of an abstract
        // class must NOT emit `new <abstract>(...)` (javac "is abstract; cannot be
        // instantiated") — it skips cleanly instead.
        let err = gen_ctor_abstract(
            "org.apache.commons.validator.routines.checkdigit.ModulusCheckDigit",
            method("ModulusCheckDigit", &[("m", "int")], false, true),
        )
        .unwrap_err();
        assert!(
            err.reason.contains("abstract") && err.reason.contains("cannot be instantiated"),
            "{}",
            err.reason
        );
        // A CONCRETE class's constructor still emits `new` as before.
        let h = gen(
            "com.acme.JsonParser",
            method("JsonParser", &[("d", "byte[]")], false, true),
        )
        .unwrap();
        assert!(h.harness_java.contains("new com.acme.JsonParser(a0);"));
        // And no harness ever contains a `new` of the abstract type.
        assert!(!h.harness_java.contains("ModulusCheckDigit"));
    }

    #[test]
    fn unsupported_param_type_is_rejected() {
        let err = gen(
            "com.acme.P",
            method("f", &[("x", "com.acme.Widget")], true, false),
        )
        .unwrap_err();
        assert!(err.reason.contains("unsupported"), "{}", err.reason);
    }

    #[test]
    fn no_arg_target_calls_directly() {
        let h = gen("com.acme.P", method("run", &[], true, false)).unwrap();
        assert!(h.harness_java.contains("com.acme.P.run();"));
    }

    #[test]
    fn harness_declares_throws_throwable_for_checked_exceptions() {
        // A target like `Hex.decodeHex(String) throws DecoderException` (checked)
        // must compile — the entry declares `throws Throwable`.
        let h = gen(
            "com.acme.P",
            method("parse", &[("s", "String")], true, false),
        )
        .unwrap();
        assert!(
            h.harness_java
                .contains("public static void govfuzzRunOne(byte[] govfuzzInput) throws Throwable"),
            "{}",
            h.harness_java
        );
    }

    fn tm(fqn: &str) -> JavaTypeModel {
        JavaTypeModel {
            fqn: fqn.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn custom_param_static_final_default_field() {
        // The commons-csv case: `CSVParser.parse(String, CSVFormat)`. CSVFormat has
        // `public static final CSVFormat DEFAULT/EXCEL` -> use DEFAULT, and the
        // String input still takes the rest channel and gets fuzzed.
        let model = JavaTypeModel {
            fqn: "org.apache.commons.csv.CSVFormat".to_owned(),
            self_constants: vec!["EXCEL".to_owned(), "DEFAULT".to_owned()],
            ..Default::default()
        };
        let h = gen_with_models(
            "org.apache.commons.csv.CSVParser",
            method("parse", &[("s", "String"), ("f", "CSVFormat")], true, false),
            vec![model],
        )
        .unwrap();
        assert!(
            h.harness_java
                .contains("var a1 = org.apache.commons.csv.CSVFormat.DEFAULT;"),
            "{}",
            h.harness_java
        );
        assert!(h
            .harness_java
            .contains("var a0 = c.consumeRemainingAsString();"));
        assert!(h
            .harness_java
            .contains("org.apache.commons.csv.CSVParser.parse(a0, a1);"));
    }

    #[test]
    fn custom_param_no_arg_ctor_and_factory_and_enum() {
        // No-arg constructor.
        let mut m = tm("com.acme.Cfg");
        m.has_public_no_arg_ctor = true;
        let h = gen_with_models(
            "com.acme.P",
            method("f", &[("c", "Cfg"), ("d", "byte[]")], true, false),
            vec![m],
        )
        .unwrap();
        assert!(
            h.harness_java.contains("var a0 = new com.acme.Cfg();"),
            "{}",
            h.harness_java
        );

        // No-arg static factory, with the conventional name preferred.
        let mut m = tm("com.acme.Cfg");
        m.no_arg_self_factories = vec!["build".to_owned(), "getDefault".to_owned()];
        let h = gen_with_models(
            "com.acme.P",
            method("f", &[("c", "Cfg"), ("d", "byte[]")], true, false),
            vec![m],
        )
        .unwrap();
        assert!(
            h.harness_java
                .contains("var a0 = com.acme.Cfg.getDefault();"),
            "{}",
            h.harness_java
        );

        // Enum-typed custom param -> first constant.
        let mut m = tm("com.acme.Mode");
        m.is_enum = true;
        let h = gen_with_models(
            "com.acme.P",
            method("f", &[("c", "Mode"), ("d", "byte[]")], true, false),
            vec![m],
        )
        .unwrap();
        assert!(
            h.harness_java
                .contains("var a0 = com.acme.Mode.values()[0];"),
            "{}",
            h.harness_java
        );
    }

    #[test]
    fn custom_param_unconstructible_still_skips() {
        // A model with NO viable strategy (private ctor only, no constants/factory)
        // keeps the existing clean skip with the unsupported-type message.
        let err = gen_with_models(
            "com.acme.P",
            method("f", &[("w", "Widget")], true, false),
            vec![tm("com.acme.Widget")],
        )
        .unwrap_err();
        assert!(err.reason.contains("unsupported"), "{}", err.reason);
        // No model at all also skips.
        let err = gen("com.acme.P", method("f", &[("w", "Widget")], true, false)).unwrap_err();
        assert!(err.reason.contains("unsupported"), "{}", err.reason);
    }

    #[test]
    fn jdk_charset_locale_timezone_get_safe_defaults() {
        let h = gen(
            "com.acme.P",
            method(
                "parse",
                &[("cs", "java.nio.charset.Charset"), ("s", "String")],
                true,
                false,
            ),
        )
        .unwrap();
        assert!(
            h.harness_java
                .contains("var a0 = java.nio.charset.StandardCharsets.UTF_8;"),
            "{}",
            h.harness_java
        );
        assert_eq!(
            decode_expr("java.util.Locale", false).as_deref(),
            Some("java.util.Locale.ROOT")
        );
        assert_eq!(
            decode_expr("TimeZone", false).as_deref(),
            Some("java.util.TimeZone.getTimeZone(\"UTC\")")
        );
    }

    #[test]
    fn char_array_is_a_byte_channel() {
        let h = gen(
            "com.acme.P",
            method("decodeHex", &[("d", "char[]")], true, false),
        )
        .unwrap();
        assert!(
            h.harness_java
                .contains("c.consumeRemainingAsString().toCharArray()"),
            "{}",
            h.harness_java
        );
        assert!(h.harness_java.contains("com.acme.P.decodeHex(a0);"));
    }
}
