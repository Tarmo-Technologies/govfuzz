// SPDX-License-Identifier: Apache-2.0

//! Ruby fuzzing lane (M3.9) — discovery/parser half.
//!
//! Strategy (like the Python/Perl/JS lanes): reuse govfuzz's builtin engine over the
//! framed fork-server protocol driving a warm `ruby` process. A method taking at
//! least one argument is the fuzzable unit; the first argument is the
//! attacker-controlled channel (fed a fuzz `String`). The generated launcher execs
//! `ruby ruby_runtime/govfuzz_driver.rb`, which `require`s the target file, calls the
//! method with the fuzz bytes, records per-line edge coverage via a `TracePoint`
//! folded into the shared `GOVFUZZ_COV_SHM` bitmap, and reports an uncaught
//! bug-class exception as a finding (exit 86) — no third-party fuzzer.
//!
//! This module is the discovery/parser half; the build + launch half is
//! [`crate::auto::ruby_build`].

/// A discovered, callable Ruby method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubyMethod {
    /// Display + candidate name. For a module/class method: `Mod.method`; for a
    /// top-level method: `method`; for an instance method: `Class#method`.
    pub name: String,
    /// The bare method name (`parse`), used to build the call in the harness.
    pub method: String,
    /// The dotted module/class path the driver resolves the method on
    /// (`Foo::Bar`), or empty for a top-level method.
    pub receiver_path: String,
    /// Whether calling needs an INSTANCE (`Class.new.method`) rather than a module
    /// function / `self.` method / top-level method callable directly.
    pub needs_instance: bool,
    pub line: u32,
    /// The first parameter's name (the input channel).
    pub first_param: String,
}

/// Whether the first parameter's name marks the method as NOT a string/bytes input
/// channel — an internal helper taking an array/options/callback/block. Fuzzing such
/// a method with a `String` only produces our-fault `TypeError`s, so it is skipped.
fn non_input_first_param(name: &str) -> bool {
    let p = name
        .trim_start_matches('&')
        .trim_start_matches('*')
        .to_ascii_lowercase();
    const NON_INPUT: &[&str] = &[
        "arr",
        "array",
        "list",
        "items",
        "item",
        "nodes",
        "node",
        "tree",
        "opts",
        "options",
        "option",
        "config",
        "cfg",
        "settings",
        "obj",
        "object",
        "hash",
        "block",
        "blk",
        "proc",
        "cb",
        "callback",
        "re",
        "regex",
        "regexp",
        "pattern",
        "map",
        "set",
        "el",
        "elem",
        "element",
        "ctx",
        "context",
        "opts_hash",
        "args",
        "kwargs",
        "params",
        "collection",
        "coll",
        "other",
        "count",
        "n",
        "num",
        "index",
        "idx",
        "size",
        "len",
        "length",
    ];
    NON_INPUT.contains(&p.as_str())
}

impl RubyMethod {
    /// A method is fuzzable when it has an input-channel first parameter. Instance
    /// methods stay eligible (the driver constructs a no-arg receiver where possible).
    pub fn is_fuzzable(&self) -> bool {
        !self.first_param.is_empty() && !non_input_first_param(&self.first_param)
    }
}

/// Strip a Ruby comment (`#` to end of line, outside a string) and string CONTENTS
/// (so `def`/`end`/quotes inside a literal don't confuse the scanner), keeping the
/// opening quote. Uppercase is NOT applied (Ruby is case-sensitive). One line out per
/// line in.
fn normalize(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in source.lines() {
        let bytes = raw.as_bytes();
        let mut line = String::with_capacity(raw.len());
        let mut i = 0;
        let mut in_str: Option<u8> = None;
        while i < bytes.len() {
            let c = bytes[i];
            if let Some(q) = in_str {
                if c == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
                i += 1;
                continue;
            }
            if c == b'#' {
                break; // comment to end of line
            }
            if c == b'"' || c == b'\'' || c == b'`' {
                in_str = Some(c);
                line.push(c as char);
                i += 1;
                continue;
            }
            line.push(c as char);
            i += 1;
        }
        out.push(line.trim_end().to_owned());
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// A frame on the block stack. Named frames (module/class/def) contribute to the
/// receiver path; anonymous frames only balance `end`.
#[derive(Clone)]
enum Frame {
    Module(String),
    Class(String),
    /// `class << self` makes ordinary `def name` declarations singleton
    /// methods on the enclosing class/module. It contributes no path component,
    /// but changes the call shape from `Klass.new.name` to `Klass.name`.
    SingletonClass,
    Def,
    Anon,
}

/// The keyword-openers that require a matching `end` when they START a statement
/// (as a statement modifier — `return x if y` — they do NOT open a block, so only a
/// line whose first token is one of these opens a block).
fn opens_block_keyword(first_tok: &str) -> bool {
    matches!(
        first_tok,
        "if" | "unless" | "while" | "until" | "for" | "begin" | "case"
    )
}

/// Scan Ruby source for callable, fuzzable methods.
pub fn parse_ruby(source: &str) -> Vec<RubyMethod> {
    let lines = normalize(source);
    let mut out: Vec<RubyMethod> = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    // A `private` with no arguments flips subsequent instance methods of the current
    // class to private until the class closes; keyed by the stack depth of the class.
    let mut private_depth: Option<usize> = None;

    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let line_no = (idx + 1) as u32;
        let first_tok: String = t.chars().take_while(|&c| is_ident_char(c)).collect();

        // A bare `private` / `private_class_method` marks following methods private.
        if t == "private" || t == "private_class_method" {
            private_depth = Some(stack.len());
            // still counts as a normal line (no block); fall through to end-tracking.
        }

        // `def name(params)` / `def self.name(params)` / `def Mod.name` — a method.
        if first_tok == "def" {
            if let Some(m) = parse_def(t, &stack, line_no, private_depth) {
                if m.is_fuzzable() {
                    out.push(m);
                }
            }
            // An endless method `def f(x) = expr` has no `end`; a normal or one-line
            // `def f; ...; end` balances on this line. Only push a Def frame when the
            // def opens a block that a later `end` closes.
            if def_opens_block(t) {
                stack.push(Frame::Def);
            }
            continue;
        }

        // Track module/class/anon openers and `end` closers to keep the receiver path.
        apply_block_delta(t, &first_tok, &mut stack, &mut private_depth);
    }

    dedup(out)
}

/// Parse a `def` line into a [`RubyMethod`], or `None` if it isn't a fuzzable method
/// header (operator method, no params, private instance method).
fn parse_def(
    t: &str,
    stack: &[Frame],
    line_no: u32,
    private_depth: Option<usize>,
) -> Option<RubyMethod> {
    let rest = t.strip_prefix("def")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let rest = rest.trim_start();
    // `def self.name` / `def Klass.name` — a singleton (module/class) method.
    let (self_method, after_recv) = if let Some(r) = rest.strip_prefix("self.") {
        (true, r)
    } else if let Some(dot) = rest.find('.') {
        // `def Receiver.name` — treat as a module method on the current path.
        (true, &rest[dot + 1..])
    } else {
        (false, rest)
    };
    let method: String = after_recv
        .chars()
        .take_while(|&c| is_ident_char(c))
        .collect();
    // Reject operator methods (`+`, `[]`, `<=>`) and empty names.
    if method.is_empty() || !method.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    // A setter (`name=`) or predicate is a lower-value target; keep predicates but
    // drop assignment methods (they take the value, not an input channel).
    let after_name = &after_recv[method.len()..];
    if after_name.starts_with('=') && !after_name.starts_with("==") {
        return None;
    }
    let params = parse_params(after_name);
    let first_param = params.into_iter().next().unwrap_or_default();

    // The receiver path is the enclosing module/class chain.
    let path: Vec<String> = stack
        .iter()
        .filter_map(|f| match f {
            Frame::Module(n) | Frame::Class(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    let receiver_path = path.join("::");

    // An instance method (not `self.`, defined inside a class) needs a receiver.
    let inside_class = stack.iter().any(|f| matches!(f, Frame::Class(_)));
    let inside_singleton_class = stack
        .iter()
        .rev()
        .take_while(|frame| !matches!(frame, Frame::Def))
        .any(|frame| matches!(frame, Frame::SingletonClass));
    let needs_instance = !self_method && inside_class && !inside_singleton_class;

    // A private instance method isn't externally callable — skip it (the accessibility
    // rule shared with the other lanes).
    if needs_instance {
        if let Some(pd) = private_depth {
            if pd <= stack.len() {
                return None;
            }
        }
    }

    let display = if receiver_path.is_empty() {
        method.clone()
    } else if needs_instance {
        format!("{receiver_path}#{method}")
    } else {
        format!("{receiver_path}.{method}")
    };

    Some(RubyMethod {
        name: display,
        method,
        receiver_path,
        needs_instance,
        line: line_no,
        first_param,
    })
}

/// The parameter names from a `def`'s `(...)` list (or a paren-less list up to a
/// trailing comment/`=`). Keyword args (`k:`), defaults (`= v`), splats (`*a`,
/// `**kw`), and block args (`&b`) are reduced to the bare leading name.
fn parse_params(after_name: &str) -> Vec<String> {
    let s = after_name.trim_start();
    let inner: &str = if let Some(rest) = s.strip_prefix('(') {
        rest.split(')').next().unwrap_or("")
    } else if s.is_empty() || s.starts_with('=') {
        // endless method `def f = expr` or a no-paren no-arg def
        ""
    } else {
        // paren-less params: `def f a, b`
        s.split(&['=', '#'][..]).next().unwrap_or("")
    };
    inner
        .split(',')
        .filter_map(|p| {
            let p = p.trim().trim_start_matches("**").trim_start_matches('*');
            let name: String = p
                .trim_start_matches('&')
                .chars()
                .take_while(|&c| is_ident_char(c))
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// Whether a `def` line opens a block a later `end` will close (i.e. it is NOT an
/// endless method `def f = expr` and NOT a one-line `def f; body; end`).
fn def_opens_block(t: &str) -> bool {
    // Endless method: `def name(...) = expr` (an `=` after the param list, not `==`).
    if let Some(eq) = find_endless_eq(t) {
        // Ensure the `=` is the method-body assignment, i.e. balanced parens before it.
        if paren_balanced(&t[..eq]) {
            return false;
        }
    }
    // One-line def closed by `; end` / ` end` on the same line.
    let trimmed = t.trim_end();
    if trimmed.ends_with(";end") || trimmed.ends_with("; end") || trimmed.ends_with(" end") {
        return false;
    }
    true
}

/// Find the position of an endless-method `=` (a single `=` not part of `==`/`>=`/
/// `<=`/`!=` and after the def header), else `None`.
fn find_endless_eq(t: &str) -> Option<usize> {
    let b = t.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'=' {
            let prev = if i > 0 { b[i - 1] } else { b' ' };
            let next = if i + 1 < b.len() { b[i + 1] } else { b' ' };
            if next != b'=' && !matches!(prev, b'=' | b'<' | b'>' | b'!') {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn paren_balanced(s: &str) -> bool {
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth == 0
}

/// Apply block open/close deltas from a non-`def` line to the scope stack.
fn apply_block_delta(
    t: &str,
    first_tok: &str,
    stack: &mut Vec<Frame>,
    private_depth: &mut Option<usize>,
) {
    // Closers: `end` (a line that is just `end`, or begins with `end` as a keyword).
    if t == "end" || first_tok == "end" {
        if let Some(pd) = *private_depth {
            if stack.len() <= pd {
                *private_depth = None;
            }
        }
        stack.pop();
        return;
    }

    // `module Name` / `class Name` open a named frame (but not `class << self`).
    if first_tok == "module" {
        if let Some(name) = named_after(t, "module") {
            stack.push(Frame::Module(name));
            return;
        }
    }
    if first_tok == "class" {
        let after = t["class".len()..].trim_start();
        if after.starts_with("<<") {
            stack.push(Frame::SingletonClass);
        } else if let Some(name) = named_after(t, "class") {
            stack.push(Frame::Class(name));
        } else {
            stack.push(Frame::Anon);
        }
        return;
    }

    // Other block openers that need an `end`: keyword-led statements, or a trailing
    // `do` (a block). A line can also close what it opens (`3.times do ... end`), so
    // only push when the line does not itself contain a matching `end`.
    let opens = opens_block_keyword(first_tok) || opens_rhs_keyword(t) || ends_with_do(t);
    if opens && !line_self_closes(t) {
        stack.push(Frame::Anon);
    }
}

/// Ruby permits expression blocks on the right-hand side of an assignment:
/// `path = if condition ... end`. Missing that opener makes the closing `end`
/// pop the enclosing class and turns all following instance methods into bogus
/// module functions.
fn opens_rhs_keyword(t: &str) -> bool {
    ["if", "unless", "case", "begin"].iter().any(|keyword| {
        let needle = format!("= {keyword}");
        t.find(&needle).is_some_and(|at| {
            t[at + needle.len()..]
                .chars()
                .next()
                .is_none_or(char::is_whitespace)
        })
    })
}

/// Whether a `module X`/`class X` line names X; returns the (possibly namespaced)
/// name's LAST segment path element (`Foo::Bar` -> uses the whole thing as one frame).
fn named_after(t: &str, kw: &str) -> Option<String> {
    let after = t[kw.len()..].trim_start();
    let name: String = after
        .chars()
        .take_while(|&c| is_ident_char(c) || c == ':')
        .collect();
    let name = name.trim_end_matches(':').to_owned();
    (!name.is_empty() && name.starts_with(|c: char| c.is_ascii_uppercase())).then_some(name)
}

/// Whether the line ends with a block `do` / `do |args|`.
fn ends_with_do(t: &str) -> bool {
    let trimmed = t.trim_end();
    if trimmed.ends_with(" do") || trimmed == "do" {
        return true;
    }
    // `do |x, y|` at end of line.
    if let Some(pos) = trimmed.rfind(" do ") {
        let after = trimmed[pos + 4..].trim();
        return after.starts_with('|') && after.ends_with('|');
    }
    false
}

/// Whether a keyword-opened line also closes itself with a trailing `end` (a one-line
/// `if x then y end`). Conservative — only the explicit trailing-`end` case.
fn line_self_closes(t: &str) -> bool {
    let trimmed = t.trim_end();
    trimmed.ends_with(";end") || trimmed.ends_with("; end") || trimmed.ends_with(" end")
}

/// Drop duplicate (name) methods, keeping the first (lowest line).
fn dedup(methods: Vec<RubyMethod>) -> Vec<RubyMethod> {
    let mut seen = std::collections::HashSet::new();
    methods
        .into_iter()
        .filter(|m| seen.insert(m.name.clone()))
        .collect()
}

/// Mine string/integer literals as a fuzzing dictionary (magic values that gate
/// coverage), skipping trivial values and format placeholders. Mirrors the JS/Perl
/// dictionary miners.
pub fn extract_ruby_dictionary_tokens(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in source.lines() {
        let bytes = raw.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'#' {
                break;
            }
            if c == b'"' || c == b'\'' {
                let q = c;
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() {
                    if bytes[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == q {
                        break;
                    }
                    j += 1;
                }
                if j <= bytes.len() && j > start {
                    let lit = &raw[start..j.min(raw.len())];
                    if lit.len() >= 2
                        && lit.len() <= 64
                        && !lit.contains("#{")
                        && lit.chars().all(|ch| !ch.is_control())
                        && seen.insert(lit.to_owned())
                    {
                        out.push(lit.to_owned());
                    }
                }
                i = j + 1;
                continue;
            }
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_method() {
        let src = "def parse(input)\n  input.length\nend\n";
        let m = &parse_ruby(src)[0];
        assert_eq!(m.name, "parse");
        assert_eq!(m.method, "parse");
        assert_eq!(m.receiver_path, "");
        assert!(!m.needs_instance);
        assert_eq!(m.first_param, "input");
        assert!(m.is_fuzzable());
    }

    #[test]
    fn module_self_method_is_callable_without_instance() {
        let src = "\
module Toml
  def self.parse(str)
    str
  end
end
";
        let m = &parse_ruby(src)[0];
        assert_eq!(m.name, "Toml.parse");
        assert_eq!(m.receiver_path, "Toml");
        assert_eq!(m.method, "parse");
        assert!(!m.needs_instance);
        assert!(m.is_fuzzable());
    }

    #[test]
    fn singleton_class_method_is_callable_without_instance() {
        let src = "\
module Tmuxinator
  class Project
    class << self
      def load(path, options = {})
        path
      end
    end
  end
end
";
        let m = &parse_ruby(src)[0];
        assert_eq!(m.name, "Tmuxinator::Project.load");
        assert_eq!(m.receiver_path, "Tmuxinator::Project");
        assert_eq!(m.method, "load");
        assert!(!m.needs_instance);
    }

    #[test]
    fn instance_method_needs_receiver() {
        let src = "\
class Parser
  def parse(data)
    data
  end
end
";
        let m = &parse_ruby(src)[0];
        assert_eq!(m.name, "Parser#parse");
        assert!(m.needs_instance);
        assert_eq!(m.receiver_path, "Parser");
    }

    #[test]
    fn private_instance_method_is_skipped() {
        let src = "\
class Parser
  def public_parse(s)
    s
  end
  private
  def helper(s)
    s
  end
end
";
        let methods = parse_ruby(src);
        let names: Vec<&str> = methods.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"Parser#public_parse"));
        assert!(
            !names.contains(&"Parser#helper"),
            "private method leaked: {names:?}"
        );
    }

    #[test]
    fn non_input_first_param_is_skipped() {
        let src = "def render(options)\n  options\nend\ndef build(nodes)\n  nodes\nend\n";
        assert!(parse_ruby(src).is_empty());
    }

    #[test]
    fn nested_blocks_keep_receiver_path() {
        // A method whose body opens `if`/`do`/`case` blocks must still be attributed
        // to its class, and the class must close correctly.
        let src = "\
module M
  class C
    def scan(text)
      if text.empty?
        return nil
      end
      text.each_char do |ch|
        ch
      end
      case text
      when 'a'
        1
      end
      text
    end
  end
end
";
        let m = &parse_ruby(src)[0];
        assert_eq!(m.name, "M::C#scan");
        assert_eq!(m.receiver_path, "M::C");
        assert!(m.needs_instance);
    }

    #[test]
    fn rhs_expression_block_does_not_pop_the_enclosing_class() {
        let src = "\
module M
  class C
    def public_method(text)
      path = if text.empty?
        'empty'
      end
      path
    end
    private
    def helper(text)
      text
    end
  end
end
";
        let methods = parse_ruby(src);
        let names: Vec<&str> = methods.iter().map(|method| method.name.as_str()).collect();
        assert_eq!(names, vec!["M::C#public_method"]);
    }

    #[test]
    fn endless_and_one_line_defs() {
        // Endless method (no `end`) and one-line def must not corrupt the block stack.
        let src = "\
module M
  def self.up(s) = s.upcase
  def self.down(s); s.downcase; end
  def self.plain(s)
    s
  end
end
";
        let methods = parse_ruby(src);
        let names: Vec<&str> = methods.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"M.up"), "{names:?}");
        assert!(names.contains(&"M.down"), "{names:?}");
        assert!(names.contains(&"M.plain"), "{names:?}");
    }

    #[test]
    fn setter_and_operator_methods_skipped() {
        let src = "\
class C
  def value=(v)
    @value = v
  end
  def +(other)
    other
  end
end
";
        assert!(parse_ruby(src).is_empty());
    }
}
