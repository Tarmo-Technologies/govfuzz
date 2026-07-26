// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CParamDescriptor {
    pub name: String,
    pub c_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CFunction {
    pub name: String,
    pub line: u32,
    pub return_type: String,
    pub params: Vec<CParamDescriptor>,
    /// `static` storage class — internal linkage, not callable from
    /// an external harness translation unit.
    pub is_static: bool,
    /// Set when the definition sits under a preprocessor conditional
    /// that names a foreign-platform macro (e.g. `_WIN32` on a
    /// non-Windows host). Carries the condition text for skip
    /// messaging. Heuristic: positive `#ifdef`/`#if` mentions only —
    /// negated conditions (`#ifndef`, `!defined`) are not flagged.
    pub foreign_guard: Option<String>,
    /// True when the parameter list ends in an ellipsis (`...`), i.e. the
    /// function is variadic (`int printf(const char *fmt, ...)`). The `...`
    /// itself is not surfaced as a parameter; this flag lets the harness
    /// emitter recognise a printf-style format parameter (the last fixed
    /// `const char *` before the ellipsis) and neutralise its specifiers so a
    /// fuzzed format with no matching varargs cannot crash in vfprintf.
    pub variadic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CDeclaration {
    pub name: String,
    pub return_type: String,
    pub param_types: Vec<String>,
    pub variadic: bool,
    pub line: u32,
}

impl c_stub_gen::DeclarationView for CDeclaration {
    fn name(&self) -> &str {
        &self.name
    }
    fn return_type(&self) -> &str {
        &self.return_type
    }
    fn param_types(&self) -> &[String] {
        &self.param_types
    }
    fn variadic(&self) -> bool {
        self.variadic
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CStructDef {
    /// Struct tag, or the typedef alias for `typedef struct { .. } alias;`.
    pub name: String,
    pub fields: Vec<CParamDescriptor>,
    pub line: u32,
    /// false when only a forward declaration was seen.
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CEnumDef {
    pub name: String,
    pub members: Vec<String>,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CTypedefDef {
    pub name: String,
    /// Raw text of the aliased type, e.g. `unsigned long` or `struct point`.
    pub underlying: String,
    pub line: u32,
}

/// Struct/enum/typedef definitions extracted from one translation
/// unit. Consumed by `type_model::TypeRegistry` to resolve parameter
/// type strings into decodable shapes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CTypeDefs {
    pub structs: Vec<CStructDef>,
    pub enums: Vec<CEnumDef>,
    pub typedefs: Vec<CTypedefDef>,
}

impl CTypeDefs {
    /// Append all definitions from `other` into `self`. Used to accumulate a
    /// tree-wide type-def index across many parsed headers.
    pub fn merge(&mut self, other: CTypeDefs) {
        self.structs.extend(other.structs);
        self.enums.extend(other.enums);
        self.typedefs.extend(other.typedefs);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CParseError {
    #[error("failed to load C grammar")]
    Grammar,
    #[error("failed to parse C source")]
    Parse,
}

/// Hard cap on recursive AST-walk depth. tree-sitter parses deep input fine
/// (its parser is iterative), but our recursive walkers use one stack frame
/// per AST level; a pathologically deep source (long else-if/||/&& chains,
/// nested parens) otherwise overflows the stack and aborts the process
/// before the build (#407).
///
/// 250 is still ~4x the C standard's guaranteed 63-level nesting minimum and
/// below clang's default 256-level expression-nesting limit, so it never
/// truncates code a compiler would accept; yet it stays well under the
/// empirical overflow threshold on a 2 MiB worker-thread stack (debug builds,
/// the worst case — the daemon parses untrusted source on such threads, not
/// just the CLI's larger main-thread stack).
const MAX_AST_DEPTH: usize = 250;

thread_local! {
    static AST_WALK_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// RAII guard: returns None once the recursion is at MAX_AST_DEPTH (the caller
/// then stops descending), and decrements on drop. A tree is never cyclic, so
/// a depth cap — not a visited-set — is the correct bound.
struct AstDepthGuard;

impl AstDepthGuard {
    fn enter() -> Option<AstDepthGuard> {
        AST_WALK_DEPTH.with(|d| {
            let cur = d.get();
            if cur >= MAX_AST_DEPTH {
                None
            } else {
                d.set(cur + 1);
                Some(AstDepthGuard)
            }
        })
    }
}

impl Drop for AstDepthGuard {
    fn drop(&mut self) {
        AST_WALK_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Walk the tree-sitter tree counting `ERROR` and `MISSING` nodes.
/// Used by the CLI to surface "parser confused, results may be
/// incomplete" warnings when list-targets / generate-harness comes
/// up empty against a real-world file (eg. macro-heavy headers where
/// tree-sitter's recovery gives up).
pub fn count_parse_errors(source: &str) -> usize {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return 0;
    }
    let Some(tree) = parser.parse(source, None) else {
        return 0;
    };
    let mut count = 0_usize;
    walk_errors(tree.root_node(), &mut count);
    count
}

fn walk_errors(node: tree_sitter::Node<'_>, count: &mut usize) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.is_error() || node.is_missing() {
        *count = count.saturating_add(1);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_errors(child, count);
    }
}

pub fn parse_c_functions(source: &str) -> Result<Vec<CFunction>, CParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .map_err(|_| CParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CParseError::Parse)?;
    let mut functions = Vec::new();
    collect_functions(tree.root_node(), source.as_bytes(), None, &mut functions);
    Ok(functions)
}

/// M22: a tolerant extractor for **K&R / pre-ANSI C** function definitions.
///
/// tree-sitter-c (like every modern C grammar) cannot represent an old-style
/// function definition — a header whose parameter list is bare identifiers
/// followed by a separate declaration block:
///
/// ```c
/// int add(a, b)
///     int a;
///     char *b;
/// { return a; }
/// ```
///
/// so [`parse_c_functions`] never discovers them. This fallback recognizes that
/// shape directly and synthesizes the equivalent ANSI prototype as a
/// [`CFunction`] (the "K&R -> ANSI prototype synthesis" of M22 Phase 3), mapping
/// each parameter to the type declared in the declaration block (defaulting to
/// `int`, K&R implicit-int). Only top-level definitions are considered (brace
/// depth 0), so calls and prototypes inside bodies are ignored.
pub fn parse_knr_functions(source: &str) -> Vec<CFunction> {
    // Comments are not code. redis' module.c documents its API with example
    // calls inside a block comment; scanning those matched a "K&R definition"
    // whose parameter type read `// Set`, which classified the whole modern C99
    // file as legacy and routed every real target in it to report-only.
    let decommented = strip_c_comments(source);
    let lines: Vec<&str> = decommented.lines().collect();
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut i = 0;
    while i < lines.len() {
        if depth == 0 {
            if let Some(func) = knr_def_at(&lines, i) {
                out.push(func);
            }
        }
        depth += brace_delta(lines[i]);
        if depth < 0 {
            depth = 0;
        }
        i += 1;
    }
    out
}

/// Blank out comment spans, keeping every byte position and line break so the
/// reported line numbers stay the source's own.
fn strip_c_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    let (mut in_block, mut in_line, mut in_str, mut in_char) = (false, false, false, false);
    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        if in_block {
            if b == b'*' && next == Some(b'/') {
                out.push_str("  ");
                i += 2;
                in_block = false;
                continue;
            }
            out.push(if b == b'\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }
        if in_line {
            if b == b'\n' {
                out.push('\n');
                in_line = false;
            } else {
                out.push(' ');
            }
            i += 1;
            continue;
        }
        if in_str || in_char {
            out.push(b as char);
            if b == b'\\' {
                if let Some(n) = next {
                    out.push(n as char);
                    i += 2;
                    continue;
                }
            }
            if (in_str && b == b'"') || (in_char && b == b'\'') {
                in_str = false;
                in_char = false;
            }
            i += 1;
            continue;
        }
        match (b, next) {
            (b'/', Some(b'*')) => {
                out.push_str("  ");
                i += 2;
                in_block = true;
            }
            (b'/', Some(b'/')) => {
                out.push_str("  ");
                i += 2;
                in_line = true;
            }
            (b'"', _) => {
                in_str = true;
                out.push('"');
                i += 1;
            }
            (b'\'', _) => {
                in_char = true;
                out.push('\'');
                i += 1;
            }
            _ => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

/// Net `{` minus `}` on a line (string/char literals not stripped — adequate for
/// the top-level-definition scan, which only needs to track entering/leaving
/// function bodies in normal source).
fn brace_delta(line: &str) -> i32 {
    line.bytes().fold(0i32, |d, b| match b {
        b'{' => d + 1,
        b'}' => d - 1,
        _ => d,
    })
}

/// Try to parse a K&R definition whose header is on `lines[start]`. Returns the
/// synthesized [`CFunction`] or `None` if this is not a K&R definition.
fn knr_def_at(lines: &[&str], start: usize) -> Option<CFunction> {
    let header = lines[start];
    // A preprocessor directive is never a K&R definition. A function-like macro
    // (`#define EXPECT_CHAR(ch) ...`) has the exact `name(bare, idents)` header
    // shape, and its body — which has no `{` of its own — lets the declaration
    // scan below run on into unrelated lines until it swallows a later
    // `EXPECT_CHAR_NO_CHECK(ch);`, which `knr_param_types` then mis-reads as a
    // declaration of `ch`, satisfying the param-declared check. The result is a
    // phantom K&R "function" that makes a modern-C99 file (picohttpparser,
    // http_parser) classify as K&R and route its entire real API to report-only
    // (a false-clean). Reject `#` headers outright.
    if header.trim_start().starts_with('#') {
        return None;
    }
    // The header must contain a complete `name(args)` on this line.
    let open = header.find('(')?;
    let close = header[open..].find(')')? + open;
    // Before `(`: `[storage/return type] name`.
    let prefix = header[..open].trim();
    // A control-flow keyword followed by `(` is not a definition header.
    let last_word: String = prefix
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if last_word.is_empty()
        || matches!(
            last_word.as_str(),
            "if" | "for" | "while" | "switch" | "return" | "sizeof"
        )
    {
        return None;
    }
    let name = last_word;
    let is_static = prefix.split_whitespace().any(|w| w == "static");
    let mut return_type = prefix[..prefix.len() - name.len()].trim().to_owned();
    // Drop storage-class / linkage specifiers from the return type (is_static
    // carries `static` separately, matching the tree-sitter parser's shape).
    loop {
        let trimmed = return_type
            .strip_prefix("static")
            .or_else(|| return_type.strip_prefix("extern"))
            .or_else(|| return_type.strip_prefix("register"))
            .or_else(|| return_type.strip_prefix("inline"))
            .filter(|rest| rest.starts_with(char::is_whitespace) || rest.is_empty());
        match trimmed {
            Some(rest) => return_type = rest.trim_start().to_owned(),
            None => break,
        }
    }
    if return_type.is_empty() {
        return_type = "int".to_owned(); // K&R implicit int
    }

    // Parameters must be a non-empty list of bare identifiers (no types) — that
    // is what distinguishes a K&R header from an ANSI prototype.
    let arg_src = header[open + 1..close].trim();
    if arg_src.is_empty() {
        return None;
    }
    let mut param_names = Vec::new();
    for raw in arg_src.split(',') {
        let p = raw.trim();
        if p.is_empty() || !p.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None; // a type token / `*` / `[` means this is an ANSI prototype
        }
        // `f(void)` is the ANSI spelling for "no parameters", and no keyword can
        // be a parameter NAME. Reading `void` as one let a run of ordinary
        // prototypes (redis' sentinel.c) look like a K&R definition, classifying
        // a modern file as legacy so none of it was ever fuzzed.
        if is_c_keyword(p) {
            return None;
        }
        param_names.push(p.to_owned());
    }

    // The declaration block: everything after `)` up to the body's `{`, which must
    // contain at least one `;` (the parameter declarations). No `{` before a `;`
    // means this is a prototype (`int f(a, b);`), not a definition.
    let mut decls = String::new();
    decls.push_str(&header[close + 1..]);
    decls.push(' ');
    let mut found_brace = false;
    for line in &lines[start + 1..] {
        // A genuine K&R declaration block is only parameter declarations between
        // `)` and the body `{`; it never crosses a preprocessor directive. Stop at
        // one rather than scanning on into unrelated code (a following macro / next
        // function), which is how a header whose body-`{` is far away swallows
        // spurious `name(...)` text and mis-validates.
        if line.trim_start().starts_with('#') {
            break;
        }
        if let Some(brace) = line.find('{') {
            decls.push_str(&line[..brace]);
            found_brace = true;
            break;
        }
        decls.push_str(line);
        decls.push(' ');
        if decls.len() > 4096 {
            break;
        }
    }
    if !found_brace || !decls.contains(';') {
        return None;
    }

    let types = knr_param_types(&decls);
    // A genuine K&R definition declares its parameters in the block. If none of
    // the declared names match a parameter, this is not a K&R def — most often a
    // prototype (`int f(a, b);`) whose trailing `;` plus a *following* function's
    // `{` masqueraded as a declaration block.
    if !param_names
        .iter()
        .any(|n| types.iter().any(|(tn, _)| tn == n))
    {
        return None;
    }
    let params = param_names
        .into_iter()
        .map(|name| {
            let c_type = types
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, t)| t.clone())
                .unwrap_or_else(|| "int".to_owned());
            CParamDescriptor { name, c_type }
        })
        .collect();

    Some(CFunction {
        name,
        line: (start + 1) as u32,
        return_type,
        params,
        is_static,
        foreign_guard: None,
        variadic: false,
    })
}

/// Parse a K&R parameter declaration block (`int a; char *b, *c;`) into
/// `(name, c_type)` pairs. A `*`/array suffix binds to the individual declarator,
/// so `char *b, c` yields `b: char *` and `c: char`.
fn knr_param_types(decls: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for stmt in decls.split(';') {
        let stmt = stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        // Split into the leading type-specifier run and the declarator list. The
        // base type is every leading whitespace-separated word that is not the
        // first declarator (heuristic: the base type is everything up to the last
        // run that introduces declarators). Simpler: the declarators are the
        // comma-separated tail; the base type is the tokens before the first
        // declarator's name.
        let (base, first_decl_start) = split_base_type(stmt);
        if base.is_empty() {
            continue;
        }
        for decl in stmt[first_decl_start..].split(',') {
            let decl = decl.trim();
            if decl.is_empty() {
                continue;
            }
            let stars = decl.chars().filter(|c| *c == '*').count();
            let name: String = decl
                .trim_start_matches('*')
                .trim()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            let mut c_type = base.clone();
            if stars > 0 {
                c_type.push(' ');
                c_type.push_str(&"*".repeat(stars));
            }
            // An array declarator (`buf[10]`) decays to a pointer parameter.
            if decl.contains('[') {
                c_type.push_str(" *");
            }
            out.push((name, c_type));
        }
    }
    out
}

/// Split a declaration statement into `(base_type, byte_index_of_first_declarator)`.
/// The base type is the leading run of type-specifier words; the first declarator
/// begins at the first `*` or the last identifier preceded by another identifier.
fn split_base_type(stmt: &str) -> (String, usize) {
    const SPECIFIERS: &[&str] = &[
        "const", "volatile", "unsigned", "signed", "short", "long", "int", "char", "float",
        "double", "void", "struct", "union", "enum", "register",
    ];
    let bytes = stmt.as_bytes();
    let mut words: Vec<(usize, usize)> = Vec::new(); // (start,end) of each word
    let mut j = 0;
    while j < bytes.len() {
        if bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' {
            let s = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            words.push((s, j));
        } else {
            if bytes[j] == b'*' || bytes[j] == b',' {
                break; // declarators begin
            }
            j += 1;
        }
    }
    // All leading words that are specifiers (or a struct/union/enum tag) form the
    // base type; the first non-specifier word is the first declarator name.
    let mut base_end = 0usize;
    let mut tag_pending = false;
    let mut first_decl = stmt.len();
    for (idx, (s, e)) in words.iter().enumerate() {
        let w = &stmt[*s..*e];
        let is_spec = SPECIFIERS.contains(&w);
        if idx == 0 || is_spec || tag_pending {
            base_end = *e;
            tag_pending = matches!(w, "struct" | "union" | "enum");
            if !is_spec && idx > 0 {
                // a tag name after struct/union/enum
                tag_pending = false;
            }
        } else {
            first_decl = *s;
            break;
        }
    }
    // If only one word and it is a specifier, the next thing (a `*`/declarator)
    // starts after base_end.
    if first_decl == stmt.len() {
        first_decl = base_end;
    }
    (stmt[..base_end].trim().to_owned(), first_decl)
}

/// The set of function names this translation unit *calls* directly (the
/// callee identifier of every `call_expression`). Used to walk a library's
/// dependency graph: the symbols a source file references point at the other
/// in-tree sources a harness must link to satisfy them.
pub fn referenced_symbols(source: &str) -> Result<Vec<String>, CParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .map_err(|_| CParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CParseError::Parse)?;
    let mut names = std::collections::BTreeSet::new();
    collect_call_targets(tree.root_node(), source.as_bytes(), &mut names);
    Ok(names.into_iter().collect())
}

fn collect_call_targets(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    names: &mut std::collections::BTreeSet<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                if let Ok(name) = func.utf8_text(source) {
                    if !is_c_keyword(name) {
                        names.insert(name.to_owned());
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_call_targets(child, source, names);
    }
}

/// One field-access chain observed on a value whose root variable is declared
/// with a given type — e.g. `MsgPtr->CCSDS.Pri.StreamId[0]` yields components
/// `["CCSDS", "Pri", "StreamId"]`, `leaf_indexed = true`, `max_index = 0`.
///
/// Used to synthesise a real `struct` for a missing type the target
/// dereferences by field (cFE's `CFE_MSG_Message_t`, etc.), instead of the
/// unusable `void *` placeholder that cannot be field-accessed at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldAccessPath {
    pub components: Vec<String>,
    /// Component indexes whose value is dereferenced with `->` to reach the
    /// following component. For a missing `Node`, `n->next->value` marks `next`
    /// as a pointer to another `Node`; `n->embedded.value` marks none.
    pub self_pointer_components: Vec<usize>,
    pub leaf_indexed: bool,
    pub leaf_pointer: bool,
    /// The indexed element, rather than the field itself, is consumed as a
    /// pointer (`free(x->items[i])`). The field therefore needs pointer depth
    /// two, not the ordinary one-level indexed-buffer shape.
    pub leaf_index_element_pointer: bool,
    pub leaf_callable: bool,
    pub max_index: usize,
}

/// Extract every field-access chain rooted at a variable / parameter declared
/// with type `type_name` (with or without pointer / const decoration) across the
/// translation unit. Returns empty when the type is never field-accessed — the
/// caller then keeps the `void *` placeholder.
pub fn field_access_paths(
    source: &str,
    type_name: &str,
) -> Result<Vec<FieldAccessPath>, CParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .map_err(|_| CParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CParseError::Parse)?;
    let bytes = source.as_bytes();
    let mut roots = std::collections::BTreeSet::new();
    collect_typed_roots(tree.root_node(), bytes, type_name, &mut roots);
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    collect_field_chains(tree.root_node(), bytes, &roots, &mut paths);
    Ok(paths)
}

/// Variable / parameter names declared with exactly `type_name` (the `type`
/// field of a parameter/variable/field declaration; const and pointer
/// decoration live in sibling nodes, so a plain text compare matches
/// `const CFE_MSG_Message_t *MsgPtr`).
fn collect_typed_roots(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    type_name: &str,
    roots: &mut std::collections::BTreeSet<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if matches!(
        node.kind(),
        "parameter_declaration" | "declaration" | "field_declaration"
    ) {
        if let Some(type_node) = node.child_by_field_name("type") {
            if type_node.utf8_text(bytes).map(str::trim) == Ok(type_name) {
                if let Some(decl) = node.child_by_field_name("declarator") {
                    collect_declarator_idents(decl, bytes, roots);
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_typed_roots(child, bytes, type_name, roots);
    }
}

fn collect_declarator_idents(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    roots: &mut std::collections::BTreeSet<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    match node.kind() {
        "identifier" => {
            if let Ok(name) = node.utf8_text(bytes) {
                roots.insert(name.to_owned());
            }
        }
        "pointer_declarator" | "array_declarator" | "init_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                collect_declarator_idents(inner, bytes, roots);
            }
        }
        _ => {}
    }
}

fn collect_field_chains(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    roots: &std::collections::BTreeSet<String>,
    paths: &mut Vec<FieldAccessPath>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    // Only the *outermost* field_expression of a chain (its parent is not
    // itself a field_expression) carries the full path; inner ones are bases.
    if node.kind() == "field_expression"
        && node
            .parent()
            .map(|p| p.kind() != "field_expression")
            .unwrap_or(true)
    {
        if let Some((root, components, self_pointer_components)) = chain_components(node, bytes) {
            if roots.contains(&root) && !components.is_empty() {
                let (leaf_indexed, max_index) = leaf_index_info(node, bytes);
                paths.push(FieldAccessPath {
                    components,
                    self_pointer_components,
                    leaf_indexed,
                    leaf_pointer: leaf_pointer_info(node, bytes),
                    leaf_index_element_pointer: leaf_index_element_pointer_info(node, bytes),
                    leaf_callable: leaf_callable_info(node),
                    max_index,
                });
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_field_chains(child, bytes, roots, paths);
    }
}

/// Walk a field_expression down its `argument` spine, collecting member names.
/// Returns `(root_identifier, [field, ...])` (root-first) when the spine bottoms
/// out at a plain identifier; `None` when the root is a cast/subscript/call/etc.
fn chain_components(
    field_expr: tree_sitter::Node<'_>,
    bytes: &[u8],
) -> Option<(String, Vec<String>, Vec<usize>)> {
    let mut components = Vec::new();
    let mut operators = Vec::new();
    let mut cur = field_expr;
    loop {
        match cur.kind() {
            "field_expression" => {
                let argument = cur.child_by_field_name("argument")?;
                let field = cur.child_by_field_name("field")?;
                components.push(field.utf8_text(bytes).ok()?.to_owned());
                operators.push(
                    std::str::from_utf8(&bytes[argument.end_byte()..field.start_byte()])
                        .ok()?
                        .trim()
                        .to_owned(),
                );
                cur = argument;
            }
            "identifier" => {
                let root = cur.utf8_text(bytes).ok()?.to_owned();
                components.reverse();
                operators.reverse();
                let self_pointer_components = operators
                    .iter()
                    .enumerate()
                    .skip(1)
                    .filter_map(|(index, operator)| (operator == "->").then_some(index - 1))
                    .collect();
                return Some((root, components, self_pointer_components));
            }
            "parenthesized_expression" => {
                cur = cur.named_child(0)?;
            }
            _ => return None,
        }
    }
}

fn leaf_pointer_info(field_expr: tree_sitter::Node<'_>, bytes: &[u8]) -> bool {
    expression_pointer_context(field_expr, bytes)
}

fn leaf_index_element_pointer_info(field_expr: tree_sitter::Node<'_>, bytes: &[u8]) -> bool {
    let mut node = field_expr;
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "parenthesized_expression" => node = parent,
            "subscript_expression" => return expression_pointer_context(parent, bytes),
            _ => return false,
        }
    }
    false
}

fn expression_pointer_context(expression: tree_sitter::Node<'_>, bytes: &[u8]) -> bool {
    let mut node = expression;
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "parenthesized_expression" => node = parent,
            "cast_expression" => {
                return parent
                    .child_by_field_name("type")
                    .and_then(|ty| ty.utf8_text(bytes).ok())
                    .is_some_and(|ty| ty.contains('*'));
            }
            "pointer_expression" => {
                let operator = parent
                    .child(0)
                    .and_then(|op| op.utf8_text(bytes).ok())
                    .unwrap_or("");
                return operator == "*";
            }
            // A comparison with NULL is not enough to establish pointer type:
            // C integer flags are routinely compared with zero/NULL-compatible
            // constants, and a larger `a == NULL || (x->flags & BIT)` expression
            // must not turn `flags` into `void *`.
            "binary_expression" => return false,
            "assignment_expression" => {
                let field_is_left = parent.child_by_field_name("left").is_some_and(|left| {
                    left.start_byte() <= expression.start_byte()
                        && left.end_byte() >= expression.end_byte()
                });
                if field_is_left {
                    return parent
                        .child_by_field_name("right")
                        .and_then(|right| right.utf8_text(bytes).ok())
                        .is_some_and(|right| {
                            right.trim() == "NULL"
                                || right.contains("malloc(")
                                || right.contains("calloc(")
                                || right.contains("realloc(")
                                || right.trim_start().starts_with('(') && right.contains("*)")
                        });
                }
                return false;
            }
            "argument_list" => {
                let callee = parent
                    .parent()
                    .filter(|call| call.kind() == "call_expression")
                    .and_then(|call| call.child_by_field_name("function"))
                    .and_then(|function| function.utf8_text(bytes).ok())
                    .unwrap_or("");
                return matches!(
                    callee,
                    "free"
                        | "realloc"
                        | "strlen"
                        | "strcpy"
                        | "strncpy"
                        | "strcmp"
                        | "strncmp"
                        | "strchr"
                        | "memcpy"
                        | "memmove"
                        | "memcmp"
                        | "memset"
                );
            }
            _ => return false,
        }
    }
    false
}

/// Whether the leaf field is used as the callee of a call expression, e.g.
/// `hooks->allocate(size)`. This is stronger evidence than argument decay or a
/// scalar read and lets the synthetic struct expose an old-style function
/// pointer that accepts the observed call without guessing its ABI.
fn leaf_callable_info(field_expr: tree_sitter::Node<'_>) -> bool {
    let mut node = field_expr;
    while let Some(parent) = node.parent() {
        if parent.kind() == "parenthesized_expression" {
            node = parent;
            continue;
        }
        if parent.kind() != "call_expression" {
            return false;
        }
        return parent
            .child_by_field_name("function")
            .is_some_and(|function| {
                function.start_byte() <= field_expr.start_byte()
                    && function.end_byte() >= field_expr.end_byte()
            });
    }
    false
}

/// Whether the leaf field is array-shaped, and the largest constant index seen
/// at this site. A field is array-shaped when it is subscripted
/// (`...StreamId[0]`) OR passed by name as a call argument (`f(...Sequence,...)`),
/// where it decays to a pointer — CCSDS `Sequence`/`Length` are `uint8[2]` read
/// through byte-pointer macros and would otherwise be mis-inferred as scalars
/// (`error: incompatible integer to pointer conversion`). Address-of
/// (`&...field`) decays the same way.
fn leaf_index_info(field_expr: tree_sitter::Node<'_>, bytes: &[u8]) -> (bool, usize) {
    // Default size for a pointer-decayed (non-subscripted) array leaf: large
    // enough that a callee reading a few header bytes stays in bounds.
    const DECAY_ARRAY_MAX_INDEX: usize = 7; // -> length 8
    if let Some(parent) = field_expr.parent() {
        match parent.kind() {
            "subscript_expression" => {
                let idx = parent
                    .child_by_field_name("index")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    .and_then(|t| t.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                return (true, idx);
            }
            "argument_list" | "pointer_expression" => return (true, DECAY_ARRAY_MAX_INDEX),
            _ => {}
        }
    }
    (false, 0)
}

fn is_c_declaration_decoration(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "__cdecl"
            | "__stdcall"
            | "__fastcall"
            | "__thiscall"
            | "__vectorcall"
            | "_cdecl"
            | "_stdcall"
            | "_fastcall"
            | "mi_cdecl"
    ) {
        return true;
    }
    if lower.contains("attr_")
        || lower.ends_with("_noexcept")
        || lower.ends_with("_nothrow")
        || lower.ends_with("_callconv")
    {
        return true;
    }
    let upper = token.to_ascii_uppercase();
    [
        "_API",
        "_EXPORT",
        "_IMPORT",
        "_PUBLIC",
        "INLINE",
        "NODISCARD",
        "DEPRECATED",
        "NORETURN",
        "WARN_UNUSED",
        "VISIBILITY",
        "CALLCONV",
    ]
    .iter()
    .any(|marker| upper.contains(marker))
}

/// Blank known declaration-decoration macros before feeding headers to
/// tree-sitter-c. Legacy libraries commonly place calling conventions between
/// the return type and name and attribute macros after the parameter list:
/// `void mi_cdecl f(void) mi_attr_noexcept;`. Those identifiers are expanded by
/// the real preprocessor, but as raw source they can hide the prototype or turn
/// the macro into its apparent return type. Replacing only recognized tokens,
/// while preserving bytes and newlines, keeps declaration locations stable.
fn prepare_c_declaration_source(source: &str) -> String {
    let bytes = source.as_bytes();
    let is_ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut out = bytes.to_vec();
    let mut i = 0usize;
    let mut line_is_directive = false;
    let mut at_line_start = true;
    while i < bytes.len() {
        if at_line_start {
            let mut cursor = i;
            while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
                cursor += 1;
            }
            line_is_directive = bytes.get(cursor) == Some(&b'#');
            at_line_start = false;
        }
        if bytes[i] == b'\n' {
            at_line_start = true;
            i += 1;
            continue;
        }
        if line_is_directive || !is_ident(bytes[i]) || (i > 0 && is_ident(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_ident(bytes[i]) {
            i += 1;
        }
        if is_c_declaration_decoration(&source[start..i]) {
            for byte in &mut out[start..i] {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_owned())
}

pub fn parse_c_declarations(source: &str) -> Result<Vec<CDeclaration>, CParseError> {
    let source = prepare_c_declaration_source(source);
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .map_err(|_| CParseError::Grammar)?;
    let tree = parser.parse(&source, None).ok_or(CParseError::Parse)?;
    let mut decls = Vec::new();
    collect_declarations(tree.root_node(), source.as_bytes(), &mut decls);
    Ok(decls)
}

pub fn parse_c_type_defs(source: &str) -> Result<CTypeDefs, CParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .map_err(|_| CParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CParseError::Parse)?;
    let mut defs = CTypeDefs::default();
    collect_type_defs(tree.root_node(), source.as_bytes(), &mut defs);
    // tree-sitter does not surface object-like `#define` macros as types, so a
    // `#define ID3TAG_U32 unsigned int`-style type alias otherwise reads as an
    // opaque type and the whole target is skipped. Register such macros as typedefs.
    collect_define_type_aliases(source, &mut defs);
    // A forward declaration (`struct opaque;`) and the full definition
    // can both appear; keep the complete one under each name.
    let mut keep: Vec<CStructDef> = Vec::with_capacity(defs.structs.len());
    for d in defs.structs.drain(..) {
        match keep.iter_mut().find(|k| k.name == d.name) {
            Some(existing) => {
                if d.complete && !existing.complete {
                    *existing = d;
                }
            }
            None => keep.push(d),
        }
    }
    defs.structs = keep;
    Ok(defs)
}

pub fn extract_c_dictionary_tokens(source: &str) -> Result<Vec<String>, CParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .map_err(|_| CParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CParseError::Parse)?;
    let mut tokens = Vec::new();

    for enum_def in parse_c_type_defs(source)?.enums {
        for member in enum_def.members {
            push_dictionary_token(&mut tokens, member);
        }
    }
    collect_c_string_dictionary_tokens(tree.root_node(), source.as_bytes(), &mut tokens);
    collect_c_case_dictionary_tokens(tree.root_node(), source.as_bytes(), &mut tokens);
    collect_c_comparison_dictionary_tokens(tree.root_node(), source.as_bytes(), &mut tokens);
    collect_c_define_dictionary_tokens(source, &mut tokens);

    Ok(tokens)
}

/// Mine literal operands of equality/relational comparisons
/// (`== != < <= > >=`) — the magic-byte, sentinel, and length gates a parser
/// checks. Scalar `==` is a CPU compare (no libc call the runtrace shim can
/// hook), so static mining is the only way these reach the dictionary (#379).
fn collect_c_comparison_dictionary_tokens(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    tokens: &mut Vec<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.kind() == "binary_expression" {
        if let Some(op) = node.child_by_field_name("operator") {
            if let Ok(op) = op.utf8_text(source) {
                if matches!(op, "==" | "!=" | "<" | "<=" | ">" | ">=") {
                    for field in ["left", "right"] {
                        if let Some(operand) = node.child_by_field_name(field) {
                            if matches!(
                                operand.kind(),
                                "number_literal" | "char_literal" | "string_literal"
                            ) {
                                if let Ok(text) = operand.utf8_text(source).map(str::trim) {
                                    push_c_case_label_dictionary_token(text, tokens);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_c_comparison_dictionary_tokens(child, source, tokens);
    }
}

fn collect_c_string_dictionary_tokens(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    tokens: &mut Vec<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.kind() == "string_literal" {
        if let Ok(raw) = node.utf8_text(source) {
            if let Some(value) = c_string_literal_value(raw) {
                push_dictionary_token(tokens, value);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_c_string_dictionary_tokens(child, source, tokens);
    }
}

/// Collect object-like `#define NAME <C-type>` macros (e.g. `#define ID3TAG_U32
/// unsigned int`, `#define MZ_U32 unsigned int`) as type aliases. A library that
/// types a parameter with such a macro otherwise reads as an opaque type and the
/// whole target is skipped ("no byte-buffer decoder ... opaque type"). Conservative:
/// only register a value that is unambiguously a C type expression (builtin type
/// keywords / pointers, or a single `_t`-suffixed alias) — never a numeric/string
/// constant or an arbitrary identifier.
fn collect_define_type_aliases(source: &str, defs: &mut CTypeDefs) {
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("#define") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some((name, value)) = rest.split_once(char::is_whitespace) else {
            continue;
        };
        // Object-like only (a function-like macro has `(` adjacent to the name).
        if name.contains('(') || !is_c_identifier(name) {
            continue;
        }
        let value = value
            .split("//")
            .next()
            .unwrap_or("")
            .split("/*")
            .next()
            .unwrap_or("")
            .trim();
        if value.is_empty() || !value_is_c_type_expr(value) {
            continue;
        }
        // Don't shadow a real typedef/struct/enum of the same name.
        if defs.typedefs.iter().any(|t| t.name == name)
            || defs.structs.iter().any(|s| s.name == name)
            || defs.enums.iter().any(|e| e.name == name)
        {
            continue;
        }
        defs.typedefs.push(CTypedefDef {
            name: name.to_owned(),
            underlying: value.to_owned(),
            line: (idx + 1) as u32,
        });
    }
}

/// True when `value` is unambiguously a C type expression (so a `#define` of it is
/// a type alias, not a constant): every token is a builtin type keyword / pointer
/// star / cv-qualifier, or it is a single `_t`-suffixed type identifier.
fn value_is_c_type_expr(value: &str) -> bool {
    const TYPE_KW: &[&str] = &[
        "void", "char", "short", "int", "long", "unsigned", "signed", "float", "double", "_Bool",
        "const", "volatile",
    ];
    let toks: Vec<&str> = value.split_whitespace().collect();
    if toks.is_empty() {
        return false;
    }
    if toks.len() == 1 {
        let t = toks[0].trim_end_matches('*');
        if t.len() > 2
            && t.ends_with("_t")
            && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return true;
        }
    }
    toks.iter()
        .all(|t| TYPE_KW.contains(t) || t.chars().all(|c| c == '*'))
}

fn collect_c_define_dictionary_tokens(source: &str, tokens: &mut Vec<String>) {
    for line in source.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("#define") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some((name, value)) = rest.split_once(char::is_whitespace) else {
            continue;
        };
        if name.contains('(') {
            continue;
        }
        let value = value
            .split("//")
            .next()
            .unwrap_or("")
            .split("/*")
            .next()
            .unwrap_or("")
            .trim();
        let first = value.split_whitespace().next().unwrap_or("");
        if let Some(value) = c_string_literal_value(first) {
            push_dictionary_token(tokens, value);
        } else if is_c_integer_literal(first) {
            push_dictionary_token(tokens, first.to_owned());
        }
    }
}

fn collect_c_case_dictionary_tokens(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    tokens: &mut Vec<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.kind() == "case_statement" {
        if let Some(label) = node.child_by_field_name("value") {
            if let Ok(label) = label.utf8_text(source).map(str::trim) {
                push_c_case_label_dictionary_token(label, tokens);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_c_case_dictionary_tokens(child, source, tokens);
    }
}

fn push_c_case_label_dictionary_token(label: &str, tokens: &mut Vec<String>) {
    if label.is_empty() {
        return;
    }
    if let Some(value) = c_string_literal_value(label) {
        push_dictionary_token(tokens, value);
    } else if let Some(value) = c_char_literal_value(label) {
        push_dictionary_token(tokens, value);
    } else if is_c_integer_literal(label) || is_c_identifier(label) {
        push_dictionary_token(tokens, label.to_owned());
    }
}

fn c_string_literal_value(raw: &str) -> Option<String> {
    let start = raw.find('"')?;
    let end = raw.rfind('"')?;
    if end <= start {
        return None;
    }
    let mut out = String::new();
    let mut chars = raw[start + 1..end].chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('0') => out.push('\0'),
            Some(other) => out.push(other),
            None => break,
        }
    }
    Some(out)
}

fn c_char_literal_value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let body = raw.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut chars = body.chars();
    let ch = match chars.next()? {
        '\\' => match chars.next()? {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            '0' => '\0',
            '\\' => '\\',
            '\'' => '\'',
            other => other,
        },
        other => other,
    };
    Some(ch.to_string())
}

fn is_c_integer_literal(raw: &str) -> bool {
    let trimmed = raw
        .trim_start_matches(['+', '-'])
        .trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return !hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit());
    }
    !trimmed.is_empty() && trimmed.chars().all(|ch| ch.is_ascii_digit())
}

fn is_c_identifier(raw: &str) -> bool {
    let mut chars = raw.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !is_c_keyword(raw)
}

fn push_dictionary_token(tokens: &mut Vec<String>, token: String) {
    let token = token.trim().to_owned();
    if token.is_empty() || token.len() > 256 || tokens.contains(&token) {
        return;
    }
    tokens.push(token);
}

fn collect_type_defs(node: tree_sitter::Node<'_>, source: &[u8], defs: &mut CTypeDefs) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    match node.kind() {
        "struct_specifier" | "union_specifier" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok())
                .map(str::to_owned);
            if let Some(name) = name {
                if !is_c_keyword(&name) {
                    let body = node.child_by_field_name("body");
                    defs.structs.push(CStructDef {
                        name,
                        fields: body.map(|b| struct_fields(b, source)).unwrap_or_default(),
                        line: node.start_position().row as u32 + 1,
                        complete: body.is_some(),
                    });
                }
            }
        }
        "enum_specifier" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok())
                .map(str::to_owned);
            if let (Some(name), Some(body)) = (name, node.child_by_field_name("body")) {
                if !is_c_keyword(&name) {
                    defs.enums.push(CEnumDef {
                        name,
                        members: enum_members(body, source),
                        line: node.start_position().row as u32 + 1,
                    });
                }
            }
        }
        "type_definition" => {
            collect_typedef(node, source, defs);
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_type_defs(child, source, defs);
    }
}

fn collect_typedef(node: tree_sitter::Node<'_>, source: &[u8], defs: &mut CTypeDefs) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    // The alias name sits in a type_identifier, possibly wrapped in
    // pointer/array declarators (those make the alias non-scalar; we
    // record the raw underlying text either way).
    // For a function typedef, inspect only the declarator's name-bearing group.
    // Recursing through the whole function_declarator can encounter a parameter
    // type_identifier first and index the typedef under that parameter type
    // (`read_file_func` became a bogus second `voidpf` typedef in zlib).
    // Never scan inside a struct/union/enum body for a typedef-level function
    // pointer alias. Anonymous records commonly contain callback fields; the
    // old whole-node textual fallback mistook the first member (`next`) for the
    // outer alias (`bz_stream`) when a later member was a function pointer.
    let textual_funcptr_alias = (!matches!(
        type_node.kind(),
        "struct_specifier" | "union_specifier" | "enum_specifier"
    ))
    .then(|| function_pointer_typedef_alias(node, source))
    .flatten();
    let alias = textual_funcptr_alias.clone().unwrap_or_else(|| {
        if declarator.kind() == "function_declarator" {
            declarator
                .child_by_field_name("declarator")
                .map(|group| {
                    let name = funcptr_declarator_name(group, source);
                    if name.is_empty() {
                        type_identifier_text(group, source).unwrap_or_default()
                    } else {
                        name
                    }
                })
                .unwrap_or_default()
        } else {
            type_identifier_text(declarator, source).unwrap_or_default()
        }
    });
    if alias.is_empty() {
        return;
    }
    if is_c_keyword(&alias) {
        return;
    }
    let line = node.start_position().row as u32 + 1;

    // `typedef enum { .. } alias;` has no tag, so the alias is the only
    // stable name the type model can resolve. `typedef enum tag { .. } alias;`
    // keeps the tag and records the alias as a typedef to that tag.
    if type_node.kind() == "enum_specifier" {
        let enum_name = type_node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(str::to_owned)
            .unwrap_or_else(|| alias.clone());
        if !is_c_keyword(&enum_name) {
            if let Some(body) = type_node.child_by_field_name("body") {
                defs.enums.push(CEnumDef {
                    name: enum_name.clone(),
                    members: enum_members(body, source),
                    line,
                });
            }
            defs.typedefs.push(CTypedefDef {
                name: alias,
                underlying: format!("enum {enum_name}"),
                line,
            });
        }
        return;
    }

    if textual_funcptr_alias.is_some() || typedef_declarator_is_function_pointer(declarator, source)
    {
        if let Some(underlying) =
            function_pointer_typedef_underlying(type_node, declarator, source, &alias)
        {
            defs.typedefs.push(CTypedefDef {
                name: alias,
                underlying,
                line,
            });
        }
        return;
    }

    // `typedef struct { .. } alias;` — the anonymous struct's fields
    // belong to the alias name.
    if matches!(type_node.kind(), "struct_specifier" | "union_specifier")
        && type_node.child_by_field_name("name").is_none()
    {
        if let Some(body) = type_node.child_by_field_name("body") {
            defs.structs.push(CStructDef {
                name: alias,
                fields: struct_fields(body, source),
                line,
                complete: true,
            });
            return;
        }
    }
    // `typedef struct tag { .. } alias;` — record both the named
    // struct (the recursive walk handles it) and the alias mapping.
    let mut underlying = type_node
        .utf8_text(source)
        .map(typedef_underlying_text)
        .unwrap_or_default();
    if underlying.is_empty() {
        return;
    }
    for _ in 0..typedef_pointer_depth(declarator) {
        underlying.push_str(" *");
    }
    // Preserve an array dimension on the typedef (`typedef unsigned char
    // nd_uint8_t[1]` -> underlying `unsigned char [1]`). Dropping it made
    // tcpdump's `nd_uintN_t` resolve to a scalar, so a struct field of that type
    // was cast from a scalar (`(nd_uint8_t)gf_u8(...)` — illegal) instead of
    // filled element-wise.
    let array_suffix = typedef_array_suffix(declarator, source);
    if !array_suffix.is_empty() {
        underlying.push(' ');
        underlying.push_str(&array_suffix);
    }
    defs.typedefs.push(CTypedefDef {
        name: alias,
        underlying,
        line,
    });
}

/// The trailing array dimension(s) of a typedef declarator, e.g. `[1]` for
/// `nd_uint8_t[1]` (empty for non-array typedefs). Taken from the first `[` in
/// the declarator text — the name precedes it, pointer depth is handled
/// separately.
fn typedef_array_suffix(declarator: tree_sitter::Node<'_>, source: &[u8]) -> String {
    let Ok(text) = declarator.utf8_text(source) else {
        return String::new();
    };
    match text.find('[') {
        Some(i) => text[i..].split_whitespace().collect::<String>(),
        None => String::new(),
    }
}

fn typedef_declarator_is_function_pointer(
    declarator: tree_sitter::Node<'_>,
    source: &[u8],
) -> bool {
    declarator.kind() == "function_declarator"
        || declarator
            .utf8_text(source)
            .is_ok_and(|text| text.contains("(*") && text.contains(')'))
}

fn function_pointer_typedef_underlying(
    type_node: tree_sitter::Node<'_>,
    declarator: tree_sitter::Node<'_>,
    source: &[u8],
    alias: &str,
) -> Option<String> {
    let return_type = type_node
        .utf8_text(source)
        .ok()
        .map(typedef_underlying_text)?;
    if return_type.is_empty() {
        return None;
    }
    let declarator_text = declarator.utf8_text(source).ok()?.trim();
    let signature = if return_type.contains(alias) {
        // With an unknown calling-convention macro, tree-sitter can attach the
        // entire `(CONV *alias)` group to the type node and leave only the
        // parameter list as the declarator. Remove the alias where it actually
        // appears before assembling the abstract function-pointer spelling.
        normalize_type(&format!(
            "{} {declarator_text}",
            return_type.replacen(alias, "", 1)
        ))
    } else {
        let without_alias = declarator_text.replacen(alias, "", 1);
        normalize_type(&format!("{return_type} {without_alias}"))
    };
    (!signature.is_empty()).then_some(signature)
}

/// Recover the declared alias from a function-pointer typedef's source text.
/// Unknown calling-convention macros can make tree-sitter attach the outer
/// `(CONV *alias)` group to the type node, so AST-only name traversal falls into
/// the parameter list and mistakes its first type_identifier for the alias.
fn function_pointer_typedef_alias(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let text = node.utf8_text(source).ok()?;
    for (star, _) in text.match_indices('*') {
        let after_star = text[star + 1..].trim_start();
        let ident_len = after_star
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .map(char::len_utf8)
            .sum::<usize>();
        if ident_len == 0 {
            continue;
        }
        let alias = &after_star[..ident_len];
        let after_alias = after_star[ident_len..].trim_start();
        let Some(close) = after_alias.find(')') else {
            continue;
        };
        if after_alias[close + 1..].trim_start().starts_with('(') {
            return Some(alias.to_owned());
        }
    }
    None
}

fn typedef_pointer_depth(declarator: tree_sitter::Node<'_>) -> usize {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return 0;
    };
    if declarator.kind() == "pointer_declarator" {
        return 1 + declarator
            .child_by_field_name("declarator")
            .map(typedef_pointer_depth)
            .unwrap_or(0);
    }
    0
}

/// `struct point { ... }` referenced as a typedef target reads as the
/// full definition text; collapse it to the reference form
/// (`struct point`). Plain scalar targets pass through trimmed.
fn typedef_underlying_text(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(brace) = trimmed.find('{') {
        trimmed[..brace].trim().to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn type_identifier_text(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let _depth_guard = AstDepthGuard::enter()?;
    if node.kind() == "type_identifier" {
        return node.utf8_text(source).ok().map(str::to_owned);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = type_identifier_text(child, source) {
            return Some(found);
        }
    }
    None
}

fn struct_fields(body: tree_sitter::Node<'_>, source: &[u8]) -> Vec<CParamDescriptor> {
    let mut fields = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() != "field_declaration" {
            continue;
        }
        let Some(type_node) = child.child_by_field_name("type") else {
            continue;
        };
        let base_type = type_node
            .utf8_text(source)
            .map(typedef_underlying_text)
            .unwrap_or_default();
        if base_type.is_empty() {
            continue;
        }
        // A field_declaration can carry several declarators
        // (`int x, *y, z[4];`); each gets its own descriptor with the
        // pointer/array decoration recovered from its wrapper nodes.
        let mut field_cursor = child.walk();
        for part in child.children(&mut field_cursor) {
            if let Some(descriptor) = field_descriptor(part, source, &base_type) {
                fields.push(descriptor);
            }
        }
    }
    fields
}

fn field_descriptor(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    base_type: &str,
) -> Option<CParamDescriptor> {
    let _depth_guard = AstDepthGuard::enter()?;
    match node.kind() {
        "field_identifier" => Some(CParamDescriptor {
            name: node.utf8_text(source).ok()?.to_owned(),
            c_type: base_type.to_owned(),
        }),
        "pointer_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            let mut descriptor = field_descriptor(inner, source, base_type)?;
            descriptor.c_type = format!("{} *", descriptor.c_type);
            Some(descriptor)
        }
        "array_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            let descriptor = field_descriptor(inner, source, base_type)?;
            let size = node
                .child_by_field_name("size")
                .and_then(|s| s.utf8_text(source).ok())
                .unwrap_or("");
            Some(CParamDescriptor {
                name: descriptor.name,
                c_type: format!("{}[{}]", descriptor.c_type, size),
            })
        }
        "function_declarator" => {
            // A function-pointer field — `RET (*name)(params)` (an inline callback,
            // the cmp/hash slots of a hashmap struct) or an array of them
            // `RET (*name[N])(params)` (a callback dispatch table). Reconstruct the
            // canonical funcptr type so the type model resolves it (FuncPtr, or an
            // array whose element is FuncPtr) and the decoder synthesises a
            // trampoline, instead of dropping the field or recording a signature-less
            // `RET (*)()` the decoder cannot drive (§27.3/§27.9).
            funcptr_field_descriptor(node, source, base_type)
        }
        _ => None,
    }
}

/// Reconstruct a function-pointer struct/union FIELD from its `function_declarator`
/// node, mirroring `function_params` for parameters. Emits the canonical funcptr type
/// `RET (*)(params)` (so the type model resolves it to `FuncPtr` and the decoder
/// synthesises a no-op trampoline) and recovers the field name from the parenthesized
/// pointer declarator. A callback ARRAY — `RET (*name[N])(params)` — is emitted as
/// `RET (*)(params)[N]` so the type model resolves it to an array whose element is a
/// function pointer (§27.3). Returns `None` for an unnamed funcptr field (no usable
/// member name) so the caller leaves it out.
fn funcptr_field_descriptor(
    func_decl: tree_sitter::Node<'_>,
    source: &[u8],
    ret: &str,
) -> Option<CParamDescriptor> {
    let inner_params = func_decl
        .child_by_field_name("parameters")
        .and_then(|n| n.utf8_text(source).ok())
        .map(normalize_type)
        .unwrap_or_else(|| "(void)".to_owned());
    // The parenthesized declarator group `(*name)` / `(*name[N])` — or with a
    // calling convention `(CJSON_CDECL *name)` — holds the field name and any array
    // dimension. `funcptr_declarator_name` reads the name from the `*name` pointer
    // declarator so a leading convention macro (cJSON's `CJSON_CDECL`, empty on
    // Linux) is not mistaken for the field name (which then emitted `.<empty> =`).
    let group = func_decl.child_by_field_name("declarator")?;
    let name = funcptr_declarator_name(group, source);
    if name.is_empty() {
        return None;
    }
    let array_suffix = declarator_array_suffix(group, source);
    let c_type = normalize_type(&format!("{ret} (*){inner_params}{array_suffix}"));
    if c_type.is_empty() || c_type == "(*)(void)" {
        return None;
    }
    Some(CParamDescriptor { name, c_type })
}

/// The first `[N]` array dimension found under a declarator subtree, e.g. `[4]` for
/// the `(*handlers[4])` group of a callback-array field. Empty when no array
/// declarator is present (a plain `(*name)` funcptr).
fn declarator_array_suffix(node: tree_sitter::Node<'_>, source: &[u8]) -> String {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return String::new();
    };
    if node.kind() == "array_declarator" {
        let size = node
            .child_by_field_name("size")
            .and_then(|s| s.utf8_text(source).ok())
            .unwrap_or("");
        return format!("[{}]", size.trim());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let found = declarator_array_suffix(child, source);
        if !found.is_empty() {
            return found;
        }
    }
    String::new()
}

fn enum_members(body: tree_sitter::Node<'_>, source: &[u8]) -> Vec<String> {
    let mut members = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() != "enumerator" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let Ok(name) = name_node.utf8_text(source) else {
            continue;
        };
        // Skip an X-macro invocation mis-parsed as an enumerator: a body like
        // `enum http_errno { HTTP_ERRNO_MAP(HTTP_ERRNO_GEN) };` has no literal
        // enumerators — the real variant names come from expanding the macro,
        // which we cannot do. tree-sitter labels `HTTP_ERRNO_MAP` an enumerator
        // name, but the next non-whitespace byte after it is `(`, marking a
        // function-like-macro call rather than a `NAME`/`NAME = value`
        // enumerator. Emitting it as a constant (`(enum E)HTTP_ERRNO_MAP`) does
        // not compile, so drop it; the decoder falls back to a bounded int.
        let after = &source[name_node.end_byte()..];
        let next = after
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .map(|i| after[i]);
        if next == Some(b'(') {
            continue;
        }
        members.push(name.to_owned());
    }
    members
}

fn collect_declarations(node: tree_sitter::Node<'_>, source: &[u8], decls: &mut Vec<CDeclaration>) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.kind() == "function_definition" {
        // Has a body - parse_c_functions handles it.
        return;
    }
    if node.kind() == "declaration" {
        if let Some(declarator) = find_function_declarator(node) {
            if let Some(name) = macro_wrapped_name(declarator, source).or_else(|| {
                function_identifier(declarator)
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(str::to_owned)
            }) {
                if !is_c_keyword(&name) {
                    let return_type = declaration_return_type(node, source);
                    let param_types = function_param_types(declarator, source);
                    decls.push(CDeclaration {
                        name,
                        return_type,
                        param_types,
                        variadic: parameter_list_is_variadic(declarator),
                        line: node.start_position().row as u32 + 1,
                    });
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_declarations(child, source, decls);
    }
}

fn find_function_declarator<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let _depth_guard = AstDepthGuard::enter()?;
    if node.kind() == "function_declarator" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_function_declarator(child) {
            return Some(found);
        }
    }
    None
}

fn declaration_return_type(decl: tree_sitter::Node<'_>, source: &[u8]) -> String {
    let Some(type_node) = decl.child_by_field_name("type") else {
        return String::new();
    };

    // Collect leading type_qualifier siblings (const, volatile, restrict).
    // tree-sitter-c exposes them as direct children of the declaration,
    // siblings of the type field rather than children of it. Without this
    // scan, `extern const decoder_t * foo(...)` yields a return type of
    // `decoder_t *` and the synthesised stub link-fails against any
    // upstream consumer that took the const form.
    let mut leading_quals = Vec::<String>::new();
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        if child.start_byte() >= type_node.start_byte() {
            break;
        }
        if child.kind() == "type_qualifier" {
            if let Ok(text) = child.utf8_text(source) {
                leading_quals.push(text.trim().to_owned());
            }
        }
    }

    // Prefer the raw prefix before the declarator over the `type`
    // field alone. Macro-decorated prototypes such as
    // `MINIZ_EXPORT int mz_uncompress(...)` expose `MINIZ_EXPORT`
    // as the tree-sitter `type` field and leave the real `int` as a
    // sibling. Reading the prefix lets us recover the real return
    // type, then strip storage/export decoration below.
    let mut return_type = decl
        .child_by_field_name("declarator")
        .and_then(|declarator| {
            std::str::from_utf8(&source[decl.start_byte()..declarator.start_byte()])
                .ok()
                .map(normalize_return_type_prefix)
        })
        .unwrap_or_default();
    // Unknown decoration macros can make tree-sitter recover by starting the
    // declaration node after part of the type (`ZEXTERN int ZEXPORT f`, or
    // `__LA_DECL struct archive *f`). Retry from the physical line start and
    // prefer it when it restores a concrete builtin/tag marker absent from the
    // apparent return type.
    if let Some(declarator) = decl.child_by_field_name("declarator") {
        let line_start = source[..decl.start_byte()]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index.saturating_add(1));
        if let Ok(prefix) = std::str::from_utf8(&source[line_start..declarator.start_byte()]) {
            let recovered = normalize_return_type_prefix(prefix);
            let has_type_marker = |text: &str| {
                text.split_whitespace()
                    .any(|part| is_c_builtin_type_word(part) || is_c_tag_keyword(part))
            };
            if has_type_marker(&recovered) && !has_type_marker(&return_type) {
                return_type = recovered;
            }
        }
    }
    if return_type.is_empty() {
        let Ok(type_text) = type_node.utf8_text(source) else {
            return String::new();
        };
        return_type = if leading_quals.is_empty() {
            type_text.trim().to_owned()
        } else {
            format!("{} {}", leading_quals.join(" "), type_text.trim())
        };
    }

    // The `declarator` field of an extern prototype may be a
    // `pointer_declarator` wrapping the `function_declarator`. The
    // leading `*`/`&` characters belong to the return type, not the
    // declarator name. Walk pointer_declarator wrappers and collect
    // each `*` / `&` so `decoder_t * foo(...)` yields `decoder_t *`,
    // not just `decoder_t`.
    let mut pointer_suffix = String::new();
    if let Some(mut node) = decl.child_by_field_name("declarator") {
        loop {
            match node.kind() {
                "pointer_declarator" => {
                    pointer_suffix.push('*');
                    match node.child_by_field_name("declarator") {
                        Some(child) => node = child,
                        None => break,
                    }
                }
                "reference_declarator" => {
                    pointer_suffix.push('&');
                    match node.child_by_field_name("declarator") {
                        Some(child) => node = child,
                        None => break,
                    }
                }
                _ => break,
            }
        }
    }
    if !pointer_suffix.is_empty() {
        return_type.push(' ');
        return_type.push_str(&pointer_suffix);
    }
    return_type
}

fn normalize_return_type_prefix(prefix: &str) -> String {
    let mut parts = prefix
        .split_whitespace()
        .filter(|part| {
            !matches!(
                *part,
                "extern" | "static" | "inline" | "__inline" | "__inline__"
            )
        })
        .collect::<Vec<_>>();
    while parts.len() > 1
        && (is_export_macro_token(parts[0])
            || (is_macro_shaped_token(parts[0])
                && parts
                    .iter()
                    .skip(1)
                    .any(|part| is_c_builtin_type_word(part) || is_c_tag_keyword(part))))
    {
        parts.remove(0);
    }
    // Some legacy headers use linkage macros whose names do not contain the
    // usual API/EXPORT marker, or place a calling-convention macro after the
    // actual type (`__LA_DECL int`, `ZEXTERN int ZEXPORT`). Once a concrete C
    // builtin is present, macro-shaped tokens are decorations rather than the
    // return type. Keep an all-caps typedef intact when no builtin is present.
    if parts.iter().any(|part| is_c_builtin_type_word(part)) {
        parts.retain(|part| is_c_builtin_type_word(part) || !is_macro_shaped_token(part));
    }
    parts.join(" ")
}

fn is_c_builtin_type_word(token: &str) -> bool {
    matches!(
        token,
        "void"
            | "char"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "signed"
            | "unsigned"
            | "_Bool"
            | "bool"
            | "const"
            | "volatile"
            | "restrict"
            | "_Atomic"
    )
}

fn is_c_tag_keyword(token: &str) -> bool {
    matches!(token, "struct" | "union" | "enum")
}

fn is_macro_shaped_token(token: &str) -> bool {
    token.chars().any(|ch| ch.is_ascii_alphabetic())
        && token
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn is_export_macro_token(token: &str) -> bool {
    token
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        && (token.contains("EXPORT")
            || token.contains("API")
            || token.contains("PUBLIC")
            || token.contains("INLINE")
            || token.contains("STATIC"))
}

fn function_param_types(declarator: tree_sitter::Node<'_>, source: &[u8]) -> Vec<String> {
    let Some(params_node) = declarator.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = params_node.walk();
    for child in params_node.children(&mut cursor) {
        if child.kind() != "parameter_declaration" {
            continue;
        }
        let declarator_node = child.child_by_field_name("declarator");
        // An inline function-pointer parameter — `int (*cb)(int, int)`, or the
        // pointer-returning `void *(*alloc)(void *, size_t)` — must keep its full
        // type through the DECLARATION path too, exactly as `function_params` does
        // for the definition path. Without this the declarator collapses to the bare
        // return type (`int`) and the funcptr is lost, so a prototype-only target's
        // callback param can be neither stubbed nor driven (§27.9).
        if let Some(decl) = declarator_node {
            if let Some(func_decl) = funcptr_declarator(decl) {
                let ret = std::str::from_utf8(&source[child.start_byte()..func_decl.start_byte()])
                    .map(|s| s.trim().to_owned())
                    .unwrap_or_default();
                let inner_params = func_decl
                    .child_by_field_name("parameters")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(normalize_type)
                    .unwrap_or_else(|| "(void)".to_owned());
                let c_type = normalize_type(&format!("{ret} (*){inner_params}"));
                if !c_type.is_empty() && c_type != "(*)(void)" {
                    out.push(c_type);
                }
                continue;
            }
        }
        // Capture everything before the declarator as the type text so we
        // keep qualifiers like `const`, `volatile`, and `unsigned`. Falls
        // back to the `type` field for parameters with no declarator.
        let raw_type = match declarator_node {
            Some(decl) => {
                let start = child.start_byte();
                let end = decl.start_byte();
                std::str::from_utf8(&source[start..end])
                    .map(|s| s.trim().to_owned())
                    .unwrap_or_default()
            }
            None => child
                .child_by_field_name("type")
                .and_then(|n| n.utf8_text(source).ok())
                .map(|s| s.trim().to_owned())
                .unwrap_or_default(),
        };
        let pointer_suffix = declarator_node
            .and_then(|d| d.utf8_text(source).ok())
            .map(str::to_owned)
            .unwrap_or_default();
        // Use the same declarator split the real harness path uses so an array
        // parameter decays to a pointer (`cv[8]` -> `*`, `*data[4]` -> `**`),
        // keeping the stub signature compatible with the real prototype.
        let (_, stars) = split_declarator(&pointer_suffix);
        if raw_type == "void" && stars.is_empty() {
            continue;
        }
        if raw_type.is_empty() && stars.is_empty() {
            continue;
        }
        let full = if stars.is_empty() {
            raw_type
        } else if raw_type.is_empty() {
            stars
        } else {
            format!("{raw_type} {stars}")
        };
        out.push(full);
    }
    out
}

/// Keywords that can never be function names. tree-sitter's error
/// recovery on preprocessor-split control flow (an #ifdef between an
/// `if` and its `else if`, miniz.c style) can mangle a statement into
/// a function_definition whose declarator reads `if (cond)`.
const C_KEYWORDS: &[&str] = &[
    "if", "else", "for", "while", "do", "switch", "case", "default", "return", "sizeof", "goto",
    "break", "continue", "typedef", "struct", "union", "enum", "static", "extern", "inline",
    "const", "volatile", "register", "auto", "unsigned", "signed", "int", "char", "long", "short",
    "float", "double", "void",
];

fn is_c_keyword(name: &str) -> bool {
    C_KEYWORDS.contains(&name)
}

fn immediately_preceding_preproc_has_static(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let Some(prefix) = source
        .get(..node.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
    else {
        return false;
    };
    let lines: Vec<&str> = prefix.lines().collect();
    let Some(end) = lines.iter().rposition(|line| !line.trim().is_empty()) else {
        return false;
    };
    if !lines[end].trim_start().starts_with("#endif") {
        return false;
    }

    let mut depth = 0usize;
    let mut start = None;
    for index in (0..=end).rev() {
        let line = lines[index].trim_start();
        if line.starts_with("#endif") {
            depth += 1;
        } else if line.starts_with("#if") {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                start = Some(index);
                break;
            }
        }
    }
    let Some(start) = start else {
        return false;
    };

    lines[start + 1..end].iter().any(|line| {
        let line = line.trim_start();
        !line.starts_with('#')
            && line
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|token| token == "static")
    })
}

fn has_static_storage(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    // Function bodies can contain thousands of nested expression nodes. Walk
    // iteratively so looking for a declaration-level storage specifier cannot
    // overflow the thread stack on otherwise valid deep input.
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "storage_class_specifier"
            && current.utf8_text(source).is_ok_and(|text| text == "static")
        {
            return true;
        }
        let mut cursor = current.walk();
        pending.extend(current.children(&mut cursor));
    }
    immediately_preceding_preproc_has_static(node, source)
}

// RTOS/vendor platform macros are foreign on ANY host (a Linux/Windows lab box
// can't run a VxWorks/INTEGRITY/QNX image), so they appear in both variants. A
// `#ifdef __vxworks` branch is then tagged + routed to a stub-isolated build.
#[cfg(not(windows))]
const FOREIGN_PLATFORM_MACROS: &[&str] = &[
    "_WIN32",
    "_WIN64",
    "_MSC_VER",
    "__MINGW32__",
    "__MINGW64__",
    "__vxworks",
    "__VXWORKS__",
    "__INTEGRITY",
    "__QNX__",
    "__QNXNTO__",
];
#[cfg(windows)]
const FOREIGN_PLATFORM_MACROS: &[&str] = &[
    "__linux__",
    "__APPLE__",
    "__unix__",
    "__vxworks",
    "__VXWORKS__",
    "__INTEGRITY",
    "__QNX__",
    "__QNXNTO__",
];

/// `#ifdef FOO` → Some("FOO") when FOO is foreign. `#if <expr>` →
/// Some(expr) when the expr mentions a foreign macro and contains no
/// negation (`!`), so `#if !defined(_WIN32)` stays unflagged.
fn foreign_guard_of(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "preproc_ifdef" => {
            let directive = node.child(0)?.utf8_text(source).ok()?;
            if directive != "#ifdef" {
                return None; // #ifndef FOREIGN guards the *portable* branch
            }
            let name = node.child_by_field_name("name")?.utf8_text(source).ok()?;
            FOREIGN_PLATFORM_MACROS
                .contains(&name)
                .then(|| name.to_owned())
        }
        "preproc_if" => {
            let cond = node
                .child_by_field_name("condition")?
                .utf8_text(source)
                .ok()?;
            (!cond.contains('!') && FOREIGN_PLATFORM_MACROS.iter().any(|m| cond.contains(m)))
                .then(|| cond.trim().to_owned())
        }
        _ => None,
    }
}

/// `#if 0` bodies are dead by definition; only the #else/#elif
/// alternatives can be live.
fn is_dead_preproc_if(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    node.kind() == "preproc_if"
        && node
            .child_by_field_name("condition")
            .and_then(|c| c.utf8_text(source).ok())
            .is_some_and(|t| t.trim() == "0")
}

fn collect_functions(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    guard: Option<&str>,
    functions: &mut Vec<CFunction>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    let guard_outer = guard;
    if is_dead_preproc_if(node, source) {
        if let Some(alt) = node.child_by_field_name("alternative") {
            collect_functions(alt, source, guard_outer, functions);
        }
        return;
    }
    let own_guard = foreign_guard_of(node, source);
    let guard = own_guard.as_deref().or(guard_outer);

    if node.kind() == "function_definition" {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let macro_wrapped = macro_wrapped_name(declarator, source);
            let name_opt = macro_wrapped.clone().or_else(|| {
                function_identifier(declarator)
                    .and_then(|n| n.utf8_text(source).ok().map(str::to_owned))
            });
            if let Some(name) = name_opt {
                if !is_c_keyword(&name) {
                    let return_type = function_return_type(node, source);
                    let params = function_params(declarator, source);
                    let line = if let Some(id) = function_identifier(declarator) {
                        id.start_position().row as u32 + 1
                    } else {
                        node.start_position().row as u32 + 1
                    };
                    functions.push(CFunction {
                        name,
                        line,
                        return_type,
                        params,
                        is_static: has_static_storage(node, source),
                        foreign_guard: guard.map(str::to_owned),
                        variadic: parameter_list_is_variadic(declarator),
                    });
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // The #else/#elif branch of a foreign-guarded conditional is
        // the *non-foreign* branch — recurse with the outer guard.
        let child_guard = if matches!(child.kind(), "preproc_else" | "preproc_elif") {
            guard_outer
        } else {
            guard
        };
        collect_functions(child, source, child_guard, functions);
    }
}

/// Detect the export-macro-wrapped declarator shape:
///
/// ```text
/// function_declarator                    # outer (real params)
///   function_declarator                  # inner (the macro call)
///     identifier "BZ_API"                # macro name
///     parameter_list "(BZ2_bzWhatever)"  # macro's single arg
///       parameter_declaration
///         type_identifier "BZ2_bzWhatever"   # this is the REAL function name
///   parameter_list "(char *...)"         # REAL params
/// ```
///
/// Returns the real function name when the outer declarator's `declarator`
/// field is itself a function_declarator. Used for bzip2's `BZ_API`,
/// libxml2's `LIBXML_DLL_IMPORT`, libsodium's `SODIUM_EXPORT`, etc.
fn macro_wrapped_name(mut declarator: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    // Pointer-returning functions (`const char *BZ_API(name)(void)`) own the
    // return star in one or more pointer_declarator wrappers outside the real
    // function_declarator. Peel only that declarator spine before recognizing
    // the nested macro-call/real-parameter shape.
    while declarator.kind() == "pointer_declarator" {
        declarator = declarator.child_by_field_name("declarator")?;
    }
    if declarator.kind() != "function_declarator" {
        return None;
    }
    let inner = declarator.child_by_field_name("declarator")?;
    if inner.kind() != "function_declarator" {
        return None;
    }
    // Inner's parameter_list carries the real function name as a single
    // parameter_declaration's type_identifier.
    let inner_params = inner.child_by_field_name("parameters")?;
    let mut cursor = inner_params.walk();
    for child in inner_params.children(&mut cursor) {
        if child.kind() != "parameter_declaration" {
            continue;
        }
        // Either field name 'type' or first child works for the simple case.
        let target = child.child_by_field_name("type").unwrap_or(child);
        if let Ok(text) = target.utf8_text(source) {
            let name = text.trim();
            if !name.is_empty() {
                return Some(name.to_owned());
            }
        }
    }
    None
}

fn function_identifier<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let _depth_guard = AstDepthGuard::enter()?;
    if node.kind() == "identifier" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(id) = function_identifier(child) {
            return Some(id);
        }
    }
    None
}

fn function_return_type(def: tree_sitter::Node<'_>, source: &[u8]) -> String {
    let Some(type_node) = def.child_by_field_name("type") else {
        return String::new();
    };
    let mut return_type = def
        .child_by_field_name("declarator")
        .and_then(|declarator| {
            std::str::from_utf8(&source[def.start_byte()..declarator.start_byte()])
                .ok()
                .map(normalize_return_type_prefix)
        })
        .unwrap_or_default();
    if return_type.is_empty() {
        return_type = type_node
            .utf8_text(source)
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
    }
    // If the function_definition's declarator wraps the function_declarator in
    // a pointer_declarator (e.g. `xmlDoc *xmlReadMemory(...)`), the `*`s are
    // owned by the declarator, not the type. Walk the declarator tree to
    // recover them so the harness sees `xmlDoc *` instead of `xmlDoc`.
    let mut pointer_suffix = String::new();
    let mut cursor = def.child_by_field_name("declarator");
    while let Some(node) = cursor {
        if node.kind() != "pointer_declarator" {
            break;
        }
        pointer_suffix.push('*');
        cursor = node.child_by_field_name("declarator");
    }
    if pointer_suffix.is_empty() {
        return_type
    } else {
        format!("{return_type} {pointer_suffix}")
    }
}

/// Find the `function_declarator` (or unnamed `abstract_function_declarator`)
/// that makes a parameter a function pointer. A plain `int (*cb)(int)` IS the
/// function declarator; a pointer-returning funcptr `void *(*cb)(int)` nests it
/// inside one or more `pointer_declarator`s (the return-type star(s)). Returns
/// `None` for an ordinary (non-funcptr) declarator — e.g. a `pointer_declarator`
/// whose innermost child is a plain `identifier` (`void *user_data`).
fn funcptr_declarator(decl: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    match decl.kind() {
        "function_declarator" | "abstract_function_declarator" => Some(decl),
        "pointer_declarator" => funcptr_declarator(decl.child_by_field_name("declarator")?),
        _ => None,
    }
}

/// The first declared identifier in a declarator subtree — the parameter name,
/// e.g. `callback` from a function-pointer declarator `(*callback)(int, int)`.
/// Empty for an unnamed declarator (a forward-declaration `int (*)(int)`).
fn first_declarator_identifier(node: tree_sitter::Node<'_>, source: &[u8]) -> String {
    if matches!(node.kind(), "identifier" | "field_identifier") {
        return node.utf8_text(source).unwrap_or("").trim().to_owned();
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let found = first_declarator_identifier(child, source);
        if !found.is_empty() {
            return found;
        }
    }
    String::new()
}

/// Standard calling-convention keywords/macros that can decorate a
/// function-pointer declarator `RET (CONV *name)(args)`. A recognised keyword
/// (`__stdcall`) is modelled by tree-sitter as an `ms_call_modifier`; an UNKNOWN
/// project macro (`CJSON_CDECL`, `WINAPI`) is stranded in an `ERROR` node. Either
/// way it sits in the CONV slot, not the name.
const CALLING_CONVENTION_KEYWORDS: &[&str] = &[
    "__cdecl",
    "_cdecl",
    "cdecl",
    "__stdcall",
    "_stdcall",
    "stdcall",
    "__fastcall",
    "_fastcall",
    "__thiscall",
    "__vectorcall",
    "__pascal",
    "pascal",
    "WINAPI",
    "WINAPIV",
    "APIENTRY",
    "CALLBACK",
    "PASCAL",
    "STDMETHODCALLTYPE",
];

/// Whether `tok` is a calling-convention keyword or a project macro standing in for
/// one (`CJSON_CDECL`, `WINAPI`). Recognised keywords match case-insensitively; an
/// unknown all-caps macro-shaped token in the CONV position is treated as a
/// calling-convention decoration (the task's `CJSON_CDECL`/`XXH_PUBLIC_API` shape).
fn is_calling_convention_macro(tok: &str) -> bool {
    CALLING_CONVENTION_KEYWORDS
        .iter()
        .any(|kw| kw.eq_ignore_ascii_case(tok))
        || is_macro_shaped_qualifier(tok)
}

/// First `pointer_declarator` in document order under `node` (the `*name` group of
/// a function-pointer declarator), if any.
fn first_pointer_declarator<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let _depth_guard = AstDepthGuard::enter()?;
    if node.kind() == "pointer_declarator" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = first_pointer_declarator(child) {
            return Some(found);
        }
    }
    None
}

/// The declared name of a function-pointer declarator group, e.g. `allocate` from
/// `(CJSON_CDECL *allocate)` or `cb` from `(__stdcall *cb)`. The real name always
/// sits under the `*name` `pointer_declarator`; a leading calling-convention
/// keyword (`ms_call_modifier`) or UNKNOWN convention macro (`CJSON_CDECL`,
/// stranded in an `ERROR` node BEFORE the `*`) would otherwise be picked up by
/// [`first_declarator_identifier`] as the "first" identifier. Reading the name from
/// the pointer declarator skips the convention decoration. Returns an empty string
/// for an unnamed funcptr (`(*)` / `(CONV *)`), so the caller drops the field/param.
fn funcptr_declarator_name(group: tree_sitter::Node<'_>, source: &[u8]) -> String {
    if let Some(ptr) = first_pointer_declarator(group) {
        return first_declarator_identifier(ptr, source);
    }
    // No `*name` group (an unexpected shape): fall back to the first identifier that
    // is not a calling-convention decoration, so a CONV macro is never the name.
    let mut cursor = group.walk();
    for child in group.children(&mut cursor) {
        let id = first_declarator_identifier(child, source);
        if !id.is_empty() && !is_calling_convention_macro(&id) {
            return id;
        }
    }
    String::new()
}

/// Whether the function's parameter list ends in an ellipsis (`...`) — a
/// variadic function. tree-sitter-c models the `...` as a `variadic_parameter`
/// node inside the `parameter_list` (it is NOT a `parameter_declaration`, so it
/// is dropped by `function_params`). The same macro-wrapped declarator handling
/// as `function_params` is applied so the real parameter list is inspected.
fn parameter_list_is_variadic(mut declarator: tree_sitter::Node<'_>) -> bool {
    while declarator.kind() == "pointer_declarator" {
        let Some(inner) = declarator.child_by_field_name("declarator") else {
            return false;
        };
        declarator = inner;
    }
    let Some(list) = declarator
        .child_by_field_name("parameters")
        .or_else(|| find_parameter_list(declarator))
    else {
        return false;
    };
    let mut cursor = list.walk();
    let mut children = list.children(&mut cursor);
    children.any(|child| child.kind() == "variadic_parameter")
}

/// Whether `tok` is a `restrict`-style qualifier: the standard keyword spellings
/// (`restrict` / `__restrict` / `__restrict__`) or a project macro that expands to
/// one (xxHash's `XXH_RESTRICT`, glibc's `__restrict_arr`, the conventional
/// `RESTRICT` / `_Restrict`). Such a token sits in the parameter QUALIFIER
/// position — after the base type and any `*`, immediately before the parameter
/// name — exactly like `const`/`volatile`, and must be stripped, never treated as
/// a type or a name. Matched whole-word against the macro convention (any
/// underscore-separated segment is exactly `restrict`) so an ordinary identifier
/// like `restrictions` or `__restricted` is not stripped.
fn is_restrict_qualifier_macro(tok: &str) -> bool {
    tok.to_ascii_lowercase()
        .split('_')
        .any(|seg| seg == "restrict")
}

/// Whether `tok` is a macro-shaped qualifier decorator — an ALL-CAPS identifier
/// (uppercase, digits, underscores only, with at least one letter). Used solely to
/// disambiguate the first of two adjacent declarator identifiers
/// (`<type> * MACRO name`): in valid C the first must be a qualifier macro and the
/// second the real name. Real parameter names are conventionally not ALL-CAPS, so
/// this never strips a genuine lower/mixed-case name.
fn is_macro_shaped_qualifier(tok: &str) -> bool {
    !tok.is_empty()
        && tok.chars().any(|c| c.is_ascii_uppercase())
        && tok
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Recover the real parameter name that tree-sitter stranded in a trailing `ERROR`
/// sibling when an UNKNOWN restrict-qualifier macro sits between the `*` and the
/// name (`const void* XXH_RESTRICT input`). The grammar does not know
/// `XXH_RESTRICT`, so it takes the macro as the declarator's identifier and pushes
/// the real `input` into an `ERROR` node that follows the `parameter_declaration`.
/// Returns the first plain identifier among the sibling tokens up to the next
/// `,` / `)`.
fn trailing_error_param_name(param_decl: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let mut sib = param_decl.next_sibling();
    while let Some(node) = sib {
        if matches!(node.kind(), "," | ")") {
            break;
        }
        let id = first_declarator_identifier(node, source);
        if is_c_identifier(&id) {
            return Some(id);
        }
        sib = node.next_sibling();
    }
    None
}

fn function_params(mut declarator: tree_sitter::Node<'_>, source: &[u8]) -> Vec<CParamDescriptor> {
    let mut params = Vec::new();
    while declarator.kind() == "pointer_declarator" {
        let Some(inner) = declarator.child_by_field_name("declarator") else {
            return params;
        };
        declarator = inner;
    }
    // For macro-wrapped declarators (`int BZ_API(name)(real, args)`),
    // the OUTER function_declarator's `parameters` field is the real
    // parameter list. Recursive search would pick the macro's args
    // (`(name)`) instead. Prefer the explicit field when present.
    let list = declarator
        .child_by_field_name("parameters")
        .or_else(|| find_parameter_list(declarator));
    let Some(list) = list else {
        return params;
    };
    let mut cursor = list.walk();
    for child in list.children(&mut cursor) {
        if child.kind() != "parameter_declaration" {
            continue;
        }
        // Capture everything before the declarator as the type text so we keep
        // qualifiers like `const`, `volatile`, and `unsigned`.
        let declarator_node = child.child_by_field_name("declarator");
        // An inline function-pointer parameter — `int (*cb)(int, int)` — has a
        // `function_declarator` declarator (`(*cb)(int, int)`). `split_declarator`
        // can't shape it, so reconstruct the canonical funcptr type `RET (*)(params)`
        // (name lifted from the parenthesized pointer declarator) — otherwise the
        // type collapses to just `RET` and the declarator leaks into the name.
        if let Some(decl) = declarator_node {
            // An inline function-pointer parameter reaches here in two spellings:
            //   `int (*cb)(int, int)`        -> the declarator IS the function_declarator;
            //   `void *(*alloc)(void *, T)`  -> a funcptr whose RETURN type is itself a
            //      pointer, which tree-sitter wraps in pointer_declarator(s) for the
            //      return star(s), nesting the function_declarator one level down.
            // `funcptr_declarator` returns the function_declarator in either case
            // (and for the unnamed `abstract_function_declarator` form `(*)(int)`).
            // Without the nested case, a pointer-returning funcptr collapsed to
            // `c_type = "void *"` with the declarator leaking into the name
            // (`(*alloc)(...)`), which the harness emitter then spliced a buffer
            // initializer into the middle of — uncompilable C.
            if let Some(func_decl) = funcptr_declarator(decl) {
                // `child.start_byte()..func_decl.start_byte()` is the return type
                // INCLUDING any return-pointer star(s) (`void *`), so the canonical
                // funcptr type is reconstructed faithfully.
                let ret = std::str::from_utf8(&source[child.start_byte()..func_decl.start_byte()])
                    .map(|s| s.trim().to_owned())
                    .unwrap_or_default();
                let inner_params = func_decl
                    .child_by_field_name("parameters")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(normalize_type)
                    .unwrap_or_else(|| "(void)".to_owned());
                let name = func_decl
                    .child_by_field_name("declarator")
                    .map(|d| funcptr_declarator_name(d, source))
                    .unwrap_or_default();
                let c_type = normalize_type(&format!("{ret} (*){inner_params}"));
                if !c_type.is_empty() && c_type != "(*)(void)" {
                    params.push(CParamDescriptor { name, c_type });
                }
                continue;
            }
        }
        let type_text = match declarator_node {
            Some(decl) => {
                let start = child.start_byte();
                let end = decl.start_byte();
                std::str::from_utf8(&source[start..end])
                    .map(|s| s.trim().to_owned())
                    .unwrap_or_default()
            }
            None => child
                .child_by_field_name("type")
                .and_then(|n| n.utf8_text(source).ok())
                .map(|s| s.trim().to_owned())
                .unwrap_or_default(),
        };
        let raw_decl = declarator_node
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();

        let (mut name, pointer_suffix) = split_declarator(&raw_decl);
        // An unknown restrict-qualifier macro between the `*` and the name
        // (`const void* XXH_RESTRICT input`, xxhash.h) is mis-modelled by
        // tree-sitter as the declarator's identifier, leaving the macro as the
        // parameter `name` and stranding the real `input` in a trailing ERROR
        // node. The type text before the declarator is already clean
        // (`const void *`); only the name is wrong. Treat the macro as the
        // qualifier it is — drop it and recover the real name — so the harness
        // neither emits nor stubs `XXH_RESTRICT` (emitting it as the decode
        // variable yields `redefinition of 'XXH_RESTRICT'` once the project
        // header that #defines the macro is included).
        if is_restrict_qualifier_macro(&name) || is_macro_shaped_qualifier(&name) {
            match trailing_error_param_name(child, source) {
                Some(real) => name = real,
                // No recovered name: a clearly restrict-flavoured macro with no
                // following identifier is still a qualifier, so drop it (the
                // harness synthesises a positional name). A merely ALL-CAPS token
                // with no trailing name may be a genuine (if unconventional)
                // parameter name, so it is left intact.
                None if is_restrict_qualifier_macro(&name) => name.clear(),
                None => {}
            }
        }
        if name.is_empty() && type_text.is_empty() {
            continue;
        }
        // Skip `(void)` parameter declarations.
        if type_text == "void" && name.is_empty() {
            continue;
        }
        let full_type = if pointer_suffix.is_empty() {
            normalize_type(&type_text)
        } else {
            normalize_type(&format!("{type_text} {pointer_suffix}"))
        };
        params.push(CParamDescriptor {
            name,
            c_type: full_type,
        });
    }
    params
}

fn normalize_type(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn find_parameter_list<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let _depth_guard = AstDepthGuard::enter()?;
    if node.kind() == "parameter_list" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(list) = find_parameter_list(child) {
            return Some(list);
        }
    }
    None
}

/// Split a raw declarator string like `*input` or `name` into (name, pointer_suffix).
fn split_declarator(raw: &str) -> (String, String) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (String::new(), String::new());
    }
    let mut pointer = String::new();
    let mut name = trimmed.trim_start();
    // Peel off pointer stars and any cv-qualifiers that bind to the pointer
    // (`T * const name`, `T * restrict name`, `T * const * volatile name`).
    // Without this the qualifier leaks into the parameter name, e.g.
    // `const internal_hooks * const hooks` (cJSON) yielded name "const hooks"
    // and emitted `internal_hooks _gf_value_const hooks;`.
    loop {
        if let Some(rest) = name.strip_prefix('*') {
            pointer.push('*');
            name = rest.trim_start();
            continue;
        }
        let mut stripped = false;
        // `__restrict__` before `__restrict` so the longer GNU spelling strips
        // whole. `restrict`/`__restrict`/`__restrict__` all bind to the pointer
        // exactly like `const`/`volatile`; without stripping them the qualifier
        // leaks into the parameter name (`void* __restrict dst` -> name
        // `__restrict`, dropping the real `dst`).
        for qualifier in [
            "const",
            "volatile",
            "restrict",
            "__restrict__",
            "__restrict",
        ] {
            if let Some(rest) = name.strip_prefix(qualifier) {
                // Only a *whole-word* qualifier, not a prefix of an
                // identifier like `constant` or `restrictions`.
                if rest.is_empty() || rest.starts_with(|c: char| c.is_whitespace() || c == '*') {
                    name = rest.trim_start();
                    stripped = true;
                    break;
                }
            }
        }
        if !stripped {
            break;
        }
    }
    // A trailing array declarator on a parameter decays to one more pointer
    // level (`T x[]` is `T *x`; `T *x[]` is `T **x`). Strip it from the name —
    // otherwise the `[...]` leaks into the identifier (tinyexpr's
    // `const te_expr *parameters[]` yielded name "parameters[]", and the decoder
    // emitted `te_expr _gf_value_parameters[];` — an unsized-array decl that does
    // not compile). Folding it into the pointer suffix keeps the type honest so
    // the decoder builds (or cleanly skips) the right shape.
    if let Some(bracket) = name.find('[') {
        name = name[..bracket].trim_end();
        pointer.push('*');
    }
    // A real parameter name is a single identifier. When more tokens follow it,
    // they are a conditional-argument macro glued to the declarator without
    // preprocessing (`addr LWIP_DNS_ADDRTYPE_ARG(u8_t dns_addrtype)` -> `addr`,
    // also any `IDENT(...)` config macro). Keep only the leading identifier so
    // the decoder emits a valid declarator. Declarators that don't start with an
    // identifier (e.g. a function-pointer `(*fp)(int)`) are left untouched.
    let name = name.trim();
    if name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        let ident_len = name
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(name.len());
        if !name[ident_len..].trim().is_empty() {
            return (name[..ident_len].to_owned(), pointer);
        }
    }
    (name.to_owned(), pointer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pathologically deep source must not stack-overflow (abort the process)
    /// in our recursive walkers before the build (#407). tree-sitter parses the
    /// deep input fine; the bound lives in our walkers. Each construct is built
    /// well past `MAX_AST_DEPTH` so the guard is exercised on every entry point.
    #[test]
    fn deep_nesting_does_not_overflow() {
        const DEEP: usize = 6000;
        // A normal shallow function placed ABOVE each deep construct so the
        // walker reaches it before bottoming out in the deep subtree.
        let shallow = "typedef int my_int_t;\nint top_decl(int);\nint f(void) { return 0; }\n";

        // ~6000-deep else-if ladder (nested if_statement.alternative).
        let mut else_if = String::from(shallow);
        else_if.push_str("int g(int x) {\n    if (x == 0) { return 0; }\n");
        for _ in 0..DEEP {
            else_if.push_str("    else if (x == 0) { return 0; }\n");
        }
        else_if.push_str("    return 1;\n}\n");

        // ~6000-deep nested parenthesised initializer.
        let mut parens = String::from(shallow);
        parens.push_str("int h(void) {\n    int y = ");
        parens.push_str(&"(".repeat(DEEP));
        parens.push('0');
        parens.push_str(&")".repeat(DEEP));
        parens.push_str(";\n    return y;\n}\n");

        // ~6000-term || chain (left-nested binary_expression).
        let mut or_chain = String::from(shallow);
        or_chain.push_str("int k(int a) {\n    return a");
        for _ in 0..DEEP {
            or_chain.push_str(" || a");
        }
        or_chain.push_str(";\n}\n");

        for src in [&else_if, &parens, &or_chain] {
            // None of these calls may abort the process via stack overflow.
            let funcs = parse_c_functions(src).expect("parse functions");
            assert!(
                funcs.iter().any(|fun| fun.name == "f"),
                "shallow function above the deep construct must still be found"
            );
            let decls = parse_c_declarations(src).expect("parse declarations");
            assert!(
                decls.iter().any(|d| d.name == "top_decl"),
                "shallow prototype above the deep construct must still be found"
            );
            let defs = parse_c_type_defs(src).expect("parse type defs");
            assert!(
                defs.typedefs.iter().any(|t| t.name == "my_int_t"),
                "shallow typedef above the deep construct must still be found"
            );
            count_parse_errors(src);
            referenced_symbols(src).expect("referenced symbols");
        }
    }

    /// The depth cap is far above any legitimate nesting: a modest ~50-deep
    /// construct still walks fully, so a call buried at the bottom is found.
    #[test]
    fn normal_nesting_is_unaffected() {
        const DEPTH: usize = 50;
        let mut src = String::from("int probe(void);\nint g(int x) {\n    if (x == 0) {}\n");
        for _ in 0..DEPTH {
            src.push_str("    else if (x == 0) {}\n");
        }
        src.push_str("    else { probe(); }\n    return 0;\n}\n");

        let refs = referenced_symbols(&src).expect("referenced symbols");
        assert!(
            refs.iter().any(|s| s == "probe"),
            "a call nested ~{DEPTH} deep must still be discovered (cap must not truncate real code)"
        );
    }

    #[test]
    fn referenced_symbols_collects_direct_call_targets() {
        let syms = referenced_symbols(
            r#"
            int adler32(int a);
            void trees_init(void);
            int deflate(int x) {
                int s = adler32(x);
                trees_init();
                return sizeof(int) + s;   /* sizeof is not a call */
            }
            "#,
        )
        .unwrap();
        assert!(syms.contains(&"adler32".to_owned()));
        assert!(syms.contains(&"trees_init".to_owned()));
        assert!(!syms.iter().any(|s| s == "sizeof"));
    }

    #[test]
    fn discovers_c_function_definitions() {
        let functions = parse_c_functions(
            r#"
            static int helper(int x) { return x + 1; }
            void process(void);
            void process(void) {
                helper(1);
            }
            "#,
        )
        .expect("C parses");

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "helper");
        assert_eq!(functions[0].line, 2);
        assert_eq!(functions[0].return_type, "int");
        assert_eq!(functions[0].params.len(), 1);
        assert_eq!(functions[0].params[0].name, "x");
        assert_eq!(functions[0].params[0].c_type, "int");

        assert_eq!(functions[1].name, "process");
        assert_eq!(functions[1].return_type, "void");
        assert!(
            functions[1].params.is_empty(),
            "(void) parameter list is empty, got {:?}",
            functions[1].params
        );
    }

    #[test]
    fn parse_c_functions_recovers_name_from_export_macro_declarator() {
        let src = "int BZ_API(BZ2_bzBuffToBuffDecompress)(char *dest, unsigned int *destLen, char *source, unsigned int sourceLen) { return 0; }";
        let fns = parse_c_functions(src).unwrap();
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(
            f.name, "BZ2_bzBuffToBuffDecompress",
            "name should be the macro's argument, not the macro itself"
        );
        assert_eq!(f.params.len(), 4, "real param count, not macro's");
        assert_eq!(f.params[0].name, "dest");
        assert_eq!(f.params[1].name, "destLen");
        assert_eq!(f.params[3].name, "sourceLen");
    }

    #[test]
    fn parse_c_functions_recovers_pointer_return_wrapped_name() {
        let src = "const char * BZ_API(BZ2_bzlibVersion)(void) { return \"1.0\"; }";
        let fns = parse_c_functions(src).unwrap();
        assert_eq!(fns.len(), 1, "{fns:?}");
        assert_eq!(fns[0].name, "BZ2_bzlibVersion");
        assert_eq!(fns[0].return_type, "const char *");
        assert!(fns[0].params.is_empty(), "{:?}", fns[0].params);
    }

    #[test]
    fn parse_c_declarations_recovers_pointer_return_wrapped_name() {
        let src = "extern const char * BZ_API(BZ2_bzlibVersion)(void);";
        let decls = parse_c_declarations(src).unwrap();
        let decl = decls
            .iter()
            .find(|decl| decl.name == "BZ2_bzlibVersion")
            .expect("real wrapped function name");
        assert_eq!(decl.return_type, "const char *");
        assert!(decl.param_types.is_empty(), "{:?}", decl.param_types);
    }

    #[test]
    fn parse_c_functions_captures_const_char_pointer_param() {
        let src = "int parse(const char *input, size_t len) { return 0; }";
        let fns = parse_c_functions(src).unwrap();
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(f.name, "parse");
        assert_eq!(f.return_type, "int");
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "input");
        assert_eq!(
            f.params[0].c_type, "const char *",
            "input param type should keep const qualifier"
        );
        assert_eq!(f.params[1].name, "len");
        assert_eq!(f.params[1].c_type, "size_t");
    }

    #[test]
    fn parse_c_functions_preserves_typedef_hidden_pointer_param_spelling() {
        // redis sds is `typedef char *sds`, but function signatures use the
        // typedef name directly. The harness lifecycle detector depends on that
        // spelling so it can construct an sds via sdsempty instead of treating
        // the first parameter as a raw char* buffer.
        let src =
            "typedef char *sds;\nsds sdscatlen(sds s, const void *t, size_t len) { return s; }";
        let fns = parse_c_functions(src).unwrap();
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(f.name, "sdscatlen");
        assert_eq!(f.return_type, "sds");
        assert_eq!(f.params[0].name, "s");
        assert_eq!(f.params[0].c_type, "sds");
    }

    #[test]
    fn parse_c_functions_flags_variadic_functions() {
        // log.c's logger: the `...` is variadic but is not surfaced as a param.
        let src =
            "void log_log(int level, const char *file, int line, const char *fmt, ...) { (void)level; }";
        let fns = parse_c_functions(src).unwrap();
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert!(f.variadic, "log_log must be flagged variadic");
        assert_eq!(
            f.params.len(),
            4,
            "the ellipsis must NOT be surfaced as a parameter: {:?}",
            f.params
        );
        assert_eq!(f.params[3].name, "fmt");

        // A non-variadic function is not flagged.
        let plain = parse_c_functions("int parse(const char *input) { return 0; }").unwrap();
        assert!(!plain[0].variadic, "a fixed-arity function is not variadic");
    }

    #[test]
    fn parse_c_functions_strips_pointer_const_qualifier_from_param_name() {
        // cJSON's allocator-injection pattern: `const internal_hooks * const
        // hooks`. The trailing `* const` cv-qualifier must not leak into the
        // parameter name (it produced `const hooks` -> malformed harness decl).
        let src = "char *dup(const char *s, const internal_hooks * const hooks) { return 0; }";
        let fns = parse_c_functions(src).unwrap();
        let f = &fns[0];
        assert_eq!(f.params.len(), 2);
        assert_eq!(
            f.params[1].name, "hooks",
            "pointer-const must not glue to name"
        );
        assert_eq!(f.params[1].c_type, "const internal_hooks *");
    }

    #[test]
    fn split_declarator_handles_pointer_cv_qualifiers() {
        assert_eq!(
            split_declarator("* const hooks"),
            ("hooks".to_owned(), "*".to_owned())
        );
        assert_eq!(
            split_declarator("* restrict buf"),
            ("buf".to_owned(), "*".to_owned())
        );
        assert_eq!(
            split_declarator("* const * volatile pp"),
            ("pp".to_owned(), "**".to_owned())
        );
        // A real identifier that merely starts with a qualifier word stays intact.
        assert_eq!(
            split_declarator("constant"),
            ("constant".to_owned(), String::new())
        );
    }

    #[test]
    fn split_declarator_strips_gnu_restrict_keyword_from_param_name() {
        // tree-sitter models `__restrict` / `__restrict__` as a recognised
        // pointer modifier, so the declarator text reaches split_declarator as
        // `* __restrict dst`. The qualifier must be peeled exactly like `const`/
        // `restrict`, leaving the real name — otherwise the name became
        // `__restrict` and the real `dst` was dropped.
        assert_eq!(
            split_declarator("* __restrict dst"),
            ("dst".to_owned(), "*".to_owned())
        );
        assert_eq!(
            split_declarator("* __restrict__ dst"),
            ("dst".to_owned(), "*".to_owned())
        );
        // A real identifier that merely starts with `__restrict` stays intact.
        assert_eq!(
            split_declarator("__restricted"),
            ("__restricted".to_owned(), String::new())
        );
    }

    #[test]
    fn parse_c_functions_strips_restrict_qualifier_macro_from_param() {
        // xxHash's `XXH_RESTRICT` is a project macro (`#define XXH_RESTRICT
        // restrict`/`__restrict`/empty). The C grammar cannot expand it, so it
        // lands in the parameter QUALIFIER position — after the base type and
        // `*`, immediately before the name. It must be stripped (never emitted
        // or stubbed): emitting it as a decode variable collides with the macro
        // once the project header is included (`redefinition of 'XXH_RESTRICT'`).
        let src = "unsigned mix(void* XXH_RESTRICT acc, const void* XXH_RESTRICT input, \
                   const void* XXH_RESTRICT secret, size_t len) { return 0; }";
        let fns = parse_c_functions(src).unwrap();
        let f = &fns[0];
        assert_eq!(f.params.len(), 4, "params: {:?}", f.params);
        // The real names are recovered, never the macro.
        assert_eq!(f.params[0].name, "acc");
        assert_eq!(f.params[0].c_type, "void *");
        assert_eq!(f.params[1].name, "input");
        assert_eq!(f.params[1].c_type, "const void *");
        assert_eq!(f.params[2].name, "secret");
        assert_eq!(f.params[2].c_type, "const void *");
        assert_eq!(f.params[3].name, "len");
        assert!(
            f.params
                .iter()
                .all(|p| p.name != "XXH_RESTRICT" && !p.c_type.contains("XXH_RESTRICT")),
            "the qualifier macro must never surface as a name or a type: {:?}",
            f.params
        );
    }

    #[test]
    fn parse_c_functions_strips_gnu_restrict_param_name() {
        // The standard `__restrict` keyword spelling, recognised by the grammar.
        let src = "void copy(void* __restrict dst, const void* __restrict src) {}";
        let fns = parse_c_functions(src).unwrap();
        let f = &fns[0];
        assert_eq!(f.params.len(), 2, "params: {:?}", f.params);
        assert_eq!(f.params[0].name, "dst");
        assert_eq!(f.params[0].c_type, "void *");
        assert_eq!(f.params[1].name, "src");
        assert_eq!(f.params[1].c_type, "const void *");
    }

    #[test]
    fn parse_c_functions_keeps_uppercase_param_name_without_trailing_macro() {
        // A genuine (if unconventional) ALL-CAPS parameter name with no following
        // identifier is NOT a qualifier macro and must be preserved — only a
        // restrict-flavoured token is dropped when it stands alone.
        let src = "int read_reg(volatile unsigned* REG) { return 0; }";
        let fns = parse_c_functions(src).unwrap();
        let f = &fns[0];
        assert_eq!(f.params.len(), 1, "params: {:?}", f.params);
        assert_eq!(f.params[0].name, "REG", "uppercase name must survive");
    }

    #[test]
    fn split_declarator_strips_trailing_conditional_arg_macro() {
        // lwIP `LWIP_DNS_ADDRTYPE_ARG(x)` expands to nothing (or `, x`) by build
        // config; without preprocessing the macro call is glued to the parameter
        // declarator. A real parameter name is a single identifier, so the
        // trailing macro junk must be dropped (else the decoder emits
        // `ip_addr_t * addr LWIP_DNS_ADDRTYPE_ARG(u8_t dns_addrtype) = ...`).
        assert_eq!(
            split_declarator("*addr LWIP_DNS_ADDRTYPE_ARG(u8_t dns_addrtype)"),
            ("addr".to_owned(), "*".to_owned())
        );
        assert_eq!(
            split_declarator(
                "*callback_arg LWIP_DNS_ADDRTYPE_ARG(u8_t dns_addrtype) LWIP_DNS_ISMDNS_ARG(u8_t is_mdns)"
            ),
            ("callback_arg".to_owned(), "*".to_owned())
        );
    }

    #[test]
    fn split_declarator_decays_array_parameter_to_pointer() {
        // `T name[]` decays to `T *name`; the array suffix must not leak into
        // the identifier (tinyexpr `const te_expr *parameters[]`).
        assert_eq!(
            split_declarator("* parameters[]"),
            ("parameters".to_owned(), "**".to_owned())
        );
        assert_eq!(
            split_declarator("buf[256]"),
            ("buf".to_owned(), "*".to_owned())
        );
    }

    #[test]
    fn parse_c_functions_preserves_const_pointer_return_type() {
        let fns = parse_c_functions("const char *version(void) { return \"1.0\"; }").unwrap();
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "version");
        assert_eq!(
            fns[0].return_type, "const char *",
            "function definitions must preserve const return qualifiers"
        );
    }

    #[test]
    fn parse_c_functions_strips_export_macro_prefix_from_pointer_return_type() {
        let fns = parse_c_functions("MINIZ_EXPORT void *alloc_func(void) { return 0; }").unwrap();
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "alloc_func");
        assert_eq!(
            fns[0].return_type, "void *",
            "function definitions must strip export macro prefixes without losing the real base type"
        );
    }

    #[test]
    fn parse_c_declarations_finds_extern_prototypes() {
        let decls = parse_c_declarations(
            "extern int decoder_feed(decoder_t *d, const uint8_t *buf, size_t len);\n\
             extern void decoder_destroy(decoder_t *d);\n\
             int decoder_create(void) { return 0; }\n",
        )
        .expect("parses");
        let names: Vec<_> = decls.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"decoder_feed"));
        assert!(names.contains(&"decoder_destroy"));
        assert!(
            !names.contains(&"decoder_create"),
            "function with body must be filtered out - it goes to parse_c_functions instead"
        );
    }

    #[test]
    fn parse_c_declarations_captures_return_and_params() {
        let decls = parse_c_declarations(
            "extern decoder_t * decoder_feed(decoder_t *d, const uint8_t *buf, size_t len);\n",
        )
        .expect("parses");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "decoder_feed");
        assert_eq!(decls[0].return_type, "decoder_t *");
        assert_eq!(
            decls[0].param_types,
            vec![
                "decoder_t *".to_owned(),
                "const uint8_t *".to_owned(),
                "size_t".to_owned()
            ]
        );
    }

    #[test]
    fn parse_c_declarations_strips_export_macro_prefix_from_return_type() {
        let decls = parse_c_declarations(
            "MINIZ_EXPORT int mz_uncompress(unsigned char *dest, mz_ulong *dest_len);\n",
        )
        .expect("parses");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "mz_uncompress");
        assert_eq!(decls[0].return_type, "int");
    }

    #[test]
    fn parse_c_declarations_strips_legacy_linkage_macros_around_builtin_type() {
        let decls = parse_c_declarations(
            "__LA_DECL int archive_read_open1(struct archive *a);\n\
             ZEXTERN int ZEXPORT inflate(void *stream, int flush);\n",
        )
        .expect("parses");
        assert_eq!(decls.len(), 2);
        assert_eq!(decls[0].name, "archive_read_open1");
        assert_eq!(decls[0].return_type, "int");
        assert_eq!(decls[1].name, "inflate");
        assert_eq!(decls[1].return_type, "int");

        let typedef_return = parse_c_declarations("RESULT_CODE run(void);\n").expect("parses");
        assert_eq!(typedef_return[0].return_type, "RESULT_CODE");

        let tagged = parse_c_declarations("__LA_DECL struct archive *archive_read_new(void);\n")
            .expect("parses");
        assert_eq!(tagged[0].return_type, "struct archive *");
    }

    #[test]
    fn parse_c_declarations_strips_calling_convention_and_postfix_attribute() {
        let decls =
            parse_c_declarations("void mi_cdecl _mi_auto_process_done(void) mi_attr_noexcept;\n")
                .expect("parses");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "_mi_auto_process_done");
        assert_eq!(decls[0].return_type, "void");
        assert!(decls[0].param_types.is_empty());
    }

    #[test]
    fn parse_c_type_defs_preserves_old_style_function_typedef_profile() {
        let defs = parse_c_type_defs(
            "struct archive;\n\
             typedef int archive_open_callback(struct archive *, void *);\n",
        )
        .expect("parses");
        let callback = defs
            .typedefs
            .iter()
            .find(|typedef| typedef.name == "archive_open_callback")
            .expect("callback typedef");
        assert!(callback.underlying.starts_with("int ("), "{callback:?}");
        assert!(
            callback.underlying.contains("struct archive *"),
            "{callback:?}"
        );
        assert!(callback.underlying.contains("void *"), "{callback:?}");
    }

    #[test]
    fn function_pointer_typedef_name_does_not_alias_its_first_parameter_type() {
        let defs = parse_c_type_defs(
            "typedef void *voidpf;\n\
             typedef unsigned long uLong;\n\
             typedef uLong (ZCALLBACK *read_file_func)(voidpf opaque, voidpf stream);\n",
        )
        .expect("parses zlib callback typedef");

        let voidpf = defs
            .typedefs
            .iter()
            .filter(|typedef| typedef.name == "voidpf")
            .collect::<Vec<_>>();
        assert_eq!(
            voidpf.len(),
            1,
            "parameter type must not become the alias: {:?}",
            defs.typedefs
        );
        assert_eq!(voidpf[0].underlying, "void *");

        let callback = defs
            .typedefs
            .iter()
            .find(|typedef| typedef.name == "read_file_func")
            .expect("callback alias is recorded under its declared name");
        assert!(callback.underlying.starts_with("uLong"), "{callback:?}");
        assert!(
            callback.underlying.contains("voidpf opaque"),
            "{callback:?}"
        );
    }

    #[test]
    fn parse_c_declarations_decays_array_params_to_pointers() {
        // A stub signature must match the real prototype's decayed pointer types.
        // `cv[8]` is `unsigned char *`, `*data[4]` is `int **` — collapsing the
        // brackets to nothing (`unsigned char`) gives a conflicting stub signature
        // (gnatcoll/blake3 `blake3_compress_xof(const uint32_t cv[8], ...)`).
        let decls = parse_c_declarations("void process(unsigned char cv[8], int *data[4]);\n")
            .expect("parses");
        assert_eq!(decls.len(), 1);
        assert_eq!(
            decls[0].param_types,
            vec!["unsigned char *".to_owned(), "int **".to_owned()]
        );
    }

    #[test]
    fn parse_c_declarations_handles_void_param() {
        let decls = parse_c_declarations("extern int sync(void);").expect("parses");
        assert_eq!(decls.len(), 1);
        assert!(decls[0].param_types.is_empty(), "void params -> empty list");
    }

    #[test]
    fn parse_c_declarations_preserves_const_return_qualifier() {
        let decls = parse_c_declarations("extern const decoder_t * foo(int x);\n").expect("parses");
        assert_eq!(decls.len(), 1);
        assert_eq!(
            decls[0].return_type, "const decoder_t *",
            "const qualifier must survive the declaration return-type walk"
        );
    }

    #[test]
    fn parse_c_declarations_preserves_volatile_return_qualifier() {
        let decls =
            parse_c_declarations("extern volatile int *status_ptr(void);\n").expect("parses");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].return_type, "volatile int *");
    }

    #[test]
    fn parse_c_functions_strips_forceinline_macro_from_return_type() {
        let functions = parse_c_functions(
            "#define MZ_FORCEINLINE __inline__ __attribute__((__always_inline__))\n\
             static MZ_FORCEINLINE void reset(void) {}\n",
        )
        .expect("C parses");
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].return_type, "void");
    }

    #[test]
    fn parse_c_functions_strips_static_storage_macro_from_typedef_return() {
        let functions = parse_c_functions(
            "MEM_STATIC size_t ZSTD_decompressLegacy(const void *src) { return 0; }",
        )
        .expect("parses");
        assert_eq!(functions[0].return_type, "size_t");
    }

    #[test]
    fn marks_static_functions() {
        let functions = parse_c_functions(
            "static int helper(int x) { return x + 1; }\nint entry(int x) { return helper(x); }\n",
        )
        .expect("C parses");
        assert!(functions[0].is_static, "helper is static");
        assert!(!functions[1].is_static, "entry is external");
    }

    #[test]
    fn marks_preprocessor_split_static_function() {
        let functions = parse_c_functions(
            "#if !defined(_WIN32) || defined(__CYGWIN__)\n\
             static\n\
             #endif\n\
             int archive_read_open_filenames_w(void *archive) { return archive != 0; }\n",
        )
        .expect("C parses");
        let function = functions
            .iter()
            .find(|function| function.name == "archive_read_open_filenames_w")
            .expect("function found");
        assert!(function.is_static, "conditional storage class is preserved");
    }

    #[test]
    fn skips_if_zero_regions() {
        let functions = parse_c_functions(
            r#"
        #if 0
        unsigned long mz_crc32(unsigned long crc, const unsigned char *p, unsigned long n)
        { return 0; }
        #else
        unsigned long mz_crc32(unsigned long crc, const unsigned char *p, unsigned long n)
        { return crc + *p + n; }
        #endif
        "#,
        )
        .expect("C parses");
        assert_eq!(
            functions.len(),
            1,
            "only the live #else branch is indexed: {:?}",
            functions
                .iter()
                .map(|f| (f.name.clone(), f.line))
                .collect::<Vec<_>>()
        );
        assert_eq!(functions[0].line, 6);
    }

    #[test]
    fn labels_foreign_platform_guards() {
        let functions = parse_c_functions(
            r#"
        #ifdef _WIN32
        int win_only(int x) { return x; }
        #endif
        #if defined(_MSC_VER) || defined(__MINGW64__)
        int msvc_only(int x) { return x; }
        #endif
        #ifndef _WIN32
        int posix_only(int x) { return x; }
        #endif
        #ifdef __vxworks
        int vxworks_only(int x) { return x; }
        #endif
        #if defined(__QNX__)
        int qnx_only(int x) { return x; }
        #endif
        int portable(int x) { return x; }
        "#,
        )
        .expect("C parses");
        let by_name = |n: &str| functions.iter().find(|f| f.name == n).unwrap();
        assert!(by_name("win_only").foreign_guard.is_some());
        assert!(by_name("msvc_only").foreign_guard.is_some());
        // RTOS-guarded branches are foreign on this host too (routed to a
        // stub-isolated build via foreign_platform_stub).
        assert_eq!(
            by_name("vxworks_only").foreign_guard.as_deref(),
            Some("__vxworks")
        );
        assert!(by_name("qnx_only").foreign_guard.is_some());
        assert!(
            by_name("posix_only").foreign_guard.is_none(),
            "#ifndef guards the portable branch"
        );
        assert!(by_name("portable").foreign_guard.is_none());
    }

    #[test]
    fn no_keyword_targets_from_preprocessor_split_functions() {
        // Mirrors miniz.c:4612-4640: an if/else-if chain split by an
        // #ifndef/#else so tree-sitter's recovery emits a mangled tree
        // that used to surface a "function" named `if`.
        let functions = parse_c_functions(
            r#"
        static int mz_zip_set_error(void *zip, int err) { (void)zip; return err; }
        int check_block(void *zip, unsigned long out_ofs, unsigned long want,
                        unsigned int crc_a, unsigned int crc_b)
        {
            int status = 0;
            if (out_ofs != want)
            {
                status = mz_zip_set_error(zip, -1);
            }
        #ifndef DISABLE_CRC_CHECKS
            else if (crc_a != crc_b)
            {
                status = mz_zip_set_error(zip, -2);
            }
        #endif
            return status;
        }
        "#,
        )
        .expect("C parses");
        assert!(
            functions.iter().all(|f| f.name != "if" && f.name != "else"),
            "keyword extracted as function: {:?}",
            functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn type_defs_extracts_structs_enums_typedefs() {
        let defs = parse_c_type_defs(
            r#"
        struct point { int x; int y; };
        typedef struct { unsigned char *data; unsigned long size; } blob;
        typedef struct point point_alias;
        typedef struct point *point_ptr;
        typedef unsigned long mz_ulong;
        enum mode { MODE_OFF, MODE_ON = 3, MODE_AUTO };
        typedef enum { TDEFL_NO_FLUSH, TDEFL_SYNC_FLUSH } tdefl_flush;
        typedef enum tinfl_status { TINFL_STATUS_DONE, TINFL_STATUS_FAILED } tinfl_status;
        typedef int (*callback_t)(void *opaque);
        struct opaque;
        struct outer { struct point origin; char tag[16]; };
        "#,
        )
        .expect("C parses");

        let s = |n: &str| defs.structs.iter().find(|d| d.name == n);
        let point = s("point").expect("struct point");
        assert!(point.complete);
        assert_eq!(point.fields.len(), 2);
        assert_eq!(point.fields[0].name, "x");
        assert_eq!(point.fields[0].c_type, "int");

        let blob = s("blob").expect("anonymous struct typedef takes alias name");
        assert_eq!(blob.fields.len(), 2);
        assert_eq!(blob.fields[0].c_type, "unsigned char *");
        assert_eq!(blob.fields[1].name, "size");

        let opaque = s("opaque").expect("forward decl recorded");
        assert!(!opaque.complete);
        assert!(opaque.fields.is_empty());

        let outer = s("outer").expect("struct outer");
        assert_eq!(outer.fields[0].c_type, "struct point");
        assert_eq!(outer.fields[1].name, "tag");
        assert_eq!(outer.fields[1].c_type, "char[16]");

        let td = |n: &str| defs.typedefs.iter().find(|d| d.name == n);
        assert_eq!(
            td("mz_ulong").expect("scalar typedef").underlying,
            "unsigned long"
        );
        assert_eq!(
            td("point_alias").expect("struct typedef").underlying,
            "struct point"
        );
        assert_eq!(
            td("point_ptr").expect("pointer typedef").underlying,
            "struct point *"
        );
        assert_eq!(
            td("tdefl_flush")
                .expect("anonymous enum typedef")
                .underlying,
            "enum tdefl_flush"
        );
        assert_eq!(
            td("tinfl_status").expect("named enum typedef").underlying,
            "enum tinfl_status"
        );
        assert_eq!(
            td("callback_t")
                .expect("function pointer typedef")
                .underlying,
            "int (*)(void *opaque)"
        );

        let mode = defs
            .enums
            .iter()
            .find(|d| d.name == "mode")
            .expect("enum mode");
        assert_eq!(mode.members, vec!["MODE_OFF", "MODE_ON", "MODE_AUTO"]);
        let flush = defs
            .enums
            .iter()
            .find(|d| d.name == "tdefl_flush")
            .expect("anonymous enum alias recorded under typedef name");
        assert_eq!(flush.members, vec!["TDEFL_NO_FLUSH", "TDEFL_SYNC_FLUSH"]);
        let status = defs
            .enums
            .iter()
            .find(|d| d.name == "tinfl_status")
            .expect("named enum typedef recorded");
        assert_eq!(
            status.members,
            vec!["TINFL_STATUS_DONE", "TINFL_STATUS_FAILED"]
        );
    }

    #[test]
    fn x_macro_enum_body_yields_no_phantom_member() {
        // http_parser.h: `enum http_errno { HTTP_ERRNO_MAP(HTTP_ERRNO_GEN) };`.
        // The real variants are generated by expanding the macro; tree-sitter
        // mislabels `HTTP_ERRNO_MAP` an enumerator. It must NOT become a member,
        // or the harness emits `(enum http_errno)HTTP_ERRNO_MAP` which won't
        // compile. A real `= (expr)` enumerator is still kept.
        let defs = parse_c_type_defs(
            "#define HTTP_ERRNO_MAP(XX) XX(0, OK, \"ok\")\n\
             enum http_errno { HTTP_ERRNO_MAP(HTTP_ERRNO_GEN) };\n\
             enum flags { F_A = (1 << 0), F_B = (1 << 1) };\n",
        )
        .expect("C parses");
        let errno = defs
            .enums
            .iter()
            .find(|d| d.name == "http_errno")
            .expect("enum http_errno recorded");
        assert!(
            errno.members.is_empty(),
            "X-macro invocation must not be a phantom enumerator: {:?}",
            errno.members
        );
        // A genuine `NAME = (expr)` enumerator (parens after `=`, not after the
        // name) is unaffected.
        let flags = defs
            .enums
            .iter()
            .find(|d| d.name == "flags")
            .expect("enum flags recorded");
        assert_eq!(flags.members, vec!["F_A", "F_B"]);
    }

    #[test]
    fn array_typedef_preserves_its_dimension() {
        // tcpdump's `typedef unsigned char nd_uint8_t[1];` — the array dimension
        // must survive so the type model resolves it to an array (not a scalar),
        // otherwise a struct field of that type is cast from a scalar (illegal C).
        let defs =
            parse_c_type_defs("typedef unsigned char nd_uint8_t[1];\ntypedef int quad_t[4];\n")
                .expect("C parses");
        let nd = defs
            .typedefs
            .iter()
            .find(|t| t.name == "nd_uint8_t")
            .expect("nd_uint8_t typedef");
        assert_eq!(nd.underlying, "unsigned char [1]");
        let quad = defs.typedefs.iter().find(|t| t.name == "quad_t").unwrap();
        assert_eq!(quad.underlying, "int [4]");
        // A plain scalar typedef is unaffected.
        let plain = parse_c_type_defs("typedef unsigned int u32;\n").unwrap();
        assert_eq!(plain.typedefs[0].underlying, "unsigned int");
    }

    #[test]
    fn define_type_aliases_become_typedefs_constants_do_not() {
        // `#define ID3TAG_U32 unsigned int` (id3tag) typed a parameter; without
        // expanding it the target was skipped ("opaque type ID3TAG_U32"). Register
        // object-like `#define` type aliases as typedefs.
        let defs = parse_c_type_defs(
            "#define ID3TAG_U32 unsigned int\n\
             #define MZ_PTR void *\n\
             #define SIZE_ALIAS size_t\n\
             #define BUF_SIZE 4096\n\
             #define MAGIC \"GIF89a\"\n\
             #define MAX(a,b) ((a)>(b)?(a):(b))\n\
             #define ENABLED 1\n",
        )
        .expect("parses");
        let alias = |n: &str| {
            defs.typedefs
                .iter()
                .find(|t| t.name == n)
                .map(|t| t.underlying.clone())
        };
        assert_eq!(alias("ID3TAG_U32").as_deref(), Some("unsigned int"));
        assert_eq!(alias("MZ_PTR").as_deref(), Some("void *"));
        assert_eq!(alias("SIZE_ALIAS").as_deref(), Some("size_t"));
        // Constants / strings / function-like macros are NOT type aliases.
        assert!(
            alias("BUF_SIZE").is_none(),
            "numeric constant is not a type"
        );
        assert!(alias("MAGIC").is_none(), "string constant is not a type");
        assert!(alias("MAX").is_none(), "function-like macro is not a type");
        assert!(alias("ENABLED").is_none(), "flag constant is not a type");
    }

    #[test]
    fn extracts_c_dictionary_tokens_from_enums_strings_defines_and_cases() {
        let tokens = extract_c_dictionary_tokens(
            r#"
            #define MAGIC_TEXT "GIF89a"
            #define MAGIC_NUM 0x504b0304
            enum mode { MODE_FAST, MODE_SAFE };
            int parse(const char *s, int tag) {
                switch (tag) { case 0x42: return 1; case MODE_FAST: return 2; case 'Z': return 3; default: break; }
                return s && s[0] == 'P' && !strcmp(s, "READY");
            }
            "#,
        )
        .expect("C parses");

        assert!(tokens.contains(&"GIF89a".to_owned()));
        assert!(tokens.contains(&"0x504b0304".to_owned()));
        assert!(tokens.contains(&"MODE_FAST".to_owned()));
        assert!(tokens.contains(&"MODE_SAFE".to_owned()));
        assert!(tokens.contains(&"READY".to_owned()));
        assert!(tokens.contains(&"0x42".to_owned()));
        assert!(tokens.contains(&"Z".to_owned()));
    }

    #[test]
    fn extracts_c_dictionary_tokens_from_comparison_operands() {
        // #379: magic-byte / length gates appear as `==`/`!=`/`<`/`>` against
        // literal operands. Mine those so the dictionary carries the gate
        // values even when no runtime cmplog fires (scalar compares aren't
        // libc calls the shim can hook).
        let tokens = extract_c_dictionary_tokens(
            r#"
            int parse(const unsigned char *b, int n) {
                if (b[0] == 0x55 && b[1] != 'P') return 1;
                if (n >= 1234) return 2;
                return 0;
            }
            "#,
        )
        .expect("C parses");
        assert!(tokens.contains(&"0x55".to_owned()), "{tokens:?}");
        assert!(tokens.contains(&"P".to_owned()), "{tokens:?}");
        assert!(tokens.contains(&"1234".to_owned()), "{tokens:?}");
    }

    #[test]
    fn field_access_paths_extracts_nested_indexed_chains() {
        // The cFE CCSDS-accessor shape: a `CFE_MSG_Message_t *` parameter
        // dereferenced through nested members, the leaf indexed as an array.
        let src = r#"
            void f(const CFE_MSG_Message_t *MsgPtr, unsigned char *V) {
                *V = MsgPtr->CCSDS.Pri.StreamId[0] & 0x7;
                MsgPtr->CCSDS.Pri.StreamId[1] |= 1;
                (void)MsgPtr->CCSDS.Pri.Sequence;
            }
        "#;
        let paths = field_access_paths(src, "CFE_MSG_Message_t").unwrap();
        assert!(
            paths
                .iter()
                .any(|p| p.components == ["CCSDS", "Pri", "StreamId"] && p.leaf_indexed),
            "{paths:?}"
        );
        assert!(
            paths
                .iter()
                .any(|p| p.components == ["CCSDS", "Pri", "Sequence"] && !p.leaf_indexed),
            "{paths:?}"
        );
        let max_idx = paths
            .iter()
            .filter(|p| p.components == ["CCSDS", "Pri", "StreamId"])
            .map(|p| p.max_index)
            .max()
            .unwrap();
        assert_eq!(max_idx, 1, "{paths:?}");
    }

    #[test]
    fn field_access_paths_detect_pointer_valued_index_elements() {
        let src = r#"
            void release(ParseError *error) {
                free(error->expected[0]);
                error->expected[1] = NULL;
            }
        "#;
        let paths = field_access_paths(src, "ParseError").unwrap();
        assert!(
            paths.iter().any(|path| {
                path.components == ["expected"]
                    && path.leaf_indexed
                    && path.leaf_index_element_pointer
            }),
            "{paths:?}"
        );
    }

    #[test]
    fn field_access_paths_empty_when_type_absent() {
        let src = "void f(int x) { int y = x + 1; (void)y; }";
        assert!(field_access_paths(src, "CFE_MSG_Message_t")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn field_access_paths_preserve_self_pointer_and_leaf_pointer_evidence() {
        let src = r#"
            void drop_node(Node *n) {
                free(n->text);
                if (n->next != NULL) n->next->value = 1;
                n->embedded.value = 2;
            }
        "#;
        let paths = field_access_paths(src, "Node").unwrap();
        assert!(
            paths
                .iter()
                .any(|path| { path.components == ["text"] && path.leaf_pointer }),
            "{paths:?}"
        );
        assert!(
            paths.iter().any(|path| {
                path.components == ["next", "value"] && path.self_pointer_components == [0]
            }),
            "{paths:?}"
        );
        assert!(
            paths.iter().any(|path| {
                path.components == ["embedded", "value"] && path.self_pointer_components.is_empty()
            }),
            "{paths:?}"
        );
    }

    #[test]
    fn field_access_paths_distinguish_callbacks_from_numeric_null_expressions() {
        let src = r#"
            void use_hooks(Hooks *hooks, int flag) {
                void *p = hooks->allocate(32);
                hooks->type = cJSON_NULL;
                if (p == NULL || (hooks->type & flag)) hooks->deallocate(p);
            }
        "#;
        let paths = field_access_paths(src, "Hooks").unwrap();
        assert!(
            paths
                .iter()
                .any(|path| path.components == ["allocate"] && path.leaf_callable),
            "{paths:?}"
        );
        assert!(
            paths
                .iter()
                .any(|path| path.components == ["deallocate"] && path.leaf_callable),
            "{paths:?}"
        );
        assert!(
            paths.iter().any(|path| {
                path.components == ["type"] && !path.leaf_pointer && !path.leaf_callable
            }),
            "a sibling NULL comparison must not make an integer field a pointer: {paths:?}"
        );
    }

    #[test]
    fn inline_function_pointer_param_reconstructs_canonical_type() {
        // `int (*callback)(int, int)` must parse to name `callback` and the
        // canonical funcptr type `int (*)(int, int)` — not collapse to `int` with
        // the declarator leaking into the name (which broke the harness build).
        let fns =
            parse_c_functions("int handle_event(int (*callback)(int, int), int n) { return 0; }")
                .unwrap();
        let f = fns.iter().find(|f| f.name == "handle_event").unwrap();
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "callback");
        assert_eq!(f.params[0].c_type, "int (*)(int, int)");
        assert_eq!(f.params[1].name, "n");
        assert_eq!(f.params[1].c_type, "int");

        // An unnamed funcptr param keeps the type, no name.
        let decl = parse_c_functions("void reg(void (*)(int)) { }").unwrap();
        let g = decl.iter().find(|f| f.name == "reg").unwrap();
        assert_eq!(g.params.len(), 1);
        assert_eq!(g.params[0].c_type, "void (*)(int)");
        assert!(g.params[0].name.is_empty());
    }

    #[test]
    fn struct_inline_function_pointer_field_keeps_canonical_signature() {
        // §27.9: an inline (non-typedef) function-pointer struct field
        // (`int (*cmp)(const void *, const void *)`, a hashmap's compare slot) used
        // to be DROPPED by the parser (the parenthesized declarator defeated the
        // field walker). It must survive with the canonical funcptr type so the type
        // model classifies it FuncPtr and the decoder can synthesise a trampoline.
        let defs =
            parse_c_type_defs("struct ops { int (*cmp)(const void *, const void *); int x; };")
                .expect("parses");
        let ops = defs.structs.iter().find(|s| s.name == "ops").unwrap();
        assert_eq!(
            ops.fields
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            vec!["cmp", "x"],
            "the inline funcptr field must not be dropped: {:?}",
            ops.fields
        );
        let cmp = ops.fields.iter().find(|f| f.name == "cmp").unwrap();
        assert_eq!(cmp.c_type, "int (*)(const void *, const void *)");
    }

    #[test]
    fn anonymous_struct_with_function_pointer_fields_keeps_typedef_alias() {
        let source = "typedef struct { char *next; void *(*alloc)(void *, int, int); \
                      void (*free_fn)(void *, void *); } Hooks;";
        let defs = parse_c_type_defs(source).unwrap();
        let hooks = defs
            .structs
            .iter()
            .find(|record| record.name == "Hooks")
            .unwrap_or_else(|| panic!("structs={:?}, typedefs={:?}", defs.structs, defs.typedefs));
        assert_eq!(hooks.fields.len(), 3, "{:?}", hooks.fields);
    }

    #[test]
    fn struct_callback_array_field_carries_array_dimension() {
        // §27.3: a callback ARRAY field (`void (*handlers[4])(int)`, a dispatch
        // table) must survive with the canonical funcptr type plus its array
        // dimension so the type model resolves it to an array of function pointers
        // and the decoder fills every slot with a trampoline.
        let defs = parse_c_type_defs("struct dispatch { void (*handlers[4])(int); int n; };")
            .expect("parses");
        let d = defs.structs.iter().find(|s| s.name == "dispatch").unwrap();
        let handlers = d
            .fields
            .iter()
            .find(|f| f.name == "handlers")
            .expect("callback-array field must not be dropped");
        assert_eq!(handlers.c_type, "void (*)(int)[4]");
    }

    #[test]
    fn struct_funcptr_field_strips_calling_convention_macro_from_name() {
        // cJSON's `internal_hooks`: each function-pointer field carries a
        // calling-convention macro between the `(` and the `*name`
        // (`void *(CJSON_CDECL *allocate)(size_t)`). `CJSON_CDECL` is `__stdcall`
        // on Windows and EMPTY on Linux; the grammar cannot expand it, so it lands
        // in an ERROR node before the `*allocate`. It must NOT be taken as the
        // field name (which made the harness emit `.CJSON_CDECL = ...` -> after the
        // empty expansion `. = ...` -> `expected identifier`).
        let defs = parse_c_type_defs(
            "typedef struct internal_hooks { \
             void *(CJSON_CDECL *allocate)(size_t size); \
             void (CJSON_CDECL *deallocate)(void *pointer); \
             void *(CJSON_CDECL *reallocate)(void *pointer, size_t size); \
             } internal_hooks;",
        )
        .expect("parses");
        let hooks = defs
            .structs
            .iter()
            .find(|s| s.name == "internal_hooks")
            .unwrap();
        assert_eq!(
            hooks
                .fields
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            vec!["allocate", "deallocate", "reallocate"],
            "the calling-convention macro must be stripped, leaving the real field \
             names: {:?}",
            hooks.fields
        );
        assert!(
            hooks.fields.iter().all(|f| f.name != "CJSON_CDECL"),
            "CJSON_CDECL must never surface as a field name: {:?}",
            hooks.fields
        );
    }

    #[test]
    fn funcptr_param_strips_calling_convention_decoration_from_name() {
        // The same gap on a function-pointer PARAMETER, for both an unknown
        // convention macro and the standard `__stdcall` keyword.
        let fns = parse_c_functions(
            "void reg1(void (CJSON_CDECL *cb)(int)) { (void)cb; }\n\
             void reg2(void (__stdcall *cb2)(int, int)) { (void)cb2; }\n",
        )
        .unwrap();
        let reg1 = fns.iter().find(|f| f.name == "reg1").unwrap();
        assert_eq!(reg1.params.len(), 1, "params: {:?}", reg1.params);
        assert_eq!(reg1.params[0].name, "cb");
        assert_eq!(reg1.params[0].c_type, "void (*)(int)");
        let reg2 = fns.iter().find(|f| f.name == "reg2").unwrap();
        assert_eq!(reg2.params[0].name, "cb2");
        assert_eq!(reg2.params[0].c_type, "void (*)(int, int)");
    }

    #[test]
    fn parse_c_declarations_keeps_inline_function_pointer_param_type() {
        // §27.9: the DECLARATION path (extern prototype, no body) must reconstruct an
        // inline funcptr param's full type just like the definition path — otherwise
        // it collapses to the bare return type (`int`) and a prototype-only target's
        // callback param can be neither stubbed nor driven.
        let decls =
            parse_c_declarations("extern int reg(int (*cb)(int, int), int n);").expect("parses");
        let reg = decls.iter().find(|d| d.name == "reg").unwrap();
        assert_eq!(
            reg.param_types,
            vec!["int (*)(int, int)".to_owned(), "int".to_owned()],
            "inline funcptr param must keep its full type through the declaration path"
        );
        // A pointer-returning inline funcptr param too.
        let decls =
            parse_c_declarations("extern int run(void *(*alloc)(void *, unsigned long), int n);")
                .expect("parses");
        let run = decls.iter().find(|d| d.name == "run").unwrap();
        assert_eq!(run.param_types[0], "void * (*)(void *, unsigned long)");
    }

    #[test]
    fn pointer_returning_function_pointer_param_reconstructs_canonical_type() {
        // A funcptr whose RETURN type is a pointer (`void *(*alloc)(void *, size_t)`,
        // json.h's `json_parse_ex` allocator) is wrapped by tree-sitter in a
        // pointer_declarator for the return star, so the function_declarator is one
        // level down. It must still parse to name `alloc` and the canonical funcptr
        // type — not collapse to `void *` with `(*alloc)(...)` leaking into the name.
        let fns = parse_c_functions(
            "struct V *json_parse_ex(const void *src, size_t n, size_t flags, \
             void *(*alloc)(void *user_data, size_t size), void *user_data, \
             struct R *result) { return 0; }",
        )
        .unwrap();
        let f = fns.iter().find(|f| f.name == "json_parse_ex").unwrap();
        assert_eq!(f.params.len(), 6);
        assert_eq!(f.params[3].name, "alloc");
        assert_eq!(
            f.params[3].c_type,
            "void * (*)(void *user_data, size_t size)"
        );
        // The leak must not corrupt the following plain pointer param.
        assert_eq!(f.params[4].name, "user_data");
        assert_eq!(f.params[4].c_type, "void *");

        // Unnamed-inner-param spelling (the prototype form) reconstructs too.
        let proto =
            parse_c_functions("int run(void *(*alloc)(void *, size_t), int n) { return 0; }")
                .unwrap();
        let g = proto.iter().find(|f| f.name == "run").unwrap();
        assert_eq!(g.params[0].name, "alloc");
        assert_eq!(g.params[0].c_type, "void * (*)(void *, size_t)");
    }

    #[test]
    fn knr_basic_definition_synthesizes_ansi_prototype() {
        let src = "int add(a, b)\n    int a;\n    char *b;\n{\n    return a;\n}\n";
        let fns = parse_knr_functions(src);
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(f.name, "add");
        assert_eq!(f.line, 1);
        assert_eq!(f.return_type, "int");
        assert!(!f.is_static);
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "a");
        assert_eq!(f.params[0].c_type, "int");
        assert_eq!(f.params[1].name, "b");
        assert_eq!(f.params[1].c_type, "char *");
    }

    #[test]
    fn knr_implicit_int_return_and_multi_name_decl() {
        let src = "scale(x, y)\n    int x, y;\n{\n    return x * y;\n}\n";
        let fns = parse_knr_functions(src);
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(f.name, "scale");
        assert_eq!(f.return_type, "int"); // K&R implicit int
        assert_eq!(f.params.len(), 2);
        assert!(f.params.iter().all(|p| p.c_type == "int"));
    }

    #[test]
    fn knr_static_pointer_return_strips_storage_class() {
        let src = "static char *dup(s)\n    char *s;\n{\n    return s;\n}\n";
        let fns = parse_knr_functions(src);
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(f.name, "dup");
        assert!(f.is_static);
        assert_eq!(f.return_type, "char *");
        assert_eq!(f.params[0].c_type, "char *");
    }

    #[test]
    fn knr_does_not_match_ansi_definitions_or_prototypes() {
        // An ANSI definition (typed params) is not K&R.
        let ansi = "int add(int a, int b) {\n    return a + b;\n}\n";
        assert!(parse_knr_functions(ansi).is_empty());
        // A prototype (no body) is not a definition.
        let proto = "int add(a, b);\nvoid g(void) { (void)add(1, 2); }\n";
        assert!(parse_knr_functions(proto).is_empty());
        // A call inside a body must not be mistaken for a header.
        let call = "int g(void) {\n    int r;\n    r = add(1, 2);\n    return r;\n}\n";
        assert!(parse_knr_functions(call).is_empty());
    }

    #[test]
    fn ansi_void_prototypes_are_never_a_knr_definition() {
        // redis' sentinel.c: a block of ordinary ANSI prototypes. Reading the
        // `void` in `f(void)` as a K&R parameter name made the following
        // prototype look like the parameter-declaration block, so the whole
        // modern file classified as K&R and every target in it became
        // report-only — discovered, never fuzzed.
        let src = "int sentinelFlushConfig(void);\n\
                   void sentinelGenerateInitialMonitorEvents(void);\n\
                   int sentinelSendPing(sentinelRedisInstance *ri);\n\
                   void sentinelSimFailureCrash(void);\n\
                   \n\
                   void releaseSentinelRedisInstance(sentinelRedisInstance *ri) {\n\
                   \x20   free(ri);\n\
                   }\n";
        assert!(
            parse_knr_functions(src).is_empty(),
            "ANSI prototypes are not K&R: {:?}",
            parse_knr_functions(src)
        );
    }

    #[test]
    fn code_inside_a_comment_is_not_a_knr_definition() {
        // redis' module.c documents its API with example calls inside a block
        // comment. Scanning comment text produced a "K&R definition" whose
        // parameter type was `// Set`, classifying a C99 file as legacy.
        let src = "/* Usage:\n\
                   \x20 *\n\
                   \x20 *      RedisModule_ReplyWithLongLong(ctx,10);\n\
                   \x20 *      RedisModule_ReplySetArrayLength(ctx,3); // Set len\n\
                   \x20 */\n\
                   int RedisModule_ReplyWithLongLong(RedisModuleCtx *ctx, long long ll) {\n\
                   \x20   return 0;\n\
                   }\n";
        assert!(
            parse_knr_functions(src).is_empty(),
            "comment text is not code: {:?}",
            parse_knr_functions(src)
        );

        // A real K&R definition still parses when a comment sits beside it.
        let knr = "/* legacy helper */\n\
                   int add(a, b) /* two ints */\n\
                   \x20   int a;\n\
                   \x20   int b;\n\
                   {\n\
                   \x20   return a + b;\n\
                   }\n";
        let found = parse_knr_functions(knr);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].name, "add");
        assert_eq!(found[0].params.len(), 2);
        assert_eq!(found[0].params[0].c_type, "int");
    }

    #[test]
    fn knr_does_not_match_function_like_macros() {
        // picohttpparser/http_parser idiom: a function-like macro whose body has no
        // `{` must NOT be mistaken for a K&R definition. Before the fix the decl
        // scan ran past the macro into the next macro's body and swallowed an
        // `EXPECT_CHAR_NO_CHECK(ch);` call that `knr_param_types` mis-read as a
        // declaration of `ch`, so the file classified K&R and its real API was
        // dropped (false-clean).
        let src = "#define CHECK_EOF()                 \\\n\
                   \x20   if (buf == buf_end) {        \\\n\
                   \x20       return NULL;             \\\n\
                   \x20   }\n\
                   #define EXPECT_CHAR(ch)             \\\n\
                   \x20   CHECK_EOF();                 \\\n\
                   \x20   EXPECT_CHAR_NO_CHECK(ch);\n\
                   #define ADVANCE_TOKEN(tok, toklen)  \\\n\
                   \x20   do {                         \\\n\
                   \x20       tok = buf;               \\\n\
                   \x20   } while (0)\n\
                   \n\
                   const char *phr_parse(const char *buf, const char *buf_end, int *ret) {\n\
                   \x20   return buf;\n\
                   }\n";
        let fns = parse_knr_functions(src);
        assert!(
            fns.is_empty(),
            "function-like macros must not false-match as K&R, got {:?}",
            fns.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn knr_unsigned_long_and_struct_param_types() {
        let src = "process(n, p)\n    unsigned long n;\n    struct Frame *p;\n{\n    return;\n}\n";
        let fns = parse_knr_functions(src);
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        let ty = |name: &str| {
            f.params
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.c_type.as_str())
                .unwrap()
        };
        assert_eq!(ty("n"), "unsigned long");
        assert_eq!(ty("p"), "struct Frame *");
    }
}
