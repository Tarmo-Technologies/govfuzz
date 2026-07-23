// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{IdlParseError, Span};

const MAX_INCLUDE_DEPTH: usize = 32;

pub fn preprocess_idl(source: &str) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor::default();
    preprocessor.process_source(source, None)
}

pub fn preprocess_idl_with_defines(
    source: &str,
    defines: &[(String, String)],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor::with_defines(defines);
    preprocessor.process_source(source, None)
}

pub fn preprocess_idl_file(path: &Path) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor::default();
    preprocessor.process_file(path, 0)
}

pub fn preprocess_idl_file_with_defines(
    path: &Path,
    defines: &[(String, String)],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor::with_defines(defines);
    preprocessor.process_file(path, 0)
}

pub fn preprocess_idl_file_with_include_dirs(
    path: &Path,
    include_dirs: &[PathBuf],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor {
        include_dirs: include_dirs.to_vec(),
        recovery: RecoveryMode::Strict,
        ..Preprocessor::default()
    };
    preprocessor.process_file(path, 0)
}

pub fn preprocess_idl_file_recovering_with_include_dirs(
    path: &Path,
    include_dirs: &[PathBuf],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor {
        include_dirs: include_dirs.to_vec(),
        recovery: RecoveryMode::Recover,
        ..Preprocessor::default()
    };
    preprocessor.process_file(path, 0)
}

pub fn preprocess_idl_file_recovering_with_options(
    path: &Path,
    defines: &[(String, String)],
    include_dirs: &[PathBuf],
) -> Result<String, IdlParseError> {
    let mut preprocessor = Preprocessor {
        defines: defines.iter().cloned().collect(),
        include_dirs: include_dirs.to_vec(),
        recovery: RecoveryMode::Recover,
        ..Preprocessor::default()
    };
    preprocessor.process_file(path, 0)
}

/// Run the CPP-lite preprocessor over a C/C++ translation unit before tree-sitter
/// (#460): object-like `#define` expansion and `#ifdef`/`#ifndef`/`#if` guard
/// resolution, in RECOVERING mode so an unknown / function-like / unsupported
/// directive passes through rather than aborting discovery. `#include` is not
/// expanded here (no include dirs are consulted). Infallible: on a preprocessing
/// error the original source is returned unchanged, so the caller can always fall
/// back to the raw tree-sitter parse. The IDL preprocessor's directive handling is
/// language-agnostic, so the C/C++ discovery lane reuses it.
pub fn preprocess_c_like(source: &str, defines: &[(String, String)]) -> String {
    let mut preprocessor = Preprocessor {
        defines: defines.iter().cloned().collect(),
        recovery: RecoveryMode::Recover,
        ..Preprocessor::default()
    };
    preprocessor
        .process_source(source, None)
        .unwrap_or_else(|_| source.to_owned())
}

/// Maps a line number reported from a PREPROCESSED C/C++ translation unit back to
/// the line in the ORIGINAL source it came from (§27.6). [`preprocess_c_like`]
/// resolves `#ifdef` branches and expands object-like macros, which drops/folds
/// lines, so a target/finding location parsed out of the preprocessed text would be
/// shifted; this map translates it back so reported locations stay accurate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineMap {
    /// `original[i]` = 1-based original source line for preprocessed output line
    /// `i + 1` (1-based). Empty => identity (used on the raw-source fallback).
    original: Vec<usize>,
}

impl LineMap {
    /// Translate a 1-based PREPROCESSED line number to its 1-based ORIGINAL source
    /// line. Out-of-range inputs (and the identity/empty map) return the line
    /// unchanged, so a caller can always translate safely.
    pub fn to_original(&self, preprocessed_line: u32) -> u32 {
        if preprocessed_line == 0 {
            return preprocessed_line;
        }
        self.original
            .get(preprocessed_line as usize - 1)
            .map(|line| *line as u32)
            .unwrap_or(preprocessed_line)
    }

    /// An identity map (every line maps to itself) — what discovery uses when
    /// preprocessing is disabled or fell back to the raw source.
    pub fn identity() -> Self {
        Self::default()
    }
}

/// Run the recovering CPP-lite preprocessor over a C/C++ translation unit AND
/// return a [`LineMap`] translating preprocessed-line numbers back to original
/// source lines (§27.6). `#include` directives are passed through verbatim (in-tree
/// header expansion is a further increment). Infallible: on any preprocessing error
/// the original source and an identity map are returned, so the caller always has a
/// parseable text plus a correct (here, trivial) translation.
pub fn preprocess_c_like_with_line_map(
    source: &str,
    defines: &[(String, String)],
) -> (String, LineMap) {
    let mut preprocessor = Preprocessor {
        defines: defines.iter().cloned().collect(),
        recovery: RecoveryMode::Recover,
        passthrough_includes: true,
        track_lines: true,
        ..Preprocessor::default()
    };
    match preprocessor.process_source(source, None) {
        Ok(output) => (
            output,
            LineMap {
                original: std::mem::take(&mut preprocessor.line_map),
            },
        ),
        // Fall back to the raw source with an identity map so locations are exact.
        Err(_) => (source.to_owned(), LineMap::identity()),
    }
}

#[derive(Debug, Default)]
struct Preprocessor {
    defines: HashMap<String, String>,
    frames: Vec<ConditionalFrame>,
    include_stack: Vec<PathBuf>,
    include_dirs: Vec<PathBuf>,
    recovery: RecoveryMode,
    /// C/C++ discovery mode (§27.6): keep `#include` directives verbatim instead of
    /// erroring (no `current_file` to resolve against) — expanding in-tree headers
    /// is a further increment. With this set the output stays one line per source
    /// logical line, so the line map below is exact.
    passthrough_includes: bool,
    /// Accumulate, per emitted output line, the 1-based ORIGINAL source line it came
    /// from (§27.6 line map). Only populated when `track_lines` is set, so the IDL
    /// paths pay nothing. Aligned by construction: `process_source` emits exactly one
    /// output line per source logical line and pushes one entry here per iteration.
    track_lines: bool,
    line_map: Vec<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum RecoveryMode {
    #[default]
    Strict,
    Recover,
}

#[derive(Debug, Clone, Copy)]
struct ConditionalFrame {
    parent_active: bool,
    condition_active: bool,
    seen_else: bool,
}

impl Preprocessor {
    fn with_defines(defines: &[(String, String)]) -> Self {
        Self {
            defines: defines.iter().cloned().collect(),
            frames: Vec::new(),
            include_stack: Vec::new(),
            include_dirs: Vec::new(),
            recovery: RecoveryMode::Strict,
            passthrough_includes: false,
            track_lines: false,
            line_map: Vec::new(),
        }
    }

    fn process_file(&mut self, path: &Path, depth: usize) -> Result<String, IdlParseError> {
        if depth > MAX_INCLUDE_DEPTH {
            return Err(IdlParseError::new(
                "maximum include depth exceeded",
                Span::start(),
            ));
        }

        let normalized = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if self.include_stack.iter().any(|entry| entry == &normalized) {
            return Err(IdlParseError::new(
                format!("include cycle involving {}", normalized.display()),
                Span::start(),
            ));
        }

        let source = std::fs::read_to_string(&normalized).map_err(|error| {
            IdlParseError::new(format!("read {}: {error}", path.display()), Span::start())
        })?;

        self.include_stack.push(normalized.clone());
        let result = self.process_source(&source, Some(&normalized));
        self.include_stack.pop();
        result
    }

    fn process_source(
        &mut self,
        source: &str,
        current_file: Option<&Path>,
    ) -> Result<String, IdlParseError> {
        let frame_depth_at_entry = self.frames.len();
        let mut output = String::new();
        for (line_no, line, has_newline) in logical_lines(source) {
            // §27.6 line map: each loop iteration emits exactly ONE output line
            // (content, possibly empty, then an optional '\n'), so recording the
            // original source line here, once per iteration, keeps `line_map[i]`
            // aligned with output line `i + 1`. In `passthrough_includes` mode no
            // `#include` recurses, so this stays linear (one entry per output line).
            if self.track_lines {
                self.line_map.push(line_no);
            }
            if self.is_directive(&line) {
                if let Some(expansion) =
                    self.process_directive(&line, line_no, current_file, frame_depth_at_entry)?
                {
                    output.push_str(&expansion);
                }
                if has_newline {
                    output.push('\n');
                }
            } else if self.is_active() {
                output.push_str(&self.expand_line(&line));
                if has_newline {
                    output.push('\n');
                }
            } else {
                if has_newline {
                    output.push('\n');
                }
            }
        }

        if self.frames.len() > frame_depth_at_entry {
            self.frames.truncate(frame_depth_at_entry);
            return Err(IdlParseError::new(
                "missing #endif",
                line_span(source.lines().count().max(1), 1),
            ));
        }

        Ok(output)
    }

    fn is_directive(&self, line: &str) -> bool {
        line.trim_start().starts_with('#')
    }

    fn process_directive(
        &mut self,
        line: &str,
        line_no: usize,
        current_file: Option<&Path>,
        frame_depth_at_entry: usize,
    ) -> Result<Option<String>, IdlParseError> {
        let trimmed = line.trim_start();
        let rest = trimmed.strip_prefix('#').expect("directive starts with #");
        let rest = rest.trim_start();
        let (directive, payload) = split_directive(rest).ok_or_else(|| {
            IdlParseError::new("expected preprocessor directive", line_span(line_no, 1))
        })?;

        match directive {
            "define" => {
                if self.is_active() {
                    if let Err(error) = self.define_macro(payload, line_no) {
                        if self.recovery == RecoveryMode::Recover {
                            return Ok(Some(warning_pragma(format!(
                                "unsupported macro definition ignored at line {line_no}: {}",
                                error.message
                            ))));
                        }
                        return Err(error);
                    }
                }
                Ok(None)
            }
            "undef" => {
                if self.is_active() {
                    let name = parse_directive_identifier(payload, line_no)?;
                    self.defines.remove(name);
                }
                Ok(None)
            }
            "ifdef" => {
                let name = parse_directive_identifier(payload, line_no)?;
                let parent_active = self.is_active();
                self.frames.push(ConditionalFrame {
                    parent_active,
                    condition_active: self.defines.contains_key(name),
                    seen_else: false,
                });
                Ok(None)
            }
            "ifndef" => {
                let name = parse_directive_identifier(payload, line_no)?;
                let parent_active = self.is_active();
                self.frames.push(ConditionalFrame {
                    parent_active,
                    condition_active: !self.defines.contains_key(name),
                    seen_else: false,
                });
                Ok(None)
            }
            "if" => {
                let parent_active = self.is_active();
                let condition_active = if parent_active {
                    match eval_if_expression(strip_trailing_comment(payload), &self.defines) {
                        Ok(active) => active,
                        Err(error) if self.recovery == RecoveryMode::Recover => {
                            self.frames.push(ConditionalFrame {
                                parent_active,
                                condition_active: false,
                                seen_else: false,
                            });
                            return Ok(Some(warning_pragma(format!(
                                "unsupported #if expression treated as inactive at line {line_no}: {error}"
                            ))));
                        }
                        Err(error) => return Err(IdlParseError::new(error, line_span(line_no, 1))),
                    }
                } else {
                    false
                };
                self.frames.push(ConditionalFrame {
                    parent_active,
                    condition_active,
                    seen_else: false,
                });
                Ok(None)
            }
            "else" => {
                if !strip_trailing_comment(payload).trim().is_empty() {
                    return Err(IdlParseError::new(
                        "#else does not take arguments",
                        line_span(line_no, 1),
                    ));
                }
                if self.frames.len() == frame_depth_at_entry {
                    return Err(IdlParseError::new("unmatched #else", line_span(line_no, 1)));
                }
                let frame = self
                    .frames
                    .last_mut()
                    .expect("frame exists above entry depth");
                if frame.seen_else {
                    return Err(IdlParseError::new("duplicate #else", line_span(line_no, 1)));
                }
                frame.seen_else = true;
                frame.condition_active = !frame.condition_active;
                Ok(None)
            }
            "endif" => {
                if !strip_trailing_comment(payload).trim().is_empty() {
                    return Err(IdlParseError::new(
                        "#endif does not take arguments",
                        line_span(line_no, 1),
                    ));
                }
                if self.frames.len() == frame_depth_at_entry {
                    return Err(IdlParseError::new(
                        "unmatched #endif",
                        line_span(line_no, 1),
                    ));
                }
                self.frames.pop();
                Ok(None)
            }
            "include" => {
                // §27.6 C/C++ discovery: keep the directive verbatim in an active
                // region (dropped in an inactive one) rather than resolving it —
                // there is no `current_file`, and in-tree header expansion is a
                // further increment. Pass-through keeps the line map 1:1; tree-sitter
                // simply ignores the `#include` line.
                if self.passthrough_includes {
                    return Ok(self.is_active().then(|| trimmed.to_owned()));
                }
                if !self.is_active() {
                    return Ok(None);
                }
                let current_file = current_file.ok_or_else(|| {
                    IdlParseError::new("#include requires parse_idl_file", line_span(line_no, 1))
                })?;
                let include = parse_include(payload, line_no)?;
                let resolved = match self.resolve_include(current_file, &include, line_no) {
                    Ok(resolved) => resolved,
                    Err(error) if self.recovery == RecoveryMode::Recover => {
                        return Ok(Some(warning_pragma(error.to_string())));
                    }
                    Err(error) => return Err(error),
                };
                self.process_file(&resolved, self.include_stack.len())
                    .map(Some)
            }
            "pragma" => {
                if self.is_active() {
                    Ok(Some(trimmed.to_owned()))
                } else {
                    Ok(None)
                }
            }
            _ if self.recovery == RecoveryMode::Recover => Ok(Some(warning_pragma(format!(
                "unsupported directive '#{directive}' ignored at line {line_no}"
            )))),
            _ => Err(IdlParseError::new(
                format!("unsupported directive '#{directive}'"),
                line_span(line_no, 1),
            )),
        }
    }

    fn define_macro(&mut self, payload: &str, line_no: usize) -> Result<(), IdlParseError> {
        let payload = payload.trim_start();
        let (name, consumed) = read_identifier(payload).ok_or_else(|| {
            IdlParseError::new("expected macro name after #define", line_span(line_no, 1))
        })?;
        let replacement = &payload[consumed..];
        if replacement.starts_with('(') {
            return Err(IdlParseError::new(
                "function-like macros are unsupported",
                line_span(line_no, 1),
            ));
        }
        self.defines
            .insert(name.to_owned(), replacement.trim_start().to_owned());
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.frames
            .last()
            .is_none_or(|frame| frame.parent_active && frame.condition_active)
    }

    fn expand_line(&self, line: &str) -> String {
        let mut output = String::with_capacity(line.len());
        let mut chars = line.char_indices().peekable();

        while let Some((_, ch)) = chars.next() {
            if ch == '"' || ch == '\'' {
                output.push(ch);
                let quote = ch;
                let mut escaped = false;
                for (_, literal_ch) in chars.by_ref() {
                    output.push(literal_ch);
                    if escaped {
                        escaped = false;
                    } else if literal_ch == '\\' {
                        escaped = true;
                    } else if literal_ch == quote {
                        break;
                    }
                }
            } else if is_identifier_start(ch) {
                let mut ident = String::new();
                ident.push(ch);
                while let Some((_, next)) = chars.peek().copied() {
                    if is_identifier_continue(next) {
                        ident.push(next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Some(replacement) = self.defines.get(&ident) {
                    output.push_str(replacement);
                } else {
                    output.push_str(&ident);
                }
            } else {
                output.push(ch);
            }
        }

        output
    }

    fn resolve_include(
        &self,
        current_file: &Path,
        include: &IncludePath,
        line_no: usize,
    ) -> Result<PathBuf, IdlParseError> {
        let mut candidates = Vec::new();
        if matches!(include.kind, IncludeKind::Quoted) {
            let include_root = current_file.parent().unwrap_or_else(|| Path::new("."));
            candidates.push(include_root.join(&include.path));
        }
        candidates.extend(self.include_dirs.iter().map(|dir| dir.join(&include.path)));

        for candidate in &candidates {
            if candidate.is_file() {
                return Ok(candidate.clone());
            }
        }

        if matches!(include.kind, IncludeKind::Angle) && self.include_dirs.is_empty() {
            return Err(IdlParseError::new(
                format!(
                    "include <{}> requires at least one configured IDL include directory",
                    include.path
                ),
                line_span(line_no, 1),
            ));
        }

        let searched = candidates
            .iter()
            .map(|candidate| candidate.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Err(IdlParseError::new(
            format!("include '{}' not found; searched {searched}", include.path),
            line_span(line_no, 1),
        ))
    }
}

fn logical_lines(source: &str) -> Vec<(usize, String, bool)> {
    let mut lines = Vec::new();
    let mut continued = String::new();
    let mut continued_start = 1;
    let mut in_continuation = false;
    let mut last_has_newline = false;

    for (index, raw_line) in source.split_inclusive('\n').enumerate() {
        let line_no = index + 1;
        let line = raw_line.strip_suffix('\n').unwrap_or(raw_line);
        let has_newline = raw_line.ends_with('\n');
        let trimmed = line.trim_end();
        let continues = trimmed.ends_with('\\');
        let segment = if continues {
            let slash = line.rfind('\\').expect("continued line has backslash");
            line[..slash].trim_end()
        } else {
            line
        };

        if in_continuation {
            continued.push_str(segment);
        } else if continues {
            continued_start = line_no;
            continued.push_str(segment);
        } else {
            lines.push((line_no, line.to_owned(), has_newline));
            continue;
        }

        last_has_newline = has_newline;
        if continues {
            continued.push(' ');
            in_continuation = true;
        } else {
            lines.push((continued_start, std::mem::take(&mut continued), has_newline));
            in_continuation = false;
        }
    }

    if in_continuation {
        lines.push((continued_start, continued, last_has_newline));
    }

    lines
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IncludeKind {
    Quoted,
    Angle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncludePath {
    kind: IncludeKind,
    path: String,
}

fn split_directive(rest: &str) -> Option<(&str, &str)> {
    let (directive, consumed) = read_identifier(rest)?;
    Some((directive, &rest[consumed..]))
}

fn parse_directive_identifier(payload: &str, line_no: usize) -> Result<&str, IdlParseError> {
    let payload = payload.trim_start();
    let (name, consumed) = read_identifier(payload).ok_or_else(|| {
        IdlParseError::new(
            "expected identifier in preprocessor directive",
            line_span(line_no, 1),
        )
    })?;
    if !strip_trailing_comment(&payload[consumed..])
        .trim()
        .is_empty()
    {
        return Err(IdlParseError::new(
            "unexpected trailing tokens in preprocessor directive",
            line_span(line_no, 1),
        ));
    }
    Ok(name)
}

fn parse_include(payload: &str, line_no: usize) -> Result<IncludePath, IdlParseError> {
    let payload = strip_trailing_comment(payload).trim();
    if let Some(path) = parse_delimited_include(payload, '"', line_no)? {
        return Ok(IncludePath {
            kind: IncludeKind::Quoted,
            path,
        });
    }
    if let Some(path) = parse_delimited_include(payload, '<', line_no)? {
        return Ok(IncludePath {
            kind: IncludeKind::Angle,
            path,
        });
    }
    Err(IdlParseError::new(
        "expected quoted or angle-bracket include path",
        line_span(line_no, 1),
    ))
}

fn parse_delimited_include(
    payload: &str,
    opener: char,
    line_no: usize,
) -> Result<Option<String>, IdlParseError> {
    let closer = if opener == '<' { '>' } else { opener };
    let Some(rest) = payload.strip_prefix(opener) else {
        return Ok(None);
    };
    let Some(end) = rest.find(closer) else {
        return Err(IdlParseError::new(
            "unterminated include path",
            line_span(line_no, 1),
        ));
    };
    let include_path = &rest[..end];
    if !strip_trailing_comment(&rest[end + closer.len_utf8()..])
        .trim()
        .is_empty()
    {
        return Err(IdlParseError::new(
            "unexpected trailing tokens after include path",
            line_span(line_no, 1),
        ));
    }
    if include_path.is_empty() {
        return Err(IdlParseError::new(
            "empty include path",
            line_span(line_no, 1),
        ));
    }
    Ok(Some(include_path.to_owned()))
}

fn strip_trailing_comment(payload: &str) -> &str {
    let mut chars = payload.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '"' | '\'' => {
                let quote = ch;
                let mut escaped = false;
                for (_, literal_ch) in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if literal_ch == '\\' {
                        escaped = true;
                    } else if literal_ch == quote {
                        break;
                    }
                }
            }
            '/' => match chars.peek().copied() {
                Some((_, '/')) | Some((_, '*')) => return &payload[..index],
                _ => {}
            },
            _ => {}
        }
    }
    payload
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExprToken {
    Ident(String),
    Number(i64),
    Defined,
    Not,
    And,
    Or,
    LParen,
    RParen,
}

fn eval_if_expression(expression: &str, defines: &HashMap<String, String>) -> Result<bool, String> {
    let tokens = lex_expr(expression)?;
    let mut parser = ExprParser {
        tokens: &tokens,
        pos: 0,
        defines,
    };
    let value = parser.parse_or()?;
    if parser.pos != tokens.len() {
        return Err("unexpected trailing tokens in #if expression".to_owned());
    }
    Ok(value)
}

fn lex_expr(expression: &str) -> Result<Vec<ExprToken>, String> {
    let mut tokens = Vec::new();
    let mut chars = expression.char_indices().peekable();
    while let Some((start, ch)) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => {}
            '!' => {
                if chars.peek().is_some_and(|(_, next)| *next == '=') {
                    return Err("operator '!=' is unsupported".to_owned());
                }
                tokens.push(ExprToken::Not);
            }
            '&' => {
                if chars.next().is_some_and(|(_, next)| next == '&') {
                    tokens.push(ExprToken::And);
                } else {
                    return Err("expected '&&' in #if expression".to_owned());
                }
            }
            '|' => {
                if chars.next().is_some_and(|(_, next)| next == '|') {
                    tokens.push(ExprToken::Or);
                } else {
                    return Err("expected '||' in #if expression".to_owned());
                }
            }
            '(' => tokens.push(ExprToken::LParen),
            ')' => tokens.push(ExprToken::RParen),
            ch if ch.is_ascii_digit() => {
                let mut end = start + ch.len_utf8();
                while let Some((idx, next)) = chars.peek().copied() {
                    if next.is_ascii_hexdigit() || matches!(next, 'x' | 'X') {
                        end = idx + next.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                let text = &expression[start..end];
                let value = if let Some(hex) =
                    text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
                {
                    i64::from_str_radix(hex, 16)
                } else {
                    text.parse::<i64>()
                }
                .map_err(|_| format!("invalid integer constant '{text}'"))?;
                tokens.push(ExprToken::Number(value));
            }
            ch if is_identifier_start(ch) => {
                let mut end = start + ch.len_utf8();
                while let Some((idx, next)) = chars.peek().copied() {
                    if is_identifier_continue(next) {
                        end = idx + next.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                let ident = &expression[start..end];
                if ident == "defined" {
                    tokens.push(ExprToken::Defined);
                } else {
                    tokens.push(ExprToken::Ident(ident.to_owned()));
                }
            }
            _ => return Err(format!("unsupported token '{ch}' in #if expression")),
        }
    }
    Ok(tokens)
}

struct ExprParser<'a> {
    tokens: &'a [ExprToken],
    pos: usize,
    defines: &'a HashMap<String, String>,
}

impl ExprParser<'_> {
    fn parse_or(&mut self) -> Result<bool, String> {
        let mut value = self.parse_and()?;
        while self.consume(&ExprToken::Or) {
            value = value || self.parse_and()?;
        }
        Ok(value)
    }

    fn parse_and(&mut self) -> Result<bool, String> {
        let mut value = self.parse_unary()?;
        while self.consume(&ExprToken::And) {
            value = value && self.parse_unary()?;
        }
        Ok(value)
    }

    fn parse_unary(&mut self) -> Result<bool, String> {
        if self.consume(&ExprToken::Not) {
            return Ok(!self.parse_unary()?);
        }
        if self.consume(&ExprToken::Defined) {
            return self.parse_defined();
        }
        self.parse_primary()
    }

    fn parse_defined(&mut self) -> Result<bool, String> {
        if self.consume(&ExprToken::LParen) {
            let name = self.expect_ident()?;
            self.expect(&ExprToken::RParen)?;
            Ok(self.defines.contains_key(&name))
        } else {
            let name = self.expect_ident()?;
            Ok(self.defines.contains_key(&name))
        }
    }

    fn parse_primary(&mut self) -> Result<bool, String> {
        if self.consume(&ExprToken::LParen) {
            let value = self.parse_or()?;
            self.expect(&ExprToken::RParen)?;
            return Ok(value);
        }
        match self.tokens.get(self.pos) {
            Some(ExprToken::Number(value)) => {
                self.pos += 1;
                Ok(*value != 0)
            }
            Some(ExprToken::Ident(name)) => {
                self.pos += 1;
                Ok(self
                    .defines
                    .get(name)
                    .is_some_and(|value| macro_value_is_truthy(value)))
            }
            Some(token) => Err(format!("unexpected token {token:?} in #if expression")),
            None => Err("expected expression after #if".to_owned()),
        }
    }

    fn consume(&mut self, expected: &ExprToken) -> bool {
        if self.tokens.get(self.pos) == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: &ExprToken) -> Result<(), String> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(format!("expected {expected:?} in #if expression"))
        }
    }

    fn expect_ident(&mut self) -> Result<String, String> {
        match self.tokens.get(self.pos) {
            Some(ExprToken::Ident(name)) => {
                self.pos += 1;
                Ok(name.clone())
            }
            _ => Err("expected identifier in defined expression".to_owned()),
        }
    }
}

fn macro_value_is_truthy(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return true;
    }
    if let Ok(value) = trimmed.parse::<i64>() {
        return value != 0;
    }
    true
}

fn warning_pragma(message: impl AsRef<str>) -> String {
    let escaped = message.as_ref().replace('\\', "\\\\").replace('"', "\"\"");
    format!("#pragma govfuzz_warning \"{escaped}\"")
}

fn read_identifier(input: &str) -> Option<(&str, usize)> {
    let mut chars = input.char_indices();
    let (_, first) = chars.next()?;
    if !is_identifier_start(first) {
        return None;
    }
    let mut end = first.len_utf8();
    for (index, ch) in chars {
        if is_identifier_continue(ch) {
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    Some((&input[..end], end))
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn line_span(line: usize, column: usize) -> Span {
    Span {
        start: 0,
        end: 0,
        line,
        column,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preprocess_expands_object_like_defines_on_identifier_boundaries() {
        let output =
            preprocess_idl("#define SIZE 8\nconst long Limit = SIZE;\n").expect("preprocesses");
        assert!(output.contains("const long Limit = 8;"));
    }

    #[test]
    fn preprocess_c_like_resolves_ifdef_branches_and_object_macros() {
        // #460: a C TU with conditional compilation + an object-like macro. The
        // inactive #ifdef branch is dropped, the #else kept, and MAX expanded — so
        // tree-sitter sees the correct, single set of declarations.
        let src = "#define MAX 16\n\
                   #ifdef LINUX\n\
                   int linux_only(void);\n\
                   #else\n\
                   int other_only(void);\n\
                   #endif\n\
                   int buf[MAX];\n";

        let undefined = preprocess_c_like(src, &[]);
        assert!(undefined.contains("other_only"), "{undefined}");
        assert!(!undefined.contains("linux_only"), "{undefined}");
        assert!(undefined.contains("int buf[16]"), "{undefined}");

        let defined = preprocess_c_like(src, &[("LINUX".to_owned(), "1".to_owned())]);
        assert!(defined.contains("linux_only"), "{defined}");
        assert!(!defined.contains("other_only"), "{defined}");
    }

    #[test]
    fn line_map_translates_preprocessed_line_back_to_original() {
        // §27.6 regression guard: with an inactive `#ifdef` branch dropped and an
        // object macro expanded, a function that sits at original line 8 lands at a
        // DIFFERENT preprocessed line — the map must translate it back to 8, or
        // every reported location would be shifted.
        //
        // Original source (1-based):
        //   1: #define MAX 16
        //   2: #ifdef LINUX
        //   3: int linux_only(void);
        //   4: #else
        //   5: int other_only(void);
        //   6: #endif
        //   7: int buf[MAX];
        //   8: int real_target(const char *p) { return p[0]; }
        let src = "#define MAX 16\n\
                   #ifdef LINUX\n\
                   int linux_only(void);\n\
                   #else\n\
                   int other_only(void);\n\
                   #endif\n\
                   int buf[MAX];\n\
                   int real_target(const char *p) { return p[0]; }\n";

        let (out, map) = preprocess_c_like_with_line_map(src, &[]);
        assert!(out.contains("other_only"), "{out}");
        assert!(!out.contains("linux_only"), "{out}");
        assert!(out.contains("int buf[16]"), "{out}");

        // Find which PREPROCESSED line `real_target` ended up on, then translate.
        let pp_line = out
            .lines()
            .position(|l| l.contains("real_target"))
            .expect("real_target survives preprocessing") as u32
            + 1;
        assert_eq!(
            map.to_original(pp_line),
            8,
            "preprocessed line {pp_line} must map back to original line 8"
        );

        // `other_only` (kept #else branch) sits at original line 5.
        let other_pp = out
            .lines()
            .position(|l| l.contains("other_only"))
            .expect("other_only kept") as u32
            + 1;
        assert_eq!(map.to_original(other_pp), 5);

        // Out-of-range / zero inputs translate to themselves (safe identity).
        assert_eq!(map.to_original(0), 0);
        assert_eq!(map.to_original(9999), 9999);
    }

    #[test]
    fn line_map_passes_includes_through_and_stays_one_to_one() {
        // A real C file with an active `#include` must NOT abort preprocessing
        // (which would drop the line map's value): the include is kept verbatim and
        // every line maps to itself when there is no folding/conditional.
        let src = "#include <stdio.h>\n\
                   #include \"local.h\"\n\
                   int parse(const char *p) { return p[0]; }\n";
        let (out, map) = preprocess_c_like_with_line_map(src, &[]);
        assert!(out.contains("#include <stdio.h>"), "include kept: {out}");
        assert!(out.contains("#include \"local.h\""), "include kept: {out}");
        // No folding/conditionals -> identity map.
        for line in 1..=3u32 {
            assert_eq!(
                map.to_original(line),
                line,
                "line {line} should be identity"
            );
        }
    }

    #[test]
    fn line_map_corrects_for_backslash_continued_macro_fold() {
        // A 3-physical-line backslash-continued (object-like) macro folds to ONE
        // output line, so a function below it shifts up by 2 preprocessed lines —
        // the map must still resolve it to its ORIGINAL physical line.
        //   1: #define COMMON \
        //   2:   short s; \
        //   3:   long l;
        //   4: int after(const char *p) { return p[0]; }
        let src = "#define COMMON \\\n  short s; \\\n  long l;\n\
                   int after(const char *p) { return p[0]; }\n";
        let (out, map) = preprocess_c_like_with_line_map(src, &[]);
        let pp = out
            .lines()
            .position(|l| l.contains("int after"))
            .expect("after survives") as u32
            + 1;
        assert_eq!(
            map.to_original(pp),
            4,
            "function after a folded macro must map back to original line 4 (pp line {pp})"
        );
    }

    #[test]
    fn preprocess_folds_backslash_continued_macro_definitions() {
        let source =
            "#define COMMON_FIELDS \\\n  short s; \\\n  long l;\nstruct S {\n  COMMON_FIELDS\n};\n";
        let output = preprocess_idl(source).expect("preprocesses");

        assert!(output.contains("short s;"));
        assert!(output.contains("long l;"));
        assert!(!output.contains('\\'));
    }

    #[test]
    fn preprocess_preserves_string_literals_during_expansion() {
        let output =
            preprocess_idl("#define NAME Foo\nconst string S = \"NAME\";\ninterface NAME {};\n")
                .expect("preprocesses");
        assert!(output.contains("const string S = \"NAME\";"));
        assert!(output.contains("interface Foo {};"));
    }

    #[test]
    fn preprocess_selects_ifdef_and_ifndef_branches() {
        let source = "#define ENABLED\n#ifdef ENABLED\ninterface On {};\n#else\ninterface Off {};\n#endif\n#ifndef MISSING\ninterface Fallback {};\n#endif\n";
        let output = preprocess_idl(source).expect("preprocesses");
        assert!(output.contains("interface On {};"));
        assert!(output.contains("interface Fallback {};"));
        assert!(!output.contains("interface Off {};"));
    }

    #[test]
    fn preprocess_rejects_unsupported_if_expression() {
        let error = preprocess_idl("#if VENDOR_FLAG(1)\ninterface I {};\n#endif\n")
            .expect_err("unsupported directive is rejected");
        assert!(error.to_string().contains("unexpected trailing tokens"));
    }

    #[test]
    fn preprocess_if_expression_supports_defined_not_and_and() {
        let source = "#define ENABLED\n#if defined ENABLED && !defined DISABLED\ninterface Active {};\n#endif\n";
        let output = preprocess_idl(source).expect("preprocesses #if expression");

        assert!(output.contains("interface Active {};"));
    }

    #[test]
    fn preprocess_if_expression_allows_trailing_comment() {
        let source =
            "#define ENABLED\n#if defined ENABLED /* enabled */\ninterface Active {};\n#endif\n";
        let output = preprocess_idl(source).expect("preprocesses #if comment");

        assert!(output.contains("interface Active {};"));
    }

    #[test]
    fn preprocess_if_expression_treats_undefined_identifier_as_false() {
        let source = "#if MISSING\ninterface Hidden {};\n#endif\ninterface Root {};\n";
        let output = preprocess_idl(source).expect("preprocesses #if expression");

        assert!(!output.contains("interface Hidden {};"));
        assert!(output.contains("interface Root {};"));
    }

    #[test]
    fn preprocess_undef_removes_macro_definition() {
        let source = "#define ENABLED 1\n#undef ENABLED\n#if ENABLED\ninterface Hidden {};\n#endif\ninterface Root {};\n";
        let output = preprocess_idl(source).expect("preprocesses #undef");

        assert!(!output.contains("interface Hidden {};"));
        assert!(output.contains("interface Root {};"));
    }

    #[test]
    fn preprocess_allows_comments_after_conditional_directives() {
        let source = "#define ENABLED\n#ifdef ENABLED /* guard */\ninterface Root {};\n#else // disabled\ninterface Hidden {};\n#endif /* guard */\n";
        let output = preprocess_idl(source).expect("preprocesses comments after directives");

        assert!(output.contains("interface Root {};"));
        assert!(!output.contains("interface Hidden {};"));
    }

    #[test]
    fn preprocess_preserves_active_pragmas_and_drops_inactive_pragmas() {
        let source = "#define ENABLED\n#ifdef ENABLED\n#pragma prefix \"acme.example\"\n#else\n#pragma vendor disabled\n#endif\ninterface Root {};\n";

        let output = preprocess_idl(source).expect("preprocesses");

        assert!(output.contains("#pragma prefix \"acme.example\""));
        assert!(!output.contains("vendor disabled"));
        assert!(output.contains("interface Root {};"));
    }

    #[test]
    fn preprocess_file_resolves_quoted_include_relative_to_parent() {
        let root = temp_dir("include_relative");
        let _ = std::fs::remove_dir_all(&root);
        let child_dir = root.join("idl");
        std::fs::create_dir_all(&child_dir).expect("create fixture dir");
        std::fs::write(child_dir.join("common.idl"), "interface Common {};\n")
            .expect("write include");
        let root_file = child_dir.join("root.idl");
        std::fs::write(&root_file, "#include \"common.idl\"\ninterface Root {};\n")
            .expect("write root");

        let output = preprocess_idl_file(&root_file).expect("preprocesses file");

        assert!(output.contains("interface Common {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_allows_comments_after_include_path() {
        let root = temp_dir("include_comment");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        std::fs::write(root.join("common.idl"), "interface Common {};\n").expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(
            &root_file,
            "#include \"common.idl\" /* common */\ninterface Root {};\n",
        )
        .expect("write root");

        let output = preprocess_idl_file(&root_file).expect("preprocesses file");

        assert!(output.contains("interface Common {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_resolves_quoted_include_from_include_dir() {
        let root = temp_dir("include_dir_quoted");
        let _ = std::fs::remove_dir_all(&root);
        let include_dir = root.join("shared");
        std::fs::create_dir_all(&include_dir).expect("create include dir");
        std::fs::write(include_dir.join("common.idl"), "interface Common {};\n")
            .expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(&root_file, "#include \"common.idl\"\ninterface Root {};\n")
            .expect("write root");

        let output = preprocess_idl_file_with_include_dirs(&root_file, &[include_dir])
            .expect("preprocesses file");

        assert!(output.contains("interface Common {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_resolves_angle_include_from_include_dir() {
        let root = temp_dir("include_dir_angle");
        let _ = std::fs::remove_dir_all(&root);
        let include_dir = root.join("shared");
        std::fs::create_dir_all(&include_dir).expect("create include dir");
        std::fs::write(include_dir.join("common.idl"), "interface Common {};\n")
            .expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(&root_file, "#include <common.idl>\ninterface Root {};\n")
            .expect("write root");

        let output = preprocess_idl_file_with_include_dirs(&root_file, &[include_dir])
            .expect("preprocesses file");

        assert!(output.contains("interface Common {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_recovering_skips_missing_include_with_warning_pragma() {
        let root = temp_dir("recover_missing_include");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let root_file = root.join("root.idl");
        std::fs::write(&root_file, "#include \"missing.idl\"\ninterface Root {};\n")
            .expect("write root");

        let output = preprocess_idl_file_recovering_with_include_dirs(&root_file, &[])
            .expect("preprocesses with recovery");

        assert!(output.contains("#pragma govfuzz_warning"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_recovering_treats_unsupported_if_expression_as_inactive() {
        let root = temp_dir("recover_unsupported_if");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let root_file = root.join("root.idl");
        std::fs::write(
            &root_file,
            "#if VENDOR_FLAG(1)\ninterface Hidden {};\n#endif\ninterface Root {};\n",
        )
        .expect("write root");

        let output = preprocess_idl_file_recovering_with_include_dirs(&root_file, &[])
            .expect("preprocesses with recovery");

        assert!(output.contains("#pragma govfuzz_warning"));
        assert!(!output.contains("interface Hidden {};"));
        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_detects_include_cycles() {
        let root = temp_dir("include_cycle");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let a = root.join("a.idl");
        let b = root.join("b.idl");
        std::fs::write(&a, "#include \"b.idl\"\n").expect("write a");
        std::fs::write(&b, "#include \"a.idl\"\n").expect("write b");

        let error = preprocess_idl_file(&a).expect_err("cycle is rejected");

        assert!(error.to_string().contains("include cycle"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_skips_include_inside_inactive_ifdef_without_reading_file() {
        let root = temp_dir("inactive_include");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let root_file = root.join("root.idl");
        std::fs::write(
            &root_file,
            "#ifdef DISABLED\n#include \"missing.idl\"\n#endif\ninterface Root {};\n",
        )
        .expect("write root");

        let output = preprocess_idl_file(&root_file).expect("preprocesses file");

        assert!(output.contains("interface Root {};"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    #[test]
    fn preprocess_file_errors_for_missing_endif_inside_include() {
        let root = temp_dir("include_missing_endif");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dir");
        let included = root.join("common.idl");
        std::fs::write(&included, "#ifdef ENABLED\ninterface Common {};\n").expect("write include");
        let root_file = root.join("root.idl");
        std::fs::write(
            &root_file,
            "#define ENABLED\n#include \"common.idl\"\ninterface Root {};\n",
        )
        .expect("write root");

        let error = preprocess_idl_file(&root_file).expect_err("missing endif is rejected");

        assert!(error.to_string().contains("missing #endif"));
        std::fs::remove_dir_all(root).expect("remove fixture dir");
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("govfuzz-idl-{name}-{}", std::process::id()))
    }
}
