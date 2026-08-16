// SPDX-License-Identifier: Apache-2.0

//! Identifier-aware target-name matching shared by language rankers.
//!
//! Plain substring tests confuse data-flow actions with incidental spelling:
//! `download_audio` contains `load`, `mariadb_threadpool` contains `read`, and
//! `already_included` contains `read`. Expert target selection does not make
//! those associations. Split snake/kebab/qualified and camel-case identifiers,
//! then match action stems only at the beginning of an identifier token.

/// Split a qualified identifier into lowercase semantic tokens.
pub fn identifier_tokens(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut tokens = Vec::new();
    let mut current = String::new();
    for (index, &ch) in chars.iter().enumerate() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        let previous = index.checked_sub(1).and_then(|at| chars.get(at)).copied();
        let next = chars.get(index + 1).copied();
        let camel_boundary = ch.is_ascii_uppercase()
            && !current.is_empty()
            && (previous.is_some_and(|value| value.is_ascii_lowercase() || value.is_ascii_digit())
                || (previous.is_some_and(|value| value.is_ascii_uppercase())
                    && next.is_some_and(|value| value.is_ascii_lowercase())));
        if camel_boundary {
            tokens.push(std::mem::take(&mut current));
        }
        current.push(ch.to_ascii_lowercase());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Whether any identifier token begins with one of the supplied action stems.
/// Stems intentionally support ordinary inflection (`parse` -> `parser`,
/// `normaliz` -> `normalize`/`normalization`) without matching inside a word.
pub fn has_action_stem(name: &str, stems: &[&str]) -> bool {
    identifier_tokens(name).iter().any(|token| {
        stems.iter().any(|stem| {
            token.starts_with(stem)
                    // `ready`, `readable`, and `read-only` describe state; they
                    // are not a byte-reading action. These are common getter /
                    // predicate names in real projects.
                    && !(*stem == "read"
                        && (token.starts_with("ready")
                            || token.starts_with("readable")
                            || token.starts_with("readonly")))
        })
    })
}

/// Whether consecutive identifier tokens equal a semantic phrase.
pub fn has_token_sequence(name: &str, sequence: &[&str]) -> bool {
    if sequence.is_empty() {
        return false;
    }
    identifier_tokens(name)
        .windows(sequence.len())
        .any(|window| {
            window
                .iter()
                .map(String::as_str)
                .eq(sequence.iter().copied())
        })
}

/// Clear infrastructure/output helpers that should not outrank a parser solely
/// because they accept a string or byte slice.
pub fn is_low_value_helper(name: &str) -> bool {
    has_action_stem(
        name,
        &[
            "debug", "warn", "noop", "print", "logger", "fail", "report", "inspect",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_qualified_snake_and_camel_identifiers() {
        assert_eq!(
            identifier_tokens("OAuthUtils.parseWWWAuthenticateHeader"),
            [
                "o",
                "auth",
                "utils",
                "parse",
                "www",
                "authenticate",
                "header"
            ]
        );
        assert_eq!(
            identifier_tokens("parse_frontmatter"),
            ["parse", "frontmatter"]
        );
    }

    #[test]
    fn action_matching_rejects_incidental_substrings() {
        let parser_stems = ["parse", "read", "load", "decode", "unmarshal"];
        assert!(has_action_stem("readJson", &parser_stems));
        assert!(has_action_stem("unmarshalFromString", &parser_stems));
        assert!(!has_action_stem("download_audio", &parser_stems));
        assert!(!has_action_stem("mariadb_threadpool", &parser_stems));
        assert!(!has_action_stem("already_included", &parser_stems));
        assert!(!has_action_stem("my_file_readable", &parser_stems));
        assert!(!has_action_stem("isReady", &parser_stems));
        assert!(has_token_sequence("readObject", &["read", "object"]));
        assert!(!has_token_sequence("downloadObject", &["load", "object"]));
    }
}
