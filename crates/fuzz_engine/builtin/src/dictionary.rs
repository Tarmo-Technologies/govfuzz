// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use ada_parser::ast::AdaStandard;
use ada_parser::lexer::{lex, ByteRange, Token, TokenKind};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dictionary {
    tokens: Vec<Vec<u8>>,
    entries: Vec<DictionaryEntry>,
}

impl Dictionary {
    pub fn from_tokens<I, T>(tokens: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let tokens = tokens
            .into_iter()
            .map(|token| token.as_ref().to_vec())
            .filter(|token| !token.is_empty())
            .collect();

        Self {
            tokens,
            entries: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.tokens.get(index).map(Vec::as_slice)
    }

    pub fn tokens(&self) -> impl Iterator<Item = &[u8]> {
        self.tokens.iter().map(Vec::as_slice)
    }

    pub fn has_curated_entries(&self) -> bool {
        !self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &DictionaryEntry> {
        self.entries.iter()
    }

    pub fn entries_for_bucket<'a>(
        &'a self,
        bucket: &DictionaryBucket,
    ) -> impl Iterator<Item = &'a DictionaryEntry> + 'a {
        let bucket = bucket.clone();
        self.entries
            .iter()
            .filter(move |entry| entry.bucket == bucket)
    }

    pub fn tokens_for_bucket<'a>(
        &'a self,
        bucket: &DictionaryBucket,
    ) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.entries_for_bucket(bucket)
            .map(|entry| entry.token.as_slice())
    }

    fn from_entries(entries: Vec<DictionaryEntry>) -> Self {
        let tokens = entries.iter().map(|entry| entry.token.clone()).collect();
        Self { tokens, entries }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DictionaryBucket {
    String,
    WideString,
    WideWideString,
    EnumLiteral { type_name: String },
    ExceptionName,
    IdlOperationName,
    IntegerConstant { type_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionarySpan {
    pub start: u32,
    pub end: u32,
}

impl From<ByteRange> for DictionarySpan {
    fn from(range: ByteRange) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryProvenance {
    pub source_unit: String,
    pub span: DictionarySpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryEntry {
    pub bucket: DictionaryBucket,
    token: Vec<u8>,
    pub occurrences: u32,
    pub score: u32,
    pub provenance: DictionaryProvenance,
}

impl DictionaryEntry {
    pub fn token(&self) -> &[u8] {
        &self.token
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DictionaryProximity {
    #[default]
    Target,
    OneHop,
    Distance(u8),
    Utility,
}

impl DictionaryProximity {
    fn weight(self) -> u32 {
        match self {
            Self::Target | Self::OneHop => 16,
            Self::Distance(0 | 1) => 16,
            Self::Distance(distance) => (16_u32 >> distance.saturating_sub(1).min(4)).max(1),
            Self::Utility => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DictionaryCurationConfig {
    pub min_string_len: usize,
    pub max_string_len: usize,
    pub min_identifier_len: usize,
    pub max_identifier_len: usize,
    pub top_k_per_bucket: usize,
    pub near_duplicate_jaccard_percent: u8,
}

impl Default for DictionaryCurationConfig {
    fn default() -> Self {
        Self {
            min_string_len: 4,
            max_string_len: 256,
            min_identifier_len: 1,
            max_identifier_len: 32,
            top_k_per_bucket: 64,
            near_duplicate_jaccard_percent: 90,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DictionarySource<'a> {
    pub source_unit: &'a str,
    pub path: &'a str,
    pub contents: &'a str,
    pub proximity: DictionaryProximity,
}

impl<'a> DictionarySource<'a> {
    pub fn new(source_unit: &'a str, path: &'a str, contents: &'a str) -> Self {
        Self {
            source_unit,
            path,
            contents,
            proximity: DictionaryProximity::default(),
        }
    }

    pub fn with_proximity(mut self, proximity: DictionaryProximity) -> Self {
        self.proximity = proximity;
        self
    }
}

#[derive(Debug, Clone)]
pub struct DictionaryCurator {
    config: DictionaryCurationConfig,
}

impl Default for DictionaryCurator {
    fn default() -> Self {
        Self::new(DictionaryCurationConfig::default())
    }
}

impl DictionaryCurator {
    pub fn new(config: DictionaryCurationConfig) -> Self {
        Self { config }
    }

    pub fn curate<'a, I>(&self, sources: I) -> Dictionary
    where
        I: IntoIterator<Item = DictionarySource<'a>>,
    {
        let mut aggregated = BTreeMap::new();

        for source in sources {
            if should_skip_source(source.source_unit, source.path) {
                continue;
            }

            let tokens = lex(source.contents, AdaStandard::Ada2022);
            self.mine_tokens(source, &tokens, &mut aggregated);
        }

        Dictionary::from_entries(self.retain_entries(aggregated))
    }

    fn mine_tokens(
        &self,
        source: DictionarySource<'_>,
        tokens: &[Token],
        aggregated: &mut BTreeMap<(DictionaryBucket, Vec<u8>), Candidate>,
    ) {
        let typed_string_literals = self.mine_constant_declarations(source, tokens, aggregated);

        for (index, token) in tokens.iter().enumerate() {
            match &token.kind {
                TokenKind::StringLiteral(value) => {
                    if !typed_string_literals.contains(&index) {
                        self.record(
                            aggregated,
                            source,
                            DictionaryBucket::String,
                            value.as_bytes(),
                            token.text_span,
                        );
                    }
                }
                TokenKind::KwType => self.mine_enum_literals(source, tokens, index, aggregated),
                TokenKind::Identifier(_) => {
                    self.mine_exception_declaration(source, tokens, index, aggregated);
                }
                TokenKind::KwWhen => self.mine_handler_choices(source, tokens, index, aggregated),
                TokenKind::KwRaise => self.mine_raise_name(source, tokens, index, aggregated),
                TokenKind::KwProcedure | TokenKind::KwFunction => {
                    self.mine_operation_name(source, tokens, index, aggregated);
                }
                _ => {}
            }
        }
    }

    fn mine_enum_literals(
        &self,
        source: DictionarySource<'_>,
        tokens: &[Token],
        index: usize,
        aggregated: &mut BTreeMap<(DictionaryBucket, Vec<u8>), Candidate>,
    ) {
        let Some((type_name, after_type_name)) =
            identifier_text_at(source.contents, tokens, index + 1)
        else {
            return;
        };
        let Some(is_index) = next_kind_index(tokens, after_type_name, |kind| {
            matches!(kind, TokenKind::KwIs)
        }) else {
            return;
        };
        let Some(open_index) = next_non_comment_index(tokens, is_index + 1) else {
            return;
        };
        if !matches!(tokens[open_index].kind, TokenKind::LParen) {
            return;
        }

        let bucket = DictionaryBucket::EnumLiteral {
            type_name: type_name.to_owned(),
        };
        for token in tokens.iter().skip(open_index + 1) {
            match &token.kind {
                TokenKind::Identifier(canonical) => {
                    let literal =
                        token_source_text(source.contents, token).unwrap_or(canonical.as_str());
                    self.record(
                        aggregated,
                        source,
                        bucket.clone(),
                        literal.as_bytes(),
                        token.text_span,
                    );
                }
                TokenKind::RParen | TokenKind::Semicolon | TokenKind::Eof => break,
                _ => {}
            }
        }
    }

    fn mine_exception_declaration(
        &self,
        source: DictionarySource<'_>,
        tokens: &[Token],
        index: usize,
        aggregated: &mut BTreeMap<(DictionaryBucket, Vec<u8>), Candidate>,
    ) {
        if matches!(token_kind(tokens, index + 1), Some(TokenKind::Colon))
            && matches!(token_kind(tokens, index + 2), Some(TokenKind::KwException))
        {
            let TokenKind::Identifier(canonical) = &tokens[index].kind else {
                return;
            };
            let name =
                token_source_text(source.contents, &tokens[index]).unwrap_or(canonical.as_str());
            self.record(
                aggregated,
                source,
                DictionaryBucket::ExceptionName,
                name.as_bytes(),
                tokens[index].text_span,
            );
        }
    }

    fn mine_handler_choices(
        &self,
        source: DictionarySource<'_>,
        tokens: &[Token],
        index: usize,
        aggregated: &mut BTreeMap<(DictionaryBucket, Vec<u8>), Candidate>,
    ) {
        for token in tokens.iter().skip(index + 1) {
            match &token.kind {
                TokenKind::Identifier(canonical) => {
                    let name =
                        token_source_text(source.contents, token).unwrap_or(canonical.as_str());
                    self.record(
                        aggregated,
                        source,
                        DictionaryBucket::ExceptionName,
                        name.as_bytes(),
                        token.text_span,
                    );
                }
                TokenKind::Arrow | TokenKind::Semicolon | TokenKind::Eof => break,
                _ => {}
            }
        }
    }

    fn mine_raise_name(
        &self,
        source: DictionarySource<'_>,
        tokens: &[Token],
        index: usize,
        aggregated: &mut BTreeMap<(DictionaryBucket, Vec<u8>), Candidate>,
    ) {
        if let Some((name, name_index)) = identifier_text_at(source.contents, tokens, index + 1) {
            self.record(
                aggregated,
                source,
                DictionaryBucket::ExceptionName,
                name.as_bytes(),
                tokens[name_index].text_span,
            );
        }
    }

    fn mine_operation_name(
        &self,
        source: DictionarySource<'_>,
        tokens: &[Token],
        index: usize,
        aggregated: &mut BTreeMap<(DictionaryBucket, Vec<u8>), Candidate>,
    ) {
        if let Some((name, name_index)) = identifier_text_at(source.contents, tokens, index + 1) {
            self.record(
                aggregated,
                source,
                DictionaryBucket::IdlOperationName,
                name.as_bytes(),
                tokens[name_index].text_span,
            );
        }
    }

    fn mine_constant_declarations(
        &self,
        source: DictionarySource<'_>,
        tokens: &[Token],
        aggregated: &mut BTreeMap<(DictionaryBucket, Vec<u8>), Candidate>,
    ) -> BTreeSet<usize> {
        let mut typed_string_literals = BTreeSet::new();

        for index in 0..tokens.len() {
            if !matches!(token_kind(tokens, index), Some(TokenKind::Identifier(_)))
                || !matches!(token_kind(tokens, index + 1), Some(TokenKind::Colon))
                || !matches!(token_kind(tokens, index + 2), Some(TokenKind::KwConstant))
            {
                continue;
            }

            let Some((type_name, after_type_name)) =
                identifier_text_at(source.contents, tokens, index + 3)
            else {
                continue;
            };
            let Some(assign_index) = next_kind_index(tokens, after_type_name, |kind| {
                matches!(kind, TokenKind::Assign)
            }) else {
                continue;
            };
            let Some(value_token) = tokens.get(assign_index + 1) else {
                continue;
            };

            match &value_token.kind {
                TokenKind::IntLiteral(value) | TokenKind::BasedLiteral(value) => self.record(
                    aggregated,
                    source,
                    DictionaryBucket::IntegerConstant {
                        type_name: type_name.to_owned(),
                    },
                    value.as_bytes(),
                    value_token.text_span,
                ),
                TokenKind::StringLiteral(value) => {
                    let bucket = string_bucket_for_type(type_name);
                    typed_string_literals.insert(assign_index + 1);
                    self.record(
                        aggregated,
                        source,
                        bucket,
                        value.as_bytes(),
                        value_token.text_span,
                    );
                }
                _ => {}
            }
        }

        typed_string_literals
    }

    fn record(
        &self,
        aggregated: &mut BTreeMap<(DictionaryBucket, Vec<u8>), Candidate>,
        source: DictionarySource<'_>,
        bucket: DictionaryBucket,
        token: &[u8],
        span: ByteRange,
    ) {
        if !self.token_length_allowed(&bucket, token) {
            return;
        }

        let normalized = normalize_token(token);
        if normalized.is_empty() || is_boilerplate(&normalized) {
            return;
        }

        let key = (bucket.clone(), normalized.clone());
        let weight = source.proximity.weight();
        aggregated
            .entry(key)
            .and_modify(|candidate: &mut Candidate| {
                candidate.occurrences = candidate.occurrences.saturating_add(1);
                candidate.score = candidate.score.saturating_add(weight);
            })
            .or_insert_with(|| Candidate {
                bucket,
                token: token.to_vec(),
                normalized,
                occurrences: 1,
                score: weight,
                provenance: DictionaryProvenance {
                    source_unit: source.source_unit.to_owned(),
                    span: span.into(),
                },
            });
    }

    fn token_length_allowed(&self, bucket: &DictionaryBucket, token: &[u8]) -> bool {
        let len = token.len();
        match bucket {
            DictionaryBucket::String
            | DictionaryBucket::WideString
            | DictionaryBucket::WideWideString => {
                len >= self.config.min_string_len && len <= self.config.max_string_len
            }
            DictionaryBucket::EnumLiteral { .. }
            | DictionaryBucket::ExceptionName
            | DictionaryBucket::IdlOperationName
            | DictionaryBucket::IntegerConstant { .. } => {
                len >= self.config.min_identifier_len && len <= self.config.max_identifier_len
            }
        }
    }

    fn retain_entries(
        &self,
        aggregated: BTreeMap<(DictionaryBucket, Vec<u8>), Candidate>,
    ) -> Vec<DictionaryEntry> {
        let mut by_bucket: BTreeMap<DictionaryBucket, Vec<Candidate>> = BTreeMap::new();
        for candidate in aggregated.into_values() {
            by_bucket
                .entry(candidate.bucket.clone())
                .or_default()
                .push(candidate);
        }

        let mut entries = Vec::new();
        for (_bucket, mut candidates) in by_bucket {
            candidates.sort_by(|left, right| {
                right
                    .score
                    .cmp(&left.score)
                    .then_with(|| right.occurrences.cmp(&left.occurrences))
                    .then_with(|| {
                        left.provenance
                            .source_unit
                            .cmp(&right.provenance.source_unit)
                    })
                    .then_with(|| left.provenance.span.start.cmp(&right.provenance.span.start))
                    .then_with(|| left.token.cmp(&right.token))
            });

            let mut retained: Vec<Candidate> = Vec::new();
            for candidate in candidates {
                if retained.iter().any(|existing| {
                    jaccard_percent_4gram(&existing.normalized, &candidate.normalized)
                        >= self.config.near_duplicate_jaccard_percent
                }) {
                    continue;
                }

                retained.push(candidate);
                if retained.len() >= self.config.top_k_per_bucket {
                    break;
                }
            }

            entries.extend(retained.into_iter().map(DictionaryEntry::from));
        }

        entries
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    bucket: DictionaryBucket,
    token: Vec<u8>,
    normalized: Vec<u8>,
    occurrences: u32,
    score: u32,
    provenance: DictionaryProvenance,
}

impl From<Candidate> for DictionaryEntry {
    fn from(candidate: Candidate) -> Self {
        Self {
            bucket: candidate.bucket,
            token: candidate.token,
            occurrences: candidate.occurrences,
            score: candidate.score,
            provenance: candidate.provenance,
        }
    }
}

fn should_skip_source(source_unit: &str, path: &str) -> bool {
    let unit = source_unit.to_ascii_lowercase();
    if matches!(unit.as_str(), "ada" | "system" | "interfaces" | "gnat")
        || unit.starts_with("ada.")
        || unit.starts_with("system.")
        || unit.starts_with("interfaces.")
        || unit.starts_with("gnat.")
    {
        return true;
    }

    path.replace('\\', "/")
        .split('/')
        .any(|component| component.eq_ignore_ascii_case("fake_corba"))
}

fn string_bucket_for_type(type_name: &str) -> DictionaryBucket {
    match normalize_type_name(type_name).as_str() {
        "wide_string" => DictionaryBucket::WideString,
        "wide_wide_string" => DictionaryBucket::WideWideString,
        _ => DictionaryBucket::String,
    }
}

fn normalize_type_name(type_name: &str) -> String {
    type_name
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn token_kind(tokens: &[Token], index: usize) -> Option<&TokenKind> {
    tokens.get(index).map(|token| &token.kind)
}

fn next_non_comment_index(tokens: &[Token], start: usize) -> Option<usize> {
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token.kind {
            TokenKind::Comment(_) => {}
            TokenKind::Eof | TokenKind::Semicolon => return None,
            _ => return Some(index),
        }
    }
    None
}

fn identifier_text_at<'a>(
    source: &'a str,
    tokens: &'a [Token],
    index: usize,
) -> Option<(&'a str, usize)> {
    let token = tokens.get(index)?;
    match &token.kind {
        TokenKind::Identifier(name) => Some((
            token_source_text(source, token).unwrap_or(name.as_str()),
            index,
        )),
        _ => None,
    }
}

fn token_source_text<'a>(source: &'a str, token: &Token) -> Option<&'a str> {
    source.get(token.text_span.start as usize..token.text_span.end as usize)
}

fn next_kind_index(
    tokens: &[Token],
    start: usize,
    predicate: impl Fn(&TokenKind) -> bool,
) -> Option<usize> {
    for (offset, token) in tokens.iter().enumerate().skip(start) {
        if matches!(token.kind, TokenKind::Semicolon | TokenKind::Eof) {
            return None;
        }
        if predicate(&token.kind) {
            return Some(offset);
        }
    }
    None
}

fn normalize_token(token: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(token.len());
    let mut pending_space = false;

    for byte in token {
        if byte.is_ascii_whitespace() {
            pending_space = !output.is_empty();
            continue;
        }

        if pending_space {
            output.push(b' ');
            pending_space = false;
        }
        output.push(byte.to_ascii_lowercase());
    }

    output
}

fn is_boilerplate(normalized: &[u8]) -> bool {
    if normalized
        .iter()
        .all(|byte| byte.is_ascii_punctuation() || byte.is_ascii_whitespace())
    {
        return true;
    }

    let text = String::from_utf8_lossy(normalized);
    if text.contains("spdx-license-identifier")
        || text.contains("copyright")
        || text.contains("http://")
        || text.contains("https://")
        || text.contains("www.")
    {
        return true;
    }

    matches!(
        text.as_ref(),
        "the" | "and" | "or" | "with" | "from" | "this" | "that" | "todo" | "fixme"
    )
}

fn jaccard_percent_4gram(left: &[u8], right: &[u8]) -> u8 {
    if left == right {
        return 100;
    }
    if left.len() < 4 || right.len() < 4 {
        return 0;
    }

    let left_grams = grams_4(left);
    let right_grams = grams_4(right);
    let intersection = left_grams
        .iter()
        .filter(|gram| right_grams.binary_search(gram).is_ok())
        .count();
    let union = left_grams.len() + right_grams.len() - intersection;
    if union == 0 {
        0
    } else {
        ((intersection * 100) / union) as u8
    }
}

fn grams_4(value: &[u8]) -> Vec<[u8; 4]> {
    let mut grams: Vec<[u8; 4]> = value
        .windows(4)
        .map(|window| [window[0], window[1], window[2], window[3]])
        .collect();
    grams.sort_unstable();
    grams.dedup();
    grams
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed::{typed_candidates, TypedValueKind};

    #[test]
    fn dictionary_filters_empty_tokens() {
        let dictionary = Dictionary::from_tokens([
            Vec::<u8>::new(),
            b"alpha".to_vec(),
            Vec::<u8>::new(),
            b"beta".to_vec(),
        ]);

        assert_eq!(dictionary.len(), 2);
        assert_eq!(
            dictionary.tokens().collect::<Vec<_>>(),
            vec![&b"alpha"[..], &b"beta"[..]]
        );
    }

    #[test]
    fn dictionary_owns_tokens() {
        let mut token = b"alpha".to_vec();
        let dictionary = Dictionary::from_tokens([token.as_slice()]);

        token.fill(b'x');

        assert_eq!(dictionary.get(0), Some(&b"alpha"[..]));
    }

    #[test]
    fn dictionary_returns_tokens_by_index() {
        let dictionary = Dictionary::from_tokens([&b"alpha"[..], &b"beta"[..]]);

        assert_eq!(dictionary.get(0), Some(&b"alpha"[..]));
        assert_eq!(dictionary.get(1), Some(&b"beta"[..]));
        assert_eq!(dictionary.get(2), None);
    }

    #[test]
    fn curator_mines_strings_with_provenance_and_filters_boilerplate() {
        let source = r#"
package body P is
   Message : constant String := "NEEDLE";
   Too_Short : constant String := "abc";
   Url : constant String := "https://example.test/license";
begin
   null;
end P;
"#;

        let dictionary =
            DictionaryCurator::default().curate([DictionarySource::new("P", "src/p.adb", source)]);

        let entries: Vec<&DictionaryEntry> = dictionary
            .entries_for_bucket(&DictionaryBucket::String)
            .collect();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].token(), b"NEEDLE");
        assert_eq!(entries[0].occurrences, 1);
        assert_eq!(entries[0].provenance.source_unit, "P");
        assert!(entries[0].provenance.span.start < entries[0].provenance.span.end);
    }

    #[test]
    fn curator_skips_system_units_and_fake_corba_sources() {
        let source =
            r#"package body Ignored is X : constant String := "SHOULD_NOT_APPEAR"; end Ignored;"#;
        let dictionary = DictionaryCurator::default().curate([
            DictionarySource::new("Ada.Text_IO", "src/ada-text_io.ads", source),
            DictionarySource::new("Fake", "govfuzz_work/fake_corba/corba.ads", source),
        ]);

        assert!(dictionary.is_empty());
    }

    #[test]
    fn curator_keeps_string_and_enum_literals_in_separate_buckets() {
        let source = r#"
package P is
   type Color is (Red, Green, GREEN);
   Label : constant String := "Alpha";
   Wide_Label : constant Wide_String := "WideToken";
   Wider_Label : constant Wide_Wide_String := "WideWideToken";
end P;
"#;

        let dictionary =
            DictionaryCurator::default().curate([DictionarySource::new("P", "src/p.ads", source)]);

        let string_tokens: Vec<&[u8]> = dictionary
            .tokens_for_bucket(&DictionaryBucket::String)
            .collect();
        let enum_tokens: Vec<&[u8]> = dictionary
            .tokens_for_bucket(&DictionaryBucket::EnumLiteral {
                type_name: "Color".to_owned(),
            })
            .collect();
        let wide_tokens: Vec<&[u8]> = dictionary
            .tokens_for_bucket(&DictionaryBucket::WideString)
            .collect();
        let wide_wide_tokens: Vec<&[u8]> = dictionary
            .tokens_for_bucket(&DictionaryBucket::WideWideString)
            .collect();

        assert_eq!(string_tokens, vec![&b"Alpha"[..]]);
        assert_eq!(enum_tokens, vec![&b"Green"[..], &b"Red"[..]]);
        assert_eq!(wide_tokens, vec![&b"WideToken"[..]]);
        assert_eq!(wide_wide_tokens, vec![&b"WideWideToken"[..]]);
        assert_eq!(
            typed_candidates(TypedValueKind::String, &dictionary),
            vec![b"Alpha".to_vec()]
        );
    }

    #[test]
    fn curator_does_not_mine_array_index_constraints_as_enum_literals() {
        let source = r#"
package P is
   type Int_Array is array (Positive range <>) of Integer;
   type Color is (Red, Green);
end P;
"#;

        let dictionary =
            DictionaryCurator::default().curate([DictionarySource::new("P", "src/p.ads", source)]);

        assert_eq!(
            dictionary
                .tokens_for_bucket(&DictionaryBucket::EnumLiteral {
                    type_name: "Int_Array".to_owned(),
                })
                .collect::<Vec<_>>(),
            Vec::<&[u8]>::new()
        );
        assert_eq!(
            dictionary
                .tokens_for_bucket(&DictionaryBucket::EnumLiteral {
                    type_name: "Color".to_owned(),
                })
                .collect::<Vec<_>>(),
            vec![&b"Red"[..], &b"Green"[..]]
        );
    }

    #[test]
    fn curator_mines_exception_names_idl_operation_names_and_integer_constants() {
        let source = r#"
package body P is
   Limit : constant Integer := 42;
   Network_Error : exception;
   procedure Ping is
   begin
      raise Network_Error;
   end Ping;
end P;
"#;

        let dictionary =
            DictionaryCurator::default().curate([DictionarySource::new("P", "src/p.adb", source)]);

        assert_eq!(
            dictionary
                .tokens_for_bucket(&DictionaryBucket::IntegerConstant {
                    type_name: "Integer".to_owned(),
                })
                .collect::<Vec<_>>(),
            vec![&b"42"[..]]
        );
        assert_eq!(
            dictionary
                .tokens_for_bucket(&DictionaryBucket::ExceptionName)
                .collect::<Vec<_>>(),
            vec![&b"Network_Error"[..]]
        );
        assert_eq!(
            dictionary
                .tokens_for_bucket(&DictionaryBucket::IdlOperationName)
                .collect::<Vec<_>>(),
            vec![&b"Ping"[..]]
        );
    }

    #[test]
    fn curator_scores_by_proximity_and_caps_each_bucket() {
        let config = DictionaryCurationConfig {
            top_k_per_bucket: 2,
            ..DictionaryCurationConfig::default()
        };
        let far_source = r#"
package body Utility is
   A : constant String := "common-value";
   B : constant String := "common-value";
   C : constant String := "common-value";
   D : constant String := "utility-only";
end Utility;
"#;
        let target_source =
            r#"package body Target is T : constant String := "target-specific"; end Target;"#;

        let dictionary = DictionaryCurator::new(config).curate([
            DictionarySource::new("Utility", "src/utility.adb", far_source)
                .with_proximity(DictionaryProximity::Utility),
            DictionarySource::new("Target", "src/target.adb", target_source)
                .with_proximity(DictionaryProximity::Target),
        ]);

        let tokens: Vec<&[u8]> = dictionary
            .tokens_for_bucket(&DictionaryBucket::String)
            .collect();

        assert_eq!(tokens, vec![&b"target-specific"[..], &b"common-value"[..]]);
    }

    #[test]
    fn curator_dedups_case_folded_tokens_and_collapses_near_duplicates() {
        let source = r#"
package body P is
   A : constant String := "AlphaValue";
   B : constant String := "alphavalue";
   C : constant String := "temperature-limit-high";
   D : constant String := "temperature-limit-high!";
end P;
"#;

        let dictionary =
            DictionaryCurator::default().curate([DictionarySource::new("P", "src/p.adb", source)]);

        let tokens: Vec<&[u8]> = dictionary
            .tokens_for_bucket(&DictionaryBucket::String)
            .collect();

        assert_eq!(
            tokens,
            vec![&b"AlphaValue"[..], &b"temperature-limit-high"[..]]
        );
    }
}
