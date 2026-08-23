//! The line grammar: one entry per line, absolute time, literal CURIEs.
//!
//! ```text
//! # ikigai-log v1
//! @prefix log:  <https://ikigai-rs.dev/ns/log#> .
//! @prefix prov: <http://www.w3.org/ns/prov#> .
//! @name     urn:log:bug:daemon:2026-08-23T09-00-00Z
//! @instance urn:ikigai:instance:bug:daemon
//! @level    log:info
//! @started  2026-08-23T09:00:00.000Z
//! @prev     genesis
//!
//! 2026-08-23T09:14:22.031Z log:Message urn:agent:calendar msg="sync started"
//! #seal 1-42 sha256:4c1e… sig:MEUCIQD…
//! ```
//!
//! Every column is chosen so that `grep` is a first-class query surface: the
//! timestamp is fixed-width and sorts lexically, the class is a literal CURIE,
//! and the subject is a bare absolute IRI. Compaction tricks that would defeat
//! that — offset timestamps, a JSON-LD context rooting the file — are
//! deliberately absent; disk is cheap and rotation compresses.
//!
//! **One entry is one line** is load-bearing three times over: for `grep`, for
//! the per-line hash chain, and for a rotation that has to reason about a
//! prefix of a file. So a newline inside a value is escaped on the way out, and
//! a raw newline can never appear in rendered output.
//!
//! Prefixes bind the CLASS column only. A subject is always written as the
//! absolute IRI it is: `urn:agent:calendar` is indistinguishable from a CURIE
//! by shape, and a grammar that had to guess would be a grammar that guesses
//! wrong on the day it matters.

use std::collections::BTreeMap;
use std::fmt;

/// The format version, written as the first line of every segment.
pub const FORMAT_VERSION: u32 = 1;

/// The first line of a segment, minus the version number.
const VERSION_PREFIX: &str = "# ikigai-log v";

/// The `#seal` line's marker, chosen so a seal reads as a comment to anything
/// that does not know the format and greps as `^#seal` to anything that does.
const SEAL_MARKER: &str = "#seal";

/// The `@prev` value for the first segment of a chain. Written explicitly,
/// never left absent: an absent `@prev` is then unambiguously an error, and a
/// genesis claim on a log that is not new is a claim someone can check.
const GENESIS: &str = "genesis";

// =====================================================================================
// Errors
// =====================================================================================

/// A line (or header) that does not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The timestamp column is not exactly `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    Timestamp(String),
    /// A column is missing entirely.
    MissingColumn(&'static str),
    /// A `key=value` column is malformed.
    Field(String),
    /// A CURIE whose prefix the header never bound.
    UnboundPrefix(String),
    /// A token that must be an absolute IRI is not one.
    NotAnIri(String),
    /// A header directive is missing, repeated, or malformed.
    Header(String),
    /// A `#seal` line that does not parse.
    Seal(String),
    /// The version line is absent or names a version this build cannot read.
    Version(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Timestamp(s) => write!(f, "bad timestamp: {s}"),
            ParseError::MissingColumn(c) => write!(f, "missing {c} column"),
            ParseError::Field(s) => write!(f, "bad key=value column: {s}"),
            ParseError::UnboundPrefix(s) => write!(f, "unbound prefix in CURIE: {s}"),
            ParseError::NotAnIri(s) => write!(f, "not an absolute IRI: {s}"),
            ParseError::Header(s) => write!(f, "bad header: {s}"),
            ParseError::Seal(s) => write!(f, "bad seal line: {s}"),
            ParseError::Version(s) => write!(f, "bad version line: {s}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A value that cannot be written as a line without losing or corrupting it.
/// Rendering is fallible on purpose: a subject that is not an IRI or a key with
/// a space in it would produce a line that parses back as something else, and
/// silently writing that into a hash-chained file is worse than refusing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// A token that must be an absolute IRI is not one.
    NotAnIri(String),
    /// A key that is not `[A-Za-z][A-Za-z0-9_.-]*`.
    Key(String),
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderError::NotAnIri(s) => write!(f, "not an absolute IRI: {s}"),
            RenderError::Key(s) => write!(f, "not a usable key: {s}"),
        }
    }
}

impl std::error::Error for RenderError {}

// =====================================================================================
// Time
// =====================================================================================

/// A point in time, milliseconds since the Unix epoch, rendered as exactly
/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// Fixed width and always UTC, because the column doubles as the sort key and
/// as a `grep` prefix: `grep '^2026-08-23T09:' segment.log` is a legitimate
/// query, and it stops being one the moment offsets or local zones appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(u64);

/// The rendered width of a timestamp — `2026-08-23T09:14:22.031Z`.
const TIMESTAMP_WIDTH: usize = 24;

impl Timestamp {
    /// A timestamp from milliseconds since the Unix epoch (`ikigai_core::Time`'s
    /// representation, so the kernel's clock drops straight in).
    pub fn from_millis(millis: u64) -> Self {
        Timestamp(millis)
    }

    /// Milliseconds since the Unix epoch.
    pub fn as_millis(self) -> u64 {
        self.0
    }

    /// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub fn render(self) -> String {
        let days = (self.0 / 86_400_000) as i64;
        let rem = self.0 % 86_400_000;
        let (y, m, d) = civil_from_days(days);
        let (hh, mm, ss, ms) = (
            rem / 3_600_000,
            rem / 60_000 % 60,
            rem / 1000 % 60,
            rem % 1000,
        );
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{ms:03}Z")
    }

    /// Parse `YYYY-MM-DDTHH:MM:SS.mmmZ`, and nothing else.
    ///
    /// Strict by design: the shape is verified by re-rendering what was parsed
    /// and comparing, which rejects an impossible civil date (February 30th)
    /// without a table of month lengths.
    pub fn parse(s: &str) -> Result<Timestamp, ParseError> {
        let bad = || ParseError::Timestamp(s.to_string());
        if s.len() != TIMESTAMP_WIDTH {
            return Err(bad());
        }
        let b = s.as_bytes();
        if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
            return Err(bad());
        }
        if b[19] != b'.' || b[23] != b'Z' {
            return Err(bad());
        }
        let num = |from: usize, to: usize| -> Result<u64, ParseError> {
            s.get(from..to)
                .ok_or_else(bad)?
                .parse::<u64>()
                .map_err(|_| bad())
        };
        let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
        let (hh, mm, ss, ms) = (num(11, 13)?, num(14, 16)?, num(17, 19)?, num(20, 23)?);
        if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
            return Err(bad());
        }
        let days = days_from_civil(y as i64, mo as u32, d as u32);
        if days < 0 {
            return Err(bad());
        }
        let millis = days as u64 * 86_400_000 + hh * 3_600_000 + mm * 60_000 + ss * 1000 + ms;
        let stamp = Timestamp(millis);
        // The round-trip check: a date that does not exist renders as a different
        // (real) one, so this is the whole calendar validation.
        if stamp.render() == s {
            Ok(stamp)
        } else {
            Err(bad())
        }
    }
}

/// Days since the Unix epoch → (year, month, day). Howard Hinnant's
/// `civil_from_days`, which is exact for the proleptic Gregorian calendar and
/// needs no leap-year table.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) → days since the Unix epoch. The inverse of
/// [`civil_from_days`].
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

// =====================================================================================
// Tokens: IRIs, CURIEs, keys, values
// =====================================================================================

/// Whether `s` can be written bare in an IRI column: absolute (it has a scheme
/// separator), no whitespace to break the column split, no angle brackets to
/// collide with the `<iri>` escape.
pub fn is_iri(s: &str) -> bool {
    !s.is_empty()
        && s.contains(':')
        && !s.contains(['<', '>', '"'])
        && !s.chars().any(char::is_whitespace)
}

/// Whether `k` is usable as a `key=` column: `[A-Za-z][A-Za-z0-9_.-]*`.
fn is_key(k: &str) -> bool {
    let mut chars = k.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Whether a value can be written without quotes: non-empty and free of
/// anything the scanner treats as structure.
fn is_bare_value(v: &str) -> bool {
    !v.is_empty() && !v.contains('"') && !v.contains('\\') && !v.chars().any(char::is_whitespace)
}

/// Quote and escape a value. Newlines and tabs become escapes rather than
/// characters — one entry is one line, and nothing may break that.
fn quote(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render a value: bare when it can be, quoted when it must be.
fn render_value(v: &str) -> String {
    if is_bare_value(v) {
        v.to_string()
    } else {
        quote(v)
    }
}

/// Shorten an IRI to a CURIE against `prefixes`, or fall back to `<iri>`.
///
/// The fallback exists so that an entry class from a vocabulary the header did
/// not bind is still written correctly rather than refused — the CURIE is a
/// convenience for readers, not a constraint on what can be logged.
fn render_iri_column(
    iri: &str,
    prefixes: &BTreeMap<String, String>,
) -> Result<String, RenderError> {
    if !is_iri(iri) {
        return Err(RenderError::NotAnIri(iri.to_string()));
    }
    let mut best: Option<(&str, &str)> = None;
    for (prefix, namespace) in prefixes {
        if let Some(local) = iri.strip_prefix(namespace.as_str()) {
            if local.is_empty() || local.contains([':', '/', '#']) {
                continue;
            }
            if best.is_none_or(|(_, b)| namespace.len() > b.len()) {
                best = Some((prefix, namespace));
            }
        }
    }
    Ok(match best {
        Some((prefix, namespace)) => format!("{prefix}:{}", &iri[namespace.len()..]),
        None => format!("<{iri}>"),
    })
}

/// Expand a class column — a CURIE, or `<iri>` — to an absolute IRI.
fn parse_iri_column(
    token: &str,
    prefixes: &BTreeMap<String, String>,
) -> Result<String, ParseError> {
    if let Some(inner) = token.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
        return if is_iri(inner) {
            Ok(inner.to_string())
        } else {
            Err(ParseError::NotAnIri(token.to_string()))
        };
    }
    let (prefix, local) = token
        .split_once(':')
        .ok_or_else(|| ParseError::NotAnIri(token.to_string()))?;
    match prefixes.get(prefix) {
        Some(namespace) => Ok(format!("{namespace}{local}")),
        None => Err(ParseError::UnboundPrefix(token.to_string())),
    }
}

// =====================================================================================
// Scanning
// =====================================================================================

/// Split a line into whitespace-separated tokens, keeping a quoted run whole
/// (and unescaped). Quoting is only ever needed inside a `key=value` column, so
/// the scanner does not need to know about columns at all.
fn scan(line: &str) -> Result<Vec<String>, ParseError> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            return Ok(tokens);
        }
        let mut token = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() && !quoted {
                break;
            }
            chars.next();
            match c {
                '"' => quoted = !quoted,
                '\\' if quoted => match chars.next() {
                    Some('n') => token.push('\n'),
                    Some('r') => token.push('\r'),
                    Some('t') => token.push('\t'),
                    Some(esc) => token.push(esc),
                    None => return Err(ParseError::Field(line.to_string())),
                },
                c => token.push(c),
            }
        }
        if quoted {
            return Err(ParseError::Field(line.to_string()));
        }
        tokens.push(token);
    }
}

// =====================================================================================
// Entries
// =====================================================================================

/// One log line: when, what kind, about what, and the typed columns.
///
/// The class and subject are held as absolute IRIs — CURIE shortening is a
/// rendering concern — so a consumer that has just parsed a line can look the
/// class straight up in the vocabulary without expanding anything first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The leading column, and `prov:startedAtTime` after transreption.
    pub time: Timestamp,
    /// The entry class, as an absolute IRI.
    pub class: String,
    /// What the entry is about, as an absolute IRI.
    pub subject: String,
    /// The `key=value` columns, in written order. A key may repeat — a
    /// resolution under two capability scopes writes `cap=` twice — so this is
    /// a list, not a map.
    pub fields: Vec<(String, String)>,
}

impl Entry {
    /// An entry with no fields yet.
    pub fn new(time: Timestamp, class: impl Into<String>, subject: impl Into<String>) -> Entry {
        Entry {
            time,
            class: class.into(),
            subject: subject.into(),
            fields: Vec::new(),
        }
    }

    /// Add one `key=value` column.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Entry {
        self.fields.push((key.into(), value.into()));
        self
    }

    /// The first value written for `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Every value written for `key`, in order.
    pub fn all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Render the line (no trailing newline). Never contains a raw newline.
    pub fn render(&self, prefixes: &BTreeMap<String, String>) -> Result<String, RenderError> {
        if !is_iri(&self.subject) {
            return Err(RenderError::NotAnIri(self.subject.clone()));
        }
        let mut out = String::new();
        out.push_str(&self.time.render());
        out.push(' ');
        out.push_str(&render_iri_column(&self.class, prefixes)?);
        out.push(' ');
        out.push_str(&self.subject);
        for (key, value) in &self.fields {
            if !is_key(key) {
                return Err(RenderError::Key(key.clone()));
            }
            out.push(' ');
            out.push_str(key);
            out.push('=');
            out.push_str(&render_value(value));
        }
        Ok(out)
    }

    /// Parse one entry line.
    pub fn parse(line: &str, prefixes: &BTreeMap<String, String>) -> Result<Entry, ParseError> {
        let tokens = scan(line)?;
        let mut tokens = tokens.into_iter();
        let time = Timestamp::parse(&tokens.next().ok_or(ParseError::MissingColumn("time"))?)?;
        let class = parse_iri_column(
            &tokens.next().ok_or(ParseError::MissingColumn("class"))?,
            prefixes,
        )?;
        let subject = tokens.next().ok_or(ParseError::MissingColumn("subject"))?;
        if !is_iri(&subject) {
            return Err(ParseError::NotAnIri(subject));
        }
        Ok(Entry {
            time,
            class,
            subject,
            fields: fields_from_tokens(tokens)?,
        })
    }
}

/// Parse a bare run of `key=value` columns — a line's TAIL, without the three
/// fixed columns in front of it.
///
/// This is the same scanner [`Entry::parse`] uses, exposed so that a caller
/// supplying fields by some other route (an endpoint argument, a config file, a
/// test) writes them in the syntax the file already uses instead of a second,
/// nearly-identical one. Quoting, escaping and repeated keys all behave exactly
/// as they do in a segment, because it is not "exactly as" — it is the same code.
///
/// ```
/// # use ikigai_log::parse_fields;
/// let fields = parse_fields(r#"dur=12 cap=urn:cap:fs msg="two words""#).unwrap();
/// assert_eq!(fields[2], ("msg".to_string(), "two words".to_string()));
/// ```
pub fn parse_fields(tail: &str) -> Result<Vec<(String, String)>, ParseError> {
    fields_from_tokens(scan(tail)?.into_iter())
}

fn fields_from_tokens(
    tokens: impl Iterator<Item = String>,
) -> Result<Vec<(String, String)>, ParseError> {
    let mut fields = Vec::new();
    for token in tokens {
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| ParseError::Field(token.clone()))?;
        if !is_key(key) {
            return Err(ParseError::Field(token.clone()));
        }
        fields.push((key.to_string(), value.to_string()));
    }
    Ok(fields)
}

// =====================================================================================
// Seals
// =====================================================================================

/// A signed checkpoint over the entries `first..=last` of this segment.
///
/// The per-entry hash chain itself is computed in memory and never materialized
/// per line — that noise is exactly what would wreck `grep`. What lands is this:
/// periodic, so tampering localizes to "between seal K and seal K+1", and
/// written as a `#` line so an unaware reader sees a comment.
///
/// The hash and signature are opaque here. What goes in them, and the walk that
/// verifies a segment against its predecessor, belong to rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seal {
    /// First entry sequence covered.
    pub first: u64,
    /// Last entry sequence covered.
    pub last: u64,
    /// The chain hash at `last`, tagged with its algorithm (`sha256:…`).
    pub hash: String,
    /// The signature over that hash, tagged (`sig:…`). Absent while a segment
    /// is written without a key — an unsigned seal still localizes tampering.
    pub signature: Option<String>,
}

impl Seal {
    /// Render the `#seal` line (no trailing newline).
    pub fn render(&self) -> String {
        let mut out = format!("{SEAL_MARKER} {}-{} {}", self.first, self.last, self.hash);
        if let Some(sig) = &self.signature {
            out.push(' ');
            out.push_str(sig);
        }
        out
    }

    /// Parse a `#seal` line.
    pub fn parse(line: &str) -> Result<Seal, ParseError> {
        let bad = || ParseError::Seal(line.to_string());
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some(SEAL_MARKER) {
            return Err(bad());
        }
        let range = tokens.next().ok_or_else(bad)?;
        let (first, last) = range.split_once('-').ok_or_else(bad)?;
        Ok(Seal {
            first: first.parse().map_err(|_| bad())?,
            last: last.parse().map_err(|_| bad())?,
            hash: tokens.next().ok_or_else(bad)?.to_string(),
            signature: tokens.next().map(str::to_string),
        })
    }
}

// =====================================================================================
// Lines
// =====================================================================================

/// Anything a segment file can hold, one line at a time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// An empty or whitespace-only line — the header ends at the first one.
    Blank,
    /// A `#` line that is not a seal.
    Comment(String),
    /// An `@name value` header directive (`@prefix` included, with its Turtle
    /// syntax kept whole so a Turtle parser can read the header block as-is).
    Directive { name: String, value: String },
    /// An entry.
    Entry(Entry),
    /// A `#seal` checkpoint.
    Seal(Seal),
}

impl Line {
    /// Classify and parse one line.
    pub fn parse(line: &str, prefixes: &BTreeMap<String, String>) -> Result<Line, ParseError> {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.trim().is_empty() {
            return Ok(Line::Blank);
        }
        if trimmed.starts_with(SEAL_MARKER) {
            return Ok(Line::Seal(Seal::parse(trimmed)?));
        }
        if let Some(rest) = trimmed.strip_prefix('#') {
            return Ok(Line::Comment(rest.trim().to_string()));
        }
        if let Some(rest) = trimmed.strip_prefix('@') {
            let (name, value) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            return Ok(Line::Directive {
                name: name.to_string(),
                value: value.trim().to_string(),
            });
        }
        Ok(Line::Entry(Entry::parse(trimmed, prefixes)?))
    }
}

// =====================================================================================
// Headers
// =====================================================================================

/// What a segment chains from: the previous segment's final seal, or the
/// beginning of the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prev {
    /// The first segment of a chain.
    Genesis,
    /// The prior segment's final seal hash, tagged (`sha256:…`).
    Seal(String),
}

/// A segment's header: what this file is, who wrote it, at what level, and what
/// it chains from.
///
/// The level lives here and nowhere else, and a segment has exactly one, which
/// is the point: a level change takes effect only at a rotation, so a verifier
/// reasons per sealed segment ("this ran at `info`, so absent resolutions are
/// explained") instead of tracking transitions inside sealed content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Format version from the `# ikigai-log vN` line.
    pub version: u32,
    /// Prefix → namespace, for the class column. Dumped into the file so it is
    /// self-describing without being opaque.
    pub prefixes: BTreeMap<String, String>,
    /// This segment's IRI — the named graph its entries land in.
    pub name: String,
    /// The writing process, as an IRI: the attribution key, since the log is
    /// per-process, not per-machine.
    pub instance: String,
    /// The level this whole segment ran at, as an absolute IRI.
    pub level: String,
    /// When the segment was opened.
    pub started: Timestamp,
    /// The chain link across the rotation boundary.
    pub prev: Prev,
}

impl Header {
    /// Render the header block, ending with the blank line that separates it
    /// from the entries.
    pub fn render(&self) -> Result<String, RenderError> {
        for iri in [&self.name, &self.instance, &self.level] {
            if !is_iri(iri) {
                return Err(RenderError::NotAnIri(iri.clone()));
            }
        }
        let mut out = format!("{VERSION_PREFIX}{}\n", self.version);
        let width = self.prefixes.keys().map(String::len).max().unwrap_or(0);
        for (prefix, namespace) in &self.prefixes {
            let padded = format!("{prefix}:");
            out.push_str(&format!(
                "@prefix {padded:<w$} <{namespace}> .\n",
                w = width + 1
            ));
        }
        out.push_str(&format!("@name     {}\n", self.name));
        out.push_str(&format!("@instance {}\n", self.instance));
        out.push_str(&format!(
            "@level    {}\n",
            render_iri_column(&self.level, &self.prefixes)?
        ));
        out.push_str(&format!("@started  {}\n", self.started.render()));
        out.push_str(&match &self.prev {
            Prev::Genesis => format!("@prev     {GENESIS}\n"),
            Prev::Seal(hash) => format!("@prev     {hash}\n"),
        });
        out.push('\n');
        Ok(out)
    }

    /// Parse the header block at the start of `text`, up to the first blank
    /// line. Returns the header and the byte offset where the entries begin.
    ///
    /// Every directive is required. A destination or a level that silently
    /// defaults is a hole in the record that nothing brackets, so an incomplete
    /// header is an error and not a set of assumptions.
    pub fn parse(text: &str) -> Result<(Header, usize), ParseError> {
        let mut prefixes = BTreeMap::new();
        let (mut version, mut name, mut instance, mut level, mut started, mut prev) =
            (None, None, None, None, None, None);
        let mut offset = 0;
        for raw in text.split_inclusive('\n') {
            offset += raw.len();
            let line = raw.trim_end_matches(['\n', '\r']);
            if line.trim().is_empty() {
                break;
            }
            if let Some(rest) = line.strip_prefix(VERSION_PREFIX) {
                version = Some(
                    rest.trim()
                        .parse::<u32>()
                        .map_err(|_| ParseError::Version(line.to_string()))?,
                );
                continue;
            }
            match Line::parse(line, &prefixes)? {
                Line::Directive { name: n, value } => match n.as_str() {
                    "prefix" => {
                        let (p, ns) = parse_prefix_directive(&value)?;
                        prefixes.insert(p, ns);
                    }
                    "name" => name = Some(require_iri(&value)?),
                    "instance" => instance = Some(require_iri(&value)?),
                    "level" => level = Some(parse_iri_column(&value, &prefixes)?),
                    "started" => started = Some(Timestamp::parse(&value)?),
                    "prev" => {
                        prev = Some(if value == GENESIS {
                            Prev::Genesis
                        } else if value.is_empty() {
                            return Err(ParseError::Header("empty @prev".into()));
                        } else {
                            Prev::Seal(value)
                        })
                    }
                    other => return Err(ParseError::Header(format!("unknown directive @{other}"))),
                },
                Line::Comment(_) => {}
                _ => return Err(ParseError::Header(line.to_string())),
            }
        }
        let missing = |what: &str| ParseError::Header(format!("missing @{what}"));
        let version = version.ok_or_else(|| ParseError::Version("no version line".into()))?;
        if version != FORMAT_VERSION {
            return Err(ParseError::Version(format!(
                "segment is v{version}, this build reads v{FORMAT_VERSION}"
            )));
        }
        Ok((
            Header {
                version,
                prefixes,
                name: name.ok_or_else(|| missing("name"))?,
                instance: instance.ok_or_else(|| missing("instance"))?,
                level: level.ok_or_else(|| missing("level"))?,
                started: started.ok_or_else(|| missing("started"))?,
                prev: prev.ok_or_else(|| missing("prev"))?,
            },
            offset,
        ))
    }
}

/// `log: <https://ikigai-rs.dev/ns/log#> .` → `("log", "https://…#")`.
fn parse_prefix_directive(value: &str) -> Result<(String, String), ParseError> {
    let bad = || ParseError::Header(format!("@prefix {value}"));
    let mut parts = value.split_whitespace();
    let prefix = parts.next().ok_or_else(bad)?.trim_end_matches(':');
    let namespace = parts
        .next()
        .ok_or_else(bad)?
        .trim_start_matches('<')
        .trim_end_matches('>');
    if prefix.is_empty() || namespace.is_empty() {
        return Err(bad());
    }
    Ok((prefix.to_string(), namespace.to_string()))
}

fn require_iri(value: &str) -> Result<String, ParseError> {
    if is_iri(value) {
        Ok(value.to_string())
    } else {
        Err(ParseError::NotAnIri(value.to_string()))
    }
}
