//! A key history anchored outside the operator's control, and anchored tree
//! heads.
//!
//! A seal signature is only as good as the answer to "which key was signing
//! then?". If that answer is a file the operator keeps, the operator can
//! rewrite it: swap in a key they hold, back-date the change, and re-sign
//! history with it. The chain does not object, because the chain is unkeyed. So
//! every key change, and every hourly tree head ([`crate::merkle`]), is
//! **anchored**: its digest is handed to a party the operator does not control,
//! and the receipt that party returns is kept beside it.
//!
//! ## What an anchor is
//!
//! Two kinds are named, and both are a seam here, not a client:
//!
//! * [`RFC3161`]: a time-stamp token from a time-stamping authority
//!   ([RFC 3161](https://www.rfc-editor.org/rfc/rfc3161)). The host sends a
//!   `TimeStampReq` whose `messageImprint` is SHA-256 over the record line. That
//!   is the 32 bytes the tagged digest spells in hex, so the imprint is exactly
//!   [`KeyRecord::digest`] or [`TreeHead::digest`](crate::merkle::TreeHead::digest)
//!   without its `sha256:` tag. The receipt is the token, base64.
//! * [`TRANSPARENCY_LOG`]: an entry in a public append-only log (an RFC 9162
//!   log, Sigstore's Rekor and the like). The receipt is whatever that log
//!   returns as proof of inclusion, base64.
//!
//! [`Anchor`] obtains a receipt and [`AnchorCheck`] checks one. This crate makes
//! no network call, parses no ASN.1 and holds no trust root. It does the same
//! for signatures, which go through [`SealSigner`](crate::SealSigner). A host
//! wires these traits to its TSA client or transparency-log client, and
//! `AnchorCheck` reports the time the outside party attests it saw the digest.
//!
//! ## What the key history is
//!
//! One `#key` line per key change, each followed by the `#anchor` line its
//! receipt came back as:
//!
//! ```text
//! #key 2026-11-15T12:00:00.000Z Ed25519 urn:key:ops-1 genesis
//! #anchor rfc3161 MIIEZjAD…
//! #key 2026-12-01T09:30:00.000Z Ed25519 urn:key:ops-2 sha256:6b1f…
//! #anchor rfc3161 MIIEaDAD…
//! ```
//!
//! A record says the key named by an IRI, of an algorithm, is the signing key
//! from a time on. Its last column chains it to the record before it (the
//! tagged digest of that record's line, or `genesis` for the first), so
//! changing any record changes the digest of every record after it, and every
//! one of those receipts stops matching.
//!
//! ## Why a rewrite is seen
//!
//! [`verify_key_history`] requires every record to be chained, in time order,
//! anchored, accepted by the checker, and anchored within `max_lag_millis` of
//! the time it says it took effect. The last requirement is what an operator
//! cannot meet after the fact. A rewritten record needs a fresh receipt, and a
//! fresh receipt carries today's time, not the time the record claims. A
//! history whose receipts all arrived on time was not rewritten after they
//! were issued.
//!
//! What it does not establish: that the key named was the operator's to name,
//! or that a seal was signed by it. Checking a seal signature is still
//! `urn:sign:verify` with the public key, and [`KeyHistory::key_at`] says which
//! key to ask it with.

use std::fmt;

use crate::chain::tagged;
use crate::line::{is_iri, shown, Timestamp};
use crate::merkle::{check_heads, BadLine, HeadFinding, SealLeaf, TreeHead};

/// The anchor kind of an RFC 3161 time-stamp token.
pub const RFC3161: &str = "rfc3161";

/// The anchor kind of a transparency-log inclusion receipt.
pub const TRANSPARENCY_LOG: &str = "transparency-log";

/// The marker a key record line starts with.
pub const KEY_MARKER: &str = "#key";

/// The marker an anchor receipt line starts with.
pub const ANCHOR_MARKER: &str = "#anchor";

/// What a first record chains from.
pub const GENESIS: &str = "genesis";

/// What obtains a receipt for a digest from a party outside the operator's
/// control.
pub trait Anchor: Send {
    /// The receipt kind: [`RFC3161`], [`TRANSPARENCY_LOG`], or a host's own.
    fn kind(&self) -> &str;

    /// Anchor the tagged digest (`sha256:…`), returning the receipt as base64.
    ///
    /// `None` is not an error here. The record is written without a receipt,
    /// and [`verify_key_history`] reports it unanchored until one is attached
    /// with [`KeyHistory::attach`]. A key change does not wait on a network.
    fn anchor(&self, digest: &str) -> Option<String>;
}

/// What checks a receipt against a digest.
pub trait AnchorCheck {
    /// Check that `receipt` anchors the tagged digest `digest`, returning the
    /// time the outside party attests it saw the digest: an RFC 3161 token's
    /// `genTime`, or the time a transparency log integrated the entry.
    ///
    /// `Err` carries why not, in words. It is shown escaped in the finding.
    fn check(&self, digest: &str, receipt: &Receipt) -> Result<Timestamp, String>;
}

/// An anchor's receipt, as the `#anchor <kind> <base64>` line holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// [`RFC3161`], [`TRANSPARENCY_LOG`], or a host's own kind.
    pub kind: String,
    /// The receipt, base64.
    pub token: String,
}

impl Receipt {
    /// The `#anchor` line, with no trailing newline.
    pub fn render(&self) -> String {
        format!("{ANCHOR_MARKER} {} {}", self.kind, self.token)
    }

    /// Parse an `#anchor` line.
    pub fn parse(line: &str) -> Result<Receipt, BadLine> {
        let bad = || BadLine::new("anchor", line);
        let mut tokens = line.trim_end_matches(['\n', '\r']).split(' ');
        if tokens.next() != Some(ANCHOR_MARKER) {
            return Err(bad());
        }
        let kind = tokens.next().filter(|t| is_token(t)).ok_or_else(bad)?;
        let token = tokens.next().filter(|t| is_token(t)).ok_or_else(bad)?;
        if tokens.next().is_some() {
            return Err(bad());
        }
        Ok(Receipt {
            kind: kind.to_string(),
            token: token.to_string(),
        })
    }
}

/// A printable token with no whitespace, so a line splits back into the
/// columns it was written as.
fn is_token(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_ascii_graphic())
}

/// One key change: from `at`, seals are signed with `key`.
///
/// ```
/// use ikigai_log::anchor::{KeyRecord, GENESIS};
/// use ikigai_log::Timestamp;
/// let record = KeyRecord {
///     at: Timestamp::parse("2026-11-15T12:00:00.000Z").unwrap(),
///     algorithm: "Ed25519".into(),
///     key: "urn:key:ops-1".into(),
///     prev: GENESIS.into(),
/// };
/// let line = record.render();
/// assert_eq!(line, "#key 2026-11-15T12:00:00.000Z Ed25519 urn:key:ops-1 genesis");
/// assert_eq!(KeyRecord::parse(&line).unwrap(), record);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    /// When the key took effect.
    pub at: Timestamp,
    /// The algorithm, spelled as a seal's signature token spells it.
    pub algorithm: String,
    /// The key, as an IRI a verifier resolves to the public key.
    pub key: String,
    /// The tagged digest of the record before, or [`GENESIS`].
    pub prev: String,
}

impl KeyRecord {
    /// The `#key` line, with no trailing newline.
    pub fn render(&self) -> String {
        format!(
            "{KEY_MARKER} {} {} {} {}",
            self.at.render(),
            self.algorithm,
            self.key,
            self.prev
        )
    }

    /// Parse a `#key` line.
    pub fn parse(line: &str) -> Result<KeyRecord, BadLine> {
        let bad = || BadLine::new("key", line);
        let mut tokens = line.trim_end_matches(['\n', '\r']).split(' ');
        if tokens.next() != Some(KEY_MARKER) {
            return Err(bad());
        }
        let at = Timestamp::parse(tokens.next().ok_or_else(bad)?).map_err(|_| bad())?;
        let algorithm = tokens.next().filter(|t| is_token(t)).ok_or_else(bad)?;
        let key = tokens
            .next()
            .filter(|t| is_token(t) && is_iri(t))
            .ok_or_else(bad)?;
        let prev = tokens.next().filter(|t| is_token(t)).ok_or_else(bad)?;
        if tokens.next().is_some() {
            return Err(bad());
        }
        Ok(KeyRecord {
            at,
            algorithm: algorithm.to_string(),
            key: key.to_string(),
            prev: prev.to_string(),
        })
    }

    /// The tagged SHA-256 of [`KeyRecord::render`]: what the next record's
    /// `prev` names and what an anchor is asked to timestamp.
    pub fn digest(&self) -> String {
        tagged(self.render().as_bytes())
    }
}

/// Why a key change was refused before it was recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyChangeError {
    /// The algorithm is empty or holds whitespace or a non-ASCII character.
    Algorithm(String),
    /// The key is not an absolute IRI without whitespace.
    Key(String),
    /// The time is before the last record's, or beyond what a line can hold.
    Time {
        /// The time asked for.
        at: Timestamp,
        /// The last record's time, when there is one.
        last: Option<Timestamp>,
    },
}

impl fmt::Display for KeyChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyChangeError::Algorithm(a) => {
                write!(f, "algorithm {} is not one printable ASCII word", shown(a))
            }
            KeyChangeError::Key(k) => {
                write!(f, "key {} is not an absolute IRI without spaces", shown(k))
            }
            KeyChangeError::Time {
                at,
                last: Some(last),
            } => write!(
                f,
                "a key change at {} would come before the last one, at {}",
                at.render(),
                last.render()
            ),
            KeyChangeError::Time { at, last: None } => write!(
                f,
                "a key change at {} is past the last time a line can hold",
                at.render()
            ),
        }
    }
}

impl std::error::Error for KeyChangeError {}

/// The key history: records in order, each with the receipt anchoring it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyHistory {
    /// `(record, its receipt)`, oldest first.
    pub records: Vec<(KeyRecord, Option<Receipt>)>,
}

impl KeyHistory {
    /// An empty history.
    pub fn new() -> KeyHistory {
        KeyHistory::default()
    }

    /// Record a key change and anchor it.
    ///
    /// The record is chained to the last one and refused when it would come
    /// before it. With an `anchor`, the receipt is obtained now. A record the
    /// anchor could not reach is kept without one and reported unanchored by
    /// [`verify_key_history`], so a late [`KeyHistory::attach`] is visible as
    /// late.
    pub fn change(
        &mut self,
        at: Timestamp,
        algorithm: &str,
        key: &str,
        anchor: Option<&dyn Anchor>,
    ) -> Result<&KeyRecord, KeyChangeError> {
        if !is_token(algorithm) {
            return Err(KeyChangeError::Algorithm(algorithm.to_string()));
        }
        if !is_token(key) || !is_iri(key) {
            return Err(KeyChangeError::Key(key.to_string()));
        }
        let last = self.records.last().map(|(record, _)| record);
        if last.is_some_and(|last| at < last.at) || at.validate().is_err() {
            return Err(KeyChangeError::Time {
                at,
                last: last.map(|last| last.at),
            });
        }
        let record = KeyRecord {
            at,
            algorithm: algorithm.to_string(),
            key: key.to_string(),
            prev: last.map_or_else(|| GENESIS.to_string(), KeyRecord::digest),
        };
        let receipt = anchor.and_then(|anchor| {
            anchor.anchor(&record.digest()).map(|token| Receipt {
                kind: anchor.kind().to_string(),
                token,
            })
        });
        self.records.push((record, receipt));
        Ok(&self.records.last().expect("just pushed").0)
    }

    /// Attach a receipt obtained later to the record at `index`. `false` when
    /// there is no such record.
    pub fn attach(&mut self, index: usize, receipt: Receipt) -> bool {
        match self.records.get_mut(index) {
            Some((_, slot)) => {
                *slot = Some(receipt);
                true
            }
            None => false,
        }
    }

    /// The record in effect at `at`: the last one whose time is not after it.
    /// `None` before the first.
    pub fn key_at(&self, at: Timestamp) -> Option<&KeyRecord> {
        self.records
            .iter()
            .map(|(record, _)| record)
            .take_while(|record| record.at <= at)
            .last()
    }

    /// The history as lines: each `#key` line, then its `#anchor` line when it
    /// has a receipt. Ends with a newline when it holds anything.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (record, receipt) in &self.records {
            out.push_str(&record.render());
            out.push('\n');
            if let Some(receipt) = receipt {
                out.push_str(&receipt.render());
                out.push('\n');
            }
        }
        out
    }

    /// Parse what [`KeyHistory::render`] writes. Blank lines and other `#`
    /// comment lines are skipped. An `#anchor` line belongs to the `#key` line
    /// before it, and one with no record to belong to, or a second for the same
    /// record, is refused rather than guessed at.
    pub fn parse(text: &str) -> Result<KeyHistory, BadLine> {
        let mut history = KeyHistory::new();
        for raw in text.lines() {
            let line = raw.trim_end_matches('\r');
            if line.starts_with(KEY_MARKER) {
                history.records.push((KeyRecord::parse(line)?, None));
            } else if line.starts_with(ANCHOR_MARKER) {
                let receipt = Receipt::parse(line)?;
                match history.records.last_mut() {
                    Some((_, slot @ None)) => *slot = Some(receipt),
                    _ => return Err(BadLine::new("anchor", line)),
                }
            } else if !line.trim().is_empty() && !line.starts_with('#') {
                return Err(BadLine::new("key", line));
            }
        }
        Ok(history)
    }
}

/// What anchoring covers: a key record, or a tree head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchored {
    /// The key record at this index of the history.
    Key {
        /// Its index, from 0.
        index: usize,
        /// The key it names.
        key: String,
    },
    /// A tree head.
    Head(TreeHead),
}

impl fmt::Display for Anchored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Anchored::Key { index, key } => {
                write!(f, "key record {} ({})", index + 1, shown(key))
            }
            Anchored::Head(head) => write!(
                f,
                "the head until {} over {} seals",
                head.until.render(),
                head.size
            ),
        }
    }
}

/// What verifying an anchored history found. Every variant is breaking: an
/// anchor exists to make a rewrite visible, and each of these is how one looks.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorFinding {
    /// A record's `prev` does not name the record before it.
    Unchained {
        /// The record's index, from 0.
        index: usize,
        /// What its `prev` says.
        stated: String,
        /// The digest of the record before it, or `genesis`.
        expected: String,
    },
    /// A record takes effect before the record before it.
    OutOfOrder {
        /// The record's index, from 0.
        index: usize,
        /// Its time.
        at: Timestamp,
        /// The previous record's time.
        previous: Timestamp,
    },
    /// No receipt anchors it.
    Unanchored {
        /// What is not anchored.
        what: Anchored,
    },
    /// The checker refused its receipt.
    Rejected {
        /// What the receipt was for.
        what: Anchored,
        /// Why, in the checker's words.
        reason: String,
    },
    /// The outside party first saw it more than the allowed lag after it says
    /// it took effect: it may have been written after the fact.
    Late {
        /// What was anchored late.
        what: Anchored,
        /// When it says it took effect, or when its interval ended.
        stated: Timestamp,
        /// When the anchor attests it was seen.
        anchored: Timestamp,
        /// The lag allowed, in milliseconds.
        allowed_millis: u64,
    },
    /// An anchored head does not match the seals in the files.
    Head(HeadFinding),
}

impl fmt::Display for AnchorFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnchorFinding::Unchained {
                index,
                stated,
                expected,
            } => write!(
                f,
                "key record {} chains from {} but the record before it is {}: the history was \
                 edited",
                index + 1,
                shown(stated),
                shown(expected)
            ),
            AnchorFinding::OutOfOrder {
                index,
                at,
                previous,
            } => write!(
                f,
                "key record {} takes effect at {}, before the record before it, at {}",
                index + 1,
                at.render(),
                previous.render()
            ),
            AnchorFinding::Unanchored { what } => write!(
                f,
                "{what} has no anchor receipt: nothing outside the operator's control has seen it"
            ),
            AnchorFinding::Rejected { what, reason } => write!(
                f,
                "the anchor receipt for {what} does not check: {}",
                shown(reason)
            ),
            AnchorFinding::Late {
                what,
                stated,
                anchored,
                allowed_millis,
            } => write!(
                f,
                "{what} says {} but was first anchored at {}, more than {allowed_millis} ms \
                 later: it may have been written after the fact",
                stated.render(),
                anchored.render()
            ),
            AnchorFinding::Head(finding) => finding.fmt(f),
        }
    }
}

/// Check one receipt, and that it came in time.
fn check_anchor(
    what: Anchored,
    digest: &str,
    receipt: Option<&Receipt>,
    stated: Timestamp,
    check: &dyn AnchorCheck,
    max_lag_millis: u64,
    findings: &mut Vec<AnchorFinding>,
) {
    let Some(receipt) = receipt else {
        findings.push(AnchorFinding::Unanchored { what });
        return;
    };
    match check.check(digest, receipt) {
        Err(reason) => findings.push(AnchorFinding::Rejected { what, reason }),
        Ok(anchored)
            if anchored.as_millis() > stated.as_millis().saturating_add(max_lag_millis) =>
        {
            findings.push(AnchorFinding::Late {
                what,
                stated,
                anchored,
                allowed_millis: max_lag_millis,
            })
        }
        Ok(_) => {}
    }
}

/// Verify a key history: chained record to record, in time order, and every
/// record anchored, accepted by `check`, and anchored no more than
/// `max_lag_millis` after the time it says it took effect.
///
/// Empty means no record was rewritten after its receipt was issued. The lag
/// is the operator's tolerance for an anchor that was briefly unreachable, and
/// it is exactly the window in which a record could be back-dated.
pub fn verify_key_history(
    history: &KeyHistory,
    check: &dyn AnchorCheck,
    max_lag_millis: u64,
) -> Vec<AnchorFinding> {
    let mut findings = Vec::new();
    let mut previous: Option<&KeyRecord> = None;
    for (index, (record, receipt)) in history.records.iter().enumerate() {
        let expected = previous.map_or_else(|| GENESIS.to_string(), KeyRecord::digest);
        if record.prev != expected {
            findings.push(AnchorFinding::Unchained {
                index,
                stated: record.prev.clone(),
                expected,
            });
        }
        if let Some(previous) = previous.filter(|previous| record.at < previous.at) {
            findings.push(AnchorFinding::OutOfOrder {
                index,
                at: record.at,
                previous: previous.at,
            });
        }
        check_anchor(
            Anchored::Key {
                index,
                key: record.key.clone(),
            },
            &record.digest(),
            receipt.as_ref(),
            record.at,
            check,
            max_lag_millis,
            &mut findings,
        );
        previous = Some(record);
    }
    findings
}

/// Verify anchored tree heads against the seals the files hold now: each head
/// anchored, accepted by `check` and anchored no more than `max_lag_millis`
/// after its interval ended, and each a prefix of the tree the files make
/// ([`check_heads`]).
///
/// Empty means no seal any of these heads counted has been rewritten or
/// removed since the head was anchored. That includes the oldest segments,
/// whose removal a chain walk alone takes for retention.
pub fn verify_anchored_heads(
    leaves: &[SealLeaf],
    heads: &[(TreeHead, Option<Receipt>)],
    check: &dyn AnchorCheck,
    max_lag_millis: u64,
) -> Vec<AnchorFinding> {
    let mut findings = Vec::new();
    for (head, receipt) in heads {
        check_anchor(
            Anchored::Head(head.clone()),
            &head.digest(),
            receipt.as_ref(),
            head.until,
            check,
            max_lag_millis,
            &mut findings,
        );
    }
    let bare: Vec<TreeHead> = heads.iter().map(|(head, _)| head.clone()).collect();
    findings.extend(
        check_heads(leaves, &bare)
            .into_iter()
            .map(AnchorFinding::Head),
    );
    findings
}
