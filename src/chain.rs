//! The chain, the seal, and verification — the four layers that make a segment
//! evidence rather than a file.
//!
//! ## 1. A per-entry hash chain, computed in memory and never written per line
//!
//! ```text
//! h₀ = sha256(the segment's canonical header)
//! hᵢ = sha256(hᵢ₋₁ ‖ "\n" ‖ the i-th entry line)
//! ```
//!
//! `hᵢ₋₁` enters as the **tagged ASCII string** it is rendered as (`sha256:…`),
//! not as raw digest bytes — so every input to every step is exactly what a
//! reader can see, and a verifier written in another language has no byte-order
//! question to get wrong.
//!
//! **Nothing per line lands on disk.** A hash column on every entry is precisely
//! the noise that would wreck `grep`, which is a first-order requirement of this
//! format; the chain is recomputed on read, which costs one SHA-256 per line and
//! is a rounding error beside the parse that has to happen anyway.
//!
//! The header enters as [`Header::render`]'s output rather than as the file's
//! literal bytes. Canonical, not raw, on purpose: the chain commits to what the
//! header *says* — its name, instance, level, start and `@prev` — and re-deriving
//! it from a parsed header is what lets a verifier compute h₀ without depending
//! on how many blank lines a writer happened to emit.
//!
//! ## 2. Seals: signed checkpoints every N entries **or** T milliseconds
//!
//! A `#seal first-last <hash> [<alg>:<base64>]` line lands periodically, which
//! localizes tampering to "between seal K and seal K+1". The **time** bound is
//! not optional and not a convenience: N alone leaves a quiet log unsealed for
//! days, and an unsealed tail is exactly what an attacker goes for.
//!
//! Seal lines are **not** themselves chained — a seal states the hash, so it
//! cannot be an input to it. Deleting one is caught two other ways: seal ranges
//! must be contiguous ([`Finding::SealRangeGap`]), and the **final** seal of a
//! segment is what the next segment's `@prev` names.
//!
//! ## 3. ★ The chain spans rotations
//!
//! This is the layer earlier designs missed. If each file chains from scratch,
//! **rotation is a seam at which history can be rewritten wholesale**: delete a
//! file, forge a replacement, and nothing detects it. So a segment's `@prev`
//! carries its predecessor's final seal hash, and [`head_of`] is the one
//! definition of what that is:
//!
//! * the hash on the segment's **last `#seal` line**, when it has one;
//! * otherwise **h₀**, the header hash — a segment that never checkpointed
//!   committed nothing beyond its own header, and saying so is better than
//!   refusing to chain from it (a crashed process must not break the successor).
//!
//! Segment ordering falls out of it: the chain is a linked list, and
//! [`verify_chain`] walks it rather than trusting a directory listing.
//!
//! ## 4. ★ Verify checks more than hashes
//!
//! A hash chain is **tamper-evident, not omission-evident**. It proves nothing
//! was ALTERED; it cannot prove nothing was LEFT OUT — and a level change is
//! legitimate, sanctioned omission. An attacker who lowers the level opens a
//! hole that a hash-only verifier then blesses as perfectly intact.
//!
//! So verification also checks that **every gap is BRACKETED by an always-land
//! marker**. Concretely, today:
//!
//! * two adjacent segments at different levels require a `log:LevelChange` (or a
//!   `log:ConfigChange` naming `key=level`) in one of them —
//!   [`Finding::UnbracketedLevelChange`];
//! * entry sequence numbers must be dense within a segment, because
//!   [`Writer::write`](crate::Writer::write) advances the counter only for
//!   entries it actually emits — a level-filtered entry consumes no sequence
//!   number, so a jump means lines were REMOVED, not filtered;
//! * seal coverage must be contiguous from 1.
//!
//! ## ★ What verification does NOT establish
//!
//! **The level is checked as RECORDED, not as AUTHENTIC.** A `log:LevelChange`
//! entry brackets a gap, and the chain proves that entry was not altered after
//! the fact — but nothing here stops whoever holds the writer from lowering the
//! level and honestly recording that they did. A level MAC (`locked` mode) needs
//! a key the application itself cannot hold, which lands on the helper-app work
//! that does not exist yet. Verify says the gap is explained; it does not say the
//! explanation was involuntary.
//!
//! **Signatures are stated, not checked.** A seal's `<alg>:<base64>` token is
//! reported and carried into the graph as `sig:algorithm` + `sig:value`, and
//! checking it is `urn:sign:verify`'s job with the public key — this crate holds
//! no key and resolves none. **An unsigned seal still localizes tampering**,
//! which is why a segment written without a key chains and seals anyway.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::line::{Entry, Header, Line, Prev, Seal, Timestamp};
use crate::vocabulary::{
    Vocabulary, CONFIG_CHANGE_CLASS, LEVEL_CHANGE_CLASS, PROCESS_STOP_CLASS, ROTATION_CLASS,
};

/// `log:successor` — the forward link a rotation marker writes.
const LOG_SUCCESSOR: &str = "https://ikigai-rs.dev/ns/log#successor";

/// The digest algorithm every hash in this module is tagged with.
///
/// Taken from `ikigai-sign`, not copied: the two crates write `sig:contentHash`
/// with the same predicate, so writing two lexical forms of one value would mean
/// they never join in a query — a silent failure rather than a loud one. That
/// export exists for exactly this consumer.
pub const HASH_ALGORITHM: &str = ikigai_sign::HASH_ALG_SHA256;

/// The lowercase hex of a SHA-256 digest, tagged with its algorithm.
///
/// Tagged at every boundary, never bare: a bare hex string is a permanent,
/// unrecoverable commitment to one hash function, and a verifier years later can
/// only guess what produced it.
///
/// ```
/// # use ikigai_log::chain::tagged;
/// // The shape is the contract: `sha256:` then 64 lowercase hex digits, and
/// // this is the literal that lands in `sig:contentHash` and on a `#seal` line.
/// let hash = tagged(b"abc");
/// assert_eq!(
///     hash,
///     "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/// );
/// ```
pub fn tagged(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(HASH_ALGORITHM.len() + 1 + digest.len() * 2);
    out.push_str(HASH_ALGORITHM);
    out.push(':');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

// =====================================================================================
// The chain
// =====================================================================================

/// The running hash of a segment: h₀ from the header, advanced once per entry.
///
/// Held by the writer as it appends and rebuilt by the verifier as it reads, from
/// the same two functions — so "the writer and the verifier agree" is not a
/// discipline, it is the same code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    head: String,
}

impl Chain {
    /// h₀: the chain rooted at a header. The header carries `@prev`, so the
    /// predecessor's final seal is bound into every hash that follows.
    pub fn open(header: &Header) -> Chain {
        // A header that will not render cannot have been written, so the fallback
        // is unreachable from a writer; a verifier reaching it hashes the token
        // that says so rather than panicking inside a log reader.
        let canonical = header
            .render()
            .unwrap_or_else(|e| format!("unrenderable header: {e}"));
        Chain {
            head: tagged(canonical.as_bytes()),
        }
    }

    /// hᵢ = sha256(hᵢ₋₁ ‖ "\n" ‖ line). `line` is the entry line exactly as it
    /// appears, with no trailing newline — so whitespace tampering inside a line
    /// is caught along with everything else.
    ///
    /// The step is spelled out here because a verifier in another language has to
    /// reproduce it exactly, and prose about a hash construction is the kind of
    /// documentation that drifts:
    ///
    /// ```
    /// # use ikigai_log::chain::tagged;
    /// # let head = tagged(b"whatever the header was");
    /// # let line = "2026-08-23T09:14:22.031Z log:Message urn:x seq=1";
    /// // What `Chain::advance` computes, written out:
    /// let next = tagged(format!("{head}\n{line}").as_bytes());
    /// # let mut chain = ikigai_log::chain::Chain::from_head(head);
    /// # chain.advance(line);
    /// # assert_eq!(chain.head(), next);
    /// ```
    pub fn advance(&mut self, line: &str) {
        let mut buffer = String::with_capacity(self.head.len() + 1 + line.len());
        buffer.push_str(&self.head);
        buffer.push('\n');
        buffer.push_str(line);
        self.head = tagged(buffer.as_bytes());
    }

    /// The chain hash after the last entry folded in, tagged.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// A chain resumed at a head someone else computed — for a verifier written
    /// against this construction, and for the doctest above that spells the step
    /// out longhand.
    pub fn from_head(head: String) -> Chain {
        Chain { head }
    }
}

// =====================================================================================
// Signing
// =====================================================================================

/// What signs a seal.
///
/// The seam is a trait rather than a key, because **keys resolve as resources**:
/// a host wires this to `urn:sign:sign` over `key=urn:file:…` today and
/// `key=urn:secret:…` or a Secure Enclave slot tomorrow, and nothing in this
/// crate changes. This crate holds no key material and performs no cryptography
/// beyond SHA-256.
///
/// What is signed is the **ASCII bytes of the tagged chain hash** (`sha256:…`),
/// which is what a verifier reconstructs. So the host-side composition is
/// literally `urn:sign:sign in={the tagged hash} key={the key}`, and the check is
/// `urn:sign:verify in={the tagged hash} sig={the graph} key={the public key}`.
pub trait SealSigner: Send {
    /// The algorithm id, spelled as `ikigai-sign`'s `sig:algorithm` spells it —
    /// `Ed25519` or `ES256`.
    fn algorithm(&self) -> &str;

    /// Sign the tagged chain hash, returning the base64 signature.
    ///
    /// `None` is not an error: an unsigned seal still localizes tampering, so a
    /// signer that cannot reach its key right now yields a seal that chains and
    /// does not attest.
    fn sign(&self, tagged_hash: &str) -> Option<String>;
}

/// The `#seal` token for a signature: `{algorithm}:{base64}`.
pub(crate) fn signature_token(signer: &dyn SealSigner, tagged_hash: &str) -> Option<String> {
    signer
        .sign(tagged_hash)
        .map(|value| format!("{}:{value}", signer.algorithm()))
}

/// Split a `#seal` signature token back into `(algorithm, base64)`.
///
/// An untagged token is not guessed at: it has no algorithm, and inventing one
/// would make the tag decorative.
///
/// ```
/// # use ikigai_log::chain::split_signature;
/// // The `#seal` line's fourth column, and the shape the graph face splits into
/// // `sig:algorithm` + `sig:value`.
/// assert_eq!(split_signature("Ed25519:MEUCIQD"), Some(("Ed25519", "MEUCIQD")));
/// assert_eq!(split_signature("MEUCIQD"), None);
/// ```
pub fn split_signature(token: &str) -> Option<(&str, &str)> {
    let (algorithm, value) = token.split_once(':')?;
    (!algorithm.is_empty() && !value.is_empty()).then_some((algorithm, value))
}

// =====================================================================================
// Policy
// =====================================================================================

/// When a checkpoint lands: every N entries **or** every T milliseconds,
/// whichever comes first.
///
/// Both bounds, always. N alone leaves a log that is merely quiet unsealed
/// indefinitely, and the unsealed tail is the part an attacker can rewrite for
/// free; T alone would seal a busy log far too rarely to localize anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealPolicy {
    /// Seal once this many entries have accumulated since the last seal.
    pub every_entries: u64,
    /// Seal once this many milliseconds have passed since the last seal — judged
    /// when an entry is written, since a process writing nothing has nothing new
    /// to commit.
    pub every_millis: u64,
}

impl Default for SealPolicy {
    /// 1,000 entries or 60 seconds.
    ///
    /// A seal is one short line and one already-computed hash, so the cost is the
    /// line; 1,000 entries keeps that under a tenth of a percent of a segment's
    /// bytes, and 60 seconds bounds the rewritable tail of a quiet log at a
    /// minute of entries rather than at a day of them.
    fn default() -> SealPolicy {
        SealPolicy {
            every_entries: 1_000,
            every_millis: 60_000,
        }
    }
}

impl SealPolicy {
    /// Never seal on its own — for a caller that seals explicitly. Close and
    /// rotate still seal, because an unsealed segment cannot be chained from at
    /// anything better than its header.
    pub fn manual() -> SealPolicy {
        SealPolicy {
            every_entries: u64::MAX,
            every_millis: u64::MAX,
        }
    }

    fn due(&self, since_seal: u64, elapsed_millis: u64) -> bool {
        since_seal >= self.every_entries || elapsed_millis >= self.every_millis
    }
}

/// When a segment rolls over. Both bounds are optional and both are on by
/// default; `None` disables that trigger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationPolicy {
    /// Rotate once the open segment holds this many entries.
    pub max_entries: Option<u64>,
    /// Rotate once the open segment is this old.
    pub max_age_millis: Option<u64>,
}

impl Default for RotationPolicy {
    /// 100,000 entries or 24 hours.
    ///
    /// The day bound is the one that matters for reading: a segment is the unit
    /// a query names and the unit that caches, so "yesterday's log" should be one
    /// IRI. The entry bound is the guard against a burst turning that day into a
    /// file nothing wants to transrept.
    fn default() -> RotationPolicy {
        RotationPolicy {
            max_entries: Some(100_000),
            max_age_millis: Some(24 * 60 * 60 * 1_000),
        }
    }
}

impl RotationPolicy {
    /// Never rotate on its own — rotation stays an explicit act.
    pub fn manual() -> RotationPolicy {
        RotationPolicy {
            max_entries: None,
            max_age_millis: None,
        }
    }

    pub(crate) fn due(&self, entries: u64, age_millis: u64) -> bool {
        self.max_entries.is_some_and(|max| entries >= max)
            || self.max_age_millis.is_some_and(|max| age_millis >= max)
    }
}

// =====================================================================================
// Findings
// =====================================================================================

/// One thing verification found. Every variant names the range it is about,
/// because localization IS the product: "this segment is broken" is not an
/// answer, "between sequence 2001 and 3000 of this segment" is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// The segment's bytes do not parse as a segment.
    Malformed {
        /// The 1-based line the parser stopped on.
        line: usize,
        /// What was wrong with it.
        detail: String,
    },
    /// A seal states a chain hash that recomputation does not agree with.
    /// **This is the localization claim**: the alteration is inside this range.
    SealMismatch {
        /// First sequence the seal covers.
        first: u64,
        /// Last sequence the seal covers.
        last: u64,
        /// What the seal line says.
        stated: String,
        /// What the entries actually hash to.
        recomputed: String,
    },
    /// Seal coverage is not contiguous — a checkpoint line was removed.
    SealRangeGap {
        /// The last sequence the previous seal covered (0 before the first).
        after: u64,
        /// The first sequence the next seal claims.
        next_first: u64,
    },
    /// Entry sequence numbers jump. Emission advances the counter only for
    /// entries that are actually written, so a level-filtered entry consumes no
    /// number and a jump means lines were REMOVED.
    SequenceGap {
        /// The last sequence seen.
        after: u64,
        /// The next one found.
        next: u64,
    },
    /// `@prev` does not name the predecessor's final seal. **This is the
    /// rotation seam**: a forged replacement segment fails exactly here.
    PrevMismatch {
        /// The predecessor this segment follows.
        predecessor: String,
        /// What `@prev` says.
        stated: String,
        /// The predecessor's actual chain head.
        expected: String,
    },
    /// The segment claims to start a chain, but a predecessor exists for this
    /// instance. A genesis claim on a log that is not new is a claim someone can
    /// check, which is why it is written explicitly rather than left absent.
    UnexpectedGenesis {
        /// The predecessor it should have chained from.
        predecessor: String,
    },
    /// A segment's rotation marker names a successor that is not in the chain.
    ///
    /// **This closes the hole `@prev` cannot**: `@prev` catches a segment
    /// replaced or removed from the MIDDLE, because the one after it still
    /// points at what it should have been. Nothing points forward at the LAST
    /// segment, so truncating a chain at its head would otherwise be free — and
    /// the head is the recent past, which is the part worth erasing.
    MissingSuccessor {
        /// The segment whose rotation named it.
        after: String,
        /// The successor that is not here.
        successor: String,
    },
    /// Two adjacent segments ran at different levels and nothing recorded the
    /// change. **The omission check**: the chain would otherwise bless the hole
    /// as perfectly intact.
    UnbracketedLevelChange {
        /// The earlier segment.
        from_segment: String,
        /// Its level.
        from: String,
        /// The later segment.
        to_segment: String,
        /// Its level.
        to: String,
    },
    /// The segment's last entry is neither an orderly stop nor a rotation, so the
    /// process died. **Noted, not breaking**: a crash is not tampering, and a
    /// file alone cannot tell the two apart — what tells them apart is the
    /// successor, whose `@prev` cannot match a seal that was never written.
    UnmarkedEnd {
        /// The class of the last entry, when there was one.
        last_class: Option<String>,
    },
    /// Entries past the final seal are committed to no checkpoint, so nothing
    /// carries them across the rotation boundary. **Noted, not breaking**: an
    /// orderly close or rotation always seals, so this only ever describes a
    /// crashed tail.
    UnsealedTail {
        /// First uncommitted sequence.
        from: u64,
        /// Last uncommitted sequence.
        to: u64,
    },
}

impl Finding {
    /// Whether this finding means the record cannot be trusted, as opposed to
    /// describing something the record honestly says about itself.
    ///
    /// The split is deliberate and it is the difference between a verifier that
    /// gets read and one that gets ignored: a daemon that was killed leaves an
    /// unmarked end on every restart, and a tool that called that "BROKEN" would
    /// train its operator to disregard the word.
    pub fn is_breaking(&self) -> bool {
        !matches!(
            self,
            Finding::UnmarkedEnd { .. } | Finding::UnsealedTail { .. }
        )
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::Malformed { line, detail } => write!(f, "line {line}: {detail}"),
            Finding::SealMismatch {
                first,
                last,
                stated,
                recomputed,
            } => write!(
                f,
                "seal {first}-{last} states {stated} but the entries hash to {recomputed} — \
                 the alteration is between sequence {first} and {last}"
            ),
            Finding::SealRangeGap { after, next_first } => write!(
                f,
                "seal coverage jumps from {after} to {next_first}: a checkpoint line is missing"
            ),
            Finding::SequenceGap { after, next } => write!(
                f,
                "sequence jumps from {after} to {next}: entries were removed (filtering \
                 consumes no sequence number)"
            ),
            Finding::PrevMismatch {
                predecessor,
                stated,
                expected,
            } => write!(
                f,
                "@prev is {stated} but <{predecessor}> ends at {expected}: this segment does not \
                 follow the one before it"
            ),
            Finding::UnexpectedGenesis { predecessor } => write!(
                f,
                "@prev is genesis, but <{predecessor}> precedes this segment: a chain was restarted"
            ),
            Finding::MissingSuccessor { after, successor } => write!(
                f,
                "<{after}> rotated into <{successor}>, which is not here: the chain \
                 was truncated at its head, where nothing points forward"
            ),
            Finding::UnbracketedLevelChange {
                from_segment,
                from,
                to_segment,
                to,
            } => write!(
                f,
                "the level went from {from} (<{from_segment}>) to {to} (<{to_segment}>) with no \
                 log:LevelChange to bracket it: the gap that opened is unexplained"
            ),
            Finding::UnmarkedEnd { last_class } => match last_class {
                Some(class) => write!(
                    f,
                    "ends on {class}, not an orderly stop or a rotation: the process died"
                ),
                None => f.write_str("has no entries at all"),
            },
            Finding::UnsealedTail { from, to } => write!(
                f,
                "sequences {from}-{to} are past the final seal and committed to no checkpoint"
            ),
        }
    }
}

// =====================================================================================
// Reports
// =====================================================================================

/// What verification found in one segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentReport {
    /// The segment's own IRI, from its `@name`.
    pub name: String,
    /// The instance that wrote it.
    pub instance: String,
    /// The one level it ran at.
    pub level: String,
    /// What it chains from.
    pub prev: Prev,
    /// Its chain head — the last seal's hash, or h₀ when it never sealed. This is
    /// what a successor's `@prev` must name.
    pub head: String,
    /// How many entries it holds.
    pub entries: u64,
    /// How many seals it holds.
    pub seals: usize,
    /// The algorithms its seals were signed with, in order of first appearance.
    pub signed_with: Vec<String>,
    /// The successor its rotation marker named, when it ended in one. The only
    /// FORWARD link in the chain, and the only thing that can notice a chain
    /// truncated at its head.
    pub successor: Option<String>,
    /// Whether this segment RECORDS a level change — the always-land marker that
    /// brackets the gap one opens. Carried on the report rather than checked
    /// inline because the check spans two segments: the config write lands its
    /// entry in whatever segment was open at the time, and the change takes
    /// effect at the next one, so either end may hold the bracket.
    pub records_level_change: bool,
    /// Everything found.
    pub findings: Vec<Finding>,
}

impl SegmentReport {
    /// Whether the segment verified — no BREAKING finding. See
    /// [`Finding::is_breaking`] for why that is not "no findings".
    pub fn ok(&self) -> bool {
        !self.findings.iter().any(Finding::is_breaking)
    }

    /// The findings as lines, each prefixed `BROKEN` or `noted`.
    pub fn render_findings(&self) -> String {
        self.findings
            .iter()
            .map(|finding| {
                format!(
                    "{} {finding}\n",
                    if finding.is_breaking() {
                        "BROKEN"
                    } else {
                        "noted"
                    }
                )
            })
            .collect()
    }
}

/// What verification found across a chain of segments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainReport {
    /// One report per segment, in chain order.
    pub segments: Vec<SegmentReport>,
}

impl ChainReport {
    /// Whether every segment verified.
    pub fn ok(&self) -> bool {
        self.segments.iter().all(SegmentReport::ok)
    }

    /// How many segments carry a breaking finding.
    pub fn broken(&self) -> usize {
        self.segments.iter().filter(|s| !s.ok()).count()
    }

    /// The greppable report: one `segment <iri> OK|BROKEN …` line per segment,
    /// each finding indented beneath the segment it belongs to, and a total.
    ///
    /// Shaped for `grep`, like everything else in this crate: `grep '^segment'`
    /// is the summary and `grep BROKEN` is the alarm.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for report in &self.segments {
            out.push_str(&format!(
                "segment {} {} entries={} seals={} level={} prev={}",
                report.name,
                if report.ok() { "OK" } else { "BROKEN" },
                report.entries,
                report.seals,
                report.level,
                match &report.prev {
                    Prev::Genesis => "genesis".to_string(),
                    Prev::Seal(hash) => hash.clone(),
                }
            ));
            if report.signed_with.is_empty() {
                // Stated, not omitted: an unsigned seal still localizes tampering,
                // and a reader should not have to infer which guarantee they have.
                out.push_str(" signed=none");
            } else {
                out.push_str(&format!(" signed={}", report.signed_with.join(",")));
            }
            out.push_str(&format!(" head={}\n", report.head));
            for line in report.render_findings().lines() {
                out.push_str(&format!("  {line}\n"));
            }
        }
        out.push_str(&format!(
            "verified {} segment(s), {} broken\n",
            self.segments.len(),
            self.broken()
        ));
        out
    }
}

// =====================================================================================
// Verification
// =====================================================================================

/// A segment's chain head: the hash on its last `#seal`, or h₀ when it has none.
///
/// The one definition of "what a successor's `@prev` must name". A segment with
/// no seal committed nothing beyond its header, and this says exactly that
/// instead of refusing — a crashed predecessor must not make its successor
/// unchainable, or a crash and an erasure would look alike.
pub fn head_of(text: &str) -> Option<String> {
    let (header, offset) = Header::parse(text).ok()?;
    let mut head = Chain::open(&header).head().to_string();
    for raw in text[offset..].lines() {
        if let Ok(Line::Seal(seal)) = Line::parse(raw, &header.prefixes) {
            head = seal.hash;
        }
    }
    Some(head)
}

/// Verify one segment's bytes, optionally against the predecessor it claims.
///
/// `predecessor` is `(its IRI, its chain head)`. Passing `None` verifies the
/// segment in isolation — everything except layer 3, and the report says so by
/// carrying no `PrevMismatch` rather than by asserting a link it could not check.
pub fn verify_segment(
    text: &str,
    vocab: &Vocabulary,
    predecessor: Option<(&str, &str)>,
) -> SegmentReport {
    let (header, offset) = match Header::parse(text) {
        Ok(parsed) => parsed,
        Err(error) => {
            return SegmentReport {
                name: String::new(),
                instance: String::new(),
                level: String::new(),
                prev: Prev::Genesis,
                head: String::new(),
                entries: 0,
                seals: 0,
                signed_with: Vec::new(),
                successor: None,
                records_level_change: false,
                findings: vec![Finding::Malformed {
                    line: 1,
                    detail: error.to_string(),
                }],
            }
        }
    };

    let mut findings = Vec::new();
    let mut chain = Chain::open(&header);
    let mut entries = 0u64;
    let mut seals = 0usize;
    let mut signed_with: Vec<String> = Vec::new();
    let mut last_seq: Option<u64> = None;
    let mut sealed_through = 0u64;
    let mut head = chain.head().to_string();
    let mut last_class: Option<String> = None;
    let mut level_bracketed = false;
    let mut successor: Option<String> = None;
    // By PROPERTY, not by column name: `next` is what the built-in vocabulary
    // binds log:successor to, and a module that rebound it is still understood.
    let successor_key = vocab
        .keys()
        .find(|def| def.property == LOG_SUCCESSOR)
        .map(|def| def.key.clone());

    let header_lines = text[..offset].lines().count();
    for (index, raw) in text[offset..].lines().enumerate() {
        let number = header_lines + index + 1;
        match Line::parse(raw, &header.prefixes) {
            Ok(Line::Entry(entry)) => {
                entries += 1;
                // The chain folds in the line EXACTLY as written — not a
                // re-render of the parsed entry — so whitespace and quoting
                // tampering is caught along with everything else.
                chain.advance(raw.trim_end_matches(['\n', '\r']));
                check_sequence(&entry, &mut last_seq, &mut findings);
                if brackets_a_level_change(&entry, vocab) {
                    level_bracketed = true;
                }
                successor = successor_key
                    .as_deref()
                    .filter(|_| vocab.is_a(&entry.class, ROTATION_CLASS))
                    .and_then(|key| entry.get(key))
                    .map(str::to_string)
                    // A rotation is the LAST entry of the segment it ends, so a
                    // later entry means this was not one — clear rather than keep.
                    .or(None);
                last_class = Some(entry.class);
            }
            Ok(Line::Seal(seal)) => {
                seals += 1;
                if seal.first != sealed_through + 1 {
                    findings.push(Finding::SealRangeGap {
                        after: sealed_through,
                        next_first: seal.first,
                    });
                }
                if seal.hash != chain.head() {
                    findings.push(Finding::SealMismatch {
                        first: seal.first,
                        last: seal.last,
                        stated: seal.hash.clone(),
                        recomputed: chain.head().to_string(),
                    });
                }
                if let Some(token) = &seal.signature {
                    if let Some((algorithm, _)) = split_signature(token) {
                        if !signed_with.iter().any(|a| a == algorithm) {
                            signed_with.push(algorithm.to_string());
                        }
                    }
                }
                sealed_through = seal.last;
                head = seal.hash;
            }
            Ok(Line::Blank) | Ok(Line::Comment(_)) => {}
            Ok(Line::Directive { name, .. }) => findings.push(Finding::Malformed {
                line: number,
                detail: format!("@{name} after the header block"),
            }),
            Err(error) => findings.push(Finding::Malformed {
                line: number,
                detail: error.to_string(),
            }),
        }
    }

    // An orderly end is a stop or a rotation. A rotation ends a segment exactly
    // as finally as a process stop does — that is what makes a rotated segment
    // immutable, and therefore cacheable.
    let ended = last_class.as_deref().is_some_and(|class| {
        vocab.is_a(class, PROCESS_STOP_CLASS) || vocab.is_a(class, ROTATION_CLASS)
    });
    if !ended {
        findings.push(Finding::UnmarkedEnd {
            last_class: last_class.clone(),
        });
    }
    if let Some(last) = last_seq {
        if last > sealed_through {
            findings.push(Finding::UnsealedTail {
                from: sealed_through + 1,
                to: last,
            });
        }
    }

    if let Some((predecessor, expected)) = predecessor {
        match &header.prev {
            Prev::Genesis => findings.push(Finding::UnexpectedGenesis {
                predecessor: predecessor.to_string(),
            }),
            Prev::Seal(stated) if stated != expected => findings.push(Finding::PrevMismatch {
                predecessor: predecessor.to_string(),
                stated: stated.clone(),
                expected: expected.to_string(),
            }),
            Prev::Seal(_) => {}
        }
    }

    SegmentReport {
        name: header.name,
        instance: header.instance,
        level: header.level,
        prev: header.prev,
        head,
        entries,
        seals,
        signed_with,
        successor,
        records_level_change: level_bracketed,
        findings,
    }
}

/// Whether an entry is the always-land marker that brackets a level change.
fn brackets_a_level_change(entry: &Entry, vocab: &Vocabulary) -> bool {
    if vocab.is_a(&entry.class, LEVEL_CHANGE_CLASS) {
        return true;
    }
    // A module's own config-change class counts when it names the level column —
    // the bracket is the RECORDED fact, not one particular class name.
    vocab.is_a(&entry.class, CONFIG_CHANGE_CLASS) && entry.get("key") == Some("level")
}

fn check_sequence(entry: &Entry, last_seq: &mut Option<u64>, findings: &mut Vec<Finding>) {
    // Only entries that state a sequence are checked. A hand-assembled segment
    // without `seq=` still transrepts (the transreptor supplies an ordinal), so
    // demanding one here would refuse a file the rest of the crate accepts.
    let Some(seq) = entry.get("seq").and_then(|s| s.parse::<u64>().ok()) else {
        return;
    };
    if let Some(previous) = *last_seq {
        if seq != previous + 1 {
            findings.push(Finding::SequenceGap {
                after: previous,
                next: seq,
            });
        }
    }
    *last_seq = Some(seq);
}

/// Verify a run of segments as one chain, in the order given.
///
/// Each segment is checked against its predecessor's chain head — which is the
/// whole of layer 3 — and each adjacent pair is checked for an unbracketed level
/// change, which is the whole of the omission check.
///
/// `segments` is `(name, bytes)`, oldest first. Ordering is the caller's: within
/// an instance the segment IRI sorts chronologically, because the stamp is
/// fixed-width UTC.
pub fn verify_chain(segments: &[(String, String)], vocab: &Vocabulary) -> ChainReport {
    let mut reports: Vec<SegmentReport> = Vec::with_capacity(segments.len());
    for (_, text) in segments {
        let predecessor = reports
            .last()
            .map(|previous| (previous.name.clone(), previous.head.clone()));
        let mut report = verify_segment(
            text,
            vocab,
            predecessor
                .as_ref()
                .map(|(name, head)| (name.as_str(), head.as_str())),
        );
        // The bracket for a level change may be recorded in EITHER segment: the
        // config write lands its entry in whatever segment was open at the time,
        // and the change takes effect at the next one.
        if let Some(previous) = reports.last() {
            if previous.level != report.level
                && !previous.records_level_change
                && !report.records_level_change
            {
                report.findings.push(Finding::UnbracketedLevelChange {
                    from_segment: previous.name.clone(),
                    from: previous.level.clone(),
                    to_segment: report.name.clone(),
                    to: report.level.clone(),
                });
            }
        }
        // A rotation named where it went. If the successor is not the segment
        // that follows, the chain was cut — and this is the only check that can
        // see a chain truncated at its HEAD, since nothing else points forward.
        if let Some(previous) = reports.last_mut() {
            if let Some(named) = previous.successor.clone() {
                if named != report.name {
                    previous.findings.push(Finding::MissingSuccessor {
                        after: previous.name.clone(),
                        successor: named,
                    });
                }
            }
        }
        reports.push(report);
    }
    if let Some(last) = reports.last_mut() {
        if let Some(named) = last.successor.clone() {
            last.findings.push(Finding::MissingSuccessor {
                after: last.name.clone(),
                successor: named,
            });
        }
    }
    ChainReport { segments: reports }
}

/// Whether a writer holding these counters owes a seal.
pub(crate) fn seal_due(
    policy: &SealPolicy,
    seq: u64,
    sealed_through: u64,
    now: Timestamp,
    last_seal_at: Timestamp,
) -> bool {
    seq > sealed_through
        && policy.due(
            seq - sealed_through,
            now.as_millis().saturating_sub(last_seal_at.as_millis()),
        )
}

/// Build a [`Seal`] over the range `sealed_through+1..=seq` at `head`.
pub(crate) fn seal_for(
    sealed_through: u64,
    seq: u64,
    head: &str,
    signer: Option<&dyn SealSigner>,
) -> Seal {
    Seal {
        first: sealed_through + 1,
        last: seq,
        hash: head.to_string(),
        signature: signer.and_then(|signer| signature_token(signer, head)),
    }
}
