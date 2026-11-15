//! An RFC 9162 Merkle tree over seals, and one tree head per interval.
//!
//! The chain makes a segment tamper-evident, but it is unkeyed: whoever can
//! write the files can recompute every hash from an edit forward. What stops
//! that writer is a commitment held somewhere else. This module makes the
//! commitment small enough to hold anywhere: **one tree head per hour**, a size
//! and a root over every seal the log has written so far.
//!
//! ## The tree is RFC 9162's, exactly
//!
//! [RFC 9162 §2.1.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1.1),
//! with SHA-256:
//!
//! ```text
//! MTH({})    = SHA-256()
//! MTH({d₀})  = SHA-256(0x00 ‖ d₀)
//! MTH(D[n])  = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))   k = the largest power of two < n
//! ```
//!
//! The 0x00 and 0x01 prefixes keep a leaf from ever hashing like an interior
//! node. Inclusion proofs ([`inclusion_proof`], [`verify_inclusion`]) and
//! consistency proofs ([`consistency_proof`], [`verify_consistency`]) follow
//! §2.1.3 and §2.1.4 step for step, so a verifier written against the RFC, or
//! any Certificate Transparency library, reads these trees with no help from
//! this crate.
//!
//! ## A leaf is a seal
//!
//! Each `#seal` line becomes one leaf, in chain order: segment by segment
//! along `@prev`, seal by seal within a segment. The leaf's bytes are the ASCII
//! line
//!
//! ```text
//! <segment IRI> <first>-<last> <tagged chain hash>
//! ```
//!
//! ([`SealLeaf::data`]). The chain hash already commits to the segment's header
//! and every entry before the seal. The IRI and range are in the leaf as well,
//! so a proof names its seal in words. The signature is left out: it is a
//! statement ABOUT the hash, checked with a key this crate never holds, and a
//! leaf that included it would change when a seal is re-signed.
//!
//! ## One tree, one head per interval
//!
//! The tree is **cumulative**. It is not rebuilt each hour: every seal ever
//! written is a leaf of the same tree, and the head published at the end of an
//! hour is that tree's size and root as of the last seal stamped in that hour
//! ([`interval_heads`], [`hourly_heads`]). A seal's time is the time of the
//! last entry it covers. Two consecutive heads are then joined by a
//! consistency proof, which proves the later tree extends the earlier one.
//! Nothing was rewritten, and nothing was taken from the old end. That old end
//! is the place a chain walk cannot see: removing the oldest segments looks
//! like retention to [`verify_chain`](crate::verify_chain). Removing them from
//! a tree whose head someone else holds changes the root.
//!
//! A clock stepped back across a seal (NTP, a VM restore) does not reopen an
//! hour that already has a head: such a seal counts in the interval already
//! open, so heads stay in order and each covers at least as many seals as the
//! one before.
//!
//! ## What a head proves, and what it cannot
//!
//! A head proves nothing on its own. The operator who writes the files computes
//! it, and that operator can compute a new one. Its worth is in being held
//! outside their control. Anchor it ([`crate::anchor`]) with an RFC 3161
//! timestamp or a transparency log, and [`check_heads`] then tells whether the
//! seals in the files still hash to what was anchored. A head says nothing
//! about entries past the last seal it counts. The seal cadence bounds that
//! unsealed tail.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::chain::{tagged, HASH_ALGORITHM};
use crate::line::{shown, Header, Line, ParseError, Timestamp};

/// A `#root`, `#key` or `#anchor` line that does not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BadLine {
    /// Which kind of line it was meant to be: `root`, `key` or `anchor`.
    pub kind: &'static str,
    /// The line as read.
    pub line: String,
}

impl BadLine {
    pub(crate) fn new(kind: &'static str, line: &str) -> BadLine {
        BadLine {
            kind,
            line: line.to_string(),
        }
    }
}

/// The line is shown escaped, so the error stays one printable line.
impl fmt::Display for BadLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad {} line: {}", self.kind, shown(&self.line))
    }
}

impl std::error::Error for BadLine {}

/// A SHA-256 digest: one node of the tree.
pub type NodeHash = [u8; 32];

/// One hour in milliseconds, the interval [`hourly_heads`] publishes at.
pub const HOUR_MILLIS: u64 = 60 * 60 * 1_000;

/// The marker a tree head line starts with.
pub const ROOT_MARKER: &str = "#root";

/// The leaf hash of RFC 9162 §2.1.1: SHA-256(0x00 ‖ data).
pub fn leaf_hash(data: &[u8]) -> NodeHash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    hasher.finalize().into()
}

/// An interior node of RFC 9162 §2.1.1: SHA-256(0x01 ‖ left ‖ right).
fn node_hash(left: &NodeHash, right: &NodeHash) -> NodeHash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The largest power of two strictly below `n`, for `n > 1`.
fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// MTH over leaves already hashed with [`leaf_hash`].
///
/// ```
/// use ikigai_log::merkle::{leaf_hash, root, tagged_node};
/// // RFC 9162: the empty tree is the hash of the empty string.
/// assert_eq!(
///     tagged_node(&root(&[])),
///     "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
/// );
/// // A one-leaf tree is that leaf's hash.
/// assert_eq!(root(&[leaf_hash(b"")]), leaf_hash(b""));
/// ```
pub fn root(leaves: &[NodeHash]) -> NodeHash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// A node hash tagged the way every other hash in this crate is: `sha256:` and
/// 64 lowercase hex digits.
pub fn tagged_node(hash: &NodeHash) -> String {
    let mut out = String::with_capacity(HASH_ALGORITHM.len() + 1 + 64);
    out.push_str(HASH_ALGORITHM);
    out.push(':');
    out.push_str(&hex(hash));
    out
}

/// The inverse of [`tagged_node`]. Anything other than `sha256:` and 64
/// lowercase hex digits is `None`.
pub fn parse_tagged_node(text: &str) -> Option<NodeHash> {
    let hex = text.strip_prefix(HASH_ALGORITHM)?.strip_prefix(':')?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(out)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// The inclusion proof of RFC 9162 §2.1.3.1, `PATH(index, D[n])`, over the tree
/// whose leaves are `leaves`. `None` when `index` is not a leaf of it.
pub fn inclusion_proof(leaves: &[NodeHash], index: usize) -> Option<Vec<NodeHash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    path(index, leaves, &mut proof);
    Some(proof)
}

fn path(m: usize, leaves: &[NodeHash], out: &mut Vec<NodeHash>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if m < k {
        path(m, &leaves[..k], out);
        out.push(root(&leaves[k..]));
    } else {
        path(m - k, &leaves[k..], out);
        out.push(root(&leaves[..k]));
    }
}

/// Verify an inclusion proof by the algorithm of RFC 9162 §2.1.3.2: that the
/// leaf hashing to `leaf` sits at `index` of the `size`-leaf tree whose root is
/// `root`.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf: &NodeHash,
    proof: &[NodeHash],
    root: &NodeHash,
) -> bool {
    if index >= size {
        return false;
    }
    let (mut f, mut s) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == *root
}

/// The consistency proof of RFC 9162 §2.1.4.1, `PROOF(old_size, D[n])`: that the
/// first `old_size` leaves of `leaves` are a tree the whole of `leaves`
/// extends. Empty when `old_size` is 0 or the whole tree, because nothing needs
/// proving; `None` when `old_size` is larger than the tree.
pub fn consistency_proof(leaves: &[NodeHash], old_size: usize) -> Option<Vec<NodeHash>> {
    if old_size > leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    if old_size > 0 {
        subproof(old_size, leaves, true, &mut proof);
    }
    Some(proof)
}

fn subproof(m: usize, leaves: &[NodeHash], complete: bool, out: &mut Vec<NodeHash>) {
    let n = leaves.len();
    if m == n {
        if !complete {
            out.push(root(leaves));
        }
        return;
    }
    let k = split(n);
    if m <= k {
        subproof(m, &leaves[..k], complete, out);
        out.push(root(&leaves[k..]));
    } else {
        subproof(m - k, &leaves[k..], false, out);
        out.push(root(&leaves[..k]));
    }
}

/// Verify a consistency proof by the algorithm of RFC 9162 §2.1.4.2: that the
/// `new_size`-leaf tree rooted at `new_root` extends the `old_size`-leaf tree
/// rooted at `old_root`.
///
/// The RFC's algorithm assumes `0 < old_size < new_size`. The two edges are
/// settled here: equal sizes need an empty proof and equal roots, and the empty
/// tree is extended by every tree, with an empty proof.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &NodeHash,
    new_root: &NodeHash,
    proof: &[NodeHash],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if old_size == 0 {
        return proof.is_empty();
    }
    if proof.is_empty() {
        return false;
    }
    let mut path: Vec<NodeHash> = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let (mut f, mut s) = (old_size - 1, new_size - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (path[0], path[0]);
    for c in &path[1..] {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    fr == *old_root && sr == *new_root && s == 0
}

// =====================================================================================
// Seals as leaves
// =====================================================================================

/// One `#seal` line as a leaf of the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealLeaf {
    /// The segment the seal is in, by its `@name`.
    pub segment: String,
    /// First entry sequence the seal covers.
    pub first: u64,
    /// Last entry sequence the seal covers.
    pub last: u64,
    /// The tagged chain hash the seal states.
    pub hash: String,
    /// When it sealed: the time of the last entry before the seal line, or the
    /// segment's start when there is none.
    pub at: Timestamp,
}

impl SealLeaf {
    /// The leaf's bytes: `<segment IRI> <first>-<last> <tagged chain hash>`.
    pub fn data(&self) -> String {
        format!(
            "{} {}-{} {}",
            self.segment, self.first, self.last, self.hash
        )
    }

    /// [`leaf_hash`] over [`SealLeaf::data`].
    pub fn leaf_hash(&self) -> NodeHash {
        leaf_hash(self.data().as_bytes())
    }
}

/// A segment the tree could not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnreadableSegment {
    /// The name the caller gave the segment.
    pub segment: String,
    /// Why its header did not parse.
    pub error: ParseError,
}

impl fmt::Display for UnreadableSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "segment {} has no readable header, so its seals cannot be leaves: {}",
            shown(&self.segment),
            self.error
        )
    }
}

impl std::error::Error for UnreadableSegment {}

/// Every seal in `segments`, in order, as leaves.
///
/// `segments` is `(name, bytes)` in chain order, as [`verify_chain`] takes it.
/// The seals are taken as the files state them. Whether a seal's hash is what
/// its entries recompute to is [`verify_chain`]'s question, and it should be
/// asked first: a head over a broken chain is a faithful commitment to a broken
/// chain. A segment whose header does not parse is an error rather than a skip.
/// Leaving it out would publish a tree that silently omits its seals.
///
/// [`verify_chain`]: crate::verify_chain
pub fn seal_leaves(segments: &[(String, String)]) -> Result<Vec<SealLeaf>, UnreadableSegment> {
    let mut leaves = Vec::new();
    for (name, text) in segments {
        let (header, offset) = Header::parse(text).map_err(|error| UnreadableSegment {
            segment: name.clone(),
            error,
        })?;
        let mut at = header.started;
        for raw in text[offset..].lines() {
            match Line::parse(raw, &header.prefixes) {
                Ok(Line::Entry(entry)) => at = entry.time,
                Ok(Line::Seal(seal)) => leaves.push(SealLeaf {
                    segment: header.name.clone(),
                    first: seal.first,
                    last: seal.last,
                    hash: seal.hash,
                    at,
                }),
                _ => {}
            }
        }
    }
    Ok(leaves)
}

// =====================================================================================
// Tree heads
// =====================================================================================

/// The tree as of the end of one interval: how many seals it holds and its
/// root. This is what gets anchored.
///
/// It renders as one line, the bytes an anchor commits to:
///
/// ```
/// use ikigai_log::merkle::TreeHead;
/// use ikigai_log::Timestamp;
/// let head = TreeHead {
///     until: Timestamp::parse("2026-11-15T13:00:00.000Z").unwrap(),
///     size: 42,
///     root: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
/// };
/// let line = head.render();
/// assert_eq!(
///     line,
///     "#root 2026-11-15T13:00:00.000Z 42 \
///      sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
/// );
/// assert_eq!(TreeHead::parse(&line).unwrap(), head);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeHead {
    /// The end of the interval, exclusive: every seal counted was stamped
    /// before it.
    pub until: Timestamp,
    /// How many seals the tree holds.
    pub size: u64,
    /// The tree's root, tagged.
    pub root: String,
}

impl TreeHead {
    /// The head line, `#root <until> <size> <root>`, with no trailing newline.
    pub fn render(&self) -> String {
        format!(
            "{ROOT_MARKER} {} {} {}",
            self.until.render(),
            self.size,
            self.root
        )
    }

    /// Parse a head line.
    pub fn parse(line: &str) -> Result<TreeHead, BadLine> {
        let bad = || BadLine::new("root", line);
        let mut tokens = line.trim_end_matches(['\n', '\r']).split(' ');
        if tokens.next() != Some(ROOT_MARKER) {
            return Err(bad());
        }
        let until = Timestamp::parse(tokens.next().ok_or_else(bad)?).map_err(|_| bad())?;
        let size = tokens.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
        let root = tokens.next().ok_or_else(bad)?;
        if parse_tagged_node(root).is_none() || tokens.next().is_some() {
            return Err(bad());
        }
        Ok(TreeHead {
            until,
            size,
            root: root.to_string(),
        })
    }

    /// The tagged SHA-256 of [`TreeHead::render`]: the digest an anchor is
    /// asked to timestamp.
    pub fn digest(&self) -> String {
        tagged(self.render().as_bytes())
    }
}

/// One head per interval of `interval_millis` that has a seal in it, over the
/// cumulative tree of `leaves`.
///
/// An interval with no seal publishes no head. The tree did not change, so the
/// previous head still stands. A seal stamped before the interval already open
/// (a clock stepped back) counts in the open interval, so heads come out in
/// order of `until` and of `size`.
pub fn interval_heads(leaves: &[SealLeaf], interval_millis: u64) -> Vec<TreeHead> {
    let interval = interval_millis.max(1);
    let hashes: Vec<NodeHash> = leaves.iter().map(SealLeaf::leaf_hash).collect();
    let mut heads = Vec::new();
    let mut open: Option<u64> = None;
    for (index, leaf) in leaves.iter().enumerate() {
        let bucket = (leaf.at.as_millis() / interval).max(open.unwrap_or(0));
        if let Some(current) = open.filter(|current| *current != bucket) {
            heads.push(head_at(&hashes[..index], current, interval));
        }
        open = Some(bucket);
    }
    if let Some(current) = open {
        heads.push(head_at(&hashes, current, interval));
    }
    heads
}

fn head_at(hashes: &[NodeHash], bucket: u64, interval: u64) -> TreeHead {
    TreeHead {
        until: Timestamp::from_millis(bucket.saturating_add(1).saturating_mul(interval)),
        size: hashes.len() as u64,
        root: tagged_node(&root(hashes)),
    }
}

/// [`seal_leaves`] then [`interval_heads`] at one hour: the hourly roots.
pub fn hourly_heads(segments: &[(String, String)]) -> Result<Vec<TreeHead>, UnreadableSegment> {
    Ok(interval_heads(&seal_leaves(segments)?, HOUR_MILLIS))
}

/// What [`check_heads`] found wrong with a head someone holds.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeadFinding {
    /// The head counts more seals than the files hold: seals it counted are gone.
    Truncated {
        /// The head.
        head: TreeHead,
        /// How many seals the files hold.
        held: u64,
    },
    /// The first `size` seals in the files do not hash to the head's root: a
    /// seal the head counted was changed, removed or reordered.
    RootMismatch {
        /// The head.
        head: TreeHead,
        /// What the files' first `size` seals hash to.
        recomputed: String,
    },
    /// A head counts fewer seals than the head before it. The tree only grows,
    /// so one of the two is not a head of this log.
    Shrank {
        /// The earlier head.
        earlier: TreeHead,
        /// The later head.
        later: TreeHead,
    },
}

impl fmt::Display for HeadFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeadFinding::Truncated { head, held } => write!(
                f,
                "the head until {} counts {} seals but the files hold {held}: seals it \
                 counted were removed",
                head.until.render(),
                head.size
            ),
            HeadFinding::RootMismatch { head, recomputed } => write!(
                f,
                "the head until {} states root {} over {} seals, but those seals hash to {}: \
                 history before {} was rewritten",
                head.until.render(),
                shown(&head.root),
                head.size,
                shown(recomputed),
                head.until.render()
            ),
            HeadFinding::Shrank { earlier, later } => write!(
                f,
                "the head until {} counts {} seals, fewer than the {} of the head until {}: \
                 the tree only grows, so these heads are not of one log",
                later.until.render(),
                later.size,
                earlier.size,
                earlier.until.render()
            ),
        }
    }
}

/// Check heads someone holds (anchored, published, or kept by an auditor)
/// against the seals the files hold now.
///
/// Empty means every head is a prefix of the tree the files make: nothing a
/// head counted was rewritten or removed since it was taken. Every finding is
/// breaking.
pub fn check_heads(leaves: &[SealLeaf], heads: &[TreeHead]) -> Vec<HeadFinding> {
    let hashes: Vec<NodeHash> = leaves.iter().map(SealLeaf::leaf_hash).collect();
    let mut findings = Vec::new();
    let mut previous: Option<&TreeHead> = None;
    for head in heads {
        if let Some(earlier) = previous.filter(|earlier| earlier.size > head.size) {
            findings.push(HeadFinding::Shrank {
                earlier: earlier.clone(),
                later: head.clone(),
            });
        }
        previous = Some(head);
        let Ok(size) = usize::try_from(head.size) else {
            findings.push(HeadFinding::Truncated {
                head: head.clone(),
                held: hashes.len() as u64,
            });
            continue;
        };
        if size > hashes.len() {
            findings.push(HeadFinding::Truncated {
                head: head.clone(),
                held: hashes.len() as u64,
            });
            continue;
        }
        let recomputed = tagged_node(&root(&hashes[..size]));
        if recomputed != head.root {
            findings.push(HeadFinding::RootMismatch {
                head: head.clone(),
                recomputed,
            });
        }
    }
    findings
}
