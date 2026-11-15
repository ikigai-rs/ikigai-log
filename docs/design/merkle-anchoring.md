# Design: an interval Merkle root over seals, and an externally anchored key history

Ledger #3642. Status: **proposed, for decision.** Nothing here is built on `main`. A working
prototype is on the branch `worker/item-3642-impl`; see "What the prototype already proves".

This note is grounded in `ikigai-log` as it is at 0.11.0 and in
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) (Certificate Transparency 2.0), §2.1. It ends
with numbered decisions for Brian.

## 1. What exists today

The README's "Tamper-evident across rotations — four layers, or none" lists four layers:

1. **A per-entry hash chain, in memory.** `h₀ = sha256(canonical header)`,
   `hᵢ = sha256(hᵢ₋₁ ‖ "\n" ‖ line)`. Nothing per line lands on disk.
2. **Signed checkpoints.** A `#seal first-last <hash> [<alg>:<base64>]` line every 1,000
   entries or 60 s by default. Signing is the `SealSigner` seam. An unsigned seal still
   localizes tampering.
3. **The chain spans rotations.** `@prev` carries the previous segment's final seal, `genesis`
   is explicit, and a `log:Rotation` entry's `next=` names the successor.
4. **Rotation is verify, seal and validate in one operation.** A failure lands as a
   `log:ChainBroken` entry. It is never an exception.

`urn:log:verify` walks each instance's chain by its links and reports one
`segment <iri> OK|BROKEN …` line per segment, with findings under it.

The README's "What `urn:log:verify` proves, and what it cannot" names the gaps this item
closes:

- **The chain is unkeyed SHA-256.** Anyone who can write the files can recompute every hash
  and every `@prev` after an edit. Seal signatures are stated, not checked. "An external anchor
  of the head … is the other answer, and nothing here makes one."
- **Deleting the oldest segments looks like retention.** The first segment listed is not
  checked against a predecessor. `tests/merkle_anchoring_premise.rs` pins this: after the
  oldest of two rotated segments is removed, `verify_chain` still reports `ok()`. The only
  trace is an `@prev` that names a seal no remaining segment holds.
- **A signing key is only as good as its history.** `log:KeyChange` is in the vocabulary
  (always-land: "unrecorded, it is a window in which old signatures stop verifying — which is
  indistinguishable from tampering"). Nothing writes it, chains key changes or anchors them. An
  operator who holds the key can re-sign a rewritten history and claim the key was always that
  one.

Signatures alone do not close any of these gaps against the **operator**, because the
operator holds the key. The fix is a commitment that leaves the operator's control at a known
time. A Merkle root over seals is that commitment, and it is small enough to send somewhere
else every interval.

## 2. One root per interval over that interval's seals

### Leaves

A **leaf is a seal**, never an entry. Seals already summarize entries through the chain, and
they are 1/1,000 as many. Leaf data, in UTF-8, is one line:

```
seal <segment IRI> <first>-<last> <chain hash>
```

The signature is **not** in the leaf. A re-signed seal with an unchanged hash is the same
commitment, so a key rotation does not change any root. Segment IRI and range are in the leaf,
so a seal cannot be moved to another segment or range without changing the root.

Hashing follows RFC 9162 §2.1.1 exactly: `leaf = SHA-256(0x00 ‖ data)`,
`node = SHA-256(0x01 ‖ left ‖ right)`, split at the largest power of two below `n`, and
`MTH({}) = SHA-256()`. SHA-256 is already the crate's chain hash through `sha2`, and roots are
written in the same `sha256:` tagged form as `sig:contentHash`, so they join in a query.

### Intervals

The tree is **partitioned by instance**. One `@instance` is one chain, and that is the unit
`urn:log:verify` already walks. A seal belongs to the interval that holds the timestamp of the
**last entry it covers**. Seals follow chain order, not file names. If entry times step back, an interval that already has a root is not
reopened, and the seal goes to the current interval.

The tree's shape is Decision 4: a per-interval tree that chains to the previous root, or one
cumulative tree with a head per interval. Under the recommended per-interval shape, **leaf 0
of every interval's tree is the previous interval's root** (`root <until> <hash>`, or
`root genesis`), followed by that interval's seals in chain order. So:

- an interval with no seals still has a root (a one-leaf tree over the previous root), so a
  missing root is a gap, never "a quiet hour";
- deleting the old end is visible to anyone who holds any later anchored root, because the
  roots form a chain back to `genesis`;
- retention can drop old segments and keep only their roots. The chain of roots stays
  verifiable, and the dropped seals become a recorded, anchored fact rather than a silence.

### Where a root is written

A root is **an always-land entry in the log itself**. It is not a comment line, because the
README says comment lines are not chained:

```
2026-11-15T13:00:00.004Z log:IntervalRoot urn:ikigai:instance:bug:daemon seq=4013 until=2026-11-15T13:00:00.000Z size=6 root=sha256:9f2c… prev=sha256:41aa…
```

The root entry is chained and sealed in the **next** interval, so a root never covers itself.
An anchor receipt lands later, when the anchor answers, as a `log:Anchored` entry naming the
root (or key record) and carrying the receipt. Large receipts go in a sibling file keyed by
digest. That is Decision 7.

### Inclusion proofs, and who checks them offline

RFC 9162 §2.1.3 gives an inclusion proof: `⌈log₂ n⌉` hashes from a leaf to the root. At the
default cadence, an hourly tree holds 60 or so seals, so a proof is about 6 hashes (200 bytes).

The proof answers: "was this seal, with this hash, part of history as committed at hour H?"
The people who need it, and what they hold:

- **An auditor or a court** holds one segment excerpt, its seal, the proof and the anchored
  root. They check it **offline**: recompute the chain to the seal (`verify_segment`), hash the
  leaf, fold the proof, compare to the root, and check the anchor receipt against a trust root
  they already hold. None of these steps touches the operator.
- **A peer host** that anchored a root checks proofs for seals the operator later shows it.
- **`urn:log:verify` itself** does not need proofs. It holds every seal, so it recomputes
  every root and compares it with the logged and anchored ones. Proofs are for readers who hold
  less than the whole log.

## 3. Anchoring outside the operator's control

An anchor is somewhere the root goes that the operator cannot later edit. It is a **seam**,
like `SealSigner`: a trait the host implements. This crate makes no network call and holds no
trust root. Each kind proves something different:

| | RFC 3161 TSA | Public transparency log (Sigstore Rekor; a C2SP tlog with witnesses) | A peer's ledger (another ikigai host) |
|---|---|---|---|
| **Proves** | The root existed no later than `genTime`, attested by the TSA's signature over the root's SHA-256 message imprint. | Existence by a time, **and** that every monitor sees the same entry. Equivocation (two roots for one hour) is publicly visible. | Existence by the peer's arrival time, in the peer's own chain and seals. With mutual anchoring, each host witnesses the other. |
| **Does not prove** | Uniqueness. An operator can timestamp two roots for one hour and show each to a different reader. | That the content is true. It only fixes it in time. | Anything, if the peer colludes. Its strength is the peer's independence. |
| **Costs** | One HTTP request per root. Free public TSAs exist (rate-limited); commercial ones charge. A token is 1–6 KB of DER. Verification needs CMS SignedData, X.509 chain building and usually **RSA** (most TSAs sign with RSA, and `rsa` is not in this crate's graph). Tokens outlive TSA certificates, so long-term validity needs re-timestamping (RFC 3161 alone does not solve this). | Rekor `hashedrekord` needs a signature and **publishes the public key**. Rate limits and log sharding apply, and the operator depends on a third party's retention. A C2SP log needs a witness network to be worth more than a TSA. | Nothing outside the ecosystem. One `urn:log:write` (or ledger write) per root to a peer that grants it. Needs a peer that is actually independent. |
| **Unreachable** | Queue the root, retry with backoff, and record `log:AnchorFailed` once per outage. The root stays **unanchored**, and verify reports how long. | Same. | Same. A second peer can stand in. |

**Lateness is the signal.** A rewrite done today and re-anchored today gets today's
`genTime`, which is later than the interval it claims. So verify compares each receipt's time
with the end of its interval. Receipts within the allowed lag are fine. One past the lag is
**late**, which is what a rewrite looks like. An honest outage looks the same, which is why
lateness is `noted` with its duration rather than `BROKEN`, and why `log:AnchorFailed` entries
are written during the outage. A rewrite cannot later produce those entries with the times
they claim (Decision 8).

## 4. Key changes

The key history is a **chain of key records per instance**. Each record states the time it
takes effect, the algorithm, the key's IRI (a kernel-resolved key resource, as `ikigai-sign`
names keys), and the digest of the previous record (or `genesis`). Each record is anchored
**before it takes effect**, and the old key is still valid while the anchor is pending. It
lands in the log as the existing `log:KeyChange` class:

```
2026-11-15T14:00:00.000Z log:KeyChange urn:ikigai:instance:bug:daemon seq=1 alg=Ed25519 key=urn:sign:key:daemon-2026-11 prev=sha256:77e0…
```

It is also kept in a small per-instance file (Decision 5) that outlives segment retention,
because a seal from 2024 must be checkable against the key in effect in 2024 after the 2024
segments are gone.

What an anchored key history buys: a seal signed by key K at time T verifies only if K's
record was anchored before T and the next record was not. An operator who rewrites history
and re-signs it with a new key needs a key record dated in the past, and its anchor carries
today's time. Key changes are rare (months apart), so they can afford the strongest anchor
even if roots use a cheaper one.

## 5. How verify reports it

Verify keeps its present shape and adds lines under each instance. Each line is one sentence,
and quoted text is escaped with `shown`, per ACCESSIBILITY.md:

```
root urn:log:root:bug:daemon:2026-11-15T13 OK size=6 root=sha256:9f2c… anchored=rfc3161 lag=4s
  BROKEN root until 2026-11-15T12:00:00.000Z states sha256:41aa… but the seals hash to sha256:0c3e…: history before 2026-11-15T12:00:00.000Z was rewritten
  BROKEN root until 2026-11-15T11:00:00.000Z counts 9 seals but only 4 remain: seals were removed from the old end
  noted root until 2026-11-15T10:00:00.000Z was anchored 3h12m after its interval ended
  noted root until 2026-11-15T09:00:00.000Z is not anchored
key urn:log:key:bug:daemon OK records=3 anchored=3
  BROKEN seal 3001-4012 is signed by urn:sign:key:old, which was replaced at 2026-11-01T00:00:00.000Z
```

The summary line gains a count: `verified 2 segment(s), 24 root(s), 1 key history, 1 broken`.
`BROKEN` and `noted` keep their meanings. A root that disagrees with its seals breaks. A root
that is missing, unanchored or late is noted, because each has an honest cause.

## 6. Privacy

- **A root is a hash of hashes.** It reveals nothing about entries, so anchoring it publishes
  no principal, path or `msg=`. It does publish **that the instance exists and its cadence**.
  The anchor request should carry only the digest. RFC 3161 sends only the message imprint and
  a nonce. A peer or a transparency log entry should not carry the instance name unless the
  operator configures it to.
- **A Rekor entry publishes a signing public key**, which links every root from one operator.
  That is a reason not to make it the default.
- **Inclusion proofs show sibling hashes only.** Handing an auditor one seal's proof discloses
  no other segment's content.
- **Retention and erasure.** Under the chained per-interval design, deleting segments (or
  redacting one) leaves the roots verifiable. The redaction itself is visible as a root whose
  seals are gone, and it should be recorded as an always-land entry (the README's missing
  `log:Tombstone`) so it is told apart from tampering. That is a follow-up, not part of this
  item.
- Root and receipt files are created 0600, like segments.

## 7. Resources and capabilities

Names are singular and type first, partitioned by the instance key. Each is bound **above**
`SEGMENT_TEMPLATE` (`urn:log:{segment}`), as `urn:log:verify` is.

| Resource | Answers | Capability |
|---|---|---|
| `urn:log:root:{instance}:{until}` | One interval's root, its leaves' count, its receipts. Turtle (`log:IntervalRoot`) or text. | `urn:cap:log:read` |
| `urn:log:root:{instance}` | The latest root for the instance. | `urn:cap:log:read` |
| `urn:log:proof:{segment}:{first}-{last}` | The inclusion proof for that seal against the root of its interval. | `urn:cap:log:read` |
| `urn:log:key:{instance}` | The key history, each record with its receipt. | `urn:cap:log:read` |
| `urn:log:anchor` (action) | Submit pending roots and key records through the host's anchors now. | **new** `urn:cap:log:anchor`: it makes outbound requests and spends a TSA or peer quota |
| `urn:log:key:{instance}` (action `change`) | Record a key change. | **new** `urn:cap:log:key`: sharper than `urn:cap:log:config`, because it decides which signatures verify |

**Collision to decide:** a segment IRI is `urn:log:{instance}:{stamp}`, so an instance named
`root:…`, `proof:…` or `key:…` would collide with these templates. Either reserve the three
words as instance prefixes (refused at `with_instance`), or use separate schemes
(`urn:log-root:` and so on). Decision 9.

## 8. What the prototype already proves

The branch `worker/item-3642-impl` (commit `979e2ab`, about 2,000 lines, not for merge)
implements a **cumulative** variant: one tree over all seals, with a `#root` head per hour.
What it shows, so the build can start from it:

- RFC 9162 §2.1.1 hashing, §2.1.3 inclusion and §2.1.4 consistency proofs in about 200
  lines of code in `src/merkle.rs`. These are checked against the **RFC 6962 reference tree** (roots for 1–8
  leaves, the empty tree, the reference inclusion path for leaf 0 of 8) and, for every tree size
  up to 40, every inclusion and consistency proof round-trips, and tampered proofs fail.
- Seal leaves come from real `Writer` output across a rotation, so leaves are extracted in
  chain order across segments. Its leaf data has no `seal ` type prefix. The recommended shape
  needs one, because a previous root is also a leaf.
- Old-end deletion and a recomputed seal are both caught by a held head, where `verify_chain`
  passes (`deleting_the_oldest_segment_passes_the_chain_walk_but_not_a_held_head`).
- A chained key history with `Anchor`/`AnchorCheck` seams, `key_at(time)`, and findings for
  unchained, out-of-order, unanchored, rejected and **late** records (`src/anchor.rs`).
- What it does not do: real RFC 3161 parsing or verification, any network call, wiring into
  `urn:log:verify`, or writing roots from the writer.

The build would keep the hashing, the vectors and the seam shapes. It would change the tree
shape if Decision 4 goes the recommended way, and move the standard code wherever Decision 2
says.

## Decisions for Brian

**1. Which anchor(s).**
- (a) RFC 3161 TSA only.
- (b) A peer's ledger only.
- (c) A public transparency log (Rekor or a C2SP log with witnesses).
- (d) RFC 3161 for key records and roots, a peer's ledger as an optional second witness, and
  transparency logs left to the seam.

*Recommendation: (d).* RFC 3161 is a standard that works for a single operator with no
counterpart and proves time, which is what lateness detection needs. A peer adds the
equivocation defense a TSA lacks, at no outside cost. Rekor publishes a signing identity and
adds a third-party dependency for little gain over a peer. Anything else stays possible
through the same `Anchor` seam.

**2. Where the Merkle and RFC 3161 code lives, and whether a vetted crate does it.**
Candidates checked (crates.io, 2026-11-15):
- `ct-merkle` 0.3.0 (rozbb): RFC 6962 tree with inclusion and consistency proofs. 0.3 requires
  `digest` 0.11, but the graph has 0.10 (through `sha2` 0.10 and `ikigai-sign`), so it would
  duplicate SHA-256. 0.2.0 is on `digest` 0.10. I found no published audit.
- `rs_merkle` 1.5.0: not RFC 6962 (no leaf/node domain separation by default, different
  odd-node handling). Rejected.
- `tlog_tiles` 0.2.0 (Cloudflare azul): C2SP tlog-tiles and checkpoints, RFC 6962 hashing,
  `sha2` 0.10. Worth it only if roots adopt the C2SP checkpoint format. Last release 2025-04.
- `merkle-log` 0.0.9: pre-1.0. Rejected.
- `x509-tsp` 0.1.0 (RustCrypto formats): RFC 3161 ASN.1 types on `cms` 0.2 and `der` 0.7.
  `der` 0.7.10 is already in the graph. It parses tokens. It does **not** verify the
  SignedData signature or build the TSA's chain, which needs `x509-cert`, a trust store and
  usually `rsa`.
- `cms` 0.2.3 (RustCrypto): SignedData types, the base `x509-tsp` builds on.
- `cryptographic-message-syntax` 0.28.0 (indygreg): has a TSP client and verification, but it
  brings `ring`, `reqwest` and `bcder`. That is a network client and a second DER stack in a
  crate that must stay wasm-clean. Rejected for this crate.
- No ikigai crate has a Merkle tree or a TSA client today.

Options:
- (a) Both in `ikigai-log`, as the prototype has them.
- (b) The Merkle tree in `ikigai-log` with shared vectors. RFC 3161 token verification in
  `ikigai-sign`, which already owns keys, `urn:sign:verify` and the DER/curve stack, using
  `x509-tsp` + `cms`.
- (c) A new `ikigai-anchor` crate as the one home for RFC 9162 and RFC 3161, with
  `urn:anchor:*` endpoints.
- (d) Depend on `ct-merkle` 0.2 for the tree.

*Recommendation: (b).* RFC 9162 hashing and proofs are about 200 lines of code with fixed
reference vectors. That is smaller than the ongoing cost of a pre-1.0 dependency on an older `digest`.
The RFC 6962 vectors should move to `ikigai-rs/.github/fixtures` so any second implementation
is held to the same ones. RFC 3161 is signature verification, which belongs with the
ecosystem's other signature verification, and `x509-tsp` is the vetted parser. Doing the ASN.1
by hand would be the wrong call. `ikigai-log` keeps only the seam and never verifies a token
itself. If a second consumer of the tree appears, promote it to (c).

**3. The interval.**
- (a) Hourly, fixed.
- (b) Configurable (`[anchor] interval = "1h"` in `log.toml`), hourly by default.
- (c) Every N seals.

*Recommendation: (b), with an hourly default and a floor of 1 minute.* An hour is the item's
ask and costs 24 TSA requests a day per instance. A time interval, unlike a count, makes "a
missing root" meaningful. Intervals are aligned to UTC so roots from different instances line
up.

**4. The tree's shape.**
- (a) One tree per interval over that interval's seals, with leaf 0 the previous root (§2).
- (b) One cumulative tree with a head per interval, linked by RFC 9162 consistency proofs (the
  prototype).

*Recommendation: (a).* It is what the item asks for ("one root per interval over that
interval's seals"). It survives retention: old segments go and their roots stay. Each root's
anchor stands alone. It needs no consistency proofs. The cost: someone who holds an old root
and wants to know a new one extends it walks the chain of roots (8,760 a year) rather than
checking one `O(log n)` consistency proof. Choose (b) if third-party monitors are expected to
audit live, as CT monitors do.

**5. Key-history format.**
- (a) `log:KeyChange` entries in the segments only.
- (b) A per-instance file of `#key` and `#anchor` lines (the prototype).
- (c) Both: the entry in the log for the timeline, and a small per-instance file
  (`{instance}.keys`) as the copy that outlives retention, which verify checks against the
  entries while both exist.

*Recommendation: (c).* The entry makes the change visible to anyone reading the log, and the
file is what a 2024 seal is checked against after the 2024 segments are gone. Both are
chained to the previous record's digest, and each record is anchored before it takes effect.

**6. What verify does offline vs online.**
- (a) Fully offline: recompute roots from seals, check them against the logged roots, check
  receipts through a host-supplied `AnchorCheck` with a trust store the host already holds.
  Never fetch.
- (b) Online: also query the anchor (for example, fetch the peer's copy, or check the
  transparency log for a conflicting entry).

*Recommendation: (a) for `urn:log:verify`. Online checks are a separate action*
(`urn:log:verify` with `online=true`, under `urn:cap:log:anchor`). Verify must work on an
air-gapped copy and must not fail because a TSA is down. An offline verify reports a receipt
it cannot check as `noted … receipt not checked: no trust root for rfc3161`, never as `OK`.

**7. Where roots and receipts are stored.**
- (a) As always-land entries (`log:IntervalRoot`, `log:Anchored`) in the segments.
- (b) In a sibling `{instance}.roots` file.

*Recommendation: (a) for the root and a receipt's digest, with the receipt bytes in a sibling
file keyed by that digest.* The root is then chained and sealed like everything else, and it
greps with the rest of the log. Kilobytes of DER stay out of a greppable line.

**8. How an anchor outage and lateness are classed.**
- (a) Late or unanchored is `noted`.
- (b) Late past a threshold is `BROKEN`.

*Recommendation: (a), with the allowed lag configurable (default 2 intervals), and outages
recorded as `log:AnchorFailed`.* A verifier that broke on every TSA outage would be one nobody
read, the same reasoning the README gives for crashed tails.

**9. The IRI collision with `urn:log:{segment}`.**
- (a) Reserve `root`, `proof` and `key` as instance prefixes.
- (b) Separate schemes (`urn:log-root:`, and so on).

*Recommendation: (a).* It keeps the `urn:log:` family, and an instance named `root:x` is
unlikely. Refusing it at `with_instance` makes the rule loud rather than a resolution
surprise.

## Not in this item

`log:Tombstone` and retention, a level MAC (`locked` mode), and checking seal signatures
inside verify (still `urn:sign:verify`'s job) are separate items. This one gives them a root to
stand on.
