# Design: an expected head, an anchored checkpoint, and entry inclusion proofs

Ledger #4510. Status: **part 1 built, parts 2 and 3 proposed, for decision.** This note
follows [merkle-anchoring.md](merkle-anchoring.md) (ledger #3642) and does not repeat it. That
note designs interval roots over seals and an anchored key history. This one starts from what
the two source papers on accountable agents both name: a log kept only by the party it may
accuse proves little, and "link verification alone passes any valid prefix".

## 1. Truncation: verify against an expected head (built)

**Reproduced.** `tests/audit_4510.rs`, `a_truncated_chain_passes_link_verification`: a
closed segment cut back to just after its first seal verifies `ok()` on `main`. Its links all
hold, and its missing tail reads as a crash, which is `noted`, never `BROKEN`. Removing the newest of
several rotated segments is already caught (`MissingSuccessor`: the rotation named it), but
nothing points forward from the newest seal, so a cut inside the newest segment passes.

**What verify does now.** `urn:log:verify` takes `instance=` plus either or both of:

- `head=sha256:…`: a seal hash. Some seal in the chain must state it. It is looked for in
  every seal, not only the last, so a chain that grew after the head was published still
  passes.
- `entries=N`: a stated length. The chain's segments must hold at least `N` entries between
  them. A length counts the segments walked, so after retention removes old segments, state
  the head instead.

A chain that does not reach it is `BROKEN`, and the report says so in a sentence:

```
segment urn:log:bug:daemon:2026-11-27T10-00-00Z OK entries=3 seals=1 … head=sha256:41aa…
expected BROKEN head=sha256:9f2c…
  BROKEN no seal in this chain states its expected head sha256:9f2c…: the chain ends before it, or was rewritten before it
verified 1 segment(s), 0 broken, expected head not reached
```

A hash chain cannot tell a cut apart from a rewrite before the head, so the sentence names
both. An expected head belongs to one chain, so verify refuses `head=` or `entries=` without
`instance=`, or with `segment=`. In the library: `verify_chain_to(segments, vocab,
&ExpectedHead::seal(h))`, or `ChainReport::check_expected` on a walk already made.

**What it does not do.** It does not check that the head was signed, or by whom. The caller
brings a head it already trusts: one it checked with `urn:sign:verify`, read from an anchor,
or was told by a person. Part 2 is where such a head comes from.

## 2. Anchoring: a signed checkpoint the operator does not solely control (proposed)

### The checkpoint

One line, signed with `ikigai-sign` over its bytes, in the shape of a C2SP signed note so an
existing witness or transparency log can carry it without a new format:

```
urn:ikigai:instance:bug:daemon
4013
sha256:9f2c…
— urn:sign:key:daemon-2026-11 <base64 signature>
```

The lines are the origin (the instance), the length (entries in the chain so far), and the
head (the hash of the newest seal). The signature makes it the operator's statement. Where it
is published makes it hard to take back. Verify reads one as `head=` plus `entries=`, after the
host has checked the signature. This crate resolves no key and makes no network call, so
reading a checkpoint stays the host's, through a seam like `SealSigner`.

### Cadence

Every seal is too often for most anchors (a seal every 60 s by default). **Recommended: one
checkpoint per hour, plus one at every rotation and every orderly close**, hourly aligned to
UTC as in #3642 Decision 3. What can be cut without a trace is then at most the entries since
the last checkpoint, and a missing checkpoint for an hour is visible as a gap.

### Where it goes

| Option | Protects against | Does not protect against | Costs |
|---|---|---|---|
| **A second host** (a peer ikigai host that stores what it is sent, in its own chain) | The operator cutting or rewriting its own log after a checkpoint left: the peer holds the head. | A peer that colludes, or one the operator also runs. Equivocation if the operator sends different heads to different peers. | One write per checkpoint to a peer that grants it. Needs an independent peer to exist. No outside dependency. |
| **A transparency log** (a C2SP tlog with witnesses, or Sigstore Rekor) | Cutting and rewriting, **and** equivocation: every monitor sees the same entry, so two heads for one length are public. | Whether the entries were true when written. | A third-party dependency, its rate limits and retention. Rekor publishes the signing public key, which links every checkpoint from one operator. A tlog without witnesses is worth little more than a TSA. |
| **A layer another participant reads** (the ledger, or a shared log the accused party's counterpart writes to) | Cutting and rewriting, within the reach of whoever reads that layer. The counterpart is the one most likely to check. | Collusion between the operator and the layer's owner. | Nearly free inside the ecosystem: one write per checkpoint. Its strength is exactly the independence of that layer from the operator. |
| **An RFC 3161 timestamp authority** | A checkpoint dated in the past: a rewrite re-anchored today gets today's time (lateness, #3642 §3). | Equivocation: an operator can timestamp two heads and show each to a different reader. | One HTTP request per checkpoint; verifying a token needs CMS and usually RSA, which belong in `ikigai-sign` (#3642 Decision 2). |

**Recommendation:** a layer another participant reads (the counterpart's own log or the
ledger) as the default, because it is the party the log may be used against, or for, and it
costs nothing outside the ecosystem; a peer host as the second witness; a transparency log
left to the seam for operators who need public equivocation evidence. This agrees with #3642
Decision 1 (d), with the counterpart layer added first.

### How verify reads it

Offline, always, as #3642 Decision 6 (a) says: the host fetches the latest checkpoint it
trusts, checks its signature with `urn:sign:verify`, and passes `head=` and `entries=`. Verify
never fetches. A later item could add `checkpoint=` taking the signed note itself, with the
signature check delegated to a host-supplied seam.

## 3. Inclusion proofs over a segment's entries (proposed)

#3642 puts **seals** in the leaves, so a proof shows a seal was committed. The papers ask for
more: proving **one entry** was present without handing over the whole segment. That needs a
tree over the entries.

- **Leaves.** One leaf per entry line, as written (the bytes the chain hashes):
  `leaf = SHA-256(0x00 ‖ line)`.
- **Nodes.** `node = SHA-256(0x01 ‖ left ‖ right)`, RFC 6962 §2.1 domain separation, so a
  leaf can never be presented as a node.
- **An odd node.** RFC 6962's rule, not duplication: for `n` leaves, split at `k`, the largest
  power of two less than `n`; the left subtree holds `k` leaves, the right the rest. An odd node
  is carried up unpaired, never hashed with a copy of itself, which is the flaw (CVE-2012-2459)
  that duplication opens.
- **Where the root lives.** On each seal, as one more column over that seal's run of entries:
  `#seal 1001-2000 sha256:<chain> mth=sha256:<root> [<sig>]`. The signature would then cover
  `chain ‖ mth`. A proof is about 10 hashes (`⌈log₂ 1000⌉`) and is checked against the seal and
  the checkpoint of part 2, with no other entry disclosed.

**Not built.** It changes what is persisted (the seal line, and what a signature covers), so it
needs Brian's decision and an upgrade path: old seals without `mth=` keep verifying by the
chain alone, and verify reports `mth` only where it is present. The RFC 6962 vectors and the
roughly 200-line tree from the #3642 prototype (`src/merkle.rs` on `worker/item-3642-impl`)
are reusable as they are; only the leaves change.

## Decisions for Brian

1. **The checkpoint format.** (a) A C2SP signed note as above, or (b) an always-land
   `log:Checkpoint` entry in the log plus a copy sent out. *Recommendation: (a) sent out, with
   (b) recorded locally*, so the log says when each one left.
2. **The default anchor.** *Recommendation: the counterpart's layer, then a peer host,* as in
   §2.
3. **Entry leaves on every seal.** (a) Always, (b) opt in per instance, or (c) not at all,
   relying on #3642's seal leaves. *Recommendation: (b)*, because it adds a hash per seal and
   lengthens a greppable line.
