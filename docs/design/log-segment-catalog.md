# Design: source-scoped log segment catalog and range resources

Status: **proposed for Brian's decision**. This specifies the catalog contract for the
[indexed query design](log-query-index.md). It does not implement a persistent index or a
hosted agent, choose storage, or establish performance or freshness guarantees.

## Source and range identity

Assign each logical log source a stable, canonical absolute IRI in the collector's source
registry. Bind authenticated collection credentials to allowed source IRIs and validate
that binding on receipt. A sender's label, hostname, file path, or claimed identity inside
a segment is not authority. Renaming a source or rotating its credential does not change its
IRI. Compare source IRIs exactly against the registered canonical spelling. Do not accept
aliases or try to infer equivalence by URL normalization or dereferencing. Keep distinct
sources distinct even when they have the same display name.

The range resource is `urn:log:range:source:{source}:from:{from}:to:{to}`. Names are
singular, type first, and every partition has a named key. Here the resource type is
`range` and the keys are `source`, `from`, and `to`, in that order. Preserve the
existing segment IRI as the named graph IRI. A range is a selector, not a stored graph,
a pinned snapshot, or a grant.

Split the spelling on the literal separators before decoding. Encode each nonempty value
as one UTF-8 component. Leave only ASCII letters, digits, `-`, `.`, `_`, and `~`
literal, and encode every other byte as `%HH` with uppercase hex. Decode exactly once.
Reject missing, extra, or out-of-order keys, malformed escapes, invalid UTF-8, and any
spelling that differs from canonical re-encoding (including escaped unreserved bytes).
A percent escape already present in a registered source IRI is part of that IRI. Its
percent sign is encoded as `%25` in the range, and is not decoded a second time.

Use the log timestamp format `YYYY-MM-DDTHH:MM:SS.mmmZ` for both decoded bounds.
Validate the calendar date and round-trip through the log timestamp format. Reject offsets,
leap seconds, missing or extra fractional digits, noncanonical case, and dates outside
the supported 1970–9999 years. Require `from < to`. The lower bound is inclusive and
the upper bound is exclusive. For example, the first second of August 23, 2026 UTC for
`urn:example:collector` is:

```text
urn:log:range:source:urn%3Aexample%3Acollector:from:2026-08-23T00%3A00%3A00.000Z:to:2026-08-23T00%3A00%3A01.000Z
```

## Catalog and selection

Partition the catalog by `source`, key rows by `segment` within that partition, and
expose one row per indexed segment in a committed generation. One dataset has only one
graph per segment IRI, so reject a claim that binds an already indexed segment IRI to a
different source. Do not merge graphs or silently move them between sources.

| Field | Meaning |
|---|---|
| Source | Canonical source IRI bound at authenticated receipt |
| Segment | Existing segment IRI, also the graph name |
| Minimum and maximum entry time | Inclusive extrema over every entry in the indexed bytes, or absent if empty or unknown |
| Digest | SHA-256 of the exact segment bytes used to build this graph |
| Completeness | `complete` for a finalized, fully indexed segment, `empty` for a finalized, fully inspected segment with no entries, or `partial` when the index cannot account for all entries |
| Indexing generation | Committed dataset/catalog snapshot in which this row and graph are visible |

Scan all entries to derive bounds. Never substitute header start, receipt time, filename,
or the times of the first and last entries. Sequence order is not timestamp order. A late
or backdated entry can move either extremum outside a segment's apparent rotation window.
Keep chain verification separate from completeness. Full indexing does not prove a
segment was signed or that its chain is intact.

For a complete segment with known bounds, select it when `max >= from && min < to`.
Then filter entries in each selected graph by `entry_time >= from && entry_time < to`
before evaluating result logic, including aggregates or existence checks. A graph grant
alone does not enforce the time window, including when the caller has a narrower allowed
window. A proven empty segment contributes no candidates. Unknown bounds or partial
indexing cannot rule out overlap, even if observed entries look out of range. Include
such a graph if authorized and readable, filter its available entries, and mark coverage
incomplete if any entries may be missing. If no graph is readable, report a coverage gap
within the caller's visible scope. Never interpret an unknown bound as an empty segment.

## Authorization and consistency

Authenticate the caller and check the requested source and time window against the
caller's grant before looking up catalog rows. Require the requested window to fit
inside the grant. Resolve against one committed generation and intersect candidate
graphs with the caller's graph permissions. Scope catalog rows, counts, digests,
timestamps, generation identifiers, and coverage metadata to the caller's visibility.
An unknown source and a source the caller cannot discover must not be distinguishable
through the response. Do not name hidden segments or signal their existence through
coverage reasons. Describe coverage explicitly as coverage of the caller's authorized
view, not the entire source.

Pass only the resolved graph set and enforced entry window to the trusted query path.
Even a variable graph reference may see only that set. Pin catalog and graph reads to
the same generation, but do not pin expired or revoked authority. Validate authorization
at execution and before returning results, failing closed if it no longer holds. A cached
answer must not bypass the same checks. The catalog narrows the read grant and never
widens it.

## Late data, coverage, and retention

Start with finalized segments only. Treat redelivery with the same source, segment IRI,
and digest as idempotent. Quarantine a conflicting digest for the same segment IRI.
Late arrivals use their original entry times, not receipt time, and become visible
in a new generation even if they overlap old ranges. Publish the graph and row together.
A query already pinned to an older generation stays consistent, but a later resolution
of the same range may return more evidence. Invalidate affected cached answers on
publication, including empty results.

Report the selected generation and an explicit coverage status in words. Cite returned
evidence with its segment and entry IRIs. Report known, visible gaps such as pending
receipt, unindexed or failed segments, retention, and truncated execution. A gap with
unknown entry-time bounds may affect any requested window in that authorized source.
Receipt time and the highest entry time seen are not source watermarks. Only claim
complete coverage if trustworthy source evidence establishes that no more segments
or entries can arrive for that window and the visible coverage has no gaps. Otherwise
say coverage is incomplete or not established. In particular, an empty result means
no matching entries were found in the authorized data searched, not that no such
event occurred.

Expire an indexed segment as a unit. Remove its graph and catalog row in the same
publication and invalidate affected caches. A crash or concurrent read must not see
half the change. Keep a separate, scoped deletion/coverage record as policy permits
so a removed interval is not reported as fully covered. If that record cannot be
kept, report that coverage cannot be established. Do not expose retired generations
to new reads. Define whether already pinned reads may finish under the retention
policy. If deletion must take effect immediately, cancel or drain those reads before
declaring deletion complete. Raw segment retention is a separate policy. Rebuilds and
late redeliveries must honor the deletion policy rather than resurrect expired data.

## Decisions for Brian

- Approve the registered source IRI and strict range spelling as the public contract.
  Start with finalized segments and authorize the full requested window or refuse it.
- Set the retention duration, late-arrival disposition after expiry, and whether pinned
  queries may finish. Decide how much scoped deletion metadata can survive expiry.
- Decide whether to fund source coverage evidence, durable catalog storage, and the
  hosted query path. Without source coverage evidence, report coverage as not established
  even when all currently visible segments have been indexed.

Before enabling the feature, test canonical round trips and rejected aliases, both
range boundaries, backward timestamps, unknown versus proven-empty bounds, late
delivery, conflicting digests, scoped metadata and graph reads, and atomic visibility
during ingest and expiry. These are acceptance cases for future implementation, not
claims made by this documentation change.
