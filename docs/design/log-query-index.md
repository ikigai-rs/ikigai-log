# Design: indexed log queries and a read-only query agent

Status: **research proposal; approval required before implementation**. This note changes no
production behavior. The existing [query description](../../README.md#queryable-across-segments--and-the-segment-is-the-named-graph)
loads segment IRIs as named graphs; the README also explicitly says there is no index and
transreption is O(segment). `src/graph.rs` parses the header, scans the segment and constructs
its triples on each `to_triples` call. Finished-segment caching reduces repeated reads, while
live segments are not cached. The measurement below reproduces the scan on synthetic segments;
it does not establish that all existing queries are slow or defeat the finished-segment cache.

## Dataset and range selection

A collector, under its own write authority, receives the original segment bytes, records their
source and content digest, and transrepts each into an `ikigai-store` dataset. Put exactly the
segment's existing IRI in the graph-name position; preserve all entry IRIs and `log:segment`.
Queries must use `GRAPH ?segment` and bind `?entry` for citations. This preserves the existing
`graph=` source model, though it requires a store-query adapter: today's `urn:sparql:*` loading
of `graph=` sources is not automatically a query against this persistent dataset. Use the
store's graph-scoped read interface for the authorized set; do not give the agent broad store
read authority over unrelated graphs.

Proposed range resource:
`urn:log:range:source:{source}:from:{from}:to:{to}`. Each placeholder is a single UTF-8
component percent-encoded using RFC 3986 unreserved characters only, including encoding `:` and
`%`; reject malformed escapes and noncanonical forms. `{source}` is the canonical source IRI,
not a display name. Times are canonical UTC millisecond timestamps, with inclusive `from` and
exclusive `to`; reject an empty or reversed interval. An authenticated request resolves this
resource to an explicit authorized graph set using a separate catalog: source, segment IRI,
minimum and maximum **entry** time, digest, completeness and indexing generation. Include a
segment whenever `max >= from && min < to`, then filter individual entry times with
`>= from && < to` inside each graph. Entry timestamps can move backward: never assume filename,
header start time, or sequence order establishes the bounds. Empty or unknown bounds require a
conservative inclusion or an explicit incomplete result, never silent omission. The catalog is
an optimization and must not widen authorization; catalog visibility itself is scoped.

Treat a segment IRI as an identity, not a version: duplicate delivery with the same digest is
idempotent; a different digest is a conflict to quarantine and report, not an overwrite. For
an open segment, either query the original path until sealed, or publish a complete immutable
snapshot and its digest atomically with catalog bounds. A later snapshot replaces the previous
one atomically, never appends duplicate triples; query readers pin a dataset/catalog generation.
Track source receipt, index lag, missing/failed segments and the selected generation in answers.
Do not equate a transrepted graph with a verified chain: preserve verification status separately,
including unsigned or broken results, and make that status visible with citations. Rebuild when
the vocabulary or transreptor mapping changes, using a versioned staging dataset and atomic
cutover; invalidate cached query results when graphs or catalog generations change. Define
retention and deletion of both graphs and catalog entries together; authoritative raw segments
remain the recovery source. Store persistence, graph replacement transactions, permissions and
crash recovery need integration tests before this becomes an operational promise.

## Hosted query agent boundary

The host authenticates the caller and derives the permitted source, time window and graph set
before invoking the model. `urn:nl:sparql` is a **drafter**: send the question, a constrained
schema and quoted, delimited data only as needed; never place log text in an instruction role.
Every log entry, result literal, IRI and model response is untrusted data, even when it purports
to be a system message. Quotation helps the model distinguish roles but is not the security
boundary. The model has no credentials, write, shell, network or tool execution authority.

A trusted checker parses the draft as SPARQL and accepts only a bounded SELECT/ASK subset;
reject updates, `SERVICE`, dataset clauses (`FROM` and `FROM NAMED`), unapproved graph IRIs,
external dereferencing and unsupported constructs. Bind the actual authorized graph dataset
server-side, not by trusting the draft or prompting; a variable `GRAPH` must range only over
that set. Execute via a dedicated read-only, graph-scoped log grant, never the collector's write
capability or a broad read grant. Enforce query size/depth, time, memory, concurrency, result
row and byte budgets independently of model output; surface timeout, truncation and partial
coverage. Fail closed on parse, authorization or citation failures. Avoid using raw store APIs
that bypass endpoint checks in the hosted path.

Require each factual answer to cite both the segment graph IRI and entry IRI returned by the
checked query, and verify that each pair belongs to the authorized snapshot. Give the user the
checked query, coverage and verification state. Aggregates require a bounded evidence set or an
explicit statement that individual citations are unavailable; do not manufacture citations for
ASK, empty, truncated or aggregate answers. Escape controls and bidirectional characters when
rendering untrusted values, and present failures in words. The answer generator also treats
query results as data and cannot call tools. Test adversarial instructions in log text, graph
escapes, nested queries, denial, missing citations, resource exhaustion and cross-tenant access.

## Scale measurement

The README's 5,001-entry segment is the reference unit, not a known production volume. The
reproducible [isolated example](../../examples/index-scale/src/main.rs) generates 10 and 100
such segments (50,010 and 500,100 synthetic entries), each with one `needle` message, distinct
segment/entry IRIs, identical timestamps and repeated subjects. It transrepts every complete
segment using the real `to_triples`, inserts the triples under its segment IRI into
`DurableStore::in_memory_shared`, then executes and fully consumes a selective `GRAPH` SELECT
that returns each matching graph and entry. The assertion checks the result count. Input is
unsealed synthetic text: it exercises mapping and indexing, not receipt, signatures or chain
verification. The query is run directly on the shared Oxigraph handle to isolate index cost;
it bypasses store endpoint authorization, budgets and serialization and is not the agent design.

On Linux x86-64, i7-11800H, rustc/cargo 1.99.0, release build, ikigai-store 0.6.0 and
Oxigraph 0.5.13, one run per size on a shared machine (`/usr/bin/time -v`; no warmup or
statistical claim):

| Relative to 5,001 entries | Input bytes | Quads | Transreption CPU wall time | Total ingest wall time | Select and consume | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| 10x | 3,841,620 | 350,140 | 0.215 s | 0.567 s | 0.000093 s | 115,932 KiB |
| 100x | 38,416,290 | 3,501,400 | 2.692 s | 7.019 s | 0.000192 s | 1,058,000 KiB |

Ingest includes text generation, transreption and individual indexed inserts; transreption is
measured inside that total. RSS is peak whole-process resident memory, including temporary
triples, not index-only storage. This one selective warm in-memory query is not representative
of arbitrary joins, broad result sets, cold reads or latency percentiles. The O(segment) work is
observed in the timed transreption of all segments; this is not an apples-to-apples measurement
against the existing cached endpoint. Persistent RocksDB disk size, load and restart cost,
concurrent writes, graph authorization overhead, range catalog cost, realistic data distribution,
retention and p95/p99 remain unmeasured. Do not extrapolate these numbers into a service SLO.

Reproduce from the repository root:

```sh
CARGO_TARGET_DIR=target cargo build --release --locked --manifest-path examples/index-scale/Cargo.toml
/usr/bin/time -v target/release/log-index-scale 10
/usr/bin/time -v target/release/log-index-scale 100
```

## Decisions and proposed follow-up items

Decide whether to fund the persistent index and hosted agent after reviewing the read-only
boundary, source identity, freshness and retention choices. The following are proposals only.

- **Measure persistent indexed log queries** — Repeat at 10x and 100x with representative
  verified segments, durable storage, cold and warm reads, concurrent ingest, broad and selective
  queries, disk use, recovery and latency distributions; compare equivalent existing queries.
- **Design a source-scoped segment catalog** — Specify source identity, canonical range IRIs,
  time bounds, authorization, late entries, incomplete coverage and retention semantics.
- **Build atomic segment indexing** — Prototype idempotent receipt, verification metadata,
  graph replacement, mapping-version rebuilds and crash-safe catalog cutover behind an opt-in.
- **Constrain read-only log query execution** — Implement and adversarially test a parsed query
  subset, graph-scoped grants and resource budgets with no network or write authority.
- **Design cited query answers** — Specify and test entry/segment citation validation, aggregates,
  incomplete coverage, accessible presentation and prompt-injection resistance.

## Persistent measurement (ledger #4218)

Measurement only; nothing below changes `ikigai-log` behavior, and none of it is a service-level
objective. The [persistent example](../../examples/index-scale/src/persistent.rs) runs each phase
as its own process:

- **Segments** are written by the real writer (`LogHandle`, file destination), sealed every 500
  entries, each seal signed with a real Ed25519 key (a fixed fixture seed), chained by rotation:
  5,000 entries plus a rotation marker per segment, mixed `log:Message`, `log:Warning` (1%) and
  `log:Error` (0.1%) entries, 50 subjects, one `needle` per segment. `verify_chain` must pass and
  every seal signature must check before anything is measured.
- **Ingest** opens `DurableStore::open_shared` (RocksDB, `persistent`), and for each segment
  re-verifies it against its predecessor and its signatures, transrepts it with `to_triples`, and
  writes its quads under the segment IRI in one `Store::extend` call, then flushes.
- **Query** is a fresh process: the open time is the restart cost; the first run of each query
  is the first read after open (the OS page cache was not dropped, so it is not a cold-disk read);
  then 100 repeated runs give p50/p95/p99 (nearest rank). Queries run on the shared Oxigraph
  handle, bypassing endpoint authorization, budgets and serialization, as in the spike.
- **Today's path** is `urn:sparql:select graph=<every segment IRI>` through a `Kernel` over the
  log space and `ikigai_sparql::space()`, default cache. The first run resolves and transrepts
  every segment; an identical repeat is a result-cache hit; the warm runs add a distinct SPARQL
  comment so the result cache misses while segment representations may still be cached.
- **Concurrency** reopens the 10x or 100x store, measures each query 50 times idle, then ingests 10
  more verified segments (another instance) on one thread while a second thread runs the three
  queries in a loop.

The same three query texts run on both paths (`log:` and `prov:` prefixes):
**selective** `GRAPH ?g { ?e log:text "needle" }` (one row per segment); **broad-wide**
`GRAPH ?g { ?e a log:Warning ; ?p ?o }` (every triple of every warning); **broad-join** errors
and warnings sharing a `log:subject` within a segment.

Machine: Apple M5 Pro, 18 cores, 64 GiB, macOS (Darwin 27.2.0, arm64), internal SSD; rustc and
cargo 1.99.1, release build; ikigai-store 0.6.0, ikigai-sparql 0.6.0, ikigai-core 0.4.2,
Oxigraph 0.5.13 with oxrocksdb-sys 0.5.13. One run per size on a machine doing other work.

| | 10x | 100x |
|---|---:|---:|
| Segments, entries, input bytes | 10, 50,010, 4,048,685 | 100, 500,100, 40,487,852 |
| Seals (all signed and checked) | 110 | 1,100 |
| Quads | 350,979 | 3,509,799 |
| Ingest wall time (verify, transrept inside it) | 2.05 s (0.06, 0.10) | 20.7 s (0.61, 0.98) |
| Ingest throughput | 24,300 entries/s | 24,100 entries/s |
| Peak RSS during ingest | 427 MiB | 2,390 MiB |
| Disk, sum of file lengths / allocated (`du`) | 337 MB / 435 MiB | 3,325 MB / 1.1 GiB |
| Restart (open an existing store) | 7.5 ms | 30.3 ms |

The sum of file lengths exceeds the allocated size because RocksDB preallocates its log files;
both are reported because neither alone is the dataset's footprint. Compaction state was not
controlled and the size was not measured after a compaction.

Reads at 10x (milliseconds; first = first run after open, then 100 warm runs; today's path has
20 warm runs):

| Query | Rows | Store first | Store p50 / p95 / p99 | `graph=` first | `graph=` identical repeat | `graph=` p50 / p95 / p99 |
|---|---:|---:|---:|---:|---:|---:|
| selective | 10 | 0.58 | 0.024 / 0.029 / 0.037 | 1,221 | 0.014 | 876 / 891 / 900 |
| broad-wide | 3,500 | 9.9 | 7.7 / 8.0 / 8.1 | 882 | 0.26 | 881 / 888 / 898 |
| broad-join | 350 | 10.9 | 6.8 / 6.9 / 7.0 | 884 | 0.035 | 885 / 894 / 900 |

At 10x, every `graph=` query that misses the result cache costs about 0.9 s whatever its shape,
because the sources are reloaded into a fresh in-memory store per query; the persistent index
answers the same text in microseconds to milliseconds. An identical repeat on today's path is a
result-cache hit and is the fastest of all, and is the honest case for dashboards that ask the
same question of finished segments.

Concurrent ingest at 10x (10 more segments, 350,979 quads, ingested in 1.82 s while reading):

| Query | Idle p50 / p95 / p99 | During ingest p50 / p95 / p99 (n=70) |
|---|---:|---:|
| selective | 0.023 / 0.030 / 0.180 | 0.051 / 0.070 / 0.077 |
| broad-wide | 7.8 / 8.0 / 8.9 | 12.1 / 18.2 / 19.1 |
| broad-join | 6.8 / 7.0 / 8.1 | 13.3 / 19.4 / 20.6 |

The selective query saw between 10 and 19 needles during the run, so readers observed each
segment's transaction appear whole; the store grew to 480,804,355 bytes of files.

At 100x on the store (first run after open, then 100 warm runs, milliseconds): selective, 100
rows, 0.61 first, p50 / p95 / p99 0.148 / 0.154 / 0.172; broad-wide, 35,000 rows, 103 first,
81.6 / 88.3 / 90.4; broad-join, 3,500 rows, 126 first, 122.9 / 123.5 / 124.2. Idle runs in the
concurrency process agreed (selective p99 0.59 ms). **The 100x during-ingest runs and the 100x
`graph=` comparison did not finish within this measurement session** and remain unmeasured, as
do cold-disk reads with the page cache dropped, a compacted size, crash recovery and graph-scoped
endpoint authorization overhead.

Reproduce from the repository root (each line is one process):

```sh
CARGO_TARGET_DIR=target cargo build --release --locked --manifest-path examples/index-scale/Cargo.toml
B=target/release/log-index-persistent W=$(mktemp -d)
$B generate 10 $W/seg && $B generate 10 $W/extra scale-extra
$B ingest $W/seg $W/store
$B query $W/seg $W/store 100
$B graph $W/seg 20
$B concurrent $W/extra $W/store 50
```
