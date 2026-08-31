# ikigai-log

The line grammar and RDF vocabulary of the ikigai log — the system's time axis.

A log entry is one line:

```
2026-08-23T09:14:22.031Z log:Resolution urn:calendar:today worker=ikigai-sched-2 span=7 dur=12
```

`<ISO-8601 Z> <class CURIE> <subject IRI> key=value…`, greppable three ways (by
class, by subject, by time prefix), and transrepted mechanically into a
PROV-O-aligned graph: each line becomes a skolemized `urn:log:{segment}:{seq}`
typed by its class, with `prov:startedAtTime` and one predicate per key.

A segment is self-describing without being opaque:

```
# ikigai-log v1
@prefix log:  <https://ikigai-rs.dev/ns/log#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@name     urn:log:bug:daemon:2026-08-23T09-00-00Z
@instance urn:ikigai:instance:bug:daemon
@level    log:info
@started  2026-08-23T09:00:00.000Z
@prev     sha256:6f1a…

2026-08-23T09:00:00.000Z log:ProcessStart urn:ikigai:instance:bug:daemon seq=1 pid=64213
2026-08-23T09:14:22.031Z log:Message urn:agent:calendar seq=2 msg="sync started"
#seal 1-2 sha256:4c1e… Ed25519:MEUCIQD…
```

`@prev` names the **previous segment's final seal**, so the chain crosses the
rotation boundary; `genesis` is written explicitly for the first segment of a
chain, never left absent, so a missing `@prev` is unambiguously an error rather
than an ambiguous "maybe first".

## The mapping is data

A positional mapping (`key` → `log:{key}`, value → string literal) cannot work:
`urn:calendar:today` has to become an IRI and `parent=3` has to become a graph
edge, or no entry joins to any other entry and the analysis story — CONSTRUCT
over the log, findings emitted as triples the way SHACL emits violations — dies
at the first line. So a term table is needed, and it lives in
[`src/vocabulary.ttl`](src/vocabulary.ttl):

* `log:keyName` binds a line's bare `key=` column to a property, and that
  property's `rdfs:range` decides what the value becomes;
* `log:subjectPredicate` refines the subject column per class;
* `log:minLevel` per class and `log:rank` per level make the verbosity dial one
  integer comparison over the graph.

A module introduces its own entry types with `rdfs:subClassOf` plus its own
bindings, loads them with `Vocabulary::extend`, and nothing here changes.

## What is PROV and what is ours

Straight PROV where PROV says exactly what we mean: `prov:Activity` for an entry,
`prov:Bundle` for a segment (PROV's own word for a named set of provenance
descriptions, which is what a segment's named graph is), `prov:SoftwareAgent` for
the writing process, `prov:startedAtTime`, `prov:wasAssociatedWith`,
`prov:wasDerivedFrom`. A `log:` sub-property where ours is narrower —
`log:resolved ⊂ prov:used`, `log:invoked ⊂ prov:wasInformedBy` — so a PROV reader
still gets the fact and we still get the precision. An extension where PROV has
nothing: `log:capability` above all, the authority an entry ran under, which is a
large part of why this log is worth more than a trace.

The vocabulary is self-contained under `https://ikigai-rs.dev/ns/log#` (the `sig:`
precedent), so nothing here waits on a `/ns` deploy.

## Born structured — there is no parse step

This is the claim worth leading with, because it is where log platforms spend
their money. An ikigai entry is written as columns and read as columns: no regex
layer, no grok pattern, no ingest pipeline reconstructing the fields a program
already had and threw away. `key=value` in the file IS the term table's key, and
the table is [`src/vocabulary.ttl`](src/vocabulary.ttl), so the same line is
`grep`-able as text and CONSTRUCT-able as a graph with nothing in between.

```
$ ikigai 'urn:log:write?class=log:Resolution&subject=urn:calendar:today&fields=span=7 dur=12'
urn:log:bug:serve:2026-08-23T09-00-00Z:41
```

The `fields` argument is a line's own **tail syntax**, scanned by the same code
that reads it back out of the file — one grammar, not two, so quoting, escaping
and repeated keys (`cap=` twice, for a resolution under two capability scopes)
behave identically in both directions.

## Queryable across segments — and the segment IS the named graph

This is the release where "CONSTRUCT over the log" stops being a property of the
format and becomes a thing you can do.

A segment resolves to Turtle **at its own IRI**:

```
$ ikigai 'urn:log:segments'
urn:log:bug:daemon:2025-08-22T00-00-00Z
urn:log:bug:daemon:2025-08-23T00-00-00Z

$ ikigai 'urn:log:bug:daemon:2025-08-22T00-00-00Z'
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix sig: <https://ikigai-rs.dev/ns/sign#> .
@prefix log: <https://ikigai-rs.dev/ns/log#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
<urn:log:bug:daemon:2025-08-22T00-00-00Z> a log:Segment ;
    log:level log:info ;
    prov:startedAtTime "2025-08-22T00:00:00.000Z"^^xsd:dateTime ;
    prov:wasAttributedTo <urn:ikigai:instance:bug:daemon> ;
    log:prevSeal "genesis" .
<urn:ikigai:instance:bug:daemon> a log:Instance , prov:SoftwareAgent .
<urn:log:bug:daemon:2025-08-22T00-00-00Z:1> a log:ProcessStart ;
    log:segment <urn:log:bug:daemon:2025-08-22T00-00-00Z> ;
    prov:startedAtTime "2025-08-22T00:00:00.000Z"^^xsd:dateTime ;
    prov:wasAssociatedWith <urn:ikigai:instance:bug:daemon> ;
    log:subject <urn:ikigai:instance:bug:daemon> ;
    log:sequence 1 ;
    log:processId 74210 .
```

**That is the whole named-graph story.** `urn:sparql:*` already resolves each
`graph=` source through the kernel and loads it as a named graph *named by the
URI it dereferenced* — so a segment that resolves to Turtle at its own IRI is a
named graph, with no N-Quads, no TriG and no union machinery anywhere. Listing
two of them is cross-segment analysis:

```
$ ikigai 'urn:sparql:select?as=text/csv&graph=urn:log:bug:daemon:2025-08-22T00-00-00Z,urn:log:bug:daemon:2025-08-23T00-00-00Z' <<'SPARQL'
PREFIX log:  <https://ikigai-rs.dev/ns/log#>
PREFIX prov: <http://www.w3.org/ns/prov#>
SELECT ?when ?resource ?cap ?segment WHERE {
  GRAPH ?segment {
    ?e a log:CapabilityDenied ;
       prov:startedAtTime ?when ;
       log:subject ?resource ;
       log:capability ?cap .
  }
} ORDER BY ?when
SPARQL

when,resource,cap,segment
2025-08-22T01:00:00Z,urn:calendar:today,urn:cap:personal:calendar,urn:log:bug:daemon:2025-08-22T00-00-00Z
2025-08-23T01:00:00Z,urn:calendar:today,urn:cap:personal:calendar,urn:log:bug:daemon:2025-08-23T00-00-00Z
```

"Which capability was refused, for what resource, over which days" is a question
a text log cannot answer without a parser, a schema and a pipeline. Here there is
no parse step: the events were **born structured**, `?segment` came from the IRI
the query resolved, and `?when` is a real `xsd:dateTime` because `prov:started
AtTime` says so. Golden threads come with it — `urn:sparql:*` records each
graph's thread, so a cached analysis dies when a segment it read changes. That is
the design's "alerting = golden threads" line, working through machinery that
already shipped.

### The mapping, in six rules

* the header becomes a `log:Segment` with its level, start and `log:prevSeal`;
* each entry becomes `{segment}:{seq}`, typed by its class — **skolemized, never
  a blank node**, because a blank node in a log is a fact you cannot cite;
* the subject column emits **twice**: `log:subject` always, plus the class's
  declared `log:subjectPredicate` where there is one. Two triples, both true, no
  reasoner required;
* each key becomes the property `log:keyName` binds it to, typed by that
  property's `rdfs:range` — an XSD datatype makes a typed literal, any other
  range makes an **IRI**, which is what lets `cap=urn:cap:fs:read` join to
  anything;
* a key no property claims lands as `log:{key}` with a plain literal **and** a
  `log:undeclaredKey` flag — lossless, never guessed, and measurable;
* `log:invoked` (parent → child) is materialized from `parent=`/`span=` where
  both lines sit in one segment **and one process run** — spans restart with the
  process, so the join is scoped between `log:ProcessStart` markers. Where it
  does not resolve the literal stays and no edge is invented.

`log:segment` lands on every entry too. Not as the mechanism — as insurance:
`urn:rdf:union` is triple-only and loses graph names, so this is what keeps a
triple self-identifying if it is ever flattened, and it lets a query written
against a union keep working on a single segment.

A `#seal` line becomes a `log:Seal` node carrying `sig:contentHash`,
`sig:algorithm` and `sig:value` — `ikigai-sign`'s own terms, and the digest in
the same **tagged** `sha256:<hex>` form that crate writes, because sharing a
predicate while writing two spellings of one value means the two never join in a
query. The **transreptor** verifies nothing: reading must not depend on trusting,
so a graph of a tampered segment is still a faithful graph *of* a tampered
segment. Verification is `urn:log:verify`, below, and it is a separate act.

### What it costs, measured

Transreption is **O(segment)** — every line is parsed on every read. Over a
5,001-entry / 590 KB segment (debug build; read the ratios):

| read | cost |
|---|---|
| whole segment, live | 196 ms |
| `since=` the last 1% | 1.4 ms |
| `from_seq=` the last 1% | 33 ms |
| finished segment, from cache | 40 µs |

Two things follow, and both are honest rather than flattering. **A finished
segment caches and a live one does not**: a segment whose last entry is
`log:ProcessStop` *or `log:Rotation`* will never be appended to, so it is
cacheable under a golden thread on its file; anything else — this process's open
segment, or one whose process died — stays live, because caching a live tail
would be a lie about the one fact a reader came for, and a watcher cutting a
thread per appended entry is thrash rather than freshness.

Both markers matter, and the second one is the one that pays. A daemon writes one
`log:ProcessStop` in its life and a `log:Rotation` every day, so **the rotated
segment is the common case for analysis** — and a reader that recognized only the
stop marker would treat every one of them as a live tail forever. Measured over a
585 KB / 5,002-entry rotated segment: **133 ms** to transrept, which is what an
uncached read pays *every time*, against **29 µs** served from cache. ~4,600×,
and nothing but an explicit assertion notices, because expiry is not something a
test about the graph can see.

**And `since=`/`until=` are 20× cheaper than
`from_seq=`/`to_seq=`**, because the timestamp column is fixed-width UTC and
therefore sorts lexically — the same property that makes `grep '^2026-08-23T09:'`
a query — so a line outside a time window is skipped before it is tokenized at
all. Narrow by time where you can.

The hot window is queryable. A year is not: cold segments are files, hydrated on
demand, and this README will not pretend otherwise.


## Tamper-evident across rotations — four layers, or none

A partial chain is worse than none, because it *looks* verifiable. So all four
layers landed together.

**1. A per-entry hash chain, in memory.** `h₀ = sha256(the canonical header)`,
then `hᵢ = sha256(hᵢ₋₁ ‖ "\n" ‖ the line)`, with `hᵢ₋₁` entering as the tagged
ASCII string it is written as. **Nothing per line lands on disk** — a hash column
on every entry is exactly the noise that would wreck `grep`, which is a
first-order requirement of this format. The chain is recomputed on read.

**2. Signed checkpoints, every N entries *or* T milliseconds** (1,000 / 60 s by
default). A `#seal first-last <hash> [<alg>:<base64>]` line reads as a comment to
anything that does not know the format and greps as `^#seal` to anything that
does. Tampering then localizes to *between seal K and seal K+1* — and that
localization is the product, not the detection. The time bound is not optional:
N alone leaves a merely quiet log unsealed for days, and the unsealed tail is
what an attacker rewrites for free.

Signing is a **seam**, not a key: `SealSigner` is handed the tagged chain hash
and returns a signature, so a host wires it to `urn:sign:sign` over
`key=urn:file:…` today and `key=urn:secret:…` or a Secure Enclave slot tomorrow
with no change here. This crate holds no key material. **An unsigned seal still
localizes tampering**, so a log written without a key chains and seals anyway.

**3. ★ The chain spans rotations.** `@prev` carries the predecessor's final seal.
This is the layer that is easy to skip and expensive to skip: if each file chains
from scratch, rotation is a **seam at which a whole segment can be deleted and a
replacement forged**, and every other check still passes. Segment ordering falls
out of it for free — the chain is a linked list, not a sorted directory. It spans
process restarts too: a writer opening on a file destination reads the newest
segment of its own instance and chains from its head.

**4. Rotation is verify + seal + validate, one operation.** The open segment gets
a `log:Rotation` entry naming its successor and a final seal; the successor opens
chained to that seal; and the pair is verified. Where it does not verify, a
`log:ChainBroken` **entry** lands in the successor — not an exception, because an
exception would be caught by whatever was rotating and the fact would leave no
trace. Rotation is never fatal: a rotation that refused to complete because a
predecessor was tampered with would stop the log, which is exactly what a
tamperer wants.

```
$ ikigai 'urn:log:verify'
segment urn:log:bug:daemon:2026-08-22T00-00-00Z BROKEN entries=4012 seals=5 level=log:info prev=genesis signed=Ed25519 head=sha256:9ab7…
  BROKEN seal 3001-4012 states sha256:9ab7… but the entries hash to sha256:1d40… — the alteration is between sequence 3001 and 4012
segment urn:log:bug:daemon:2026-08-23T00-00-00Z OK entries=118 seals=1 level=log:info prev=sha256:9ab7… signed=Ed25519 head=sha256:22ce…
verified 2 segment(s), 1 broken
```

### Verify checks more than hashes

A hash chain is tamper-evident and **not omission-evident**: it proves nothing
was *altered* and cannot prove nothing was *left out*. Lowering the level is
legitimate, sanctioned omission — an attacker who can do it opens a hole the
chain then blesses as perfectly intact. So verification also checks that **every
gap is bracketed by an always-land marker**:

* two adjacent segments at different levels require a `log:LevelChange` in one of
  them;
* entry sequence numbers must be dense, because emission advances the counter
  only for entries actually written — a level-filtered entry consumes no sequence
  number, so **a jump means lines were removed, not filtered**;
* seal coverage must be contiguous from 1, so a deleted checkpoint is visible;
* a rotation marker's `next=` must name the segment that follows. `@prev` catches
  a segment removed from the *middle* — the one after it still points at what
  should have been there — but nothing points forward at the **last** segment, so
  truncating a chain at its head would otherwise be free, and the head is the
  recent past.

And two things it does **not** establish, said plainly rather than implied:

* **Seal signatures are stated, not checked.** Checking one is `urn:sign:verify`
  with the public key, and this crate resolves no key.
* **The level is verified as *recorded*, not as *authentic*.** A `log:LevelChange`
  brackets the gap and the chain proves that entry was not altered afterwards,
  but nothing stops whoever holds the writer from lowering the level and honestly
  recording that they did. A level MAC (`locked` mode) needs a key the
  application itself cannot hold, and that key does not exist yet.

An unmarked end or an unsealed tail is reported as `noted`, not `BROKEN`. A
crashed process is not a tamperer, a file alone cannot tell the two apart, and a
verifier that cried wolf on every daemon restart would be a verifier nobody read.

## Attributed per process, not per machine

A segment belongs to one **process**, named by `@instance`, and that name is the
attribution key: two `ikigai serve` processes on one host are two logs, and "what
happened on this machine" is a union — which is already the model, so nothing has
to be invented to ask it.

Servers that were never given a name are the ordinary case, so a name is
self-assigned (`serve-64213`) rather than demanded, and a name that a live
process already holds is **disambiguated rather than refused** — a logging
subsystem that stopped the second server on the box would be the thing that went
wrong instead of the thing you consult about it. Contention is detected with an
advisory lock the OS releases when the process dies, so no crash strands a name;
and the disambiguation is recorded (`configured=` on `log:ProcessStart`), because
a header that quietly disagrees with the config is a question nobody can answer
later.

## The kernel writes it

`LogTracer` is an `ikigai_core::Tracer`. A host installs one with
`Kernel::set_tracer` and every resolution the kernel performs lands as an entry —
**trap-free by construction, because nobody is composing prose**:

```
2026-08-31T09:14:22.031Z log:Resolution urn:calendar:today seq=41 worker=ikigai-sched-2 span=7 parent=3 dur=12 cap=urn:cap:fs:read
2026-08-31T09:14:22.104Z log:CapabilityDenied urn:secret:api-key seq=42 denied=urn:cap:secret:read cap=urn:cap:fs:read
```

The mapping is nearly one-to-one, and two pieces of it are load-bearing:

* **A cache hit is a CLASS, not a column.** `log:CacheHit` is
  `rdfs:subClassOf log:Resolution` at `log:minLevel log:trace`, because a class is
  what the dial can exclude and a boolean could not be.
* **A refusal is a fact the kernel is the only place to see.** The capability
  floor is enforced *before dispatch*, so the endpoint that would record a denial
  is the one being denied. Core 0.1.62 reports the refusal to the tracer instead
  (`DENIED_NOTE`), and `log:CapabilityDenied` is always-land. `denied=` is the
  scope the caller **lacked**; `cap=` is the authority it **held** — two facts,
  two columns.

Two costs, stated rather than left to be discovered:

**Installing a tracer means a `TraceEvent` is BUILT for every resolution.** The
kernel gates only on `set_tracer` — there is no per-class filter upstream — so the
level dial filters what is *written*, not what is *built*. Measured over 50,000
computed resolutions (release, min of three):

| | ns/resolution |
|---|---|
| no tracer installed | 566 |
| a tracer that discards every event | 628 (+11%) |
| `LogTracer` at `error`, writing nothing | 692 (+22%) |
| `LogTracer` at `debug`, one flushed line | 2,177 (+285%) |

Half of the `error` cost is the kernel's, not this crate's. "The log is
effectively off, so it is free" is wrong; the honest lever is not installing a
tracer.

**`Tracer::record` returns `()`**, so a write failure is invisible upward by
design. Nothing propagates, nothing panics, and everything lost is counted and
lands as an always-land `log:Dropped count=N reason=…` — a drop that leaves no
marker is the one thing the design forbids outright, since a chain is
tamper-evident and not omission-evident. **There is no sampling**, for the same
reason: sampling is holes everywhere with no brackets.

## One dial, and a floor it cannot reach

The verbosity level is a **vocabulary fact**: `log:rank` orders the ladder,
`log:minLevel` sets a threshold per class, and the emit test is one integer
comparison over the graph. Turn the dial down and resolutions stop being written;
turn it to `error` and prose stops too.

What does **not** stop is the always-land set — `log:rank -1`, below every
settable level. Process start and stop, every config change, seals, rotations,
chain breaks, retention tombstones, dropped entries, capability denials, key
changes. That set exists because a hash chain is tamper-evident and **not**
omission-evident: it proves nothing was altered and cannot prove nothing was left
out, so every legitimate source of absence has to leave a marker the chain then
covers. An attacker who can lower the level would otherwise open a gap the chain
blesses as perfectly intact.

## Writing is capability-gated

`urn:log:write` requires `urn:cap:log:write`, `urn:log:config` requires
`urn:cap:log:read` to read and `urn:cap:log:config` to change. Gating a *write*
looks over-careful until the threat is named: a forged entry. A record anyone may
append to is not evidence, and this log is meant to be evidence.

The configuration is itself a resource — `urn:log:config`, served as TOML or as a
graph, layered `log.toml ⊕ {app}.log.toml` under the ikigai config home, with no
environment variables anywhere (that channel is banned here: an environment
variable is a setting no config file records and no read reports). Every change
lands an always-land `log:LevelChange` or `log:ConfigChange` — a destination
change more urgently than a level change, since lowering the level makes a hole
while repointing the destination silences the log entirely.

A level change is **recorded now and effective at the next process start**. A
segment has exactly one level for its whole life, which is what lets a verifier
reason per sealed segment — "this ran at `info`, so absent resolutions are
explained" — instead of tracking transitions inside sealed content.

The seal and rotation cadences are operator dials on the same terms:

```toml
[seal]                     # when a #seal line is written
every_entries = 1000
every_millis  = 60000

[rotation]                 # when a segment rolls over
max_entries    = 100000
max_age_millis = "never"   # roll over on age alone
```

They nest because `every_entries` names nothing on its own — it is a bound *of a
cadence* — while the four scalars above them (`level`, `destination`,
`directory`, `instance`) have no such pair to belong to. A bound is a positive
integer or the word `"never"`: zero is a bound met before anything happened, so
it is refused rather than read as "off". And a cadence change, like a level
change, takes effect at the **next** segment — a cadence that shifted inside
sealed content would make "was this segment sealed on schedule?" unanswerable.

**A number worth knowing before you leave the defaults alone.** A segment of
exactly the default `max_entries` (100,000) is 13.1 MB at ~138 B per resolution
entry, and transrepts to 49.3 MB of Turtle in ~600 ms. Since 100,000 / 24 h =
**1.16**, any process sustaining more than about **one resolution per second**
rotates on the entry bound rather than the day bound — which inverts what the day
bound is for ("yesterday's log should be one IRI"). The defaults are still the
right *shape*: the day bound is the read-side unit and the entry bound is the
guard against a burst producing a file nothing wants to transrept. But a host that
installs a tracer should expect to set them, and now it can.

## Two invariants worth knowing before you extend it

**One entry is one line.** It carries `grep`, the hash chain (which folds in each
line exactly as written), and any rotation that reasons about a prefix of a file.
Newlines inside values are escaped, never written.

**A hash chain is tamper-evident, not omission-evident.** It proves nothing was
altered; it cannot prove nothing was left out. So every legitimate source of
absence leaves a marker in the chain — level and config changes, seals, chain
breaks, rotations, retention tombstones, dropped entries, process start/stop,
capability denials, key changes — which is what `log:always` (rank −1) declares.
The same argument is why there is no sampling: sampling is holes everywhere with
nothing to bracket them.

## Status

**Built**: the line grammar, the vocabulary, the writer (one segment per process,
level-filtered, flushed per entry, wasm-clean through a sink seam), the layered
`log.toml`, the `urn:log:write` / `urn:log:config` endpoints with their
capabilities declared and enforced, **the transreptor** — `urn:log:transrept`
over piped bytes, `urn:log:{segment}` over a segment on disk (Turtle by default,
the file itself on request, windowed by `since` / `until` / `from_seq` /
`to_seq`, and answering `Exists` in O(header) so a chain walk can follow a
`@prev` without reading what it points at), `urn:log:segments` to list what
there is to query, **`LogTracer` — the kernel writing its own resolutions,
cache hits and capability denials** — the operator-settable seal and rotation
cadences, and **all four tamper-evidence layers**: the in-memory hash chain, seals on a count-or-time
cadence with a signer seam, `@prev` carrying the chain across rotations and
restarts, and rotation as verify + seal + validate with `log:ChainBroken` as an
entry. `urn:log:verify` walks it, and checks brackets as well as hashes.

**Not built, and the pitch must not outrun it**:

* **Seal signatures are not checked here, and the level is not authenticated.**
  Verification proves entries were not altered and that gaps are *recorded*; it
  does not prove a signature is good (that is `urn:sign:verify` with a key this
  crate never holds) and it does not prove a level change was involuntary (that
  needs a MAC over a key the application cannot hold — the helper-app work).
* **A segment is only greppable at the granularity it is queryable.**
  Transreption is O(segment); there is no index, and `urn:log:segments` is a
  directory listing rather than a catalog.
* No retention and no `log:Tombstone`, no central collection, no SHACL on write —
  "validate" in a rotation is the structural walk, not shapes, and this README
  will not let that word carry more than it does.
* **The tracer is per-process and single-tenant.** It rides the kernel's global
  tracer slot, which is the right shape for a daemon logging its own work and the
  wrong one for a wire server tracing one tenant's connection — that wants
  `Kernel::issue_traced`, and nothing here projects onto it yet.

**Logging is off until a host opens a writer**, and binding the endpoints does
not open one. The module cannot tell whether it is inside a daemon or a one-shot
`ikigai -c`, and a one-shot that opened a segment would put a process that did
nothing into the journal beside the servers. The knob lives here; the policy
lives in the host.

## License

Dual-licensed, at your option:

* MIT — [LICENSE-MIT](LICENSE-MIT)
* Apache License 2.0 — [LICENSE-APACHE](LICENSE-APACHE)

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this crate is dual-licensed on those terms, with no additional
conditions.
