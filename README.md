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
and repeated keys behave identically in both directions. Prose goes in `msg=`, or
arrives as the piped `content` (`… | urn:log:write`) — both declared, so the door a
pipeline uses is one the manifold shows.

The door is narrower than the grammar, on purpose. **A caller cannot speak for
anyone**, so `urn:log:write` refuses, with `InvalidArgument`:

* the columns the log writes itself — `seq` (the writer's numbering), `principal`
  (the host's, through `Principal::new` and a per-tenant tracer), `cap` and
  `denied` (the kernel's: the authority a resolution held, the scope a refusal
  lacked), and `pid`, `configured` and `next` (the writer's markers'). The list
  is `RESERVED_COLUMNS`. A tenant that could write `principal=` could attribute
  its entries to another tenant, with a `prov:Delegation` in the graph to prove
  it;
* every **always-land class** — `log:ProcessStart`/`Stop`, `log:Rotation`,
  `log:LevelChange`/`ConfigChange`, `log:Seal`, `log:ChainBroken`,
  `log:Dropped`, `log:CapabilityDenied`, and a module's subclass of any of them.
  Those are the markers verify and the cache believe: a forged stop is what makes
  a segment read as finished, a forged level change is what explains a gap;
* a class or subject RDF would not accept (`urn:x:{a}`), which the line grammar
  would. A segment that holds one anyway still transrepts: the entry degrades to
  a literal, flagged `log:unreadableIri`, instead of taking the whole segment's
  graph down.

The IRI a write returns names the segment the entry **landed** in, even when the
write rolled the segment over before it returned.

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
`log:ProcessStop` *or `log:Rotation`*, sealed, with nothing after it, will never
be appended to, so it is cacheable under a golden thread on its file (a marker
followed by more entries, or by no seal, is not how the writer ends a segment,
and caching it would be the one mistake a reader cannot take back); anything else — this process's open
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
process restarts too: a writer opening on a file destination finds the **tail of
its own instance's chain** — the segment no other segment's `@prev` names — and
chains from its head. By the links, not by the newest name: a clock stepped back
across a restart (NTP, a VM restore) used to name the new segment before its
predecessor, the next restart chained from the wrong one, and an untouched log
verified `BROKEN`. Name order is the fallback only where the links do not form one
chain, and a restart now clamps its stamp the way a rotation does, so a successor
never sorts before the segment it follows.

**4. Rotation is verify + seal + validate, one operation.** The open segment gets
a `log:Rotation` entry naming its successor and a final seal; the successor opens
chained to that seal; and the pair is verified. Where it does not verify, a
`log:ChainBroken` **entry** lands in the successor — not an exception, because an
exception would be caught by whatever was rotating and the fact would leave no
trace. Rotation is never fatal: a rotation that refused to complete because a
predecessor was tampered with would stop the log, which is exactly what a
tamperer wants. The same goes for a rotation that cannot open its successor:
everything that can make the successor fail (a level the vocabulary does not
define, a name RDF refuses, a directory that will not take a file) is checked
**before** the open segment is sealed, and a failure leaves it writing. The write
that triggered it still returns `Ok`, because the entry landed; the failure lands
once as `log:Error reason=rotation-failed` and is readable from
`LogHandle::rotation_error`. The residue is an I/O failure writing the first lines
of the file just created for the successor, which still closes the log, loudly.

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

* two adjacent segments at different levels require a **sealed**
  `log:LevelChange` in one of them that records **that** change — its `from=` and
  `to=` must lead from one segment's level to the other's, in one step or
  several. A bracket about some other change explains nothing, and one in an
  unsealed tail is committed to no checkpoint, so anyone could have appended it;
* entry sequence numbers must be dense, because emission advances the counter
  only for entries actually written — a level-filtered entry consumes no sequence
  number, so **a jump means lines were removed, not filtered**;
* seal coverage must be contiguous from 1, so a deleted checkpoint is visible —
  and each seal's `first-last` must be the run of entries its hash actually
  covers. The range is in no hash and the signature covers only the hash, but
  every entry line states its own `seq=` and every line is chained, so the range
  is checked against the entries and never believed on its own: widening it is
  how an unsealed tail used to be made to look sealed;
* **nothing follows an orderly end.** The writer ends a segment by writing
  `log:ProcessStop` or `log:Rotation` and sealing it at once, so an entry past
  that marker, or a marker no seal covers, was appended afterwards, and it is
  `BROKEN` — whatever class the appended line claims to be;
* a rotation marker's `next=` must name the segment that follows. `@prev` catches
  a segment removed from the *middle* — the one after it still points at what
  should have been there — but nothing points forward at the **last** segment, so
  truncating a chain at its head would otherwise be free, and the head is the
  recent past.

### What `urn:log:verify` proves, and what it cannot

Said plainly, because a verifier that implies more than it checks is worse than
none. Against an **unkeyed** reader of the files, an `OK` means:

* every entry line under a seal hashes to that seal's stated chain head, and the
  seal's range is the run of entries that hash covers;
* sequence numbers are dense and seal coverage is contiguous, so no line or seal
  was removed from the middle of a sealed run;
* each segment's `@prev` names the stated head of the segment before it, so a
  segment was not replaced or removed from the middle of a chain, and a
  rotation's `next=` names the segment after it, so a chain was not cut at a
  rotated head;
* nothing follows an orderly end, and every change of level between adjacent
  segments is recorded by a sealed bracket naming that change;
* every segment file in the directory was read — one it could not read is
  reported, not skipped.

What it does **not** establish:

* **The chain is unkeyed SHA-256.** Anyone who can write the files and knows the
  format can recompute every hash from an edit to the head and write matching
  seals — including `@prev` of every later segment. Tamper-evidence against that
  writer comes only from **signatures**, and seal signatures are **stated, not
  checked** here: `signed=` lists the algorithms the seals name, and checking one
  is `urn:sign:verify` with the public key, which this crate never resolves. An
  external anchor of the head (a signed or published seal) is the other answer,
  and nothing here makes one.
* **The level is verified as *recorded*, not as *authentic*.** A `log:LevelChange`
  brackets the gap and the chain proves that entry was not altered afterwards,
  but nothing stops whoever holds the writer from lowering the level and honestly
  recording that they did. A level MAC (`locked` mode) needs a key the
  application itself cannot hold, and that key does not exist yet.
* **A crashed tail cannot be told from an appended one.** Entries past the final
  seal of a segment that never ended are `noted`, because that is what a crash
  leaves — so the newest segment, or any segment whose process died, can be
  extended, or rewritten back to its last seal, without a `BROKEN`. The seal
  cadence (1,000 entries or 60 s by default) bounds how much.
* **Deleting the oldest segments looks like retention.** The first segment
  listed is not checked against a predecessor that is not there, so removing
  history from the old end is invisible to the walk. (There is no retention or
  `log:Tombstone` yet to make it distinguishable.)
* **Comment lines are not chained.** A `#` line that is not a seal carries
  nothing into the graph and nothing into the hash, so one can be added or
  removed freely. A repeated header directive is not refused either; the header
  enters the chain as its parsed, canonical form, so a second `@level` that
  changes what the header SAYS breaks every seal, and one that restates it is
  noise.
* **A partial line is possible on a full disk.** Each entry is one `writeln` and
  one flush, not an atomic append, so ENOSPC mid-line can leave a fragment that
  the next line continues; verify then reports the damaged line.
* **`urn:log:transrept` has no capability gate.** It is a pure function of the
  bytes a caller already holds, and that is deliberate.

An unmarked end or an unsealed tail is reported as `noted`, not `BROKEN`. A
crashed process is not a tamperer, a file alone cannot tell the two apart, and a
verifier that cried wolf on every daemon restart would be a verifier nobody read.
The exception is the tail of a segment that **ended**: an orderly end is sealed
at once, so a tail after one is not what a crash leaves. (The one honest path to
it is a final seal that failed to write — a full disk at the last line — and that
is reported `BROKEN` too, because the forged ending looks exactly the same and is
the one a tamperer reaches for.)

A segment file whose header will not parse is reported as
`segment <path> BROKEN unreadable` in every walk. It belongs to no chain anyone
can name, and leaving it out would be the verifier vouching for what it could not
read.

## Files are the owner's

Segment and lock files are created **0600**: a segment carries principals,
capability scopes and whatever prose a caller wrote, and none of it is any other
local user's to read. They are created that way rather than chmod-ed afterwards,
so no window exists in which one is world-readable. Files an older version
created keep their mode, and the directory is the operator's — a host that wants
it closed says so.

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

### One process, several principals

The global tracer slot holds exactly one collector. That is right for a daemon
logging its own work and wrong for a server handling several tenants at once, so
`LogTracer::on_behalf_of` derives a tracer that attributes every entry to a
`Principal` and shares the base's handle, clock and drop ledger. Hand it to
`Kernel::issue_traced` — the per-call form, which the kernel isolates and which
threads its own span-id space across `fan_out` — never to `set_tracer`:

```rust
let base = LogTracer::new(handle, clock);
let tenant = Arc::new(base.on_behalf_of(Principal::new(peer)?));
kernel.issue_traced(request, capability, tenant).await?;
```

```
2026-09-13T09:14:22.031Z log:Resolution urn:calendar:today seq=41 principal=urn:agent:alice worker=ikigai-sched-2 span=7 dur=12
```

Three things are load-bearing about that column:

* **It is a second axis, not a replacement.** `prov:wasAssociatedWith` still names
  the instance on every entry — *which process did it* — and `log:onBehalfOf`
  names *who it was done for*. The graph face states the second in standard terms
  as well, as a skolemized `prov:Delegation` at `{entry}:delegation`; it has to be
  the QUALIFIED form, because `prov:actedOnBehalfOf` is agent-to-agent and cannot
  name the activity, so one instance serving three tenants would otherwise read as
  three blanket delegations with no way back to the entries.
* **This crate records a principal; it does not authenticate one.** Where the IRI
  comes from is the host's question — a certificate fingerprint, a passkey
  credential, a peer name. A logging module inventing a fourth identity model
  would put the least-informed component in charge of the most consequential
  answer.
* **A principal is caller-supplied data reaching a greppable format**, so
  `Principal::new` **parses the output rather than filtering the input**: it
  renders a probe line, parses it back, and accepts the value only if every column
  survives and the value was written *bare*. One that would have to be quoted is
  refused, not escaped — escaping is lossless and still wrong, because
  `grep 'principal=urn:agent:alice'` is half of why the format is what it is. The
  refusal happens once, when a connection's tracer is built.

**N tracers, one segment, one hash chain.** `LogHandle` holds its writer behind
one lock and holds it across the whole of an append — sequence number, render,
write, flush, chain advance, seal — and `Writer` is not `Sync`, so the
unserialized variant does not compile. Rotation takes the same lock for its whole
duration, so nothing lands mid-rotation. Two things that were *not* sound have
been fixed:

* **A successor may not be stamped before its predecessor started.** Rotation is
  triggered from inside a write and stamped from that entry's time, and under
  concurrent writers an entry's time is not monotonic — a thread reads the clock,
  then waits for the lock. Measured with eight tracers: segments stamped tens of
  seconds out of order and `urn:log:verify` reporting five broken links on a chain
  that was perfectly intact. The stamp is now clamped.
* **The verify walk follows the chain, not the file names.** IRI order is a proxy
  for chain order and a log written before that clamp is on disk forever, so
  `urn:log:verify` now orders each instance's segments by `@prev` and falls back
  to IRI order when the links do not form one. Nothing there verifies a hash —
  that happens next — so a broken link still reports exactly as before.

**`Tracer::record` returns `()`**, so a write failure is invisible upward by
design. Nothing propagates, nothing panics, and everything lost is counted and
lands as an always-land `log:Dropped count=N reason=…` — a drop that leaves no
marker is the one thing the design forbids outright, since a chain is
tamper-evident and not omission-evident. Only real losses count: `Err` from a
write means the entry did not land, so a rotation that fails after its entry
landed, or a periodic seal that fails after its line was written (the seal is
retried at the next write, and an orderly close reports it), is not a drop.
**There is no sampling**, for the same reason: sampling is holes everywhere with
no brackets.

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
while repointing the destination silences the log entirely. Both faces, and the
layer file a change writes, go through real writers — the `toml` crate's string
encoding and the RDF serializer — so a directory holding any character a path may
hold still reads back: Rust's `{:?}` looks like a TOML string and is not one, and
it once wrote a `log.toml` the log could not read.

A change is **recorded now and takes effect at a boundary, never inside a
segment**. A segment has exactly one level for its whole life, which is what lets
a verifier reason per sealed segment — "this ran at `info`, so absent resolutions
are explained" — instead of tracking transitions inside sealed content. Which
boundary depends on the key, and the response and the entry's `effective=` both
say it:

| key | takes effect at |
|---|---|
| `level`, `[seal]`, `[rotation]` | the next segment — a rotation or a process start |
| `destination`, `directory`, `instance` | the next process start |

A rotation stays where its writer is: same directory, same instance name, same
instance lock. Letting a `directory` change move the next rotated segment left the
lock behind, so a second process could take the same name in the new directory
while this one wrote there.

A level a vocabulary does not define (`level=infoo`) is refused where it is typed,
and the refusal lands as `log:LevelChangeRejected`. It used to be accepted, and the
next rotation sealed the open segment, failed to open a successor, and left the log
closed for the rest of the process.

**The writer brackets the level it opens at.** A segment that opens at a level its
predecessor did not run at — whether an operator asked through `urn:log:config`,
edited `level =` in `log.toml` between runs, or a host called `set_config` — lands
`log:LevelChange key=level from=… to=… effective=this-segment` right after its
`log:ProcessStart` and seals it at once, so `urn:log:verify` finds the change
recorded where it took effect. It records the change; it does not authenticate it.

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

## Conformance

The module **passes
[`ikigai-conformance`](https://github.com/ikigai-rs/ikigai-conformance)** with
no opt-outs: `tests/conformance.rs` builds the space over a scratch log directory
holding one segment and walks it twice — once with the segment **live** (the
handle open, the tail still being appended to) and once **finished** (closed,
ending in `log:ProcessStop` and a final `#seal`) — so both cache paths are
exercised: a live segment is served uncacheable, a finished one is cached under
its file's golden thread, and both name `urn:file:<path>` as the thread a watcher
must cut. `urn:log:transrept` is declared `pure` and `cacheable` (Turtle from
bytes, no file, no clock); `urn:log:config`, `urn:log:segments` and
`urn:log:verify` are live by design and say so in their descriptions.

**The space has no name of its own, on purpose.** Both constructors,
`endpoints::space(handle)` and `endpoints::space_with_vocabulary(handle,
vocabulary)`, are built over the `LogHandle` a host passes in, so two hosts hold
different logs behind the same doors and a fixed name would be a false cache
claim. The HOST names the space it builds; the test declares both constructors
host-named, and conformance's `SPACE-NAME` check holds each to claiming no name.

Two namespaces are registered as the module's own beside the well-known ones:
`log:` (`https://ikigai-rs.dev/ns/log#`), defined in
[`src/vocabulary.ttl`](src/vocabulary.ttl) — and since registering a namespace
waives the vocabulary check for everything under it, the test parses both Turtle
faces and requires every `log:` term they emit to be a subject of that file — and
`sig:` (`https://ikigai-rs.dev/ns/sign#`), `ikigai-sign`'s, defined in that
crate's README and held to the three terms a seal carries.

One check is skipped, suite-wide: **NAMES**. The six ids (`logWrite`, `logConfig`,
`logSegments`, `logVerify`, `logSegment`, `logTransrept`) are camelCase, and they
are live MCP tool names — renamed in one coordinated pass across every module,
not six ids out of step. What the suite cannot see is pinned by hand in the same
file: declared outputs against served media types in both directions with `as`
omitted, the finished segment's Source cached and its Exists live (the suite's
`cacheable` is per endpoint, and holds both), and that the walk's one write is the
pipeline probe's — a refused write under no grants lands nowhere.

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
cache hits and capability denials, per process or per principal** — the
operator-settable seal and rotation cadences, and **all four tamper-evidence layers**: the in-memory hash chain, seals on a count-or-time
cadence with a signer seam, `@prev` carrying the chain across rotations and
restarts, and rotation as verify + seal + validate with `log:ChainBroken` as an
entry. `urn:log:verify` walks it, and checks brackets as well as hashes.

**Not built, and the pitch must not outrun it**:

* **Seal signatures are not checked here, and the level is not authenticated.**
  Verification proves entries were not altered by anyone who did not recompute
  the unkeyed chain, and that gaps are *recorded*; it does not prove a signature
  is good (that is `urn:sign:verify` with a key this crate never holds) and it
  does not prove a level change was involuntary (that needs a MAC over a key the
  application cannot hold — the helper-app work). The full list is under "What
  `urn:log:verify` proves, and what it cannot" above.
* **A segment is only greppable at the granularity it is queryable.**
  Transreption is O(segment); there is no index, and `urn:log:segments` is a
  directory listing rather than a catalog.
* No retention and no `log:Tombstone`, no central collection, no SHACL on write —
  "validate" in a rotation is the structural walk, not shapes, and this README
  will not let that word carry more than it does.
* **A principal is recorded, never authenticated, and never correlated.** The
  host names it; nothing here checks that the name is the one that authenticated,
  and there is no index from a principal to its entries — finding one tenant's
  work is still `grep`, or a transreption of the whole segment.

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
