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
@prev     genesis

2026-08-23T09:00:00.000Z log:ProcessStart urn:ikigai:instance:bug:daemon seq=1 pid=64213
2026-08-23T09:14:22.031Z log:Message urn:agent:calendar seq=2 msg="sync started"
```

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

## Two invariants worth knowing before you extend it

**One entry is one line.** It carries `grep`, the per-line hash chain, and any
rotation that reasons about a prefix of a file. Newlines inside values are
escaped, never written.

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
`log.toml`, and the `urn:log:write` / `urn:log:config` endpoints with their
capabilities declared and enforced.

**Not built, and the pitch must not outrun it**:

* **No hash chain and no seals.** `@prev` is `genesis`, always. The four
  fingerprint layers are one piece of work, and a partial chain is worse than
  none because it *looks* verifiable. Tamper-evidence is the design, not yet the
  code.
* **No transreption to Turtle.** The mapping is declared and mechanical; the
  transreptor that runs it is next, and until it lands "CONSTRUCT over the log"
  is a property of the format rather than a thing you can do.
* No `ikigai_core::Tracer` implementation, so the kernel is not yet writing its
  own resolutions here.
* No rotation, no retention, no central collection, no SHACL on write.
* A **known hole**: the kernel refuses a capability-gated action *before* the
  endpoint runs, so `urn:log:write` cannot record its own `log:CapabilityDenied`.
  A host that catches the refusal can, through `LogHandle::record_denial`;
  closing it properly needs a seam in the kernel.

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
