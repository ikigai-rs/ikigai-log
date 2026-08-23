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
@prev     sha256:9f3a…

2026-08-23T09:00:00.000Z log:ProcessStart urn:ikigai:instance:bug:daemon
2026-08-23T09:14:22.031Z log:Message urn:agent:calendar msg="sync started"
#seal 1-2 sha256:4c1e… sig:MEUCIQD…
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

The grammar and the vocabulary. No I/O, no clock, no kernel — writing, rotation,
the hash chain, and transreption to Turtle build on this.

## License

Dual-licensed, at your option:

* MIT — [LICENSE-MIT](LICENSE-MIT)
* Apache License 2.0 — [LICENSE-APACHE](LICENSE-APACHE)

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this crate is dual-licensed on those terms, with no additional
conditions.
