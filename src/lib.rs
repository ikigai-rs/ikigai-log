//! The line grammar and RDF vocabulary of the ikigai log.
//!
//! A log entry is one line:
//!
//! ```text
//! 2026-08-23T09:14:22.031Z log:Resolution urn:calendar:today worker=ikigai-sched-2 span=7 dur=12
//! ```
//!
//! `<ISO-8601 Z> <class CURIE> <subject IRI> key=value…`, greppable three ways —
//! by class, by subject, by time prefix — and transrepted mechanically into a
//! PROV-O-aligned graph: each line becomes a skolemized `urn:log:{segment}:{seq}`
//! typed by its class, with `prov:startedAtTime` and one predicate per key.
//!
//! ## Why the mapping is data
//!
//! A purely positional mapping (`key` → `log:{key}`, value → string literal)
//! cannot work: `urn:calendar:today` has to become an IRI and `parent=3` has to
//! become a graph edge, or no entry joins to any other entry and the analysis
//! story — CONSTRUCT over the log, findings as triples — dies at the first line.
//! So a term table is needed. It lives in [`vocabulary.ttl`](VOCABULARY_TTL),
//! not in Rust: `log:keyName` binds the column, `rdfs:range` types the value,
//! `log:minLevel` sets the verbosity threshold per class. A module extends all
//! three with `rdfs:subClassOf` and touches no code here.
//!
//! ## What is PROV and what is ours
//!
//! Where PROV-O says exactly what we mean, we use PROV: `prov:Activity` for an
//! entry, `prov:Bundle` for a segment (PROV's own word for a named set of
//! provenance descriptions, which is what a segment's named graph is),
//! `prov:SoftwareAgent` for the writing process, `prov:startedAtTime`,
//! `prov:wasAssociatedWith`, `prov:wasDerivedFrom`. Where ours is narrower we
//! declare a `log:` property as a sub-property of the PROV one — `log:resolved
//! ⊂ prov:used`, `log:invoked ⊂ prov:wasInformedBy` — so a PROV reader still
//! gets the fact and we still get the precision. Where PROV has nothing, we
//! extend: `log:capability` above all, the authority an entry ran under, which
//! is a large part of why this log is worth more than a trace.
//!
//! ## What this crate is not
//!
//! The grammar and the vocabulary, and nothing else. No I/O, no clock, no
//! kernel: writing, rotation, the hash chain, and transreption to Turtle build
//! on this.

#![forbid(unsafe_code)]

mod line;
mod vocabulary;

#[cfg(test)]
mod tests;

pub use line::{
    is_iri, Entry, Header, Line, ParseError, Prev, RenderError, Seal, Timestamp, FORMAT_VERSION,
};
pub use vocabulary::{
    ClassDef, KeyDef, VocabError, Vocabulary, DEFAULT_MIN_LEVEL, ENTRY_CLASS, LOG_NS,
    VOCABULARY_TTL,
};
