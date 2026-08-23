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
//! ## Writing
//!
//! One segment per **process**, opened once, level-filtered by the vocabulary
//! and flushed per entry. [`Writer`] is the append point; [`LogHandle`] is the
//! process-wide knob the `urn:log:*` endpoints and the host share.
//!
//! **Logging is off until a host opens a writer**, and binding the endpoints
//! does not open one. The module cannot judge what it is inside: a one-shot
//! `ikigai -c` that opened a segment would put a process that did nothing into
//! the journal beside the servers. So the deliverable is the knob, not the
//! policy — [`LogConfig::default`] is the quiet one, and a host that logs says
//! so.
//!
//! ```no_run
//! use std::sync::Arc;
//! use ikigai_log::{Destination, LogConfig, LogHandle, Timestamp, Vocabulary};
//!
//! // A server that was not given a `--name` asks for one that will not contend
//! // with the other `ikigai serve` on the box.
//! let base = LogConfig::default()
//!     .with_destination(Destination::File)
//!     .with_self_assigned_instance("serve");
//! let handle = Arc::new(LogHandle::ambient(Some("serve".into()), base)?);
//! handle.open(Vocabulary::shared_builtin(), Timestamp::from_millis(0))?;
//! let space = ikigai_log::endpoints::space(handle);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## What this crate is not, yet
//!
//! `@prev genesis`, always: the hash chain and the seals are one piece of work
//! and a partial chain is worse than none, because it looks verifiable.
//! Transreption to Turtle, the `ikigai_core::Tracer` implementation, SHACL on
//! write, rotation and retention are all still ahead.

#![forbid(unsafe_code)]

pub mod config;
pub mod endpoints;
mod line;
#[cfg(not(target_family = "wasm"))]
pub mod load;
mod vocabulary;
mod writer;

#[cfg(test)]
mod tests;

pub use config::{
    instance_iri, level_iri, ConfigError, Destination, LogConfig, Patch, DEFAULT_INSTANCE_NAME,
    DEFAULT_LEVEL, INSTANCE_NS, STEM,
};
pub use endpoints::{LogHandle, CAP_CONFIG, CAP_READ, CAP_WRITE, CONFIG_IRI, WRITE_IRI};
pub use line::{
    is_iri, parse_fields, Entry, Header, Line, ParseError, Prev, RenderError, Seal, Timestamp,
    FORMAT_VERSION,
};
pub use vocabulary::{
    ClassDef, KeyDef, VocabError, Vocabulary, CAPABILITY_DENIED_CLASS, CONFIG_CHANGE_CLASS,
    DEFAULT_MIN_LEVEL, ENTRY_CLASS, ERROR_CLASS, LEVEL_CHANGE_CLASS, LEVEL_CHANGE_REJECTED_CLASS,
    LOG_NS, MESSAGE_CLASS, PROCESS_START_CLASS, PROCESS_STOP_CLASS, PROV_NS, VOCABULARY_TTL,
    WARNING_CLASS,
};
pub use writer::{ClosureSink, LineSink, WriteError, Writer};
#[cfg(not(target_family = "wasm"))]
pub use writer::{FileSink, StderrSink};
