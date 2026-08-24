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
//! ## Tamper-evidence: four layers, or none
//!
//! [`chain`] holds all of it, and it is one piece of work on purpose — a partial
//! chain is worse than none, because it *looks* verifiable.
//!
//! 1. **A per-entry hash chain**, in memory: h₀ over the canonical header, then
//!    hᵢ = sha256(hᵢ₋₁ ‖ "\n" ‖ the line). Nothing per line lands on disk — a
//!    hash column on every entry is exactly the noise that would wreck `grep`.
//! 2. **Signed checkpoints** every N entries **or** T milliseconds
//!    ([`SealPolicy`]), written as `#seal` lines that read as comments to
//!    anything else and grep as `^#seal`. Tampering then localizes to "between
//!    seal K and seal K+1". Signing is a seam ([`SealSigner`]) rather than a key,
//!    because keys resolve as resources; **an unsigned seal still localizes**.
//! 3. **★ The chain spans rotations.** `@prev` carries the predecessor's final
//!    seal. Without it, rotation is a seam at which a whole segment can be
//!    deleted and forged and every other check still passes.
//! 4. **Rotation is verify + seal + validate, one operation**
//!    ([`LogHandle::rotate`]). A rotation that cannot verify its predecessor
//!    lands a `log:ChainBroken` **entry, not an exception** — the failure belongs
//!    in the record it is a failure of.
//!
//! `urn:log:verify` walks it, and it checks more than hashes: a chain is
//! tamper-evident and **not omission-evident**, so every gap must be bracketed by
//! an always-land marker. What it does not establish is stated in [`chain`] and
//! not implied: seal signatures are checked by `urn:sign:verify` with a key this
//! crate never holds, and the level is verified as RECORDED rather than as
//! AUTHENTIC — a level MAC needs a key the application itself cannot hold.
//!
//! ## What this crate is not, yet
//!
//! The `ikigai_core::Tracer` implementation, SHACL on write, and retention with
//! `log:Tombstone` are all still ahead.
//!
//! ## Reading
//!
//! [`graph::to_turtle`] is the transreptor, `text/x-ikigai-log` → `text/turtle`,
//! and it is the whole of the mapping. It is reached two ways: `urn:log:transrept`
//! over piped bytes, and `urn:log:{segment}` over a segment on disk — whose
//! DEFAULT face is Turtle, because that is what makes
//! `urn:sparql:* graph=urn:log:{name}` load a segment as a named graph named by
//! its own IRI. Cross-segment analysis is then two IRIs in a `graph=` list, and
//! nothing in this crate implements it.

#![forbid(unsafe_code)]

pub mod chain;
pub mod config;
pub mod endpoints;
pub mod graph;
mod line;
#[cfg(not(target_family = "wasm"))]
pub mod load;
pub mod segments;
mod vocabulary;
mod writer;

#[cfg(test)]
mod tests;

pub use chain::{
    head_of, split_signature, tagged, verify_chain, verify_segment, Chain, ChainReport, Finding,
    RotationPolicy, SealPolicy, SealSigner, SegmentReport, HASH_ALGORITHM,
};
pub use config::{
    instance_iri, level_iri, ConfigError, Destination, LogConfig, Patch, DEFAULT_INSTANCE_NAME,
    DEFAULT_LEVEL, INSTANCE_NS, STEM,
};
pub use endpoints::{LogHandle, CAP_CONFIG, CAP_READ, CAP_WRITE, CONFIG_IRI, WRITE_IRI};
pub use graph::{
    to_triples, to_turtle, GraphError, Options, LOG_MEDIA_TYPE, SIG_NS, TURTLE_MEDIA_TYPE,
};
pub use line::{
    is_iri, parse_fields, Entry, Header, Line, ParseError, Prev, RenderError, Seal, Timestamp,
    FORMAT_VERSION,
};
#[cfg(not(target_family = "wasm"))]
pub use segments::{
    SegmentEndpoint, SegmentsEndpoint, VerifyEndpoint, SEGMENTS_IRI, SEGMENT_TEMPLATE, VERIFY_IRI,
};
pub use segments::{TransreptEndpoint, TRANSREPT_IRI};
pub use vocabulary::{
    ClassDef, KeyDef, VocabError, Vocabulary, CAPABILITY_DENIED_CLASS, CHAIN_BROKEN_CLASS,
    CONFIG_CHANGE_CLASS, DEFAULT_MIN_LEVEL, ENTRY_CLASS, ERROR_CLASS, LEVEL_CHANGE_CLASS,
    LEVEL_CHANGE_REJECTED_CLASS, LOG_NS, MESSAGE_CLASS, PROCESS_START_CLASS, PROCESS_STOP_CLASS,
    PROV_NS, ROTATION_CLASS, VOCABULARY_TTL, WARNING_CLASS,
};
pub use writer::{Closed, ClosureSink, LineSink, WriteError, Writer, WriterOptions};
#[cfg(not(target_family = "wasm"))]
pub use writer::{FileSink, StderrSink};
