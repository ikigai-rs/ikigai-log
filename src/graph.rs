//! The transreptor: a segment becomes a graph.
//!
//! One function — [`to_turtle`] — turns the bytes of a segment into Turtle, and
//! it is the whole of `text/x-ikigai-log` → `text/turtle`. It runs over piped
//! content (`urn:log:transrept`) and over a segment read off disk
//! (`urn:log:{segment}`) alike, because a segment carries its own `@name`: the
//! blob is self-identifying, so nothing has to tell the transreptor which graph
//! it is producing.
//!
//! ## ★ The segment IS a named graph, and nothing here implements that
//!
//! The graph name comes from **resource identity**, not from the payload. A
//! segment resolves as `text/turtle` at its own IRI, and `urn:sparql:*` already
//! resolves each `graph=` source "through the kernel and loaded as a named graph
//! (named by its URI)". So there is no serialization tension — Turtle is exactly
//! right — and no union machinery to build:
//!
//! ```text
//! urn:sparql:select
//!   query="SELECT ?e WHERE { GRAPH ?g { ?e a log:CapabilityDenied } }"
//!   graph=urn:log:bug:daemon:2026-08-22,urn:log:bug:daemon:2026-08-23
//! ```
//!
//! is cross-segment analysis over shipped machinery. What this module owes that
//! story is one thing: that `urn:log:{name}` resolves to Turtle.
//!
//! `log:segment` still lands on every entry. Not as the mechanism — as
//! insurance: `urn:rdf:union` is triple-only and loses graph names, so a triple
//! flattened into one graph would otherwise lose its attribution, and a query
//! written against a union keeps working when pointed at a single segment.
//!
//! ## The mapping is driven by the vocabulary, not by a `match`
//!
//! Nothing below branches on a term name. [`Vocabulary::key`] binds a bare
//! `key=` column to a property and [`KeyDef::range`](crate::KeyDef::range) types
//! its value; [`Vocabulary::subject_predicate`] refines the subject column per
//! class; [`Vocabulary::is_a`] finds the run boundaries. A module that adds
//! entry types with `rdfs:subClassOf` transrepts correctly with no change here,
//! which is the entire reason the table is data.
//!
//! **A key the table does not claim lands as `log:{key}` with a plain literal
//! and a `log:undeclaredKey` flag.** Never guessed, never dropped: the flag is
//! the hygiene signal, and it only works if nothing papers over it.
//!
//! ## Skolemized, never blank
//!
//! Every node is a stable IRI — `{segment}:{seq}` for an entry,
//! `{segment}:seal:{first}-{last}` for a seal. A blank node in a log is a fact
//! you cannot cite, and a graph full of them is neither diffable nor joinable
//! across segments. [`to_turtle`] cannot emit one: nothing in it constructs a
//! `BlankNode`.
//!
//! ## What this does NOT do
//!
//! **It states what a `#seal` line says; it verifies nothing.** No hash is
//! recomputed and no signature is checked — that is T4, and a transreptor that
//! silently implied verification would be worse than one that ignored seals.
//!
//! ## Cost, measured
//!
//! **O(segment).** Every line is parsed on every read. That is the design's own
//! first stated weakness and it is not hidden here: the hot window is queryable,
//! cold segments are files hydrated on demand.
//!
//! Measured over a 5,001-entry / 590 KB segment (debug build, so read the
//! RATIOS, not the absolute numbers):
//!
//! | read | cost |
//! |---|---|
//! | whole segment, live | 196 ms |
//! | `since=` the last 1% | 1.4 ms |
//! | `from_seq=` the last 1% | 33 ms |
//! | finished segment, served from cache | 40 µs |
//!
//! **The two selectors are not the same price, and the reason is the format.**
//! `since` / `until` compare a line's leading 24 bytes as a STRING — the
//! timestamp column is fixed-width UTC and therefore sorts lexically, which is
//! the same property that makes `grep '^2026-08-23T09:'` a query — so an
//! excluded line is never tokenized. `from_seq` / `to_seq` need the `seq=`
//! column, which means parsing the line to find it. Narrow by time where you
//! can. (A substring hunt for `seq=` would close the gap and is deliberately not
//! done: `msg="seq=5"` would match it, and silently dropping an entry from a
//! query result is precisely the hole this whole design exists to prevent.)

use std::collections::{BTreeMap, BTreeSet};

use oxrdf::{Literal, NamedNode, Term, Triple};
use oxrdfio::{RdfFormat, RdfSerializer};

use crate::line::{Entry, Header, Line, ParseError, Prev, Seal, Timestamp, TIMESTAMP_WIDTH};
use crate::vocabulary::{Vocabulary, LOG_NS, PROCESS_START_CLASS, PROV_NS};

/// The media type of a segment, and the `from` side of the transreption.
///
/// `text/x-*` is the house convention (`text/x-sexpr`, `text/x-rust`). The
/// format already carries its own magic — `# ikigai-log v1` is the first line of
/// every segment — so a sniffer wants that line and not a second signature.
pub const LOG_MEDIA_TYPE: &str = "text/x-ikigai-log";

/// The `to` side.
pub const TURTLE_MEDIA_TYPE: &str = "text/turtle";

/// The signature vocabulary namespace, from `ikigai-sign`. Seals reuse
/// `sig:contentHash` / `sig:value` rather than minting parallel terms — which is
/// what makes ikigai-log the second consumer that crate names as its own
/// promotion trigger.
pub const SIG_NS: &str = "https://ikigai-rs.dev/ns/sign#";

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const XSD_NS: &str = "http://www.w3.org/2001/XMLSchema#";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_DATE_TIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";

const PROV_STARTED_AT_TIME: &str = "http://www.w3.org/ns/prov#startedAtTime";
const PROV_WAS_ASSOCIATED_WITH: &str = "http://www.w3.org/ns/prov#wasAssociatedWith";
const PROV_WAS_ATTRIBUTED_TO: &str = "http://www.w3.org/ns/prov#wasAttributedTo";
const PROV_SOFTWARE_AGENT: &str = "http://www.w3.org/ns/prov#SoftwareAgent";

const LOG_SEGMENT_CLASS: &str = "https://ikigai-rs.dev/ns/log#Segment";
const LOG_INSTANCE_CLASS: &str = "https://ikigai-rs.dev/ns/log#Instance";
const LOG_SEAL_CLASS: &str = "https://ikigai-rs.dev/ns/log#Seal";
const LOG_LEVEL: &str = "https://ikigai-rs.dev/ns/log#level";
const LOG_PREV_SEAL: &str = "https://ikigai-rs.dev/ns/log#prevSeal";
const LOG_SEGMENT: &str = "https://ikigai-rs.dev/ns/log#segment";
const LOG_SUBJECT: &str = "https://ikigai-rs.dev/ns/log#subject";
const LOG_UNDECLARED_KEY: &str = "https://ikigai-rs.dev/ns/log#undeclaredKey";
const LOG_INVOKED: &str = "https://ikigai-rs.dev/ns/log#invoked";
const LOG_FIRST_SEQUENCE: &str = "https://ikigai-rs.dev/ns/log#firstSequence";
const LOG_LAST_SEQUENCE: &str = "https://ikigai-rs.dev/ns/log#lastSequence";

const SIG_CONTENT_HASH: &str = "https://ikigai-rs.dev/ns/sign#contentHash";
const SIG_VALUE: &str = "https://ikigai-rs.dev/ns/sign#value";

/// The `key=` columns whose values are joined into `log:invoked`. Read from the
/// vocabulary by property IRI rather than hard-coded by column name, so a
/// module that rebinds `span`/`parent` to a different column still joins.
const LOG_SPAN: &str = "https://ikigai-rs.dev/ns/log#span";
const LOG_PARENT_SPAN: &str = "https://ikigai-rs.dev/ns/log#parentSpan";

// =====================================================================================
// Errors
// =====================================================================================

/// Why a segment could not be turned into a graph.
#[derive(Debug)]
pub enum GraphError {
    /// A line (or the header) does not parse. The offending line is named, so a
    /// corrupt segment reports where it went wrong rather than "invalid".
    Parse {
        /// The 1-based line number in the segment.
        line: usize,
        /// What was wrong with it.
        error: ParseError,
    },
    /// An IRI the segment supplied is not one oxrdf will accept — a header
    /// `@name`, a subject column, or an entry class. The line grammar's
    /// [`is_iri`](crate::is_iri) is deliberately looser than RDF's, so this is
    /// reachable and says which token failed.
    Iri(String),
    /// Serialization failed. Unreachable writing to a `Vec<u8>`, and reported
    /// rather than unwrapped because a panic in a log reader is worse than a
    /// sentence.
    Serialize(String),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphError::Parse { line, error } => write!(f, "line {line}: {error}"),
            GraphError::Iri(token) => write!(f, "not an RDF IRI: {token}"),
            GraphError::Serialize(message) => write!(f, "serializing the graph: {message}"),
        }
    }
}

impl std::error::Error for GraphError {}

// =====================================================================================
// Options — the range selector
// =====================================================================================

/// Which entries of a segment to include.
///
/// Transreption is O(segment) and a day of `trace` is a large segment, so the
/// narrowing belongs *before* the graph is built rather than in a SPARQL filter
/// over the whole of it. Bounds are **inclusive** on both ends.
///
/// The header always lands, whatever the window: a segment node with no level
/// and no start time would be a graph that cannot say what it is a window into.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Include entries at or after this instant.
    pub since: Option<Timestamp>,
    /// Include entries at or before this instant.
    pub until: Option<Timestamp>,
    /// Include entries with this sequence number or higher.
    pub from_seq: Option<u64>,
    /// Include entries with this sequence number or lower.
    pub to_seq: Option<u64>,
}

impl Options {
    /// The whole segment.
    pub fn all() -> Options {
        Options::default()
    }

    /// Whether the window admits everything.
    pub fn is_all(&self) -> bool {
        *self == Options::default()
    }

    fn admits(&self, entry: &Entry, seq: u64) -> bool {
        self.since.is_none_or(|since| entry.time >= since)
            && self.until.is_none_or(|until| entry.time <= until)
            && self.from_seq.is_none_or(|from| seq >= from)
            && self.to_seq.is_none_or(|to| seq <= to)
    }
}

// =====================================================================================
// The transreption
// =====================================================================================

/// One parsed entry, with the sequence number it will skolemize under.
struct Row {
    seq: u64,
    entry: Entry,
    /// The index of the process run this entry belongs to. Spans restart with
    /// the process, so a span join is scoped between `log:ProcessStart` markers
    /// — that is what those always-land entries are for.
    run: usize,
}

/// Turn a segment into Turtle.
///
/// `vocab` is the term table: the built-in one, or a host's extended graph. The
/// segment's own `@name` header names the graph, so the result is complete
/// without a caller-supplied IRI.
pub fn to_turtle(text: &str, vocab: &Vocabulary, options: &Options) -> Result<String, GraphError> {
    let triples = to_triples(text, vocab, options)?;
    serialize(&triples)
}

/// [`to_turtle`]'s graph, before serialization — for a caller that wants the
/// triples themselves (a test asserting by IRI rather than by string, which is
/// the only honest way to assert about a serialization).
pub fn to_triples(
    text: &str,
    vocab: &Vocabulary,
    options: &Options,
) -> Result<Vec<Triple>, GraphError> {
    let (header, offset) = Header::parse(text).map_err(|error| GraphError::Parse {
        // The header is the block before the first blank line; naming line 1 is
        // as precise as `Header::parse` can be and better than no location.
        line: 1,
        error,
    })?;
    let segment = iri(&header.name)?;
    let instance = iri(&header.instance)?;
    let level = iri(&header.level)?;

    // ── The header → a log:Segment node ────────────────────────────────────
    let mut out = vec![
        triple(&segment, RDF_TYPE, term_iri(LOG_SEGMENT_CLASS)?),
        triple(&segment, LOG_LEVEL, Term::NamedNode(level)),
        triple(
            &segment,
            PROV_STARTED_AT_TIME,
            Term::Literal(date_time(header.started)),
        ),
        triple(
            &segment,
            PROV_WAS_ATTRIBUTED_TO,
            Term::NamedNode(instance.clone()),
        ),
        triple(
            &segment,
            LOG_PREV_SEAL,
            Term::Literal(Literal::new_simple_literal(match &header.prev {
                // Written as the token it is. `genesis` is stated rather than
                // left absent so that a missing @prev is unambiguously an error,
                // and a graph that dropped it would give that distinction away.
                Prev::Genesis => "genesis".to_string(),
                Prev::Seal(hash) => hash.clone(),
            })),
        ),
        // Both types, because a consumer of this graph alone has no reasoner and
        // no copy of the log vocabulary: the subclass axiom lives in
        // vocabulary.ttl, and nothing loaded that here.
        triple(&instance, RDF_TYPE, term_iri(LOG_INSTANCE_CLASS)?),
        triple(&instance, RDF_TYPE, term_iri(PROV_SOFTWARE_AGENT)?),
    ];

    // ── The entries ────────────────────────────────────────────────────────
    let (rows, seals) = scan(text, offset, &header.prefixes, vocab, options)?;

    // Span → entry IRI, per run and per surviving entry, so `log:invoked` is
    // materialized only where BOTH ends are in this graph.
    let mut spans: BTreeMap<(usize, String), NamedNode> = BTreeMap::new();
    let mut edges: Vec<(usize, String, NamedNode)> = Vec::new();

    for row in &rows {
        if !options.admits(&row.entry, row.seq) {
            continue;
        }
        let node = iri(&format!("{}:{}", header.name, row.seq))?;
        let class = iri(&row.entry.class)?;
        let subject = iri(&row.entry.subject)?;
        // Where this entry's triples begin. A set has no duplicates, so neither
        // should the serialization — and two of them arise naturally here: a
        // class whose log:subjectPredicate IS prov:wasAssociatedWith (log:
        // ProcessStart's is) restates the attribution triple, and a repeated
        // `cap=urn:cap:fs cap=urn:cap:fs` is one fact written twice. Emitting
        // them twice would make two runs over one segment differ in bytes while
        // agreeing as graphs, which costs the artifact its diffability for
        // nothing.
        let first = out.len();

        out.push(triple(&node, RDF_TYPE, Term::NamedNode(class)));
        // Convenience, not mechanism — see the module docs.
        out.push(triple(&node, LOG_SEGMENT, Term::NamedNode(segment.clone())));
        out.push(triple(
            &node,
            PROV_STARTED_AT_TIME,
            Term::Literal(date_time(row.entry.time)),
        ));
        // Per-process attribution, materialized from the header — so it costs
        // nothing per line in the file and is still one triple per entry here.
        out.push(triple(
            &node,
            PROV_WAS_ASSOCIATED_WITH,
            Term::NamedNode(instance.clone()),
        ));
        // The subject column emits TWICE: log:subject always, plus the class's
        // declared log:subjectPredicate where there is one. Two triples, both
        // true, no reasoner required — an ad-hoc query asks one question of
        // every entry, a PROV reader still gets the precise reading.
        out.push(triple(&node, LOG_SUBJECT, Term::NamedNode(subject.clone())));
        if let Some(predicate) = vocab.subject_predicate(&row.entry.class) {
            push_unique(
                &mut out,
                first,
                triple(&node, predicate, Term::NamedNode(subject)),
            );
        }

        let mut flagged: BTreeSet<&str> = BTreeSet::new();
        for (key, value) in &row.entry.fields {
            match vocab.key(key) {
                Some(def) => {
                    push_unique(
                        &mut out,
                        first,
                        triple(&node, &def.property, value_term(value, &def.range)),
                    );
                    if def.property == LOG_SPAN {
                        spans.insert((row.run, value.clone()), node.clone());
                    }
                    if def.property == LOG_PARENT_SPAN {
                        edges.push((row.run, value.clone(), node.clone()));
                    }
                }
                None => {
                    // Lossless AND flagged. Never guess a range: the flag is the
                    // design's hygiene signal, counted by the same standing
                    // CONSTRUCT that counts log:Message, and it only works if
                    // nothing papers over it.
                    push_unique(
                        &mut out,
                        first,
                        triple(
                            &node,
                            &format!("{LOG_NS}{key}"),
                            Term::Literal(Literal::new_simple_literal(value)),
                        ),
                    );
                    if flagged.insert(key) {
                        out.push(triple(
                            &node,
                            LOG_UNDECLARED_KEY,
                            Term::Literal(Literal::new_simple_literal(key)),
                        ));
                    }
                }
            }
        }
    }

    // ── log:invoked: parent → child, within one run ────────────────────────
    //
    // Emitted after the entries so that the whole run's spans are known however
    // the lines were ordered — a parent's line is written when it COMPLETES, so
    // its children's lines usually precede it. Where it does not resolve — the
    // parent is in another segment, another run, or outside the window — the
    // `log:parentSpan` literal stays and no edge is invented.
    for (run, parent_span, child) in edges {
        if let Some(parent) = spans.get(&(run, parent_span)) {
            if parent != &child {
                out.push(triple(parent, LOG_INVOKED, Term::NamedNode(child)));
            }
        }
    }

    // ── Seals: STATED, never verified ──────────────────────────────────────
    for seal in seals {
        let node = iri(&format!(
            "{}:seal:{}-{}",
            header.name, seal.first, seal.last
        ))?;
        out.push(triple(&node, RDF_TYPE, term_iri(LOG_SEAL_CLASS)?));
        out.push(triple(&node, LOG_SEGMENT, Term::NamedNode(segment.clone())));
        out.push(triple(
            &node,
            LOG_FIRST_SEQUENCE,
            Term::Literal(Literal::new_typed_literal(
                seal.first.to_string(),
                integer()?,
            )),
        ));
        out.push(triple(
            &node,
            LOG_LAST_SEQUENCE,
            Term::Literal(Literal::new_typed_literal(
                seal.last.to_string(),
                integer()?,
            )),
        ));
        // The tokens exactly as the line wrote them — tagged (`sha256:…`),
        // which is this system's boundary convention for a digest. NOTE for
        // whoever owns the chain: ikigai-sign writes `sig:contentHash` as
        // UNTAGGED hex, so the two producers share a predicate and not a lexical
        // form. Reconciling them is a decision about the seal, and the seal is
        // T4's; restating it differently here would be an interpretation, and
        // T3 states what the line says.
        out.push(triple(
            &node,
            SIG_CONTENT_HASH,
            Term::Literal(Literal::new_simple_literal(&seal.hash)),
        ));
        if let Some(signature) = &seal.signature {
            out.push(triple(
                &node,
                SIG_VALUE,
                Term::Literal(Literal::new_simple_literal(signature)),
            ));
        }
    }

    Ok(out)
}

/// Walk the entry region, numbering entries and splitting them into process
/// runs.
fn scan(
    text: &str,
    offset: usize,
    prefixes: &BTreeMap<String, String>,
    vocab: &Vocabulary,
    options: &Options,
) -> Result<(Vec<Row>, Vec<Seal>), GraphError> {
    let mut rows = Vec::new();
    let mut seals = Vec::new();
    let mut run = 0usize;
    let mut started = false;
    let mut ordinal = 0u64;
    // The header block occupies the bytes before `offset`; count its lines so a
    // parse error names its true position in the file.
    let header_lines = text[..offset].lines().count();

    for (index, raw) in text[offset..].lines().enumerate() {
        let number = header_lines + index + 1;
        // ★ The cheap pre-filter, and it is the same property that makes
        // `grep '^2026-08-23T09:' segment.log` a legitimate query: the timestamp
        // column is fixed-width UTC, so it sorts LEXICALLY. A line outside a time
        // window is skipped before it is tokenized at all, which is what keeps a
        // narrow window over a long segment from costing a whole parse.
        //
        // The ordinal still advances, so an entry's `{segment}:{seq}` is the same
        // IRI whether or not a window was applied — an identity that moved with
        // the query would not be an identity.
        //
        // Safe against the span join because a time window is CONTIGUOUS: a
        // `log:ProcessStart` sitting between two entries that both survive the
        // window survives it too, so no run boundary inside the emitted set is
        // ever skipped.
        if outside_window(raw, options) {
            ordinal += 1;
            continue;
        }
        match Line::parse(raw, prefixes).map_err(|error| GraphError::Parse {
            line: number,
            error,
        })? {
            Line::Entry(entry) => {
                // A run boundary BEFORE the marker is placed, so the marker
                // itself belongs to the run it opens.
                if vocab.is_a(&entry.class, PROCESS_START_CLASS) {
                    if started {
                        run += 1;
                    }
                    started = true;
                }
                ordinal += 1;
                // `seq=` is written on every line by this crate's writer and is
                // what a seal range names. A hand-assembled segment without it
                // still transrepts — the ordinal stands in — because a graph
                // that refused would make the format harder to write by hand
                // than to grep, which is backwards.
                let seq = entry
                    .get("seq")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(ordinal);
                rows.push(Row { seq, entry, run });
            }
            Line::Seal(seal) => seals.push(seal),
            Line::Blank | Line::Comment(_) => {}
            // A directive after the header block. The header ends at the first
            // blank line by definition, so this is a malformed segment.
            Line::Directive { name, .. } => {
                return Err(GraphError::Parse {
                    line: number,
                    error: ParseError::Header(format!("@{name} after the header block")),
                })
            }
        }
    }
    Ok((rows, seals))
}

/// Append `candidate` unless the triples from `first` onward already state it.
///
/// Linear over ONE entry's triples — a handful — rather than over the graph, so
/// it stays cheap on a segment with a hundred thousand of them.
fn push_unique(out: &mut Vec<Triple>, first: usize, candidate: Triple) {
    if !out[first..].contains(&candidate) {
        out.push(candidate);
    }
}

/// Whether a line is an entry outside `options`' time window, judged from its
/// leading timestamp column alone — no tokenizing, no allocation.
///
/// Only entry lines are judged: a `#seal`, a comment or a blank does not start
/// with a digit, and a line too short to carry a timestamp is left for the
/// parser to report properly.
fn outside_window(raw: &str, options: &Options) -> bool {
    if options.since.is_none() && options.until.is_none() {
        return false;
    }
    let Some(column) = raw.get(..TIMESTAMP_WIDTH) else {
        return false;
    };
    if !column.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    options
        .since
        .is_some_and(|since| column < since.render().as_str())
        || options
            .until
            .is_some_and(|until| column > until.render().as_str())
}

/// A `key=` value as the term its declared range says it is.
///
/// **An XSD datatype range makes a typed literal; every other range makes an
/// IRI.** That is one rule rather than a list, and it is what keeps a join
/// working: `configured=urn:ikigai:instance:bug:serve` is declared
/// `rdfs:range log:Instance`, and as a string it would join to nothing.
///
/// The lexical form is NOT validated against the datatype. A malformed integer
/// stays exactly what the line said and becomes an ill-typed literal, which
/// SHACL (T7) reports; silently rewriting it as a string would hide a defect in
/// whatever wrote the line.
fn value_term(value: &str, range: &Option<String>) -> Term {
    match range.as_deref() {
        None | Some(XSD_STRING) => Term::Literal(Literal::new_simple_literal(value)),
        Some(datatype) if datatype.starts_with(XSD_NS) => match NamedNode::new(datatype) {
            Ok(datatype) => Term::Literal(Literal::new_typed_literal(value, datatype)),
            Err(_) => Term::Literal(Literal::new_simple_literal(value)),
        },
        // A class range: the value names something, so it is an IRI. When it is
        // not a usable one the literal survives rather than the triple being
        // dropped — lossless beats tidy, and the range violation is exactly what
        // SHACL is for.
        Some(_) => match NamedNode::new(value) {
            Ok(node) => Term::NamedNode(node),
            Err(_) => Term::Literal(Literal::new_simple_literal(value)),
        },
    }
}

fn date_time(time: Timestamp) -> Literal {
    match NamedNode::new(XSD_DATE_TIME) {
        Ok(datatype) => Literal::new_typed_literal(time.render(), datatype),
        Err(_) => Literal::new_simple_literal(time.render()),
    }
}

fn integer() -> Result<NamedNode, GraphError> {
    NamedNode::new(format!("{XSD_NS}integer")).map_err(|e| GraphError::Iri(e.to_string()))
}

fn iri(token: &str) -> Result<NamedNode, GraphError> {
    NamedNode::new(token).map_err(|_| GraphError::Iri(token.to_string()))
}

fn term_iri(token: &str) -> Result<Term, GraphError> {
    Ok(Term::NamedNode(iri(token)?))
}

/// One triple. The predicate is always a constant from this module or a property
/// the vocabulary supplied, so a malformed one is a bug here and not in the log
/// — hence the fallback to `rdf:type`-shaped failure is not offered: `expect`
/// would panic on a vocabulary defect. Instead an unusable predicate degrades to
/// `log:undeclaredKey`-style loss, which cannot happen for these constants.
fn triple(subject: &NamedNode, predicate: &str, object: Term) -> Triple {
    let predicate = NamedNode::new(predicate).unwrap_or_else(|_| {
        // A property IRI the vocabulary graph accepted but oxrdf will not. It
        // cannot be dropped silently, and it must not panic in a log reader, so
        // it lands under a term that says what happened.
        NamedNode::new(LOG_UNDECLARED_KEY).expect("log:undeclaredKey is a valid IRI")
    });
    Triple::new(subject.clone(), predicate, object)
}

/// Serialize in emission order — which is document order, so the graph reads
/// down the segment and two runs over the same segment are byte-identical.
///
/// Only the prefixes the output uses are bound. `rdf:` and `rdfs:` are not among
/// them: `a` is the only rdf: term emitted and Turtle spells it `a`, and an
/// unused `@prefix` line is noise in an artifact whose value is being diffable.
fn serialize(triples: &[Triple]) -> Result<String, GraphError> {
    let mut serializer = RdfSerializer::from_format(RdfFormat::Turtle)
        .with_prefix("log", LOG_NS)
        .and_then(|s| s.with_prefix("prov", PROV_NS))
        .and_then(|s| s.with_prefix("sig", SIG_NS))
        .and_then(|s| s.with_prefix("xsd", XSD_NS))
        .map_err(|e| GraphError::Serialize(e.to_string()))?
        .for_writer(Vec::new());
    for triple in triples {
        serializer
            .serialize_triple(triple)
            .map_err(|e| GraphError::Serialize(e.to_string()))?;
    }
    let bytes = serializer
        .finish()
        .map_err(|e| GraphError::Serialize(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| GraphError::Serialize(e.to_string()))
}
