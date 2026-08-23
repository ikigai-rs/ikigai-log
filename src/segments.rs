//! The addressable space: `urn:log:transrept`, `urn:log:{segment}`, and
//! `urn:log:segments`.
//!
//! ## `urn:log:{segment}` is a PREFIX binding, and that has a consequence
//!
//! The tail names a segment and `as=` selects the face, so the grammar is a
//! [`UriTemplate`] rather than an [`Exact`]. A template matches **everything**
//! under `urn:log:`, `urn:log:write` included — so the exact bindings must be
//! registered FIRST and the template LAST. [`crate::endpoints::space`] does
//! that, and a later milestone adding a `urn:log:verify` must add it above the
//! template or it will silently resolve as a segment named `verify`.
//!
//! ## The named-graph story is one sentence long
//!
//! `urn:log:{segment}` resolves to Turtle. That is all of it. `urn:sparql:*`
//! already resolves each `graph=` source through the kernel and loads it as a
//! named graph named by its URI, so a cross-segment query is available the
//! moment this endpoint answers — no N-Quads, no TriG, no union machinery. This
//! is also why **`text/turtle` is the default face** and the raw lines are the
//! opt-in one: `urn:sparql:*` issues a bare `Source` with no `as=`, and a
//! segment that answered it with log lines would not be a graph source.
//!
//! ## ★ Cacheability: two paths, and the live one is honest
//!
//! Effective expiry PROPAGATES from dependencies, so a cached read joined to a
//! live one silently stops being cached — measured at ~2000× on a hot path
//! elsewhere in this system, with every test still passing. There is no test
//! signal for it, so the rule is stated rather than discovered:
//!
//! * a segment whose last entry is `log:ProcessStop` is **finished** — nothing
//!   will ever append to it — so it is `.cacheable()`, under a golden thread on
//!   its file;
//! * anything else is **live** and uncacheable. That includes this process's own
//!   open segment (which we know directly) and a segment whose process died
//!   without an orderly stop (which we cannot distinguish from one still
//!   running, so we do not pretend to).
//!
//! The alternative — caching the live segment behind a watcher that cuts a
//! thread on every append — is a thread cut per entry. That is thrash, not
//! freshness.
//!
//! Note what this buys, and what the wrong call would cost. Measured over a
//! 5,001-entry / 590 KB segment: a live read is **196 ms** and a cached one is
//! **40 µs** — ~4,900×. So joining a live segment into an otherwise-cached
//! analysis is a four-thousand-fold regression that no test reports, which is
//! why the rule above is stated rather than left to be discovered. A rotated
//! segment is the common case for analysis, it is immutable, and it caches; the
//! live tail is the one you were going to `grep` anyway.
//!
//! ## Reading: `std::fs`, with the thread declared explicitly
//!
//! The module recipe says read through the kernel, and this is the one place
//! this crate does not — for the reason [`crate::load`] already gives for the
//! config files. A segment directory is an absolute path outside any host's
//! `urn:file:` jail, so a sub-request would mean either widening what every
//! `urn:file:` in the host can reach or the log being unreadable on hosts that
//! had not. What the kernel actually needs from the read is the golden thread,
//! and that is declared explicitly: `urn:file:{absolute path}`, so a watcher on
//! the log directory invalidates a cached segment graph without this crate
//! reaching through a jail to get it.

#[cfg(not(target_family = "wasm"))]
use std::io::Read;
#[cfg(not(target_family = "wasm"))]
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
#[cfg(not(target_family = "wasm"))]
use ikigai_core::ActionSpec;
use ikigai_core::{
    ArgSpec, Description, Endpoint, Error, Invocation, ReprType, Representation, Result, Verb,
};

#[cfg(not(target_family = "wasm"))]
use crate::endpoints::{LogHandle, CAP_READ};
use crate::graph::{to_turtle, Options, LOG_MEDIA_TYPE, TURTLE_MEDIA_TYPE};
#[cfg(not(target_family = "wasm"))]
use crate::line::{Header, Line, Timestamp};
use crate::vocabulary::Vocabulary;
#[cfg(not(target_family = "wasm"))]
use crate::vocabulary::PROCESS_STOP_CLASS;

/// The transreptor: `text/x-ikigai-log` → `text/turtle`.
pub const TRANSREPT_IRI: &str = "urn:log:transrept";

#[cfg(not(target_family = "wasm"))]
/// The segments this process can see.
pub const SEGMENTS_IRI: &str = "urn:log:segments";

#[cfg(not(target_family = "wasm"))]
/// The segment space. **Must be bound after every exact `urn:log:*` IRI** — see
/// the module docs.
pub const SEGMENT_TEMPLATE: &str = "urn:log:{segment}";

#[cfg(not(target_family = "wasm"))]
/// The binding a matched [`SEGMENT_TEMPLATE`] supplies.
const SEGMENT_BINDING: &str = "segment";

#[cfg(not(target_family = "wasm"))]
/// The suffix a segment file carries.
const SEGMENT_EXTENSION: &str = "log";

/// How much of a segment file the listing reads to find its `@name`. The header
/// is a handful of short lines; reading a day of `trace` to list it would make
/// the listing cost more than the query it exists to set up.
#[cfg(not(target_family = "wasm"))]
const HEADER_PROBE_BYTES: usize = 8 * 1024;

const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
#[cfg(not(target_family = "wasm"))]
const XSD_DATE_TIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";
#[cfg(not(target_family = "wasm"))]
const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
#[cfg(not(target_family = "wasm"))]
const TEXT_PLAIN: &str = "text/plain;charset=utf-8";

#[cfg(not(target_family = "wasm"))]
fn plain(body: impl Into<Vec<u8>>) -> Representation {
    Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        body,
    )
}

// =====================================================================================
// urn:log:transrept — the transreptor
// =====================================================================================

/// The transreptor endpoint: piped segment bytes in, Turtle out.
///
/// Holds a vocabulary because the term table is data — a host that loaded a
/// module's `rdfs:subClassOf` extension transrepts that module's entry classes
/// correctly, and it did not come from an `include_str!`.
pub struct TransreptEndpoint {
    vocabulary: Arc<Vocabulary>,
}

impl TransreptEndpoint {
    /// A transreptor reading `vocabulary` as its term table.
    pub fn new(vocabulary: Arc<Vocabulary>) -> TransreptEndpoint {
        TransreptEndpoint { vocabulary }
    }
}

#[async_trait]
impl Endpoint for TransreptEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(Error::Endpoint(format!(
                "{TRANSREPT_IRI} is a Source; it does not answer {:?}",
                inv.request.verb
            )));
        }
        // `as` is honored rather than ignored: the kernel's transreption plan
        // sets it on every step, and an endpoint that accepted `as=text/html`
        // and returned Turtle would make the plan silently wrong.
        match inv.inline_str("as").map(str::trim) {
            Err(_) | Ok("") => {}
            Ok(t) if t == TURTLE_MEDIA_TYPE => {}
            Ok(other) => {
                return Err(Error::InvalidArgument {
                    name: "as".to_string(),
                    detail: format!("this transreptor produces {TURTLE_MEDIA_TYPE}, not {other:?}"),
                })
            }
        }
        let bytes = inv.inline_arg("content").map_err(|_| {
            Error::MissingArgument("content: pipe a segment in (text/x-ikigai-log)".to_string())
        })?;
        let text = std::str::from_utf8(bytes).map_err(|e| Error::InvalidArgument {
            name: "content".to_string(),
            detail: format!("a segment is UTF-8 text: {e}"),
        })?;
        let turtle = to_turtle(text, &self.vocabulary, &Options::all())
            .map_err(|e| Error::Endpoint(e.to_string()))?;
        // A pure function of its input, so cacheable — and the transreptor is
        // the expensive half of a segment read, which is exactly what caching
        // is for. Whether the RESULT may be cached is then decided by the
        // caller's own dependency: expiry propagates, so a live segment piped
        // through here still yields an uncacheable read at the segment.
        Ok(turtle_repr(turtle).cacheable())
    }

    fn name(&self) -> &str {
        "logTransrept"
    }

    fn describe(&self) -> Description {
        Description::new("logTransrept")
            .title("Segment → graph")
            .summary(
                "Transrept a log segment (text/x-ikigai-log — the `# ikigai-log v1` line \
                 opens every one) into PROV-O-aligned Turtle. The segment names its own \
                 graph through its `@name` header, so a piped blob is self-identifying. \
                 Every key becomes the property the vocabulary binds it to, typed by that \
                 property's rdfs:range; a key no property claims lands as log:{key} with a \
                 plain literal and a log:undeclaredKey flag. Seals are STATED, never \
                 verified. O(segment): every line is parsed on every read.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .transreptor([LOG_MEDIA_TYPE], [TURTLE_MEDIA_TYPE])
            .input(
                ArgSpec::new("content")
                    .summary("the segment's bytes")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("as")
                    .summary("the output type")
                    .class(XSD_STRING)
                    .one_of([TURTLE_MEDIA_TYPE])
                    .default_value(TURTLE_MEDIA_TYPE),
            )
            .output(TURTLE_MEDIA_TYPE)
    }
}

fn turtle_repr(turtle: String) -> Representation {
    Representation::new(
        ReprType::new(TURTLE_MEDIA_TYPE).with_param("charset", "utf-8"),
        turtle.into_bytes(),
    )
}

// =====================================================================================
// urn:log:{segment} — one segment, as a graph or as itself
// =====================================================================================

#[cfg(not(target_family = "wasm"))]
/// One segment, resolved by its own IRI.
pub struct SegmentEndpoint {
    handle: Arc<LogHandle>,
    vocabulary: Arc<Vocabulary>,
}

#[cfg(not(target_family = "wasm"))]
impl SegmentEndpoint {
    /// A segment reader over `handle`'s configured directory.
    pub fn new(handle: Arc<LogHandle>, vocabulary: Arc<Vocabulary>) -> SegmentEndpoint {
        SegmentEndpoint { handle, vocabulary }
    }
}

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl Endpoint for SegmentEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(Error::Endpoint(format!(
                "a segment is a Source; it does not answer {:?}",
                inv.request.verb
            )));
        }
        // The content of a segment is at least as sensitive as the log's
        // whereabouts, so it sits behind the same capability. NOTE: one cap
        // currently covers both, and a segment's entries are the more sensitive
        // half — the capability-projected read faces are T11, and this is the
        // coarse gate they will refine.
        if !inv.capability.allows(CAP_READ) {
            return Err(Error::Denied(format!(
                "reading a log segment requires `{CAP_READ}`"
            )));
        }
        let tail = inv
            .bindings
            .get(SEGMENT_BINDING)
            .ok_or_else(|| Error::Endpoint("no segment named".to_string()))?;
        let iri = inv.request.target.as_str().to_string();
        let options = window(inv)?;

        let directory = self.directory()?;
        let path = locate(&directory, tail, &iri).ok_or_else(|| {
            Error::NotFound(format!("no segment <{iri}> in {}", directory.display()))
        })?;
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error::Endpoint(format!("{}: {e}", path.display())))?;

        // The golden thread is declared rather than acquired: this read did not
        // go through `urn:file:`, but what the kernel needs from it is the
        // dependency, and that is exactly this IRI.
        let thread = format!("urn:file:{}", path.display());
        let finished = self.is_finished(&iri, &text);

        let face = match inv.inline_str("as").map(str::trim) {
            Err(_) | Ok("") => TURTLE_MEDIA_TYPE,
            Ok(t) if t == TURTLE_MEDIA_TYPE => TURTLE_MEDIA_TYPE,
            Ok(t) if t == LOG_MEDIA_TYPE => LOG_MEDIA_TYPE,
            Ok(other) => {
                return Err(Error::InvalidArgument {
                    name: "as".to_string(),
                    detail: format!(
                        "expected one of {TURTLE_MEDIA_TYPE}|{LOG_MEDIA_TYPE}, got {other:?}"
                    ),
                })
            }
        };
        let repr = if face == TURTLE_MEDIA_TYPE {
            turtle_repr(
                to_turtle(&text, &self.vocabulary, &options)
                    .map_err(|e| Error::Endpoint(format!("<{iri}>: {e}")))?,
            )
        } else {
            if !options.is_all() {
                // A window over the raw lines would hand back something that is
                // not a segment — no header, or a header over entries it does
                // not describe — and the format's whole claim is that a file is
                // self-describing. The graph face is where a window belongs.
                return Err(Error::InvalidArgument {
                    name: "since|until|from_seq|to_seq".to_string(),
                    detail: format!(
                        "a window is only offered on the {TURTLE_MEDIA_TYPE} face: a windowed \
                         segment file would no longer be a segment"
                    ),
                });
            }
            Representation::new(
                ReprType::new(LOG_MEDIA_TYPE).with_param("charset", "utf-8"),
                text.into_bytes(),
            )
        };
        let repr = repr.depends_on(thread);
        // See the module docs. A finished segment is immutable; anything else is
        // live, and a cached live tail is a lie about the one thing a reader
        // came for.
        Ok(if finished { repr.cacheable() } else { repr })
    }

    fn name(&self) -> &str {
        "logSegment"
    }

    fn describe(&self) -> Description {
        Description::new("logSegment")
            .title("A log segment")
            .summary(
                "One segment of this process's log, resolved at its own IRI. The DEFAULT face \
                 is text/turtle, so `urn:sparql:* graph=urn:log:{name}` loads it as a named \
                 graph named by that IRI — which is the whole of the named-graph story, and \
                 makes cross-segment analysis a matter of listing two graphs. as=\
                 text/x-ikigai-log serves the segment file itself. A FINISHED segment (its \
                 last entry is log:ProcessStop) is cacheable under a golden thread on its \
                 file; a live one is not, and no watcher pretends otherwise. Transreption is \
                 O(segment) — narrow it with since/until/from_seq/to_seq rather than \
                 filtering a year of entries in SPARQL.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("the segment, as a graph or as itself")
                    .requires(CAP_READ)
                    .input(
                        ArgSpec::new("as")
                            .summary("the face: the graph by default, or the segment file")
                            .class(XSD_STRING)
                            .one_of([TURTLE_MEDIA_TYPE, LOG_MEDIA_TYPE])
                            .default_value(TURTLE_MEDIA_TYPE),
                    )
                    .input(
                        ArgSpec::new("since")
                            .summary(
                                "include entries at or after this instant \
                                 (YYYY-MM-DDTHH:MM:SS.mmmZ); graph face only",
                            )
                            .class(XSD_DATE_TIME)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("until")
                            .summary("include entries at or before this instant; graph face only")
                            .class(XSD_DATE_TIME)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("from_seq")
                            .summary("include entries with this sequence or higher")
                            .class(XSD_INTEGER)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("to_seq")
                            .summary("include entries with this sequence or lower")
                            .class(XSD_INTEGER)
                            .optional(),
                    )
                    .output(TURTLE_MEDIA_TYPE)
                    .output(LOG_MEDIA_TYPE),
            )
    }
}

#[cfg(not(target_family = "wasm"))]
impl SegmentEndpoint {
    fn directory(&self) -> Result<PathBuf> {
        crate::writer::resolve_directory(&self.handle.config())
            .ok_or_else(|| Error::Endpoint(crate::writer::WriteError::NoDirectory.to_string()))
    }

    /// Whether nothing will ever be appended to this segment again.
    ///
    /// Two questions, and the cheap definitive one first: this process's own
    /// open segment is live by construction, whatever its bytes currently say.
    /// Otherwise the segment's own always-land stop marker decides — a segment
    /// that ends without one ended because the process died, and a dead
    /// process's segment is indistinguishable from a running one's, so it stays
    /// live and uncached rather than being guessed finished.
    fn is_finished(&self, iri: &str, text: &str) -> bool {
        if self
            .handle
            .open_segment()
            .is_some_and(|(open, _)| open == iri)
        {
            return false;
        }
        ends_with_stop(text, &self.vocabulary)
    }
}

#[cfg(not(target_family = "wasm"))]
/// The window an invocation asks for.
fn window(inv: &Invocation<'_>) -> Result<Options> {
    let stamp = |name: &str| -> Result<Option<Timestamp>> {
        match inv.inline_str(name).map(str::trim) {
            Err(_) | Ok("") => Ok(None),
            Ok(value) => Timestamp::parse(value)
                .map(Some)
                .map_err(|e| Error::InvalidArgument {
                    name: name.to_string(),
                    detail: e.to_string(),
                }),
        }
    };
    let seq = |name: &str| -> Result<Option<u64>> {
        match inv.inline_str(name).map(str::trim) {
            Err(_) | Ok("") => Ok(None),
            Ok(value) => value
                .parse::<u64>()
                .map(Some)
                .map_err(|_| Error::InvalidArgument {
                    name: name.to_string(),
                    detail: format!("expected a sequence number, got {value:?}"),
                }),
        }
    };
    Ok(Options {
        since: stamp("since")?,
        until: stamp("until")?,
        from_seq: seq("from_seq")?,
        to_seq: seq("to_seq")?,
    })
}

#[cfg(not(target_family = "wasm"))]
/// Whether the last entry in `text` is a `log:ProcessStop`.
///
/// Reads the classes, not the bytes: a module's own stop subclass counts,
/// because `log:ProcessStop`'s meaning is "this process ended in an orderly
/// way" and a subclass means the same thing more precisely.
fn ends_with_stop(text: &str, vocabulary: &Vocabulary) -> bool {
    let Ok((header, offset)) = Header::parse(text) else {
        return false;
    };
    let mut last = None;
    for raw in text[offset..].lines() {
        if let Ok(Line::Entry(entry)) = Line::parse(raw, &header.prefixes) {
            last = Some(entry.class);
        }
    }
    last.is_some_and(|class| vocabulary.is_a(&class, PROCESS_STOP_CLASS))
}

#[cfg(not(target_family = "wasm"))]
/// The file a segment IRI names.
///
/// The fast path derives the name the writer would have used
/// (`{slug(instance)}-{stamp}.log` from a `{instance}:{stamp}` tail). The slow
/// path reads headers, which is what makes a hand-placed or hand-renamed
/// segment still resolvable — the `@name` in the file is the authority, and the
/// filename is a convenience.
fn locate(directory: &Path, tail: &str, iri: &str) -> Option<PathBuf> {
    if let Some((instance, stamp)) = tail.rsplit_once(':') {
        let candidate = directory.join(format!(
            "{}-{stamp}.{SEGMENT_EXTENSION}",
            crate::writer::slug(instance)
        ));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    segment_files(directory)
        .into_iter()
        .find(|(name, _)| name == iri)
        .map(|(_, path)| path)
}

#[cfg(not(target_family = "wasm"))]
/// Every readable segment in `directory`, as `(IRI, path)`, ordered by IRI —
/// which is chronological within an instance, because the stamp sorts lexically.
fn segment_files(directory: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut found: Vec<(String, PathBuf)> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == SEGMENT_EXTENSION))
        .filter_map(|path| header_name(&path).map(|name| (name, path)))
        .collect();
    found.sort();
    found
}

#[cfg(not(target_family = "wasm"))]
/// A segment's `@name`, read from the head of the file.
fn header_name(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buffer = vec![0u8; HEADER_PROBE_BYTES];
    let read = file.read(&mut buffer).ok()?;
    buffer.truncate(read);
    // The header is ASCII; lossy conversion cannot corrupt it, and a truncated
    // multi-byte entry beyond it is irrelevant to `Header::parse`.
    let text = String::from_utf8_lossy(&buffer);
    // A file shorter than the probe has no trailing blank line to end the header
    // on, so give the parser one rather than reporting a missing directive.
    let mut owned = text.into_owned();
    owned.push_str("\n\n");
    Header::parse(&owned).ok().map(|(header, _)| header.name)
}

// =====================================================================================
// urn:log:segments — what there is to query
// =====================================================================================

#[cfg(not(target_family = "wasm"))]
/// The segments in this process's log directory.
pub struct SegmentsEndpoint {
    handle: Arc<LogHandle>,
}

#[cfg(not(target_family = "wasm"))]
impl SegmentsEndpoint {
    /// A listing over `handle`'s configured directory.
    pub fn new(handle: Arc<LogHandle>) -> SegmentsEndpoint {
        SegmentsEndpoint { handle }
    }
}

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl Endpoint for SegmentsEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(Error::Endpoint(format!(
                "{SEGMENTS_IRI} is a Source; it does not answer {:?}",
                inv.request.verb
            )));
        }
        if !inv.capability.allows(CAP_READ) {
            return Err(Error::Denied(format!(
                "listing log segments requires `{CAP_READ}`"
            )));
        }
        let directory = crate::writer::resolve_directory(&self.handle.config())
            .ok_or_else(|| Error::Endpoint(crate::writer::WriteError::NoDirectory.to_string()))?;
        let mut body: String = segment_files(&directory)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>()
            .join("\n");
        if !body.is_empty() {
            // Newline-separated is the map (`..`) convention, and a trailing
            // newline is what makes `urn:log:segments | ..` iterate cleanly.
            body.push('\n');
        }
        // NOT cacheable. The directory's contents change when a segment is
        // rotated in or retired, and nothing cuts a thread on a directory —
        // a cached listing that had gone stale would send a chain walk looking
        // for a segment that is no longer there, or miss the newest one.
        Ok(plain(body))
    }

    fn name(&self) -> &str {
        "logSegments"
    }

    fn describe(&self) -> Description {
        Description::new("logSegments")
            .title("The segments there are")
            .summary(
                "Every segment IRI in this process's log directory, newline-separated and \
                 ordered — which is chronological within an instance, since the stamp sorts \
                 lexically. Read from each file's own `@name` header, so a renamed file is \
                 still found by what it says it is. Feed them to `urn:sparql:* graph=` to \
                 query across segments. Uncacheable: the directory changes under rotation \
                 and no thread is cut on a directory.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("the segment IRIs")
                    .requires(CAP_READ)
                    .output(TEXT_PLAIN),
            )
    }
}
