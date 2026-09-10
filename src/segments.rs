//! The addressable space: `urn:log:transrept`, `urn:log:{segment}`, and
//! `urn:log:segments`.
//!
//! ## `urn:log:{segment}` is a PREFIX binding, and that has a consequence
//!
//! The tail names a segment and `as=` selects the face, so the grammar is a
//! [`ikigai_core::UriTemplate`] rather than an [`ikigai_core::Exact`]. A template matches **everything**
//! under `urn:log:`, `urn:log:write` included — so the exact bindings must be
//! registered FIRST and the template LAST. [`crate::endpoints::space`] does
//! that. `urn:log:verify` is the case that proves it: bound below the template
//! it resolves as a segment named `verify`, and the failure is `no segment
//! <urn:log:verify>` rather than an unbound IRI — so nothing about the error
//! says the binding order is what went wrong.
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
//! * a segment whose last entry is `log:ProcessStop` **or `log:Rotation`** is
//!   **finished** — nothing will ever append to it — so it is `.cacheable()`,
//!   under a golden thread on its file. ★ Both markers, and the second one is
//!   the one that pays: a daemon writes one stop marker in its life and a
//!   rotation every day, so a verifier that knew only about `ProcessStop` would
//!   treat every rotated segment — the common case for analysis — as a live tail
//!   forever, at the full 4,900× below, and no test would fail;
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
use crate::vocabulary::{PROCESS_STOP_CLASS, ROTATION_CLASS};

/// The transreptor: `text/x-ikigai-log` → `text/turtle`.
pub const TRANSREPT_IRI: &str = "urn:log:transrept";

#[cfg(not(target_family = "wasm"))]
/// The segments this process can see.
pub const SEGMENTS_IRI: &str = "urn:log:segments";

#[cfg(not(target_family = "wasm"))]
/// The chain walk. **Bound ABOVE [`SEGMENT_TEMPLATE`]** — below it this resolves
/// as a segment named `verify` and the failure is `no segment <urn:log:verify>`,
/// which says nothing about binding order.
pub const VERIFY_IRI: &str = "urn:log:verify";

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
const RDFS_RESOURCE: &str = "http://www.w3.org/2000/01/rdf-schema#Resource";
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
        if inv.request.verb == Verb::Exists {
            return self.exists(inv);
        }
        if inv.request.verb != Verb::Source {
            return Err(Error::Endpoint(format!(
                "a segment is a Source or an Exists; it does not answer {:?}",
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
                 last entry is log:ProcessStop or log:Rotation — a rotated segment is as \
                 immutable as a stopped one, and it is the common case) is cacheable under a \
                 golden thread on its file; a live one is not, and no watcher pretends \
                 otherwise. Transreption is \
                 O(segment) — narrow it with since/until/from_seq/to_seq rather than \
                 filtering a year of entries in SPARQL.",
            )
            .verb(Verb::Source)
            .verb(Verb::Exists)
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Exists)
                    .summary("whether a segment with this IRI is here")
                    .requires(CAP_READ)
                    .input(segment_binding())
                    .output(TEXT_PLAIN),
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("the segment, as a graph or as itself")
                    .requires(CAP_READ)
                    .input(segment_binding())
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

/// The `{segment}` variable of [`SEGMENT_TEMPLATE`], as the binding input every
/// action declares. Declared on the action rather than assumed from the grammar
/// because the manifold forms a target IRI from the CONTRACT: an action whose
/// template variable is not an input cannot be driven from `urn:kernel:actions`
/// at all, however well the endpoint itself reads `inv.bindings`.
#[cfg(not(target_family = "wasm"))]
fn segment_binding() -> ArgSpec {
    ArgSpec::new(SEGMENT_BINDING)
        .summary(
            "the segment's name, the tail of its IRI: `{instance}:{stamp}`, as \
             `urn:log:segments` lists it",
        )
        .class(XSD_STRING)
        .binding()
}

#[cfg(not(target_family = "wasm"))]
impl SegmentEndpoint {
    /// `Exists`: is there a segment here, without paying to read one?
    ///
    /// Answering a chain walk's actual question. `@prev` and `next=` name
    /// segments, and following either wants "is it still here" — which under
    /// retention is a different answer from "does it verify", and O(header)
    /// rather than O(segment).
    fn exists(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_READ) {
            return Err(Error::Denied(format!(
                "asking after a log segment requires `{CAP_READ}`"
            )));
        }
        let iri = inv.request.target.as_str().to_string();
        let Some(tail) = inv.bindings.get(SEGMENT_BINDING) else {
            return Err(Error::Endpoint("no segment named".to_string()));
        };
        let directory = self.directory()?;
        let found = locate(&directory, tail, &iri);
        // Uncacheable for the reason the listing is: the directory changes under
        // rotation and retention, and nothing cuts a thread on a directory — but
        // a found segment still declares its file's thread, so a reader that
        // caches downstream of this is not caching a stale "yes".
        let repr = plain(if found.is_some() { "true" } else { "false" });
        Ok(match found {
            Some(path) => repr.depends_on(format!("urn:file:{}", path.display())),
            None => repr,
        })
    }

    fn directory(&self) -> Result<PathBuf> {
        crate::writer::resolve_directory(&self.handle.config())
            .ok_or_else(|| Error::Endpoint(crate::writer::WriteError::NoDirectory.to_string()))
    }

    /// Whether nothing will ever be appended to this segment again.
    ///
    /// Two questions, and the cheap definitive one first: this process's own
    /// open segment is live by construction, whatever its bytes currently say.
    /// Otherwise the segment's own always-land END marker decides — a segment
    /// that ends without one ended because the process died, and a dead
    /// process's segment is indistinguishable from a running one's, so it stays
    /// live and uncached rather than being guessed finished.
    ///
    /// ★ **There are TWO end markers, and forgetting the second one is the
    /// expensive mistake.** `log:ProcessStop` ends a segment because the process
    /// stopped; `log:Rotation` ends it because the segment rolled over — and the
    /// rotated segment is the COMMON case for analysis, since a long-running
    /// daemon writes one stop marker in its life and a rotation every day. Keying
    /// this on the stop marker alone leaves every rotated segment permanently
    /// uncacheable, at **196 ms live versus 40 µs cached — ~4,900× — on every
    /// read**, with no test failing either way, because expiry is not a property
    /// any assertion about the graph can see.
    fn is_finished(&self, iri: &str, text: &str) -> bool {
        if self
            .handle
            .open_segment()
            .is_some_and(|(open, _)| open == iri)
        {
            return false;
        }
        ends_finally(text, &self.vocabulary)
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
/// Whether the last entry in `text` ends the segment for good — a
/// `log:ProcessStop` or a `log:Rotation`.
///
/// Reads the classes, not the bytes: a module's own stop or rotation subclass
/// counts, because `log:ProcessStop` means "this process ended in an orderly
/// way" and `log:Rotation` means "this segment rolled over", and a subclass of
/// either means the same thing more precisely.
///
/// The LAST entry, not "contains one": a rotation marker is followed by a
/// `#seal` line and nothing else, and a stop marker likewise, so a segment whose
/// last entry is anything else still has a live tail.
fn ends_finally(text: &str, vocabulary: &Vocabulary) -> bool {
    let Ok((header, offset)) = Header::parse(text) else {
        return false;
    };
    let mut last = None;
    for raw in text[offset..].lines() {
        if let Ok(Line::Entry(entry)) = Line::parse(raw, &header.prefixes) {
            last = Some(entry.class);
        }
    }
    last.is_some_and(|class| {
        vocabulary.is_a(&class, PROCESS_STOP_CLASS) || vocabulary.is_a(&class, ROTATION_CLASS)
    })
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
/// The newest segment file written by `instance` in `directory`, if any.
///
/// "Newest" is the largest `@name` — the segment IRI ends in a fixed-width UTC
/// stamp, so IRI order IS chronological order within an instance. Read from each
/// file's own header rather than from its name, so a renamed file is still found
/// by what it says it is.
pub(crate) fn newest_for_instance(directory: &Path, instance: &str) -> Option<PathBuf> {
    let mut found: Vec<(String, PathBuf)> = std::fs::read_dir(directory)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == SEGMENT_EXTENSION))
        .filter_map(|path| header_of(&path).map(|header| (header, path)))
        .filter(|(header, _)| header.instance == instance)
        .map(|(header, path)| (header.name, path))
        .collect();
    found.sort();
    found.pop().map(|(_, path)| path)
}

#[cfg(not(target_family = "wasm"))]
/// The segment this instance wrote immediately BEFORE `segment` — the largest
/// `@name` strictly less than it.
///
/// What a rotation checks its newly sealed segment against. The link only means
/// something against the segment it actually claims to follow, and the newest
/// file is the one just sealed.
pub(crate) fn predecessor_of(
    directory: &Path,
    instance: &str,
    segment: &str,
) -> Option<(String, PathBuf)> {
    let mut found: Vec<(String, PathBuf)> = std::fs::read_dir(directory)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == SEGMENT_EXTENSION))
        .filter_map(|path| header_of(&path).map(|header| (header, path)))
        .filter(|(header, _)| header.instance == instance && header.name.as_str() < segment)
        .map(|(header, path)| (header.name, path))
        .collect();
    found.sort();
    found.pop()
}

#[cfg(not(target_family = "wasm"))]
/// A segment's `@name`, read from the head of the file.
fn header_name(path: &Path) -> Option<String> {
    header_of(path).map(|header| header.name)
}

#[cfg(not(target_family = "wasm"))]
/// A segment's header, read from the head of the file.
fn header_of(path: &Path) -> Option<Header> {
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
    Header::parse(&owned).ok().map(|(header, _)| header)
}

// =====================================================================================
// urn:log:verify — the chain, walked
// =====================================================================================

#[cfg(not(target_family = "wasm"))]
/// The verifier: walk the chain and say what it found.
pub struct VerifyEndpoint {
    handle: Arc<LogHandle>,
    vocabulary: Arc<Vocabulary>,
}

#[cfg(not(target_family = "wasm"))]
impl VerifyEndpoint {
    /// A verifier over `handle`'s configured directory.
    pub fn new(handle: Arc<LogHandle>, vocabulary: Arc<Vocabulary>) -> VerifyEndpoint {
        VerifyEndpoint { handle, vocabulary }
    }
}

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl Endpoint for VerifyEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(Error::Endpoint(format!(
                "{VERIFY_IRI} is a Source; it does not answer {:?}",
                inv.request.verb
            )));
        }
        if !inv.capability.allows(CAP_READ) {
            return Err(Error::Denied(format!(
                "verifying the log requires `{CAP_READ}`"
            )));
        }

        // A piped segment is verified in ISOLATION: everything except the
        // rotation link, because a blob arriving over a wire has no predecessor
        // to be checked against. Reported by the absence of a PrevMismatch
        // rather than by asserting a link that was never examined.
        if let Ok(bytes) = inv.inline_arg("content") {
            let text = std::str::from_utf8(bytes).map_err(|e| Error::InvalidArgument {
                name: "content".to_string(),
                detail: format!("a segment is UTF-8 text: {e}"),
            })?;
            let report = crate::chain::verify_segment(text, &self.vocabulary, None);
            return Ok(plain(
                crate::chain::ChainReport {
                    segments: vec![report],
                }
                .render(),
            ));
        }

        let directory = crate::writer::resolve_directory(&self.handle.config())
            .ok_or_else(|| Error::Endpoint(crate::writer::WriteError::NoDirectory.to_string()))?;
        let wanted_segment = match inv.inline_str("segment").map(str::trim) {
            Err(_) | Ok("") => None,
            Ok(iri) => Some(iri.to_string()),
        };
        let wanted_instance = match inv.inline_str("instance").map(str::trim) {
            Err(_) | Ok("") => None,
            Ok(iri) => Some(iri.to_string()),
        };

        let mut body = String::new();
        let mut chains = 0usize;
        for (instance, chain) in chains_in(&directory) {
            if wanted_instance
                .as_ref()
                .is_some_and(|want| want != &instance)
            {
                continue;
            }
            if wanted_segment
                .as_ref()
                .is_some_and(|want| !chain.iter().any(|(name, _)| name == want))
            {
                continue;
            }
            chains += 1;
            body.push_str(&crate::chain::verify_chain(&chain, &self.vocabulary).render());
        }
        if chains == 0 {
            // Named rather than answered with an empty report: "nothing to
            // verify" and "verified nothing, all fine" are opposite facts and a
            // blank body would read as the second.
            return Err(Error::NotFound(format!(
                "no segments to verify in {}",
                directory.display()
            )));
        }
        // NOT cacheable, for the reason the listing is not: the directory changes
        // under rotation, the open segment changes under every write, and nothing
        // cuts a thread on either. A cached verdict is the one kind of stale
        // answer this endpoint must never give.
        Ok(plain(body))
    }

    fn name(&self) -> &str {
        "logVerify"
    }

    fn describe(&self) -> Description {
        Description::new("logVerify")
            .title("Verify the log")
            .summary(
                "Walk the hash chain and report what it finds, one `segment <iri> OK|BROKEN` \
                 line per segment with its findings indented beneath — greppable like \
                 everything else here. Checks FOUR things, not one: that each entry hashes \
                 into the seal that covers it (so tampering localizes to `between seal K and \
                 K+1`); that each segment's @prev names its predecessor's final seal, WHICH \
                 IS WHAT MAKES ROTATION SOMETHING OTHER THAN A SEAM — a forged replacement \
                 segment fails exactly here and nowhere else; that seal coverage and entry \
                 sequences are contiguous, since emission advances the counter only for \
                 entries actually written, so a jump means lines were REMOVED and not \
                 filtered; and that every gap is BRACKETED — two adjacent segments at \
                 different levels need a log:LevelChange, because a chain is tamper-evident \
                 and NOT omission-evident, and a lowered level is sanctioned omission the \
                 chain would otherwise bless as intact. What it does NOT establish: seal \
                 SIGNATURES are stated, not checked (that is `urn:sign:verify` with the \
                 public key — this crate resolves no key), and the level is checked as \
                 RECORDED, not as authentic (a level MAC needs a key the application cannot \
                 hold). An unmarked end or an unsealed tail is reported as `noted`, not \
                 `BROKEN`: a crashed process is not a tamperer, and a verifier that cried \
                 wolf on every daemon restart would be a verifier nobody read. Uncacheable.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("verify the chain")
                    .requires(CAP_READ)
                    .input(
                        ArgSpec::new("segment")
                            .summary(
                                "verify the chain this segment belongs to; omit for every chain \
                                 in the directory",
                            )
                            .class(RDFS_RESOURCE)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("instance")
                            .summary("verify this instance's chain — one chain per instance")
                            .class(RDFS_RESOURCE)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("content")
                            .summary(
                                "a segment's bytes, verified in ISOLATION: everything except \
                                 the @prev link, which needs a predecessor this has none of",
                            )
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .output(TEXT_PLAIN),
            )
    }
}

#[cfg(not(target_family = "wasm"))]
/// Every chain in `directory`, as `(instance IRI, [(segment IRI, bytes)])`,
/// each chain oldest-first.
///
/// **One chain per INSTANCE**, because the instance is the attribution key: a
/// machine's log directory holds as many chains as it has instances, and a
/// disambiguated name is a chain of its own — which is right, since it is a
/// different process that never claimed to continue anyone.
fn chains_in(directory: &Path) -> Vec<(String, Vec<(String, String)>)> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut by_instance: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == SEGMENT_EXTENSION))
        .collect();
    found.sort();
    for path in found {
        let Some(header) = header_of(&path) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        by_instance
            .entry(header.instance)
            .or_default()
            .push((header.name, text));
    }
    for chain in by_instance.values_mut() {
        // The segment IRI ends in a fixed-width UTC stamp, so IRI order IS
        // chronological order within an instance — the same property that makes
        // `grep '^2026-08-23T09:'` a query.
        chain.sort_by(|(a, _), (b, _)| a.cmp(b));
    }
    by_instance.into_iter().collect()
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
