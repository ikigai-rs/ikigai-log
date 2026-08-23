//! The `urn:log:*` endpoints — and the handle that decides whether this
//! process logs at all.
//!
//! ## Binding is not opening
//!
//! [`space`] binds `urn:log:write` and `urn:log:config` and starts **nothing**.
//! A segment exists only once a host calls [`LogHandle::open`]. That separation
//! is the deliverable: the module cannot judge whether it is inside a daemon or
//! a one-shot `ikigai -c`, and a one-shot that opened a segment would put a
//! process that did nothing into the journal beside the servers. The host
//! decides who logs; this crate makes sure that when several do, their segments
//! neither collide nor interleave.
//!
//! ## Three capabilities, declared AND enforced
//!
//! * [`CAP_WRITE`] — append an entry. Gating a write looks over-careful until
//!   you name the threat: a forged entry. This log is meant to be evidence, and
//!   evidence anyone may append to is not evidence. A denial is itself a
//!   `log:CapabilityDenied` entry, which lands at every level.
//! * [`CAP_READ`] — read the log's own configuration. What it protects is the
//!   *whereabouts* of the log: an attacker who wants to silence one first has to
//!   find it.
//! * [`CAP_CONFIG`] — change that configuration. Strictly the sharper authority:
//!   lowering the level makes a hole, and repointing the destination silences
//!   the log outright.
//!
//! Each is declared on its action AND checked in the endpoint body. The kernel
//! already enforces a declared `requires` **before dispatch** (core 0.1.49
//! onward), so under a kernel the body check is a backstop that never fires;
//! it earns its keep on the paths where no kernel gate ran — a detached
//! invocation, a module shim — and it costs one string comparison.
//!
//! ## ★ A denied action cannot log its own denial
//!
//! `log:CapabilityDenied` is an always-land class precisely because a refused
//! authority is a security fact. But the kernel returns `Denied` *without
//! entering the endpoint*, so `urn:log:write` never runs and never writes the
//! entry — the one action that could record the refusal is the one that was
//! refused. This is not something a module can fix from inside: the kernel
//! would need a seam for reporting a pre-dispatch denial (a reporter alongside
//! `Tracer`, or a `TraceEvent` variant), and that is a core decision.
//!
//! What T2 offers instead is [`LogHandle::record_denial`], so a host that
//! catches an `Error::Denied` — a transport, an MCP projection, the REPL — can
//! land the entry from where it does see the refusal. It is a real hole until
//! the kernel grows the seam, and it is named here rather than papered over.
//!
//! ## Turtle in, SHACL on write
//!
//! Out of scope here (T7). `urn:log:write` takes a class, a subject and
//! `key=value` fields; a caller with a graph does not yet have a door.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(not(target_family = "wasm"))]
use ikigai_core::UriTemplate;
use ikigai_core::{
    ActionSpec, ArgSpec, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation,
    ReprType, Representation, Result, Verb,
};

use crate::config::LogConfig;
#[cfg(not(target_family = "wasm"))]
use crate::config::{level_iri, Destination, Patch};
use crate::line::{parse_fields, Entry, Timestamp};
#[cfg(not(target_family = "wasm"))]
use crate::segments::{SegmentEndpoint, SegmentsEndpoint, SEGMENTS_IRI, SEGMENT_TEMPLATE};
use crate::segments::{TransreptEndpoint, TRANSREPT_IRI};
use crate::vocabulary::{Vocabulary, CAPABILITY_DENIED_CLASS, LOG_NS, MESSAGE_CLASS};
#[cfg(not(target_family = "wasm"))]
use crate::vocabulary::{CONFIG_CHANGE_CLASS, LEVEL_CHANGE_CLASS, LEVEL_CHANGE_REJECTED_CLASS};
use crate::writer::{LineSink, WriteError, Writer};

/// Appending an entry.
pub const CAP_WRITE: &str = "urn:cap:log:write";
/// Reading the log's own state.
pub const CAP_READ: &str = "urn:cap:log:read";
/// Changing the log's configuration.
pub const CAP_CONFIG: &str = "urn:cap:log:config";

/// The append point.
pub const WRITE_IRI: &str = "urn:log:write";
/// The effective configuration.
pub const CONFIG_IRI: &str = "urn:log:config";

const TEXT_PLAIN: &str = "text/plain;charset=utf-8";
#[cfg(not(target_family = "wasm"))]
const TURTLE: &str = "text/turtle";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const RDFS_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const RDFS_RESOURCE: &str = "http://www.w3.org/2000/01/rdf-schema#Resource";

fn plain(body: impl Into<Vec<u8>>) -> Representation {
    Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        body,
    )
}

/// This process's log: its effective configuration, and its segment if one is
/// open.
///
/// Shared by the endpoints and by whatever host code writes entries directly,
/// so there is exactly one segment per process and exactly one answer to "what
/// level are we at".
pub struct LogHandle {
    home: Option<PathBuf>,
    app: Option<String>,
    state: Mutex<State>,
}

struct State {
    config: LogConfig,
    writer: Option<Writer>,
}

impl LogHandle {
    /// A closed handle over `config`, layered from `home` for `app`.
    ///
    /// `home` is the config home this handle reads and writes — passed in
    /// rather than read from the environment, because `$HOME` is process-global
    /// and an endpoint that consulted it ambiently could not be exercised
    /// hermetically. [`ambient`](Self::ambient) is the sugar for a host that
    /// wants the machine's own.
    pub fn new(home: Option<PathBuf>, app: Option<String>, config: LogConfig) -> LogHandle {
        LogHandle {
            home,
            app,
            state: Mutex::new(State {
                config,
                writer: None,
            }),
        }
    }

    /// A closed handle over the machine's own config home, with `base` as the
    /// host's defaults and the layer files folded in.
    #[cfg(not(target_family = "wasm"))]
    pub fn ambient(
        app: Option<String>,
        base: LogConfig,
    ) -> std::result::Result<LogHandle, crate::config::ConfigError> {
        let home = ikigai_core::config::config_home();
        let config = match &home {
            Some(home) => crate::load::complete_in(home, app.as_deref(), base)?,
            None => base,
        };
        Ok(LogHandle::new(home, app, config))
    }

    /// The config home this handle layers within.
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    /// The application whose override layer applies.
    pub fn app(&self) -> Option<&str> {
        self.app.as_deref()
    }

    /// Open this process's segment, per the effective config.
    ///
    /// `Ok(false)` means the configured destination is `off` and nothing was
    /// opened — the quiet default, not a failure.
    #[cfg(not(target_family = "wasm"))]
    pub fn open(
        &self,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
    ) -> std::result::Result<bool, WriteError> {
        let mut state = self.state.lock().expect("log state");
        if state.writer.is_some() {
            return Ok(true);
        }
        state.writer = Writer::open(&state.config, vocabulary, now)?;
        Ok(state.writer.is_some())
    }

    /// Open this process's segment onto a sink the caller supplies — the
    /// browser's `console.log`, or a test's buffer.
    pub fn open_with_sink(
        &self,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        sink: Box<dyn LineSink>,
    ) -> std::result::Result<(), WriteError> {
        let mut state = self.state.lock().expect("log state");
        if state.writer.is_none() {
            state.writer = Some(Writer::open_with_sink(
                &state.config,
                vocabulary,
                now,
                sink,
            )?);
        }
        Ok(())
    }

    /// Write `log:ProcessStop` and close the segment. A no-op when nothing is
    /// open.
    pub fn close(&self, now: Timestamp) -> std::result::Result<(), WriteError> {
        let writer = self.state.lock().expect("log state").writer.take();
        match writer {
            Some(writer) => writer.close(now),
            None => Ok(()),
        }
    }

    /// Whether a segment is being written right now.
    pub fn is_open(&self) -> bool {
        self.state.lock().expect("log state").writer.is_some()
    }

    /// Append one entry. `Ok(None)` when nothing is open or the level dial
    /// excluded the class — the two are distinguished by [`is_open`](Self::is_open).
    pub fn write(&self, entry: Entry) -> std::result::Result<Option<u64>, WriteError> {
        let mut state = self.state.lock().expect("log state");
        match &mut state.writer {
            Some(writer) => writer.write(entry),
            None => Ok(None),
        }
    }

    /// The effective configuration.
    pub fn config(&self) -> LogConfig {
        self.state.lock().expect("log state").config.clone()
    }

    /// Replace the effective configuration. Takes effect for the **next**
    /// segment: the open one keeps the level its header states, for its whole
    /// life.
    pub fn set_config(&self, config: LogConfig) {
        self.state.lock().expect("log state").config = config;
    }

    /// `(segment IRI, effective instance IRI)` when a segment is open.
    pub fn open_segment(&self) -> Option<(String, String)> {
        let state = self.state.lock().expect("log state");
        state
            .writer
            .as_ref()
            .map(|w| (w.segment().to_string(), w.instance().to_string()))
    }

    /// The IRI a written entry will skolemize to: `{segment}:{seq}`.
    fn entry_iri(&self, seq: u64) -> Option<String> {
        let state = self.state.lock().expect("log state");
        state
            .writer
            .as_ref()
            .map(|w| format!("{}:{seq}", w.segment()))
    }

    /// Land a `log:CapabilityDenied` entry: someone was refused `capability`
    /// while attempting `action`.
    ///
    /// **Public because the kernel refuses before the endpoint runs**, so the
    /// action that was denied cannot record its own denial — see the module
    /// docs. A host holding this handle and catching an `Error::Denied` (a
    /// transport, an MCP projection, the REPL) is the only place the fact can
    /// currently be written down.
    ///
    /// Best-effort by nature: a log with no open segment cannot record that
    /// something was refused, and the refusal still has to reach the caller.
    pub fn record_denial(&self, now: Timestamp, capability: &str, action: &str) -> Option<u64> {
        let entry = Entry::new(now, CAPABILITY_DENIED_CLASS, subject_for_denial(self))
            .with("cap", capability)
            .with("reason", action);
        self.write(entry).ok().flatten()
    }

    /// [`record_denial`](Self::record_denial), then the error to return.
    fn deny(&self, now: Option<Timestamp>, capability: &str, action: &str) -> Error {
        if let Some(now) = now {
            self.record_denial(now, capability, action);
        }
        Error::Denied(format!("{action} requires `{capability}`"))
    }
}

/// What a `log:CapabilityDenied` entry is about: the resource the caller was
/// refused, which is the fact worth querying later.
fn subject_for_denial(handle: &LogHandle) -> String {
    handle
        .open_segment()
        .map(|(segment, _)| segment)
        .unwrap_or_else(|| CONFIG_IRI.to_string())
}

/// The kernel's clock, as a log timestamp.
///
/// **No fallback.** An entry stamped from anywhere but the kernel's clock is an
/// entry whose time cannot be reconciled with the resolutions around it, and a
/// caller-supplied timestamp would be a forgery surface on a record whose whole
/// value is that it can be trusted.
fn now(inv: &Invocation<'_>) -> Result<Timestamp> {
    inv.now()
        .map(|t| Timestamp::from_millis(t.as_millis()))
        .ok_or_else(|| {
            Error::Endpoint(
                "the kernel has no clock, so an entry cannot be stamped — inject one with \
             Kernel::with_clock"
                    .to_string(),
            )
        })
}

/// An optional inline argument, absent when empty.
fn opt<'a>(inv: &'a Invocation<'a>, name: &str) -> Option<&'a str> {
    match inv.inline_str(name) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim()),
        _ => None,
    }
}

/// Expand a `log:` CURIE, pass an absolute IRI through.
fn expand(token: &str) -> Option<String> {
    let token = token.trim();
    if let Some(local) = token.strip_prefix("log:") {
        return (!local.is_empty()).then(|| format!("{LOG_NS}{local}"));
    }
    crate::line::is_iri(token).then(|| token.to_string())
}

// =====================================================================================
// urn:log:write
// =====================================================================================

fn write_impl(handle: &Arc<LogHandle>, inv: &Invocation<'_>) -> Result<Representation> {
    if inv.request.verb != Verb::Sink {
        return Err(Error::Endpoint(format!(
            "{WRITE_IRI} is a Sink; it does not answer {:?}",
            inv.request.verb
        )));
    }
    // Authority first, and before any argument is looked at: an unauthorized
    // caller should not learn from the error message whether this kernel has a
    // clock. Under a kernel this never fires — `requires` is enforced before
    // dispatch — but a detached or shimmed invocation reaches it.
    if !inv.capability.allows(CAP_WRITE) {
        let stamp = inv.now().map(|t| Timestamp::from_millis(t.as_millis()));
        return Err(handle.deny(stamp, CAP_WRITE, "appending a log entry"));
    }
    let stamp = now(inv)?;

    // The convenience path: a bare string, which normalizes to log:Message.
    // Deliberate, not a concession — banning prose only drives it into one
    // field of a typed class where it is invisible, whereas its own class makes
    // the unstructured ratio per module one standing CONSTRUCT away.
    let prose = opt(inv, "msg").or_else(|| opt(inv, "content"));
    let class = match opt(inv, "class") {
        Some(token) => expand(token).ok_or_else(|| Error::InvalidArgument {
            name: "class".to_string(),
            detail: format!("expected a log: CURIE or an absolute IRI, got {token:?}"),
        })?,
        None => MESSAGE_CLASS.to_string(),
    };

    let config = handle.config();
    let subject = match opt(inv, "subject") {
        Some(iri) if crate::line::is_iri(iri) => iri.to_string(),
        Some(other) => {
            return Err(Error::InvalidArgument {
                name: "subject".to_string(),
                detail: format!("expected an absolute IRI, got {other:?}"),
            })
        }
        // An entry with no stated subject is about the process that wrote it.
        None => handle
            .open_segment()
            .map(|(_, instance)| instance)
            .unwrap_or(config.instance),
    };

    let mut entry = Entry::new(stamp, &class, subject);
    if let Some(prose) = prose {
        entry = entry.with("msg", prose);
    }
    // One grammar, not two: the `fields` argument is a line's TAIL, scanned by
    // the same code that reads it back out of the file. Quoting, escaping and
    // repeated keys therefore behave identically — not "the same as", the same.
    if let Some(tail) = opt(inv, "fields") {
        for (key, value) in parse_fields(tail).map_err(|e| Error::InvalidArgument {
            name: "fields".to_string(),
            detail: e.to_string(),
        })? {
            entry = entry.with(key, value);
        }
    }

    if !handle.is_open() {
        // Not a hole: a closed log makes no claims, so there is nothing for
        // this entry to be missing FROM. Said plainly rather than silently,
        // because a host that believes it is logging and is not should find out
        // from the first write and not from an empty directory next week.
        return Ok(plain(format!(
            "closed: no segment is open, so {class} was not written"
        )));
    }
    match handle.write(entry).map_err(write_error)? {
        Some(seq) => Ok(plain(
            handle.entry_iri(seq).unwrap_or_else(|| seq.to_string()),
        )),
        None => Ok(plain(format!(
            "filtered: {class} is below this segment's level ({})",
            handle.config().level
        ))),
    }
}

fn write_error(e: WriteError) -> Error {
    Error::Endpoint(e.to_string())
}

/// `urn:log:write` — append one entry to this process's segment.
pub fn write(handle: Arc<LogHandle>) -> FnEndpoint {
    FnEndpoint::new("logWrite", move |inv| write_impl(&handle, inv)).with_description(
        Description::new("logWrite")
            .title("Append a log entry")
            .summary(
                "Append one entry to this process's segment: a class, a subject and key=value \
                 fields, or just a message (which normalizes to log:Message — severity is \
                 carried by SUBCLASS, log:Warning / log:Error, never by a level= column). \
                 Returns the entry's IRI, or says so when the class was below the segment's \
                 level or no segment is open. The segment's level is fixed for its whole life, \
                 so a level change takes effect at the next process start.",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("append one entry")
                    .requires(CAP_WRITE)
                    .input(
                        ArgSpec::new("class")
                            .summary(
                                "the entry class, as a log: CURIE or an absolute IRI — \
                                 log:Message, log:Warning, log:Error, or a module's own \
                                 rdfs:subClassOf extension",
                            )
                            .class(RDFS_CLASS)
                            .default_value("log:Message")
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("subject")
                            .summary(
                                "what the entry is ABOUT, as an absolute IRI; defaults to this \
                                 process's instance",
                            )
                            .class(RDFS_RESOURCE)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("msg")
                            .summary(
                                "prose (log:text); falls back to piped content, so `… | \
                                 urn:log:write` logs a line",
                            )
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("fields")
                            .summary(
                                "the typed columns, in a line's own tail syntax: \
                                 `dur=12 cap=urn:cap:fs msg=\"two words\"`. Same scanner as the \
                                 file, so quoting, escaping and repeated keys behave identically",
                            )
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .output(TEXT_PLAIN),
            ),
    )
}

// =====================================================================================
// urn:log:config
// =====================================================================================

#[cfg(not(target_family = "wasm"))]
fn config_impl(handle: &Arc<LogHandle>, inv: &Invocation<'_>) -> Result<Representation> {
    match inv.request.verb {
        Verb::Source => config_source(handle, inv),
        Verb::Sink => config_sink(handle, inv),
        other => Err(Error::Endpoint(format!(
            "{CONFIG_IRI} answers Source and Sink, not {other:?}"
        ))),
    }
}

#[cfg(not(target_family = "wasm"))]
fn config_source(handle: &Arc<LogHandle>, inv: &Invocation<'_>) -> Result<Representation> {
    if !inv.capability.allows(CAP_READ) {
        let stamp = inv.now().map(|t| Timestamp::from_millis(t.as_millis()));
        return Err(handle.deny(stamp, CAP_READ, "reading the log config"));
    }
    let config = handle.config();
    let open = handle.open_segment();
    let face = match inv.inline_str("as").map(str::trim) {
        Err(_) | Ok("") => TEXT_PLAIN,
        Ok(t) if t == TURTLE => TURTLE,
        Ok(t) if t.starts_with("text/plain") => TEXT_PLAIN,
        Ok(other) => {
            return Err(Error::InvalidArgument {
                name: "as".to_string(),
                detail: format!("expected one of {TEXT_PLAIN}|{TURTLE}, got {other:?}"),
            })
        }
    };
    let body = if face == TURTLE {
        config.to_turtle(
            CONFIG_IRI,
            open.as_ref().map(|(s, i)| (s.as_str(), i.as_str())),
        )
    } else {
        // The four keys first, so the face round-trips as a config file, then
        // the live state as TOML comments — which a parser ignores and a person
        // reads. `destination = "file"` in a process whose host never opened a
        // writer means nothing is being logged, and that is not in the config.
        let mut body = config.to_toml();
        match &open {
            Some((segment, instance)) => {
                body.push_str(&format!("\n# open = true\n# segment = {segment}\n"));
                body.push_str(&format!("# instance = {instance}\n"));
            }
            None => body.push_str("\n# open = false\n"),
        }
        for layer in &config.layers {
            body.push_str(&format!("# layer = {}\n", layer.display()));
        }
        body
    };
    let repr_type = if face == TURTLE {
        ReprType::new("text/turtle").with_param("charset", "utf-8")
    } else {
        ReprType::new("text/plain").with_param("charset", "utf-8")
    };
    // Deliberately NOT cacheable. The config files have golden threads, but
    // whether a segment is open is process state that no thread tracks — and a
    // cached "open = false" outliving the writer's start would be a lie about
    // the one fact a reader came for.
    Ok(Representation::new(repr_type, body.into_bytes()))
}

#[cfg(not(target_family = "wasm"))]
fn config_sink(handle: &Arc<LogHandle>, inv: &Invocation<'_>) -> Result<Representation> {
    if !inv.capability.allows(CAP_CONFIG) {
        let stamp = inv.now().map(|t| Timestamp::from_millis(t.as_millis()));
        return Err(handle.deny(stamp, CAP_CONFIG, "changing the log config"));
    }
    let stamp = now(inv)?;

    let mut change = Patch::default();
    if let Some(level) = opt(inv, "level") {
        if level_iri(level).is_none() {
            // Rejected, and the rejection lands: under any future `locked` mode
            // this entry is the evidence that a change did not take.
            let _ = handle.write(
                Entry::new(stamp, LEVEL_CHANGE_REJECTED_CLASS, CONFIG_IRI)
                    .with("to", level)
                    .with(
                        "reason",
                        "not a level name, a log: CURIE, or an absolute IRI",
                    ),
            );
            return Err(Error::InvalidArgument {
                name: "level".to_string(),
                detail: format!("{level:?} is not a level name, a log: CURIE, or an absolute IRI"),
            });
        }
        change.level = Some(level.to_string());
    }
    if let Some(destination) = opt(inv, "destination") {
        change.destination =
            Some(
                Destination::parse(destination).ok_or_else(|| Error::InvalidArgument {
                    name: "destination".to_string(),
                    detail: format!("expected off|console|file, got {destination:?}"),
                })?,
            );
    }
    if let Some(directory) = opt(inv, "directory") {
        change.directory = Some(directory.to_string());
    }
    if let Some(instance) = opt(inv, "instance") {
        change.instance = Some(instance.to_string());
    }
    if change.is_empty() {
        return Err(Error::MissingArgument(
            "one of level|destination|directory|instance".to_string(),
        ));
    }

    let home = handle
        .home()
        .ok_or_else(|| Error::Endpoint(crate::config::ConfigError::NoConfigHome.to_string()))?;
    let target = crate::load::target_layer(home, handle.app())
        .ok_or_else(|| Error::Endpoint(crate::config::ConfigError::NoConfigHome.to_string()))?;
    crate::load::write_layer(&target, &change).map_err(|e| Error::Endpoint(e.to_string()))?;

    let before = handle.config();
    let mut after = before.clone();
    after.apply(&change);
    handle.set_config(after.clone());

    // Every config write lands an always-land entry, not only a level change:
    // lowering the level makes a hole, but repointing the destination silences
    // the log entirely, so the rule is about config as a whole. One entry per
    // key that actually changed — a write that restates a value is not a change
    // and inventing an entry for it would dilute the ones that are.
    let mut landed = Vec::new();
    let mut record = |class: &str, key: &str, from: String, to: String| {
        let entry = Entry::new(stamp, class, CONFIG_IRI)
            .with("key", key)
            .with("from", from)
            .with("to", to)
            .with("effective", "next-segment")
            .with("file", target.display().to_string());
        if handle.write(entry).is_ok() {
            landed.push(key.to_string());
        }
    };
    if after.level != before.level {
        record(
            LEVEL_CHANGE_CLASS,
            "level",
            before.level.clone(),
            after.level.clone(),
        );
    }
    if after.destination != before.destination {
        record(
            CONFIG_CHANGE_CLASS,
            "destination",
            before.destination.as_str().to_string(),
            after.destination.as_str().to_string(),
        );
    }
    if after.directory != before.directory {
        record(
            CONFIG_CHANGE_CLASS,
            "directory",
            display_dir(&before),
            display_dir(&after),
        );
    }
    if after.instance != before.instance {
        record(
            CONFIG_CHANGE_CLASS,
            "instance",
            before.instance.clone(),
            after.instance.clone(),
        );
    }

    // Said in the response, because it is the part an operator gets wrong: T2
    // has no rotation, and a segment has exactly one level for its whole life,
    // so this is recorded now and effective when the process next starts.
    let mut body = format!("wrote {}\n", target.display());
    body.push_str("effective at next process start (a segment's level is fixed for its life)\n");
    if !landed.is_empty() {
        body.push_str(&format!("recorded: {}\n", landed.join(", ")));
    } else if !handle.is_open() {
        body.push_str("no segment is open, so nothing was recorded in the log\n");
    }
    Ok(plain(body))
}

#[cfg(not(target_family = "wasm"))]
fn display_dir(config: &LogConfig) -> String {
    config
        .directory
        .as_ref()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "(data home)".to_string())
}

/// `urn:log:config` — the effective configuration, and the door to change it.
#[cfg(not(target_family = "wasm"))]
pub fn config(handle: Arc<LogHandle>) -> FnEndpoint {
    FnEndpoint::new("logConfig", move |inv| config_impl(&handle, inv)).with_description(
        Description::new("logConfig")
            .title("The log's effective configuration")
            .summary(
                "The merged log settings for this process — level, destination, directory, \
                 instance — over built-in defaults ⊕ log.toml ⊕ {app}.log.toml, plus whether a \
                 segment is open right now. Source serves the effective config (as=text/turtle \
                 for the graph face); Sink changes it, writes the highest-precedence layer file, \
                 and lands an always-land log:LevelChange or log:ConfigChange. A level change is \
                 RECORDED NOW and EFFECTIVE AT NEXT PROCESS START: a segment has exactly one \
                 level for its whole life, which is what lets a verifier reason per sealed \
                 segment instead of tracking transitions inside sealed content.",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("the effective config, and whether a segment is open")
                    .requires(CAP_READ)
                    .input(
                        ArgSpec::new("as")
                            .summary("the face: TOML by default, or the skolemized graph")
                            .class(XSD_STRING)
                            .one_of([TEXT_PLAIN, TURTLE])
                            .default_value(TEXT_PLAIN),
                    )
                    .output(TEXT_PLAIN)
                    .output(TURTLE),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary(
                        "change the config: writes the layer file and lands an always-land entry",
                    )
                    .requires(CAP_CONFIG)
                    .input(
                        ArgSpec::new("level")
                            .summary(
                                "the new level — a name (info), a log: CURIE, or an absolute IRI",
                            )
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("destination")
                            .summary("where lines go")
                            .class(XSD_STRING)
                            .one_of(["off", "console", "file"])
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("directory")
                            .summary("where segment files land")
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("instance")
                            .summary("the instance name this process is attributed to")
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .output(TEXT_PLAIN),
            ),
    )
}

/// The module's space, over the built-in vocabulary.
///
/// **Binding starts nothing.** The handle decides whether this process logs,
/// and it is closed until a host opens it.
pub fn space(handle: Arc<LogHandle>) -> EndpointSpace {
    space_with_vocabulary(handle, Vocabulary::shared_builtin())
}

/// The module's space, over a vocabulary the host assembled.
///
/// `vocabulary` is the transreptor's term table, and it is a parameter for the
/// reason the table is data at all: a host that has loaded a module's own
/// `rdfs:subClassOf` extension transrepts that module's entry classes correctly,
/// and its graph did not come from an `include_str!`.
///
/// ## ★ The binding order is load-bearing
///
/// `urn:log:{segment}` is a TEMPLATE, and a template over `urn:log:` matches
/// every IRI in this space — `urn:log:write` included. The first grammar that
/// matches wins, so **every exact IRI is bound before it and the template is
/// bound last**. A later milestone adding `urn:log:verify` must add it above the
/// template; below it, the request resolves as a segment named `verify` and the
/// failure is a "no segment" error rather than an unbound IRI.
///
/// On wasm the config, segment and listing endpoints are absent rather than
/// present-and-failing: an action in the manifold that cannot succeed is worse
/// than one that is not offered, because an agent will select it. The
/// transreptor is pure and binds everywhere — a browser host that received a
/// segment over the wire can still turn it into a graph.
#[allow(clippy::let_and_return)] // three bindings are cfg'd out on wasm
pub fn space_with_vocabulary(handle: Arc<LogHandle>, vocabulary: Arc<Vocabulary>) -> EndpointSpace {
    let space = EndpointSpace::new()
        .bind(Exact::new(WRITE_IRI), write(handle.clone()))
        .bind(
            Exact::new(TRANSREPT_IRI),
            TransreptEndpoint::new(vocabulary.clone()),
        );
    #[cfg(not(target_family = "wasm"))]
    let space = space
        .bind(Exact::new(CONFIG_IRI), config(handle.clone()))
        .bind(
            Exact::new(SEGMENTS_IRI),
            SegmentsEndpoint::new(handle.clone()),
        )
        // LAST. See the note above: this template matches every IRI in the space.
        .bind(
            UriTemplate::parse(SEGMENT_TEMPLATE).expect("SEGMENT_TEMPLATE is a valid template"),
            SegmentEndpoint::new(handle, vocabulary),
        );
    space
}
