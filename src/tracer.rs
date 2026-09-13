//! The kernel writes the log: [`ikigai_core::Tracer`] → entries.
//!
//! Everything before this milestone was a log nothing wrote to. [`LogTracer`] is
//! the seam that changes that: a host installs one with
//! [`Kernel::set_tracer`](ikigai_core::Kernel::set_tracer) and every resolution
//! the kernel performs lands as a `log:Resolution` — **trap-free by
//! construction**, because nobody is composing prose. The target is an IRI
//! because a `Request` holds an IRI; the duration is a duration because the
//! kernel subtracted two instants.
//!
//! ## The mapping is nearly one-to-one, which is the point
//!
//! | [`TraceEvent`] | entry |
//! |---|---|
//! | `target` | the subject column → `log:resolved` (`⊂ prov:used`) |
//! | `thread` | `worker=` → `log:worker` — **not** `log:thread`; in ikigai a thread is a GOLDEN thread |
//! | `started` | the leading timestamp → `prov:startedAtTime` |
//! | `ended − started` | `dur=` → `log:durationMs` |
//! | `cache_hit` | **the CLASS**: `log:CacheHit` vs `log:Resolution` |
//! | `span` / `parent` | `span=` / `parent=` → `log:span` / `log:parentSpan` |
//! | `capability` | `cap=` per scope; absent = full authority |
//! | `notes` | `key=value` columns, through the vocabulary's term table |
//! | `notes[DENIED_NOTE]` | **the CLASS**: `log:CapabilityDenied`, plus `denied=` |
//!
//! One column is **not** in that table because no `TraceEvent` carries it:
//! `principal=`, the tenant a per-tenant tracer was built for. The kernel does
//! not know who a host is serving and this crate does not ask it — see
//! [`Principal`].
//!
//! `cache_hit` selects a CLASS and never a boolean column, because a class is
//! what the level dial can exclude: `log:CacheHit` is `rdfs:subClassOf
//! log:Resolution` at `log:minLevel log:trace`, one notch above the resolutions
//! it is otherwise identical to.
//!
//! ## ★ The refusal the log could not previously write
//!
//! The capability floor is enforced **before dispatch**, so the endpoint that
//! would record a refusal is the one being refused — T2 could not close that
//! and shipped [`LogHandle::record_denial`](crate::LogHandle::record_denial) for
//! hosts that catch `Error::Denied`. Core 0.1.62 reports the refusal to the
//! tracer instead ([`ikigai_core::DENIED_NOTE`]), so it lands here with no one
//! catching anything, and `log:CapabilityDenied` is `log:minLevel log:always`
//! because a refused authority is a security fact.
//!
//! A denial names something that never RAN: `started` and `ended` are both
//! `None`. So the entry carries **no `dur=`** — an invented zero would state
//! that a refused request took no time to run, which is a different claim from
//! not having run — and its timestamp is the clock's reading at the refusal.
//!
//! Two facts that must never share a column: `denied=` is the scope the caller
//! **lacked**, `cap=` is the authority it **held**.
//!
//! ## ★★ Installing a tracer costs a `TraceEvent` per resolution, at every level
//!
//! `Kernel::global_scope()` gates only on the atomic `set_tracer` flips. There is
//! **no per-class or per-level filter upstream of `record()`**, so the kernel
//! builds and hands over a fully populated `TraceEvent` — target and thread as
//! `String`s, the capability scopes cloned into a `Vec` — for every resolution
//! the moment a tracer is installed.
//!
//! ⇒ **The level dial filters what is WRITTEN, not what is BUILT.** At
//! `error`, where this tracer writes nothing but denials, the process still pays
//! that allocation per resolution. Anyone reasoning "the log is effectively off,
//! so it is free" is wrong, and the honest lever is `destination = "off"` (or
//! never installing the tracer), not a low level.
//!
//! What this side owes in return is to make its own half cheap, and it does:
//! [`LogHandle::emits`](crate::LogHandle::emits) is asked **before** an [`Entry`]
//! is built, against a rank resolved once at segment open. An excluded class
//! costs one lock and one integer comparison here and allocates nothing.
//!
//! Measured rather than asserted (release build, 50,000 computed resolutions,
//! min of three; `cargo test --release measure_tracer -- --ignored --nocapture`
//! re-derives it):
//!
//! | | ns/resolution |
//! |---|---|
//! | no tracer installed | 566 |
//! | a tracer that DISCARDS every event | 628 — **+11%, and this is the kernel's half** |
//! | `LogTracer` at `error`, writing nothing | 692 — +22% |
//! | `LogTracer` at `debug`, one flushed line | 2,177 — +285% |
//!
//! So "logging is off" costs a fifth of a resolution, and about half of that is
//! not this crate's to give back. If that is too much, the lever is not to
//! install a tracer — or, upstream, an opt-in reporter in the kernel that lets
//! an observer say what it wants before the event is built.
//!
//! ## ★★★ No sampling
//!
//! Rejected in the design, and the reason holds: a sampled log is holes
//! everywhere with no brackets — unexplainable by construction, because a hash
//! chain is tamper-evident and **not** omission-evident, and a sampled hole has
//! no marker bracketing it. The level dial is the honest knob: it excludes whole
//! CLASSES, and the segment header records the level, so an absent
//! `log:Resolution` in a segment that ran at `info` is explained by the record
//! itself. If the volume is still too high, the answer is an opt-in reporter
//! upstream in the kernel — not holes here.
//!
//! ## ★ Recursion would be catastrophic, and is impossible by construction
//!
//! A tracer that wrote by RESOLVING would produce a `TraceEvent` for its own
//! write, which would produce another, forever. Nothing here resolves:
//! [`Writer`](crate::Writer) appends through a [`LineSink`](crate::LineSink) —
//! `std::fs` for a file, `stderr` for a console — and the segment reader that
//! T3 built likewise uses `std::fs` rather than `urn:file:`. The write path
//! never touches a [`Kernel`](ikigai_core::Kernel).
//!
//! That is a property of today's code, not a law, so it is defended twice: a
//! test asserts that one resolution lands exactly one entry, and `record()`
//! holds a per-thread re-entrancy guard. If the write path ever does start
//! resolving, the guard turns an unbounded recursion into a **counted drop** —
//! the failure becomes a `log:Dropped reason=reentrant` line in the chain
//! instead of a dead process.
//!
//! ## ★ A tracer must not break the resolution it observes
//!
//! [`Tracer::record`] returns `()`. A write failure cannot reach the caller by
//! design — which makes it a silent-loss hazard, and silent loss is the thing
//! this crate has spent four milestones removing. So:
//!
//! * **Nothing propagates.** A failed write does not fail the resolution.
//! * **Nothing panics.** `record()` runs inside somebody else's resolution, and
//!   a panic there would take down a request that had nothing to do with
//!   logging. The body runs under [`std::panic::catch_unwind`],
//!   which also covers the seams this crate does not own: a host's
//!   [`ClosureSink`](crate::ClosureSink), or a `Mutex` poisoned by an unrelated
//!   thread.
//! * **Everything lost is counted**, and the count lands as a
//!   `log:Dropped count=N reason=…` entry — always-land, declared for exactly
//!   this. The reason is one of four fixed tokens rather than composed prose;
//!   see [`DROP_REASONS`].
//!
//! ## ★ Per-tenant: attribution, and the one lock everything goes through
//!
//! A daemon logging its own work installs one tracer with `set_tracer` and the
//! instance in the segment header is the whole attribution story. A server
//! handling several principals at once needs a second axis — **who the work was
//! done for**, distinct from **which process did it** — and the kernel already
//! provides the seam: [`Kernel::issue_traced`](ikigai_core::Kernel::issue_traced)
//! takes a tracer per call and gives it its own span-id space, threaded across
//! `fan_out`. What this module adds is the other two halves.
//!
//! **Attribution** is [`Principal`] and the `principal=` column it writes,
//! which transrepts to `log:onBehalfOf` plus a skolemized `prov:Delegation`.
//! The host names the principal; this crate records it and authenticates
//! nothing.
//!
//! **Write concurrency** was already safe and it is worth saying exactly why,
//! because the reason is not "the writer is careful". [`LogHandle`] holds its
//! [`Writer`](crate::Writer) behind one `Mutex` and holds that lock across the
//! whole of an append — sequence number, render, `write_line`, `flush`, chain
//! advance, and any seal the entry triggers. [`Writer`](crate::Writer) is not `Sync` and is
//! reachable no other way, so **an unserialized variant of this crate does not
//! compile**; N tracers through one handle cannot interleave a line, skip a
//! sequence number or fold the chain out of order. Rotation takes the same lock
//! for its whole duration, so no entry can land mid-rotation either — the
//! `log:ChainBroken` that nobody caused is not reachable from this direction.
//!
//! The one thing that WAS racy is now closed: [`LogHandle::write`] releases the
//! lock before rotating (it must — `rotate` takes it), so two threads could both
//! observe the same segment as due and rotate it twice, the second rolling a
//! successor one entry old. The decision is now made under the lock and behind a
//! rotation-in-progress flag. The remaining, deliberate looseness is that a
//! writer entering that window appends to the segment that is about to roll, so
//! a segment can exceed its entry bound by the number of threads that were in
//! flight. Bounded, recorded, and cheaper than holding a lock across a
//! filesystem operation.
//!
//! ## Which processes install it
//!
//! The module ships the knob; the **host** decides the policy — the same answer
//! as [`LogHandle::open`](crate::LogHandle::open), and for the same reason. A
//! space binding does not install a tracer and neither does any `Default`: a
//! one-shot `ikigai -c` must not start tracing.
//!
//! ```no_run
//! use std::sync::Arc;
//! use ikigai_core::{Kernel, SystemClock};
//! use ikigai_log::{LogHandle, LogTracer};
//!
//! # fn wire(kernel: &Kernel, handle: Arc<LogHandle>) {
//! let clock = Arc::new(SystemClock);
//! // The SAME clock the kernel was built with: an entry stamped from a second
//! // clock cannot be reconciled with the resolutions around it.
//! let tracer = Arc::new(LogTracer::new(handle, clock));
//! kernel.set_tracer(tracer);
//! # }
//! ```

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ikigai_core::{Clock, TraceEvent, Tracer, DENIED_NOTE};

use crate::endpoints::LogHandle;
use crate::line::{Entry, Timestamp};
use crate::vocabulary::{
    CACHE_HIT_CLASS, CAPABILITY_DENIED_CLASS, DROPPED_CLASS, PRINCIPAL_KEY, RESOLUTION_CLASS,
};

/// The `reason=` token on each `log:Dropped` entry, one per way this tracer can
/// lose a fact. Fixed tokens, not composed prose: the entries the kernel writes
/// are trap-free precisely because nobody is writing sentences, and the marker
/// for a lost one must hold to the same rule if it is to be queried rather than
/// read.
///
/// * `write-failed` — the sink refused it (a full disk, a closed stream).
/// * `unwritable` — the event could not be rendered as a line at all. In
///   practice a note whose key is not a writable column: a `key=` must start
///   with a letter and hold only alphanumerics, `_`, `.` or `-`, and an
///   endpoint's [`trace_note`](ikigai_core::Invocation::trace_note) is free text.
/// * `reentrant` — `record()` was entered from inside `record()` on one thread.
///   Impossible while the write path uses `std::fs`; see the module docs.
/// * `panicked` — something under `record()` unwound. Caught rather than
///   propagated, because it is not this resolution's fault.
pub const DROP_REASONS: [&str; 4] = ["write-failed", "unwritable", "reentrant", "panicked"];

const DROP_WRITE_FAILED: usize = 0;
const DROP_UNWRITABLE: usize = 1;
const DROP_REENTRANT: usize = 2;
const DROP_PANICKED: usize = 3;

thread_local! {
    /// Set while this thread is inside [`LogTracer::record`]. See the module
    /// docs: the guard exists so that a write path which someday resolves
    /// degrades into a counted drop instead of an unbounded recursion.
    static RECORDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// =====================================================================================
// The principal: attribution that is not the process
// =====================================================================================

/// The longest principal IRI this crate will write.
///
/// A bound rather than a truncation: a principal is caller-supplied in the
/// general case, it lands on **every** entry of a connection, and a log line is
/// the one artifact in this crate that must stay one line and stay greppable.
/// 512 bytes is far past every IRI shape the ecosystem uses (a `urn:*` name, a
/// certificate fingerprint, a DID) and far short of a line that no longer reads
/// as a line, and the refusal names the length so an operator can see what was
/// asked for.
pub const MAX_PRINCIPAL_LEN: usize = 512;

/// The subject of the probe line [`Principal::new`] renders and parses back.
/// Its own IRI, so a principal that swallowed the subject column is caught by
/// the column coming back as something else.
const PROBE_SUBJECT: &str = "urn:ikigai:log:principal-probe";

/// Why an IRI cannot be a [`Principal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalError {
    /// Longer than [`MAX_PRINCIPAL_LEN`].
    TooLong {
        /// How long it was.
        length: usize,
    },
    /// It does not survive a round trip through the line grammar as a **bare**
    /// column: it is not an absolute IRI, or it holds something the scanner
    /// treats as structure, so writing it would need quoting and a quoted
    /// principal is one `grep` cannot find.
    NotAColumn {
        /// What was offered.
        offered: String,
        /// What went wrong, in one clause.
        detail: String,
    },
    /// It is not an IRI RDF will accept, so the graph face would degrade it to
    /// a literal and the delegation could not be stated at all.
    NotAnRdfIri {
        /// What was offered.
        offered: String,
    },
}

impl std::fmt::Display for PrincipalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrincipalError::TooLong { length } => write!(
                f,
                "a principal may be at most {MAX_PRINCIPAL_LEN} bytes and this one is {length}"
            ),
            PrincipalError::NotAColumn { offered, detail } => {
                write!(f, "{offered} cannot be written as a principal: {detail}")
            }
            PrincipalError::NotAnRdfIri { offered } => {
                write!(f, "{offered} is not an IRI RDF will accept")
            }
        }
    }
}

impl std::error::Error for PrincipalError {}

/// Who a [`LogTracer`]'s entries were written **for** — the tenant, the
/// connection's identity, the agent a host is serving. Distinct from the
/// instance, which is the process that did the work; both facts are real and
/// neither replaces the other.
///
/// ## ★ This crate records a principal; it does not authenticate one
///
/// Where the IRI comes from is the **host's** question and deliberately not
/// answered here. A wire server has a certificate fingerprint, a passkey host
/// has a credential id, a peer has a peer name — inventing a fourth identity
/// model inside a logging module would put the least-informed component in
/// charge of the most consequential answer. So the host names the principal and
/// this crate writes down exactly what it was told, which is the only claim the
/// log can honestly make about it.
///
/// ## ★★ And it is caller-supplied data reaching a greppable format
///
/// So the constructor **parses the output rather than filtering the input**: it
/// renders a probe line carrying this value and parses that line back, and
/// accepts the principal only if every column comes back unchanged and the
/// value was written BARE. A principal that would have to be quoted (a space, a
/// tab, a newline, a `"`) is refused rather than escaped — escaping would be
/// lossless and still wrong, because `grep 'principal=urn:agent:x'` is half the
/// reason the format is what it is, and a quoted column is invisible to it.
///
/// The refusal happens **once, when a connection's tracer is built** — not per
/// entry — so a host learns immediately, by `Result`, rather than discovering a
/// silently unattributed log later.
///
/// ```
/// use ikigai_log::Principal;
///
/// assert!(Principal::new("urn:agent:calendar").is_ok());
/// assert!(Principal::new("urn:agent:two words").is_err()); // would be quoted
/// assert!(Principal::new("no-scheme").is_err()); // not an absolute IRI
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Principal(String);

impl Principal {
    /// The principal named by `iri`, or why it cannot be one.
    pub fn new(iri: impl Into<String>) -> Result<Principal, PrincipalError> {
        let iri = iri.into();
        if iri.len() > MAX_PRINCIPAL_LEN {
            return Err(PrincipalError::TooLong { length: iri.len() });
        }
        let refuse = |detail: &str| {
            Err(PrincipalError::NotAColumn {
                offered: iri.clone(),
                detail: detail.to_string(),
            })
        };
        // ★ PARSE THE OUTPUT. Everything below is a statement about a rendered
        // line, not about the characters that went in: the rules for what a
        // column may hold live in `line`, and a second copy of them here would
        // be a second copy to keep in step.
        let prefixes = std::collections::BTreeMap::new();
        let probe = Entry::new(Timestamp::from_millis(0), RESOLUTION_CLASS, PROBE_SUBJECT)
            .with(PRINCIPAL_KEY, iri.clone());
        let line = match probe.render(&prefixes) {
            Ok(line) => line,
            Err(e) => return refuse(&e.to_string()),
        };
        // Bare, not quoted. The one property `render` would happily give up:
        // it escapes rather than refuses, which is right for a message and
        // wrong for an identity that has to be found by `grep`.
        if !line.ends_with(&format!(" {PRINCIPAL_KEY}={iri}")) {
            return refuse(
                "it would have to be quoted, and a quoted principal is one `grep` cannot find",
            );
        }
        let back = match Entry::parse(&line, &prefixes) {
            Ok(entry) => entry,
            Err(e) => return refuse(&e.to_string()),
        };
        if back.subject != PROBE_SUBJECT || back.class != RESOLUTION_CLASS {
            return refuse("it displaces another column");
        }
        if back.get(PRINCIPAL_KEY) != Some(iri.as_str()) || back.fields.len() != 1 {
            return refuse("it does not read back as the value that went in");
        }
        // And an IRI the graph face can state a delegation with. `value_term`
        // degrades an unusable IRI to a literal rather than dropping it, which
        // is the right posture for a segment already on disk and the wrong one
        // for a value this crate is about to write on purpose.
        if oxrdf::NamedNode::new(&iri).is_err() {
            return Err(PrincipalError::NotAnRdfIri { offered: iri });
        }
        Ok(Principal(iri))
    }

    /// The IRI, as it is written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The per-reason loss counters, shared by every tracer derived from one base.
///
/// ★ Shared rather than per-tracer because a per-connection tracer is
/// **short-lived** and the thing it counts is a loss: a tenant tracer that
/// counted its own drops and was then dropped with the connection would carry
/// the only record that something was lost out of the process with it. One
/// ledger per handle means the next entry that lands — from any tracer — marks
/// the loss.
#[derive(Default)]
struct Drops([AtomicU64; DROP_REASONS.len()]);

/// Writes the kernel's [`TraceEvent`]s into this process's log segment.
///
/// Install with [`Kernel::set_tracer`](ikigai_core::Kernel::set_tracer). Holds
/// the same [`LogHandle`] the `urn:log:*` endpoints do, so there is exactly one
/// segment per process however many things write to it, and the same [`Clock`]
/// the kernel holds, so a denial — which the kernel stamps with nothing, having
/// run nothing — is stamped on the same timeline as its neighbours.
///
/// ## ★ One handle, N tracers: the per-tenant shape
///
/// [`on_behalf_of`](Self::on_behalf_of) derives a tracer that attributes its
/// entries to a [`Principal`] and shares this one's handle, clock and drop
/// ledger. That is what a serving host hands to
/// [`Kernel::issue_traced`](ikigai_core::Kernel::issue_traced) per connection —
/// and `issue_traced` is the whole reason the derived tracer is worth having,
/// because a per-call tracer is the only form the kernel isolates: the global
/// slot holds exactly one collector, so N tenants through `set_tracer` is N
/// tenants' events landing in whichever was installed last.
///
/// Derivation is cheap — three `Arc` clones and a `String` — so per connection
/// is the intended granularity, not a cost to design around.
///
/// ```no_run
/// # use std::sync::Arc;
/// # use ikigai_core::{Capability, Kernel, Request, SystemClock};
/// # use ikigai_log::{LogHandle, LogTracer, Principal};
/// # async fn serve(kernel: &Kernel, handle: Arc<LogHandle>, request: Request,
/// #                capability: &Capability, peer: &str)
/// #     -> Result<(), Box<dyn std::error::Error>> {
/// let base = LogTracer::new(handle, Arc::new(SystemClock));
/// // Per connection, once — the refusal for an unwritable principal lands
/// // here rather than silently per entry.
/// let tenant = Arc::new(base.on_behalf_of(Principal::new(peer)?));
/// kernel.issue_traced(request, capability, tenant).await?;
/// # Ok(())
/// # }
/// ```
pub struct LogTracer {
    handle: Arc<LogHandle>,
    clock: Arc<dyn Clock>,
    drops: Arc<Drops>,
    /// Who this tracer's entries were written for. `None` on the process's own
    /// tracer: an entry with no `principal=` is the host's own work, which is a
    /// different fact from work done for an unknown principal and is kept
    /// distinct by writing no column rather than an empty one.
    principal: Option<Principal>,
}

impl LogTracer {
    /// A tracer writing into `handle`, stamping from `clock`, attributing to
    /// the process alone.
    ///
    /// `clock` must be the kernel's own. The kernel already stamps `started` on
    /// everything it ran; this is consulted only where the kernel had nothing to
    /// stamp with — a pre-dispatch denial, or a kernel built without a clock.
    pub fn new(handle: Arc<LogHandle>, clock: Arc<dyn Clock>) -> LogTracer {
        LogTracer {
            handle,
            clock,
            drops: Arc::new(Drops::default()),
            principal: None,
        }
    }

    /// A tracer that writes the same segment as this one and attributes every
    /// entry it records to `principal`.
    ///
    /// Hand it to [`Kernel::issue_traced`](ikigai_core::Kernel::issue_traced),
    /// never to `set_tracer`: the global slot is single-tenant by construction
    /// and installing a second tracer there replaces the first.
    ///
    /// The handle, the clock and the drop ledger are shared. **The drop ledger
    /// especially**: it is per HANDLE rather than per tracer, so a loss counted
    /// by a connection that has since gone away is still marked by the next
    /// entry that lands, from whichever tracer lands it. A per-connection ledger
    /// would carry the only record that something was lost out of the process
    /// with the connection.
    pub fn on_behalf_of(&self, principal: Principal) -> LogTracer {
        LogTracer {
            handle: Arc::clone(&self.handle),
            clock: Arc::clone(&self.clock),
            drops: Arc::clone(&self.drops),
            principal: Some(principal),
        }
    }

    /// Who this tracer attributes its entries to, if anyone.
    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
    }

    /// The handle this tracer writes through.
    pub fn handle(&self) -> &Arc<LogHandle> {
        &self.handle
    }

    /// How many facts have been lost and not yet marked in the chain, per
    /// [`DROP_REASONS`].
    ///
    /// Non-zero only between a loss and the next entry that lands — the marker
    /// is written on the next successful pass — or permanently, if the log
    /// stopped being writable at all. A host that wants the number without
    /// waiting reads it here.
    /// Shared with every tracer derived from the same base, so the number a
    /// host reads is the process's loss and not one connection's.
    pub fn pending_drops(&self) -> [u64; DROP_REASONS.len()] {
        std::array::from_fn(|i| self.drops.0[i].load(Ordering::Relaxed))
    }

    /// Land the pending `log:Dropped` markers now, without waiting for the next
    /// entry — what a host calls before [`LogHandle::close`](crate::LogHandle::close),
    /// so an orderly shutdown does not carry an unreported loss out of the
    /// process.
    ///
    /// Returns how many markers were written.
    ///
    /// A marker carries **no `principal=`**, whichever tracer flushes it: the
    /// ledger is shared across a handle, so attributing the count to whichever
    /// tenant's entry happened to land next would be a fact this crate does not
    /// have. A drop is the process's.
    pub fn flush_drops(&self, now: Timestamp) -> usize {
        let Some((segment, _)) = self.handle.open_segment() else {
            // Nothing is open, so nothing can be marked. The counts stay,
            // because the alternative is discarding the only record that
            // something was lost.
            return 0;
        };
        let mut written = 0;
        for (index, reason) in DROP_REASONS.iter().enumerate() {
            let count = self.drops.0[index].swap(0, Ordering::Relaxed);
            if count == 0 {
                continue;
            }
            let entry = Entry::new(now, DROPPED_CLASS, segment.clone())
                .with("count", count.to_string())
                .with("reason", *reason);
            match self.handle.write(entry) {
                Ok(_) => written += 1,
                // The marker itself could not land. Put the count back rather
                // than losing the fact that something was lost — a drop with no
                // marker is the one thing this design forbids outright.
                Err(_) => {
                    self.drops.0[index].fetch_add(count, Ordering::Relaxed);
                }
            }
        }
        written
    }

    fn drop_one(&self, index: usize) {
        self.drops.0[index].fetch_add(1, Ordering::Relaxed);
    }

    fn any_pending(&self) -> bool {
        self.drops
            .0
            .iter()
            .any(|count| count.load(Ordering::Relaxed) != 0)
    }

    /// The body of [`Tracer::record`], minus the guards around it.
    fn record_inner(&self, event: TraceEvent) {
        let now = Timestamp::from_millis(self.clock.now().as_millis());
        // Markers first, and only when there is something to mark — an
        // unconditional call would take the state lock on every resolution for
        // an answer that is almost always "nothing".
        if self.any_pending() {
            self.flush_drops(now);
        }
        let class = class_for(&event);
        // ★ The filter, BEFORE the allocation. See the module docs: the kernel
        // has already paid for the event, and this is the one cost this side
        // controls.
        if !self.handle.emits(class) {
            return;
        }
        match self.handle.write(entry_for_principal(
            &event,
            class,
            now,
            self.principal.as_ref(),
        )) {
            Ok(_) => {}
            Err(crate::WriteError::Render(_)) => self.drop_one(DROP_UNWRITABLE),
            Err(_) => self.drop_one(DROP_WRITE_FAILED),
        }
    }
}

impl Tracer for LogTracer {
    fn record(&self, event: TraceEvent) {
        if RECORDING.with(|flag| flag.replace(true)) {
            // Already inside `record` on this thread: the write path resolved.
            // Count it and unwind one level rather than recursing — and do NOT
            // clear the flag, which belongs to the frame that set it.
            self.drop_one(DROP_REENTRANT);
            return;
        }
        // `AssertUnwindSafe` because the shared state a panic could leave
        // inconsistent is a `Mutex` that already poisons on its own, and a
        // poisoned handle is exactly what the next `catch_unwind` catches.
        let outcome = catch_unwind(AssertUnwindSafe(|| self.record_inner(event)));
        RECORDING.with(|flag| flag.set(false));
        if outcome.is_err() {
            self.drop_one(DROP_PANICKED);
        }
    }
}

/// The entry class one [`TraceEvent`] is.
///
/// Order matters: a refusal is a refusal whatever else the event says. The
/// kernel sets `cache_hit` to `false` on a denial, so the two cannot collide
/// today — but reading the note first states the priority rather than relying on
/// a field of an event that never ran.
pub fn class_for(event: &TraceEvent) -> &'static str {
    if event.notes.iter().any(|(key, _)| key == DENIED_NOTE) {
        CAPABILITY_DENIED_CLASS
    } else if event.cache_hit {
        CACHE_HIT_CLASS
    } else {
        RESOLUTION_CLASS
    }
}

/// One [`TraceEvent`] as the [`Entry`] it becomes — the whole mapping, in one
/// place and callable, so what the tracer writes can be asserted without a
/// kernel in the way.
///
/// `now` is the fallback stamp, used only when the event carries no `started`
/// of its own: a pre-dispatch denial, or a kernel built without a clock.
///
/// Attributes to the process alone;
/// [`entry_for_principal`] is the per-tenant form.
pub fn entry_for(event: &TraceEvent, class: &str, now: Timestamp) -> Entry {
    entry_for_principal(event, class, now, None)
}

/// [`entry_for`], attributing the entry to `principal` as well as to the
/// process that wrote it.
///
/// The column goes **first**, before `worker=`: an attribution is what a reader
/// scanning a mixed segment is separating lines by, and the eye wants it in the
/// same place on every line that has one. An entry with no principal writes no
/// column at all — the host's own work is not work done for an unknown
/// principal, and an empty column would conflate them.
pub fn entry_for_principal(
    event: &TraceEvent,
    class: &str,
    now: Timestamp,
    principal: Option<&Principal>,
) -> Entry {
    let started = event
        .started
        .map(|time| Timestamp::from_millis(time.as_millis()));
    let mut entry = Entry::new(started.unwrap_or(now), class, event.target.clone());
    if let Some(principal) = principal {
        entry = entry.with(PRINCIPAL_KEY, principal.as_str());
    }
    entry = entry
        .with("worker", event.thread.clone())
        .with("span", event.span.to_string());
    if let Some(parent) = event.parent {
        entry = entry.with("parent", parent.to_string());
    }
    // A duration only where both ends are real. A denial ran nothing, and
    // `dur=0` would claim it ran and finished instantly.
    if let (Some(start), Some(end)) = (event.started, event.ended) {
        entry = entry.with(
            "dur",
            end.as_millis()
                .saturating_sub(start.as_millis())
                .to_string(),
        );
    }
    // Absent = full authority. `None` and an empty scope set are different
    // facts and the kernel keeps them apart, so this does too.
    if let Some(scopes) = &event.capability {
        for scope in scopes {
            entry = entry.with("cap", scope.clone());
        }
    }
    for (key, value) in &event.notes {
        // The kernel's note key IS the log's column, so the denial mapping is
        // identity rather than a translation with two spellings to keep in step.
        entry = entry.with(key.clone(), value.clone());
    }
    entry
}
