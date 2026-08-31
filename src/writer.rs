//! The writer: one segment per process, opened once, filtered by level, and
//! flushed per entry.
//!
//! ## One segment per PROCESS
//!
//! Not per machine. The instance name is the attribution key, so two `serve`
//! processes on one host are two logs and "what happened on this machine" is a
//! union — which is already how the graph reads. That makes the writer's whole
//! concurrency story a question about names rather than about file handles.
//!
//! ## Names, and why a collision DISAMBIGUATES rather than refuses
//!
//! Any server logs, including the ones nobody named — a bare `ikigai serve`
//! beside another. So an unnamed server is the common case, not the edge, and a
//! writer that refused to open because the default name was taken would take
//! out the second server on the box. That is backwards for a logging subsystem:
//! the log is what you consult when something went wrong, and it must not be
//! the thing that goes wrong.
//!
//! So: a host with a name (`--name`, or `instance =` in `log.toml`) gets it; a
//! host without one asks for a self-assigned one
//! ([`LogConfig::with_self_assigned_instance`](crate::LogConfig::with_self_assigned_instance),
//! which suffixes the process id); and if a name is *already held by a live
//! process*, this writer suffixes the pid onto it instead of failing. The
//! disambiguation is recorded rather than silent — the `log:ProcessStart` entry
//! carries `configured=` the name that was asked for, so the graph states both
//! what the operator configured and what the process actually wrote under.
//!
//! Collision is detected with an **advisory lock** on `{directory}/{name}.lock`
//! (`File::try_lock`, stable since Rust 1.89). The OS releases it when the
//! process dies, so — unlike a lock file whose presence is the signal — a crash
//! cannot strand a name and no stale-lock sweeper is owed. Detection is
//! filesystem-mediated, so it applies to the **file** destination; two console
//! writers sharing a name have no shared artifact to arbitrate on, and a host
//! that cares gives them names.
//!
//! ## The chain, from the writer's side
//!
//! Every entry advances an in-memory hash chain ([`crate::chain::Chain`]) rooted
//! at the segment's canonical header — **nothing per line lands on disk**, because
//! a hash column on every entry is exactly the noise that would wreck `grep`.
//! Periodically ([`SealPolicy`], N entries **or** T milliseconds) a `#seal` line
//! commits the head, so tampering localizes to "between seal K and seal K+1".
//!
//! A writer opening on a file destination reads the **newest segment of its own
//! instance** and takes that segment's chain head as its `@prev`, so the chain
//! spans process restarts as well as rotations. A different instance name is a
//! different chain and starts at `genesis`, which is the right reading: the
//! instance IS the attribution key.
//!
//! **Both endings seal.** [`Writer::close`] writes `log:ProcessStop` and
//! [`Writer::rotate_out`] writes `log:Rotation`, and each then writes a final
//! `#seal` over whatever tail was uncommitted. So a segment that ends in an
//! orderly way has nothing outside a checkpoint, and a segment that does have an
//! unsealed tail ended because the process died — which verification reports as
//! noted rather than broken, because a crash is not tampering.
//!
//! **No buffering.** Every entry is flushed as it is written. A log that loses
//! its tail to a crash cannot testify about the crash, which is the moment it
//! exists for; throughput is a later measurement, not a trade to make before
//! anything has been measured. If buffering ever arrives, a dropped entry owes
//! a `log:Dropped count=N` — never a silent hole, which is the same argument
//! that rejects sampling.

use std::collections::BTreeMap;
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;

use crate::chain::{seal_due, seal_for, Chain, RotationPolicy, SealPolicy, SealSigner};
#[cfg(not(target_family = "wasm"))]
use crate::config::Destination;
use crate::config::LogConfig;
use crate::line::{Entry, Header, Prev, RenderError, Timestamp, FORMAT_VERSION};
use crate::vocabulary::{
    Vocabulary, LOG_NS, PROCESS_START_CLASS, PROCESS_STOP_CLASS, PROV_NS, ROTATION_CLASS,
};

/// Why a segment could not be opened, or an entry could not be written.
#[derive(Debug)]
pub enum WriteError {
    /// The configured level is not one the vocabulary defines.
    ///
    /// Loud, at open, and never per entry: the rank is resolved once, and a
    /// level nothing can place on the dial would otherwise silently include or
    /// exclude everything.
    UnknownLevel {
        /// The level IRI that was configured.
        level: String,
        /// The levels this vocabulary does define.
        known: Vec<String>,
    },
    /// A file destination with no directory configured and no data home to fall
    /// back on. Not a guess: a relative path here is a log that moves with the
    /// working directory, which reads as success.
    NoDirectory,
    /// A segment file already exists at the path this segment would take.
    SegmentExists(PathBuf),
    /// The instance name is held by a live process and could not be
    /// disambiguated either.
    InstanceInUse {
        /// The name that was asked for.
        name: String,
        /// The name that was tried instead.
        tried: String,
    },
    /// A filesystem or stream failure.
    Io {
        /// What was being written, when it is a file.
        path: Option<PathBuf>,
        /// The OS error.
        message: String,
    },
    /// A value that cannot be written as a line without corrupting it.
    Render(RenderError),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::UnknownLevel { level, known } => write!(
                f,
                "level {level} is not defined by this vocabulary — it knows: {}",
                known.join(", ")
            ),
            WriteError::NoDirectory => f.write_str(
                "no log directory: set `directory` in log.toml, or give the process a HOME so \
                 the data home can be found",
            ),
            WriteError::SegmentExists(path) => {
                write!(f, "{}: a segment is already there", path.display())
            }
            WriteError::InstanceInUse { name, tried } => write!(
                f,
                "instance {name} is held by another process and {tried} is too"
            ),
            WriteError::Io { path, message } => match path {
                Some(path) => write!(f, "{}: {message}", path.display()),
                None => f.write_str(message),
            },
            WriteError::Render(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WriteError {}

impl From<RenderError> for WriteError {
    fn from(e: RenderError) -> Self {
        WriteError::Render(e)
    }
}

/// Where rendered lines go.
///
/// The seam exists so the crate stays wasm-clean without pretending a browser
/// has a filesystem: the native destinations are `cfg`-gated implementations of
/// this trait, and a browser host installs a [`ClosureSink`] over `console.log`
/// and writes exactly the same lines.
pub trait LineSink: Send {
    /// Write one rendered line. The line never contains a newline; appending
    /// the terminator is the sink's job, because a `console.log` does not want
    /// one and a file does.
    fn write_line(&mut self, line: &str) -> io::Result<()>;

    /// Flush. Called after **every** entry — see the module docs.
    fn flush(&mut self) -> io::Result<()>;
}

/// A sink over any closure — the browser's `console.log`, a test's buffer, a
/// host's own tracing bridge.
pub struct ClosureSink<F>(pub F);

impl<F: FnMut(&str) + Send> LineSink for ClosureSink<F> {
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        (self.0)(line);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The process's diagnostic stream.
///
/// **stderr, not stdout.** stdout is the pipeline's data channel — a log line
/// landing in it corrupts the composition the whole system is for.
#[cfg(not(target_family = "wasm"))]
pub struct StderrSink;

#[cfg(not(target_family = "wasm"))]
impl LineSink for StderrSink {
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        use io::Write;
        writeln!(io::stderr(), "{line}")
    }

    fn flush(&mut self) -> io::Result<()> {
        use io::Write;
        io::stderr().flush()
    }
}

/// A segment file, opened for append and flushed per entry.
#[cfg(not(target_family = "wasm"))]
pub struct FileSink(std::fs::File);

#[cfg(not(target_family = "wasm"))]
impl LineSink for FileSink {
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        use io::Write;
        writeln!(self.0, "{line}")
    }

    fn flush(&mut self) -> io::Result<()> {
        use io::Write;
        self.0.flush()
    }
}

/// An open segment: its header, its level, and its append point.
///
/// Constructing one is what starts logging. **Binding the endpoints does
/// not** — a host that has not decided it is the kind of process that logs
/// leaves the handle closed and nothing is written, which is the difference
/// between a knob and a policy.
pub struct Writer {
    header: Header,
    /// The segment level's rank, resolved ONCE at open.
    rank: i64,
    vocabulary: Arc<Vocabulary>,
    sink: Box<dyn LineSink>,
    seq: u64,
    /// The running hash over the header and every entry written so far. In
    /// memory only — a hash per line would wreck `grep`.
    chain: Chain,
    /// The last sequence a `#seal` line has committed. Everything above it is
    /// the unsealed tail.
    sealed_through: u64,
    /// The chain head as of that seal — h₀ until the first one lands. This, not
    /// the running head, is what a successor's `@prev` names: an unsealed entry
    /// is committed to no checkpoint, and chaining from it would claim a
    /// guarantee the file does not carry.
    sealed_head: String,
    /// When the last seal landed — the segment's start until one does, so the
    /// time bound is measured from the first entry rather than from nothing.
    last_seal_at: Timestamp,
    /// When the segment was opened, for the rotation age trigger.
    opened_at: Timestamp,
    seals: SealPolicy,
    rotation: RotationPolicy,
    /// What signs a seal, when a host wired one. `None` still chains and seals:
    /// an unsigned seal localizes tampering, it just does not attest.
    signer: Option<Box<dyn SealSigner>>,
    path: Option<PathBuf>,
    /// The instance name the config asked for, when it differs from the one in
    /// the header.
    configured_instance: Option<String>,
    /// The advisory lock on this instance's name, held for the writer's
    /// lifetime and released by the OS when the process ends.
    #[cfg(not(target_family = "wasm"))]
    _lock: Option<std::fs::File>,
}

/// What a segment is opened WITH, beyond its configuration.
///
/// Separate from [`LogConfig`] because none of it is configuration: a signer is
/// a live object holding a key seam, and `prev` is a fact about the chain rather
/// than a setting. The policies are here — and deliberately **not** TOML keys
/// yet — so that adding an operator dial later is a schema decision made on its
/// own merits rather than a side effect of building the chain.
#[derive(Default)]
pub struct WriterOptions {
    /// When a checkpoint lands.
    pub seals: SealPolicy,
    /// When the segment rolls over.
    pub rotation: RotationPolicy,
    /// What this segment chains from. `None` means **discover it**: on a file
    /// destination, from the newest segment of this same instance; otherwise
    /// `genesis`, because a caller-supplied sink has no directory to look in.
    pub prev: Option<Prev>,
    /// What signs a seal, if anything does.
    pub signer: Option<Box<dyn SealSigner>>,
}

/// A segment that has been ended — sealed, and with its chain head settled.
///
/// Handed back rather than dropped, because rotation is a handoff: the chain
/// head becomes the successor's `@prev`, the instance lock moves across without
/// a window in which another process could take the name, and the signer is
/// still the same signer.
pub struct Closed {
    /// The segment that was ended.
    pub segment: String,
    /// Its chain head — what the successor's `@prev` must name.
    pub head: String,
    /// Its file, for a file destination.
    pub path: Option<PathBuf>,
    /// The signer it was using, so the successor keeps it.
    pub signer: Option<Box<dyn SealSigner>>,
    /// The instance name it actually wrote under.
    pub instance: String,
    /// The advisory lock on that name, held across the handoff.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) lock: Option<std::fs::File>,
}

impl Writer {
    /// Open a segment on the destination the config names, at the instant
    /// `now`.
    ///
    /// `Destination::Off` is not an error and not a writer: the caller gets
    /// `Ok(None)` and logs nothing, which is the quiet default a REPL keeps.
    #[cfg(not(target_family = "wasm"))]
    pub fn open(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
    ) -> Result<Option<Writer>, WriteError> {
        Writer::open_with(config, vocabulary, now, WriterOptions::default())
    }

    /// [`open`](Self::open), with the seal policy, rotation policy, chain link
    /// and signer stated.
    #[cfg(not(target_family = "wasm"))]
    pub fn open_with(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        options: WriterOptions,
    ) -> Result<Option<Writer>, WriteError> {
        match config.destination {
            Destination::Off => Ok(None),
            Destination::Console => Writer::start(
                config,
                vocabulary,
                now,
                Box::new(StderrSink),
                None,
                None,
                options,
                None,
            )
            .map(Some),
            Destination::File => Writer::open_file(config, vocabulary, now, options).map(Some),
        }
    }

    /// Open a segment writing through a sink the caller supplies — the browser
    /// path, and the testable one.
    ///
    /// No directory, no lock: the caller has chosen where the lines go, so
    /// nothing here can arbitrate names for it, and `@prev` is `genesis` unless
    /// the caller states one — a browser host that carries a chain across a page
    /// load knows what it carried and this crate cannot.
    pub fn open_with_sink(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        sink: Box<dyn LineSink>,
    ) -> Result<Writer, WriteError> {
        Writer::open_with_sink_and(config, vocabulary, now, sink, WriterOptions::default())
    }

    /// [`open_with_sink`](Self::open_with_sink), with the options stated.
    pub fn open_with_sink_and(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        sink: Box<dyn LineSink>,
        options: WriterOptions,
    ) -> Result<Writer, WriteError> {
        Writer::start(config, vocabulary, now, sink, None, None, options, None)
    }

    #[cfg(not(target_family = "wasm"))]
    fn open_file(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        options: WriterOptions,
    ) -> Result<Writer, WriteError> {
        Writer::open_file_claimed(config, vocabulary, now, options, None)
    }

    #[cfg(not(target_family = "wasm"))]
    fn open_file_claimed(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        mut options: WriterOptions,
        claimed: Option<(String, std::fs::File)>,
    ) -> Result<Writer, WriteError> {
        let directory = resolve_directory(config).ok_or(WriteError::NoDirectory)?;
        std::fs::create_dir_all(&directory).map_err(|e| WriteError::Io {
            path: Some(directory.clone()),
            message: e.to_string(),
        })?;

        let (name, lock) = match claimed {
            Some(held) => held,
            None => claim_instance(&directory, config.instance_name())?,
        };

        // ★ The chain spans rotations AND restarts. Read before the new file is
        // created, so the newest segment found is genuinely a predecessor: a
        // process that opens, then looks, would find itself.
        if options.prev.is_none() {
            options.prev = Some(discover_prev(
                &directory,
                &crate::config::instance_iri(&name),
            ));
        }

        let reserved = reserve_segment(&directory, &name, now)?;
        Writer::open_file_on(config, vocabulary, now, options, name, lock, reserved)
    }

    /// Open a segment onto a file that has already been reserved.
    ///
    /// Rotation needs the successor's identity BEFORE the predecessor is sealed —
    /// the `log:Rotation` entry names it — and a stamp collision means the file
    /// decides the identity, not the clock. So the file is created first and its
    /// name is the answer to both questions.
    ///
    /// The lock passes through rather than being dropped and retaken: between a
    /// drop and a retake there is a window in which another process could take
    /// the instance name, and the rotated log would silently continue under a
    /// disambiguated one.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn open_file_on(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        options: WriterOptions,
        name: String,
        lock: std::fs::File,
        reserved: Reserved,
    ) -> Result<Writer, WriteError> {
        let mut writer = Writer::start(
            config,
            vocabulary,
            now,
            Box::new(FileSink(reserved.file)),
            Some(reserved.path),
            Some(name),
            options,
            Some(reserved.stamp),
        )?;
        // Attached after the header, not before: the lock was already taken
        // (it is what decided the name), and this only parks it where the
        // writer's lifetime will hold it.
        writer._lock = Some(lock);
        Ok(writer)
    }

    #[allow(clippy::too_many_arguments)] // the private constructor every public
                                         // `open*` funnels into; splitting it
                                         // would move the argument list, not
                                         // shorten it
    fn start(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        mut sink: Box<dyn LineSink>,
        path: Option<PathBuf>,
        effective_name: Option<String>,
        options: WriterOptions,
        stamp_override: Option<String>,
    ) -> Result<Writer, WriteError> {
        // The whole level dial, resolved once. A level the vocabulary does not
        // define is a hard stop: the alternative is a segment whose header
        // claims a threshold that nothing in the graph can compare against.
        let rank = vocabulary
            .rank(&config.level)
            .ok_or_else(|| WriteError::UnknownLevel {
                level: config.level.clone(),
                known: vocabulary
                    .levels()
                    .map(|(iri, _)| iri.to_string())
                    .collect(),
            })?;

        let instance = match &effective_name {
            Some(name) => crate::config::instance_iri(name),
            None => config.instance.clone(),
        };
        let configured_instance = (instance != config.instance).then(|| config.instance.clone());

        let mut prefixes = BTreeMap::new();
        prefixes.insert("log".to_string(), LOG_NS.to_string());
        prefixes.insert("prov".to_string(), PROV_NS.to_string());

        let header = Header {
            version: FORMAT_VERSION,
            prefixes,
            // The IRI and the file name carry the SAME stamp, which is why a
            // collision-disambiguated one is threaded through rather than
            // recomputed: `locate` derives the file from the IRI, and two
            // spellings of the stamp would make a segment unresolvable by its
            // own name.
            name: segment_iri(&instance, stamp_override.unwrap_or_else(|| stamp(now))),
            instance,
            level: config.level.clone(),
            started: now,
            prev: options.prev.unwrap_or(Prev::Genesis),
        };

        let rendered = header.render()?;
        for line in rendered.lines() {
            sink.write_line(line).map_err(|e| io_error(&path, e))?;
        }
        // The blank line `Header::render` ends with is the header/entries
        // separator, and `lines()` drops trailing empties — so write it here.
        sink.write_line("").map_err(|e| io_error(&path, e))?;
        sink.flush().map_err(|e| io_error(&path, e))?;

        let chain = Chain::open(&header);
        let sealed_head = chain.head().to_string();
        let mut writer = Writer {
            header,
            rank,
            vocabulary,
            sink,
            seq: 0,
            chain,
            sealed_through: 0,
            sealed_head,
            last_seal_at: now,
            opened_at: now,
            seals: options.seals,
            rotation: options.rotation,
            signer: options.signer,
            path,
            configured_instance,
            #[cfg(not(target_family = "wasm"))]
            _lock: None,
        };

        // Liveness, and the run boundary a span join is scoped between. Always
        // lands: `log:ProcessStart` is `log:minLevel log:always`.
        let mut start = Entry::new(now, PROCESS_START_CLASS, writer.header.instance.clone());
        #[cfg(not(target_family = "wasm"))]
        {
            start = start.with("pid", std::process::id().to_string());
        }
        if let Some(configured) = writer.configured_instance.clone() {
            // The disambiguation, in the record. Two facts, both true: what was
            // asked for and what was written under.
            start = start.with("configured", configured);
        }
        writer.write(start)?;
        Ok(writer)
    }

    /// Append one entry, if this segment's level includes its class.
    ///
    /// Returns the sequence number written, or `None` when the level dial
    /// excluded it. `seq=` goes on the line explicitly and first: it is
    /// recoverable from line position, but a line that has been grepped out of
    /// its file has lost its position, and a seal range names sequences. Eight
    /// bytes buys a self-identifying line, in a format that already trades
    /// bytes for legibility.
    pub fn write(&mut self, entry: Entry) -> Result<Option<u64>, WriteError> {
        if !self.vocabulary.emits(&entry.class, self.rank) {
            return Ok(None);
        }
        let seq = self.seq + 1;
        let Entry {
            time,
            class,
            subject,
            fields: stated,
        } = entry;
        let mut fields = Vec::with_capacity(stated.len() + 1);
        fields.push(("seq".to_string(), seq.to_string()));
        fields.extend(stated);
        let line = Entry {
            time,
            class,
            subject,
            fields,
        }
        .render(&self.header.prefixes)?;
        guarded(|| self.sink.write_line(&line)).map_err(|e| io_error(&self.path, e))?;
        // Per entry, deliberately. See the module docs.
        guarded(|| self.sink.flush()).map_err(|e| io_error(&self.path, e))?;
        self.seq = seq;
        // The chain folds in the line as WRITTEN — the same bytes a verifier
        // will read back — so the two agree by construction rather than by two
        // implementations of one rule.
        self.chain.advance(&line);
        if seal_due(
            &self.seals,
            self.seq,
            self.sealed_through,
            time,
            self.last_seal_at,
        ) {
            self.seal(time)?;
        }
        Ok(Some(seq))
    }

    /// Commit everything written since the last checkpoint as a `#seal` line.
    ///
    /// A no-op when there is nothing new: a seal over an empty range would state
    /// a hash already stated and add a line whose only effect is to make the
    /// range arithmetic wrong.
    pub fn seal(&mut self, now: Timestamp) -> Result<Option<crate::line::Seal>, WriteError> {
        if self.seq <= self.sealed_through {
            return Ok(None);
        }
        let seal = seal_for(
            self.sealed_through,
            self.seq,
            self.chain.head(),
            self.signer.as_deref(),
        );
        guarded(|| self.sink.write_line(&seal.render())).map_err(|e| io_error(&self.path, e))?;
        guarded(|| self.sink.flush()).map_err(|e| io_error(&self.path, e))?;
        self.sealed_through = self.seq;
        self.sealed_head = self.chain.head().to_string();
        self.last_seal_at = now;
        Ok(Some(seal))
    }

    /// The chain head: the last sealed hash, or h₀ while nothing is sealed.
    ///
    /// This is what a successor's `@prev` names, and it is deliberately the
    /// SEALED head rather than the running one: an unsealed entry is committed
    /// to no checkpoint, so chaining from it would claim a guarantee the file
    /// does not carry.
    pub fn head(&self) -> &str {
        &self.sealed_head
    }

    /// Whether this segment has met its rotation policy.
    pub fn rotation_due(&self, now: Timestamp) -> bool {
        self.rotation.due(
            self.seq,
            now.as_millis().saturating_sub(self.opened_at.as_millis()),
        )
    }

    /// Whether an entry of this class would be written at this segment's level.
    /// One integer comparison over the vocabulary graph.
    pub fn emits(&self, class_iri: &str) -> bool {
        self.vocabulary.emits(class_iri, self.rank)
    }

    /// This segment's header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// This segment's IRI — the named graph its entries land in.
    pub fn segment(&self) -> &str {
        &self.header.name
    }

    /// The instance this segment is attributed to, **after** any
    /// disambiguation.
    pub fn instance(&self) -> &str {
        &self.header.instance
    }

    /// The instance the config asked for, when it is not the one above.
    pub fn configured_instance(&self) -> Option<&str> {
        self.configured_instance.as_deref()
    }

    /// The segment file, for a file destination.
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// The level this segment runs at, as an absolute IRI. One per segment,
    /// for its whole life: a level change takes effect at a segment boundary.
    pub fn level(&self) -> &str {
        &self.header.level
    }

    /// The vocabulary this segment's dial is read from.
    pub fn vocabulary(&self) -> &Arc<Vocabulary> {
        &self.vocabulary
    }

    /// How many entries have been written.
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// Write `log:ProcessStop` and close.
    ///
    /// **Nothing writes one on `Drop`.** A stop marker means an *orderly* stop,
    /// and that distinction is the whole value of the entry: a segment that
    /// ends without one ended because the process died, which is precisely what
    /// the absence query will want to see. A best-effort marker in a destructor
    /// would blur the two and could not report its own failure anyway.
    pub fn close(self, now: Timestamp) -> Result<Closed, WriteError> {
        let stop = Entry::new(now, PROCESS_STOP_CLASS, self.header.instance.clone());
        self.end_with(stop, now)
    }

    /// Write `log:Rotation`, seal, and hand the segment over.
    ///
    /// ★ **Rotation is verify + seal + validate as one operation**, and this is
    /// the seal half; [`LogHandle::rotate`](crate::LogHandle::rotate) is where
    /// the three are composed, because verifying the predecessor and landing a
    /// `log:ChainBroken` in the successor both need a second writer that this
    /// one cannot open for itself.
    ///
    /// `successor` is written as `next=` so the log can be walked FORWARD
    /// without sorting a directory. It is derivable at this moment — the
    /// successor's IRI is its instance and the rotation instant — which is the
    /// only reason it can be stated at all before the segment exists.
    pub fn rotate_out(self, now: Timestamp, successor: Option<&str>) -> Result<Closed, WriteError> {
        let mut rotation = Entry::new(now, ROTATION_CLASS, self.header.name.clone());
        if let Some(successor) = successor {
            rotation = rotation.with("next", successor);
        }
        self.end_with(rotation, now)
    }

    /// The shared ending: land the marker, then seal whatever tail it left.
    ///
    /// The marker is written BEFORE the seal so that the seal covers it — a
    /// rotation or a stop that sat outside every checkpoint would be the one
    /// entry an attacker could remove for free, and it is the entry that says
    /// the record ends here on purpose.
    fn end_with(mut self, marker: Entry, now: Timestamp) -> Result<Closed, WriteError> {
        self.write(marker)?;
        self.seal(now)?;
        guarded(|| self.sink.flush()).map_err(|e| io_error(&self.path, e))?;
        Ok(Closed {
            segment: self.header.name,
            head: self.sealed_head,
            path: self.path,
            signer: self.signer,
            instance: self.header.instance,
            #[cfg(not(target_family = "wasm"))]
            lock: self._lock,
        })
    }
}

/// Call into the sink without letting it take the log with it.
///
/// ★ [`LineSink`] is a **host** seam — a browser's `console.log`, a bridge into
/// somebody else's logging framework — and the writer lives behind
/// [`crate::LogHandle`]'s state `Mutex`. A panic that unwound from a sink would
/// therefore poison that mutex, and every subsequent write, close, rotation and
/// config read in the process would panic on the poison: the log would be dead
/// for the rest of the run, and — because the marker that records a loss is
/// itself a write — dead with **no marker**. That is the worst available outcome
/// for the one subsystem whose job is to notice things, so a panicking sink is
/// turned into an ordinary write error, which every caller here already knows
/// how to report.
///
/// Nothing is left half-done by the conversion: the sink is called before the
/// sequence advances and before the chain folds the line in, so a sink that
/// fails — by returning `Err` or by unwinding — leaves the writer exactly as it
/// was.
fn guarded<T>(call: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(result) => result,
        Err(_) => Err(io::Error::other("the sink panicked")),
    }
}

fn io_error(path: &Option<PathBuf>, e: io::Error) -> WriteError {
    WriteError::Io {
        path: path.clone(),
        message: e.to_string(),
    }
}

/// The segment IRI: `urn:log:{instance}:{YYYY-MM-DDTHH-MM-SSZ}`.
///
/// The instant is part of the name because the name is the named graph, and a
/// union over a machine's segments has to keep two runs of one instance apart.
/// The stamp is passed in rather than derived so that a rotation which had to
/// disambiguate a file name uses the SAME token in both places.
fn segment_iri(instance: &str, stamp: String) -> String {
    let name = instance
        .strip_prefix(crate::config::INSTANCE_NS)
        .unwrap_or(instance);
    format!("urn:log:{name}:{stamp}")
}

/// A segment file that exists but has not been written to yet, and the identity
/// it settled.
#[cfg(not(target_family = "wasm"))]
pub(crate) struct Reserved {
    pub(crate) path: PathBuf,
    pub(crate) file: std::fs::File,
    pub(crate) stamp: String,
    /// The segment IRI this file will carry — knowable now, which is what lets a
    /// rotation name its successor in the entry that precedes it.
    pub(crate) iri: String,
}

/// Create this segment's file, disambiguating a stamp another segment already
/// took.
///
/// Rotation is second-precision away from a collision — a size trigger on a busy
/// log can roll twice within one second — and refusing to rotate is the worst
/// possible response to "this segment is too big". The suffix keeps the IRI's
/// shape, so `locate`'s fast path still derives the file name from the IRI.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn reserve_segment(
    directory: &std::path::Path,
    name: &str,
    now: Timestamp,
) -> Result<Reserved, WriteError> {
    let base = stamp(now);
    for attempt in 0..MAX_STAMP_ATTEMPTS {
        let stamp = if attempt == 0 {
            base.clone()
        } else {
            format!("{base}-{attempt}")
        };
        let path = directory.join(format!("{}-{stamp}.log", slug(name)));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                let iri = segment_iri(&crate::config::instance_iri(name), stamp.clone());
                return Ok(Reserved {
                    path,
                    file,
                    stamp,
                    iri,
                });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(WriteError::Io {
                    path: Some(path),
                    message: e.to_string(),
                })
            }
        }
    }
    Err(WriteError::SegmentExists(
        directory.join(format!("{}-{base}.log", slug(name))),
    ))
}

/// The bare instance NAME behind an instance IRI — what a file is named after.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn instance_name_of(instance: &str) -> &str {
    instance
        .strip_prefix(crate::config::INSTANCE_NS)
        .unwrap_or(instance)
}

/// How many stamps to try before giving up. A second holding this many segments
/// is a rotation loop, not a busy log, and it should stop rather than fill a
/// disk quietly.
#[cfg(not(target_family = "wasm"))]
const MAX_STAMP_ATTEMPTS: usize = 100;

/// ★ What this segment chains from: the newest segment of the SAME instance in
/// this directory, at its chain head.
///
/// Per instance, not per directory, and that is the whole reading: the instance
/// is the attribution key, so one machine's log directory holds as many chains as
/// it has instances, and a disambiguated name (`serve-4321`) is a chain of its
/// own — which is right, because it is a different process that never claimed to
/// continue anyone.
///
/// Reads whole files rather than probing heads, because the chain head is at the
/// END. One read at process start, of one file; the alternative is a tail scan
/// that still has to fall back to the header when a segment never sealed.
#[cfg(not(target_family = "wasm"))]
fn discover_prev(directory: &std::path::Path, instance: &str) -> Prev {
    let Some(path) = crate::segments::newest_for_instance(directory, instance) else {
        return Prev::Genesis;
    };
    match std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| crate::chain::head_of(&text))
    {
        Some(head) => Prev::Seal(head),
        // A predecessor whose bytes will not parse is not a chain link, and
        // claiming one would be worse than claiming genesis: a `@prev` pointing
        // at nothing verifiable looks verified. Verification reports the restart.
        None => Prev::Genesis,
    }
}

/// A timestamp as a token that is safe in an IRI and in a file name: seconds
/// precision, colons and dots replaced.
fn stamp(now: Timestamp) -> String {
    let rendered = now.render();
    rendered[..19].replace(':', "-") + "Z"
}

/// An instance name as a file-name component. Native only: nothing on wasm has
/// a file to name.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn slug(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '-',
        })
        .collect()
}

/// The directory segments land in: the configured one, else `{data home}/log`.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn resolve_directory(config: &LogConfig) -> Option<PathBuf> {
    config
        .directory
        .clone()
        .or_else(|| ikigai_core::config::data_path(crate::config::DEFAULT_DIRECTORY_STEM))
}

/// Take the advisory lock on an instance name, disambiguating with the process
/// id if a live process already holds it.
///
/// Returns the name that was actually claimed, and the lock to hold for the
/// writer's lifetime.
#[cfg(not(target_family = "wasm"))]
fn claim_instance(
    directory: &std::path::Path,
    name: &str,
) -> Result<(String, std::fs::File), WriteError> {
    match try_claim(directory, name)? {
        Some(file) => Ok((name.to_string(), file)),
        None => {
            let disambiguated = crate::config::disambiguated(name, std::process::id());
            match try_claim(directory, &disambiguated)? {
                Some(file) => Ok((disambiguated, file)),
                // Unreachable in practice: no other LIVE process has this pid,
                // so nothing else can be holding this name. Reported rather
                // than asserted, because a lock on a filesystem that does not
                // implement locking would land here and an operator deserves a
                // sentence rather than a panic.
                None => Err(WriteError::InstanceInUse {
                    name: name.to_string(),
                    tried: disambiguated,
                }),
            }
        }
    }
}

/// `Ok(Some(lock))` when the name was free, `Ok(None)` when a live process
/// holds it.
#[cfg(not(target_family = "wasm"))]
fn try_claim(directory: &std::path::Path, name: &str) -> Result<Option<std::fs::File>, WriteError> {
    use io::Write;

    let path = directory.join(format!("{}.lock", slug(name)));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| WriteError::Io {
            path: Some(path.clone()),
            message: e.to_string(),
        })?;
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(std::fs::TryLockError::Error(e)) => {
            return Err(WriteError::Io {
                path: Some(path),
                message: e.to_string(),
            })
        }
    }
    // Diagnostics only — the lock is the OS's, not this file's contents. It is
    // deliberately not removed on close: unlinking races another process that
    // has already opened the same path, and an empty leftover file costs
    // nothing while a stolen lock costs the interleaving this prevents.
    let mut file = file;
    let _ = file.set_len(0);
    let _ = writeln!(file, "{}", std::process::id());
    let _ = file.flush();
    Ok(Some(file))
}
