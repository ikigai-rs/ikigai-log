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
//! ## What T2 does not do
//!
//! **`@prev genesis`, always.** No hashes, no seals, no linkage between
//! segments: the four fingerprint layers are one piece of work (T4), and a
//! partial chain is worse than none because it *looks* verifiable.
//!
//! **No buffering.** Every entry is flushed as it is written. A log that loses
//! its tail to a crash cannot testify about the crash, which is the moment it
//! exists for; throughput is a later measurement, not a trade to make before
//! anything has been measured. If buffering ever arrives, a dropped entry owes
//! a `log:Dropped count=N` — never a silent hole, which is the same argument
//! that rejects sampling.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(not(target_family = "wasm"))]
use crate::config::Destination;
use crate::config::LogConfig;
use crate::line::{Entry, Header, Prev, RenderError, Timestamp, FORMAT_VERSION};
use crate::vocabulary::{Vocabulary, LOG_NS, PROCESS_START_CLASS, PROCESS_STOP_CLASS, PROV_NS};

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
    path: Option<PathBuf>,
    /// The instance name the config asked for, when it differs from the one in
    /// the header.
    configured_instance: Option<String>,
    /// The advisory lock on this instance's name, held for the writer's
    /// lifetime and released by the OS when the process ends.
    #[cfg(not(target_family = "wasm"))]
    _lock: Option<std::fs::File>,
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
        match config.destination {
            Destination::Off => Ok(None),
            Destination::Console => {
                Writer::start(config, vocabulary, now, Box::new(StderrSink), None, None).map(Some)
            }
            Destination::File => Writer::open_file(config, vocabulary, now).map(Some),
        }
    }

    /// Open a segment writing through a sink the caller supplies — the browser
    /// path, and the testable one.
    ///
    /// No directory, no lock: the caller has chosen where the lines go, so
    /// nothing here can arbitrate names for it.
    pub fn open_with_sink(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        sink: Box<dyn LineSink>,
    ) -> Result<Writer, WriteError> {
        Writer::start(config, vocabulary, now, sink, None, None)
    }

    #[cfg(not(target_family = "wasm"))]
    fn open_file(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
    ) -> Result<Writer, WriteError> {
        let directory = resolve_directory(config).ok_or(WriteError::NoDirectory)?;
        std::fs::create_dir_all(&directory).map_err(|e| WriteError::Io {
            path: Some(directory.clone()),
            message: e.to_string(),
        })?;

        let asked = config.instance_name().to_string();
        let (name, lock) = claim_instance(&directory, &asked)?;

        let path = directory.join(format!("{}-{}.log", slug(&name), stamp(now)));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists => WriteError::SegmentExists(path.clone()),
                _ => WriteError::Io {
                    path: Some(path.clone()),
                    message: e.to_string(),
                },
            })?;

        let mut writer = Writer::start(
            config,
            vocabulary,
            now,
            Box::new(FileSink(file)),
            Some(path),
            Some(name),
        )?;
        // Attached after the header, not before: the lock was already taken
        // above (it is what decided the name), and this only parks it where the
        // writer's lifetime will hold it.
        writer._lock = Some(lock);
        Ok(writer)
    }

    fn start(
        config: &LogConfig,
        vocabulary: Arc<Vocabulary>,
        now: Timestamp,
        mut sink: Box<dyn LineSink>,
        path: Option<PathBuf>,
        effective_name: Option<String>,
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
            name: segment_iri(&instance, now),
            instance,
            level: config.level.clone(),
            started: now,
            // T4 owns the chain. A `@prev` that pointed at a predecessor
            // without the hashes to verify it would look verifiable and not be.
            prev: Prev::Genesis,
        };

        let rendered = header.render()?;
        for line in rendered.lines() {
            sink.write_line(line).map_err(|e| io_error(&path, e))?;
        }
        // The blank line `Header::render` ends with is the header/entries
        // separator, and `lines()` drops trailing empties — so write it here.
        sink.write_line("").map_err(|e| io_error(&path, e))?;
        sink.flush().map_err(|e| io_error(&path, e))?;

        let mut writer = Writer {
            header,
            rank,
            vocabulary,
            sink,
            seq: 0,
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
        self.sink
            .write_line(&line)
            .map_err(|e| io_error(&self.path, e))?;
        // Per entry, deliberately. See the module docs.
        self.sink.flush().map_err(|e| io_error(&self.path, e))?;
        self.seq = seq;
        Ok(Some(seq))
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
    pub fn close(mut self, now: Timestamp) -> Result<(), WriteError> {
        let stop = Entry::new(now, PROCESS_STOP_CLASS, self.header.instance.clone());
        self.write(stop)?;
        self.sink.flush().map_err(|e| io_error(&self.path, e))?;
        Ok(())
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
fn segment_iri(instance: &str, now: Timestamp) -> String {
    let name = instance
        .strip_prefix(crate::config::INSTANCE_NS)
        .unwrap_or(instance);
    format!("urn:log:{name}:{}", stamp(now))
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
