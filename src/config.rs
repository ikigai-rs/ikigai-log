//! The log's configuration: the schema, the key-wise layering, and the two
//! faces the effective config is served as.
//!
//! Pure — parsing, merging and rendering only. Nothing here touches a
//! filesystem (that is [`crate::load`], native-only), so this half compiles to
//! `wasm32-unknown-unknown` and a browser host configures a `console.log`
//! destination through exactly the same type.
//!
//! ## Four keys, flat
//!
//! ```toml
//! level       = "info"       # a bare level name, a log: CURIE, or an absolute IRI
//! destination = "file"       # off | console | file
//! directory   = "/var/log/ikigai"   # segments land here (file destination only)
//! instance    = "bug:serve"  # the attribution key; urn:ikigai:instance:{name}
//! ```
//!
//! Layered lowest-precedence-first over the host's own defaults:
//! **host defaults → `log.toml` → `{app}.log.toml`**, merged **key-wise**, so a
//! shared `level = "debug"` survives one application that overrides only its
//! destination. `ikigai_core::config::layered_paths_in` names the files;
//! [`Patch`] is one file's contents and [`LogConfig::apply`] folds one in.
//!
//! ## Environment variables are the banned third channel
//!
//! Config home plus explicit arguments, and nothing else. There is no
//! `IKIGAI_LOG_LEVEL`, and there will not be one: an environment variable is a
//! channel that no config file records, no `urn:log:config` read reports, and
//! no operator finds. The only variables that reach this crate are the two
//! `ikigai_core::config` reads to locate the config home itself.
//!
//! ## Absent takes the default; present-but-wrong stops
//!
//! An absent key means "the layer below decides". A key that is *present* and
//! unparseable — `destination = "flie"`, an unknown TOML key, a level that is
//! not a usable IRI — is a hard error naming the file. The operator asked for
//! something; giving them something else without saying so is the failure this
//! crate exists to make impossible elsewhere.
//!
//! One check is deliberately *not* here: whether the configured level is a
//! level the **vocabulary defines**. Levels are extensible (a module may load
//! its own), so only the writer — which holds the vocabulary it will actually
//! run against — can judge that, and it does, loudly, at
//! [`crate::Writer::open`].

use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;

use crate::line::is_iri;
use crate::vocabulary::LOG_NS;

/// The config file stem the log layers: `log.toml` shared, `{app}.log.toml` as
/// one application's override.
pub const STEM: &str = "log.toml";

/// The instance-IRI prefix a bare configured name is skolemized under.
pub const INSTANCE_NS: &str = "urn:ikigai:instance:";

/// The level a segment runs at when nothing states one.
pub const DEFAULT_LEVEL: &str = "https://ikigai-rs.dev/ns/log#info";

/// The instance name assumed when nothing states one — deliberately the same
/// string `ikigai_embedded::instance_name()` falls back to, so a host that has
/// not been told its own name and a log that has not been told either agree
/// rather than disagreeing quietly.
pub const DEFAULT_INSTANCE_NAME: &str = "repl";

/// The subdirectory of the ikigai data home that segments land in when no
/// `directory` is configured.
pub const DEFAULT_DIRECTORY_STEM: &str = "log";

/// Where a segment's lines go.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Destination {
    /// Nothing is written, and no segment is opened.
    ///
    /// **The default, and the default is the quiet one on purpose.** A one-shot
    /// `ikigai -c` or a REPL session that opened a segment would put a process
    /// that did nothing into the journal beside the daemons — the same hazard
    /// `ikigai-embedded` already dodges by scheduling its heartbeat only when
    /// reactive. A host that means to log says so.
    #[default]
    Off,
    /// The process's own diagnostic stream — stderr natively, and whatever the
    /// host installs (`console.log`) in a browser.
    ///
    /// **stderr, never stdout**: stdout is the pipeline's data channel, and a
    /// log line landing in it corrupts the very composition this system is for.
    Console,
    /// A segment file under [`LogConfig::directory`].
    File,
}

impl Destination {
    /// The token an operator writes in `log.toml`, and the one the plain face
    /// prints back.
    pub fn as_str(self) -> &'static str {
        match self {
            Destination::Off => "off",
            Destination::Console => "console",
            Destination::File => "file",
        }
    }

    /// The vocabulary individual this destination is, for the graph face.
    pub fn iri(self) -> String {
        format!("{LOG_NS}{}", self.as_str())
    }

    /// Parse a `destination =` value.
    pub fn parse(token: &str) -> Option<Destination> {
        match token {
            "off" => Some(Destination::Off),
            "console" => Some(Destination::Console),
            "file" => Some(Destination::File),
            _ => None,
        }
    }
}

/// What went wrong reading or merging a config. Every variant names the key it
/// blames, because the operator's next move is to edit that line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The TOML did not parse, or carried a key the schema does not define.
    Parse {
        /// The file it came from, when it came from one.
        path: Option<PathBuf>,
        /// The parser's own message.
        message: String,
    },
    /// A value that is present and unusable.
    BadValue {
        /// The key, as written in the file.
        key: &'static str,
        /// What was written.
        value: String,
        /// What was expected instead.
        expected: String,
    },
    /// A config file exists but could not be read.
    Unreadable {
        /// The file.
        path: PathBuf,
        /// The OS error.
        message: String,
    },
    /// A config file could not be written.
    Unwritable {
        /// The file.
        path: PathBuf,
        /// The OS error.
        message: String,
    },
    /// Neither `XDG_CONFIG_HOME` nor `HOME` is set, so there is no config home
    /// to layer within. Not the same as "no config file": an absent file means
    /// the layer below decides, an absent config HOME means the process cannot
    /// tell whether there was one.
    NoConfigHome,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Parse { path, message } => match path {
                Some(path) => write!(f, "{}: {message}", path.display()),
                None => write!(f, "{message}"),
            },
            ConfigError::BadValue {
                key,
                value,
                expected,
            } => write!(f, "{key}: {value:?} is not {expected}"),
            ConfigError::Unreadable { path, message } => write!(f, "{}: {message}", path.display()),
            ConfigError::Unwritable { path, message } => write!(f, "{}: {message}", path.display()),
            ConfigError::NoConfigHome => {
                f.write_str("no ikigai config home: neither XDG_CONFIG_HOME nor HOME is set")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// The **effective** log config: every key resolved, nothing optional except a
/// `directory` that has not been stated and is therefore the data home's.
///
/// This is what `urn:log:config` serves. It is never the contents of one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogConfig {
    /// The level this process's segment runs at, as an absolute IRI. Resolved
    /// against the vocabulary once, at [`crate::Writer::open`].
    pub level: String,
    /// Where the lines go.
    pub destination: Destination,
    /// Where segment files land. `None` is not "nowhere" — it is "the data
    /// home's `log` directory", which only a process that knows its `$HOME` can
    /// name, so the resolution belongs at open time and not here.
    pub directory: Option<PathBuf>,
    /// The writing process, as an absolute IRI: the attribution key, since the
    /// log is per-process rather than per-machine.
    pub instance: String,
    /// The files that contributed, lowest precedence first — provenance, not
    /// configuration. Skipped in the TOML face so that face round-trips as a
    /// config file; present in the graph face, where it answers "why is the
    /// level debug?" without a second lookup.
    pub layers: Vec<PathBuf>,
}

impl Default for LogConfig {
    /// The quiet default: `off`, at `info`, attributed to `repl`.
    ///
    /// A host that logs overrides this before layering the files on top —
    /// `LogConfig::default().with_destination(Destination::Console)` for a
    /// server or a browser. The module cannot make that call itself; it does
    /// not know what it is inside.
    fn default() -> Self {
        LogConfig {
            level: DEFAULT_LEVEL.to_string(),
            destination: Destination::Off,
            directory: None,
            instance: instance_iri(DEFAULT_INSTANCE_NAME),
            layers: Vec::new(),
        }
    }
}

/// A configured instance name as the IRI it means: a bare `bug:serve` becomes
/// `urn:ikigai:instance:bug:serve`, and something already absolute is left
/// alone.
///
/// The bare form is what a host has (`ikigai_embedded::instance_name()` answers
/// `repl` until it is told otherwise) and the IRI is what the header needs; a
/// config that demanded the IRI would push string concatenation into every
/// host and get a different spelling from each.
pub fn instance_iri(name: &str) -> String {
    if name.starts_with(INSTANCE_NS) {
        name.to_string()
    } else {
        format!("{INSTANCE_NS}{name}")
    }
}

/// A name made unique among the processes running right now, by suffixing the
/// process id: `serve` → `serve-64213`.
///
/// **The pid, not a random token.** Both are self-assigned and both are unique
/// among *live* processes, which is exactly the span a name has to be unique
/// over — an instance name arbitrates who may write a segment now, and the
/// run boundary a span join keys off is `log:ProcessStart`, not the name. The
/// pid additionally points at something: an operator reading
/// `urn:ikigai:instance:serve-64213` in a graph can go and look at process
/// 64213, which a random token cannot offer. Uniqueness *over time* is carried
/// by the segment IRI, which embeds the instant the segment opened, so a pid
/// the OS reuses next week names a different segment either way.
pub fn disambiguated(name: &str, token: u32) -> String {
    format!("{name}-{token}")
}

/// A configured level as the IRI it means: a bare `info` and a `log:info` CURIE
/// both become `https://ikigai-rs.dev/ns/log#info`, and an absolute IRI (a
/// module's own level) is left alone.
pub fn level_iri(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    if let Some(local) = name.strip_prefix("log:") {
        return (!local.is_empty()).then(|| format!("{LOG_NS}{local}"));
    }
    if is_iri(name) {
        return Some(name.to_string());
    }
    // A bare token — the operator-facing spelling.
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        .then(|| format!("{LOG_NS}{name}"))
}

impl LogConfig {
    /// The destination this config uses (builder).
    #[must_use]
    pub fn with_destination(mut self, destination: Destination) -> Self {
        self.destination = destination;
        self
    }

    /// The instance name this process is attributed to — bare or absolute
    /// (builder). What `--name` and the `instance =` key both land in.
    #[must_use]
    pub fn with_instance(mut self, name: &str) -> Self {
        self.instance = instance_iri(name);
        self
    }

    /// A **self-assigned** instance name under `prefix`: `serve` becomes
    /// `serve-64213` (builder).
    ///
    /// This is the knob for the common case the policy creates — several
    /// `ikigai serve` processes on one machine, none of them given a `--name`.
    /// A host that has been told a name calls [`with_instance`](Self::with_instance);
    /// a host that has not calls this and gets one that will not contend.
    ///
    /// Native only: the process id is the token, and a browser has none. A wasm
    /// host names its own tab through `with_instance`.
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn with_self_assigned_instance(self, prefix: &str) -> Self {
        self.with_instance(&disambiguated(prefix, std::process::id()))
    }

    /// The level this process's segments run at — bare, CURIE or absolute
    /// (builder). An unusable spelling is rejected here rather than silently
    /// kept.
    pub fn with_level(mut self, level: &str) -> Result<Self, ConfigError> {
        self.level = level_iri(level).ok_or_else(|| ConfigError::BadValue {
            key: "level",
            value: level.to_string(),
            expected: "a level name, a log: CURIE, or an absolute IRI".to_string(),
        })?;
        Ok(self)
    }

    /// The directory segment files land in (builder).
    #[must_use]
    pub fn with_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.directory = Some(directory.into());
        self
    }

    /// Fold one layer in, key-wise: a key the layer states wins, a key it stays
    /// silent about survives from below.
    ///
    /// **Never wholesale.** "The last file that exists wins" is the easy
    /// accidental implementation, and it drops the operator's shared level the
    /// moment one front end wants a different destination.
    pub fn apply(&mut self, patch: &Patch) {
        if let Some(level) = &patch.level {
            // Shape-checked by `Patch::parse`; unwrapping the expansion here
            // would re-derive a check the layer already passed.
            if let Some(iri) = level_iri(level) {
                self.level = iri;
            }
        }
        if let Some(destination) = patch.destination {
            self.destination = destination;
        }
        if let Some(directory) = &patch.directory {
            self.directory = Some(PathBuf::from(directory));
        }
        if let Some(instance) = &patch.instance {
            self.instance = instance_iri(instance);
        }
    }

    /// The bare instance name — the IRI with [`INSTANCE_NS`] stripped. What a
    /// file name and a lock file are built from.
    pub fn instance_name(&self) -> &str {
        self.instance
            .strip_prefix(INSTANCE_NS)
            .unwrap_or(&self.instance)
    }

    /// The TOML face: the effective config as a file an operator could paste
    /// back. Provenance (`layers`) is deliberately absent — it is not
    /// configuration, and a face that round-trips must not carry it.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("level = {:?}\n", short_level(&self.level)));
        out.push_str(&format!("destination = {:?}\n", self.destination.as_str()));
        if let Some(directory) = &self.directory {
            out.push_str(&format!(
                "directory = {:?}\n",
                directory.display().to_string()
            ));
        }
        out.push_str(&format!("instance = {:?}\n", self.instance_name()));
        out
    }

    /// The graph face — skolemized, no blank nodes, the layers included.
    ///
    /// `open_segment` is the segment being written right now, as
    /// `(name, effective instance)`. It is the question a reader of this
    /// resource most often has and the one the config alone cannot answer:
    /// `destination = "file"` in a process whose host never opened a writer
    /// means nothing is being logged — and the effective instance can differ
    /// from the configured one, since a name already held gets disambiguated
    /// rather than refused.
    pub fn to_turtle(&self, subject: &str, open_segment: Option<(&str, &str)>) -> String {
        let mut out = String::new();
        out.push_str("@prefix log:  <https://ikigai-rs.dev/ns/log#> .\n");
        out.push_str("@prefix prov: <http://www.w3.org/ns/prov#> .\n");
        out.push_str("@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .\n\n");
        out.push_str(&format!("<{subject}> a log:Config ;\n"));
        out.push_str(&format!("    log:level <{}> ;\n", self.level));
        out.push_str(&format!(
            "    log:destination <{}> ;\n",
            self.destination.iri()
        ));
        if let Some(directory) = &self.directory {
            out.push_str(&format!(
                "    log:directory {:?} ;\n",
                directory.display().to_string()
            ));
        }
        out.push_str(&format!("    log:instance <{}> ;\n", self.instance));
        for layer in &self.layers {
            out.push_str(&format!(
                "    log:configLayer {:?} ;\n",
                layer.display().to_string()
            ));
        }
        match open_segment {
            Some((name, _)) => out.push_str(&format!("    log:currentSegment <{name}> .\n\n")),
            None => out.push_str("    log:currentSegment log:none .\n\n"),
        }
        out.push_str(&format!("<{}> a log:Instance .\n", self.instance));
        if let Some((name, instance)) = open_segment {
            out.push_str(&format!(
                "<{name}> a log:Segment ;\n    log:level <{}> ;\n    prov:wasAttributedTo <{instance}> .\n",
                self.level
            ));
            if instance != self.instance {
                out.push_str(&format!(
                    "<{instance}> a log:Instance ;\n    log:configuredInstance <{}> .\n",
                    self.instance
                ));
            }
        }
        out
    }
}

/// The short spelling of a level IRI — `info` for a `log:` level, the IRI
/// itself for one from somewhere else.
fn short_level(iri: &str) -> &str {
    iri.strip_prefix(LOG_NS).unwrap_or(iri)
}

/// One layer's contents: every key optional, because a layer states only its
/// differences. `deny_unknown_fields` is what makes a typo loud.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    /// The level this layer states.
    pub level: Option<String>,
    /// The destination this layer states.
    pub destination: Option<Destination>,
    /// The segment directory this layer states.
    pub directory: Option<String>,
    /// The instance name this layer states.
    pub instance: Option<String>,
}

impl Patch {
    /// Parse one layer from TOML text. `path` is carried only for the error
    /// message; parsing does not read it.
    pub fn parse(toml_text: &str, path: Option<PathBuf>) -> Result<Patch, ConfigError> {
        let patch: Patch = toml::from_str(toml_text).map_err(|e| ConfigError::Parse {
            path,
            message: e.message().to_string(),
        })?;
        patch.validate()?;
        Ok(patch)
    }

    /// Check every value this layer *states*, before it is merged.
    ///
    /// Validating each layer rather than only the merged result is deliberate:
    /// a misspelled level in the shared `log.toml` is a real defect even when
    /// one application's override happens to hide it, and hiding it is exactly
    /// how it reaches every OTHER application unnoticed.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(level) = &self.level {
            if level_iri(level).is_none() {
                return Err(ConfigError::BadValue {
                    key: "level",
                    value: level.clone(),
                    expected: "a level name, a log: CURIE, or an absolute IRI".to_string(),
                });
            }
        }
        if let Some(instance) = &self.instance {
            if !is_iri(&instance_iri(instance)) {
                return Err(ConfigError::BadValue {
                    key: "instance",
                    value: instance.clone(),
                    expected: "a name with no whitespace, or an absolute IRI".to_string(),
                });
            }
        }
        if let Some(directory) = &self.directory {
            if directory.trim().is_empty() {
                return Err(ConfigError::BadValue {
                    key: "directory",
                    value: directory.clone(),
                    expected: "a path".to_string(),
                });
            }
        }
        Ok(())
    }

    /// This layer as the TOML file it came from — how a `urn:log:config` write
    /// lands on disk.
    ///
    /// **Comments do not survive.** The layer is read as values and written
    /// back as values, so an operator's annotations in the file being written
    /// are lost. That is the honest cost of a config resource that persists
    /// (and the reason the write names the file it touched in its response);
    /// nothing here rewrites a file the caller did not target.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        if let Some(level) = &self.level {
            out.push_str(&format!("level = {level:?}\n"));
        }
        if let Some(destination) = self.destination {
            out.push_str(&format!("destination = {:?}\n", destination.as_str()));
        }
        if let Some(directory) = &self.directory {
            out.push_str(&format!("directory = {directory:?}\n"));
        }
        if let Some(instance) = &self.instance {
            out.push_str(&format!("instance = {instance:?}\n"));
        }
        out
    }

    /// Whether this layer states anything at all.
    pub fn is_empty(&self) -> bool {
        self.level.is_none()
            && self.destination.is_none()
            && self.directory.is_none()
            && self.instance.is_none()
    }
}
