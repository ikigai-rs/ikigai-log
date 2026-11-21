//! The tool-call line: one `log:ToolCall` entry per tool call an agent made,
//! and the `session=` column that groups a trail.
//!
//! ```text
//! 2026-11-21T23:04:17.512Z log:ToolCall urn:tool:Bash session=urn:claude:session:4f1c outcome=ok dur=184 args=sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
//! ```
//!
//! The ikigai-log half of the workspace design's tool-call trail (ledger
//! #3962): a host that observes an agent's tool calls (a Claude hook, a worker
//! loop) writes them here, into the same hash-chained segment as everything
//! else the process logs, and a reader asks for one session's trail at
//! `urn:log:session:{session}` ([`SessionTrailEndpoint`](crate::SessionTrailEndpoint)).
//!
//! ## By default the line holds no argument text
//!
//! A tool call's arguments are a command line, a file's content, a query, and
//! any of them can carry a secret. So a [`ToolCall`] is built from the
//! arguments' text and writes its **digest** (`args=sha256:…`), never the text.
//! A result the host hands over is written as a digest too (`result=sha256:…`).
//! The text is written only when the writer opts in, once, for the whole log
//! ([`ToolCallLog::with_text`]), as `args-text=` and `result-text=`, quoted and
//! escaped like every free-text column. No single call can opt itself in.
//!
//! A digest tells two calls with the same arguments apart from two with
//! different ones, and lets a reader who holds the arguments check them. It is
//! **not** a secret-keeping device for short or guessable arguments: SHA-256 of
//! `ls` is one guess away. What it guarantees is that the line never states the
//! text, which is what keeps a segment shippable.
//!
//! ## The session column
//!
//! `session=` is the session's IRI, written bare so `grep 'session=urn:…'`
//! finds a trail. It is declared on `log:Entry` ([`SESSION_KEY`]), so any line
//! may carry it; a [`ToolCall`] always does, and a door line can
//! ([`Access::session`](crate::Access::session)).
//!
//! ## Long text is cut, and the cut is named
//!
//! An opted-in text column is cut at [`MAX_TOOL_TEXT`] bytes, on a character
//! boundary, and ended with [`CUT_MARKER`](crate::CUT_MARKER). Unlike the door
//! line's percent-encoded columns, this text is written as it is, so it may
//! hold a `…` of its own; a cut is therefore also named in a `cut=` column
//! (`cut=args-text`), and the digest always covers the whole text.

use std::sync::Arc;

use crate::access::{cut, encode_text, CUT_MARKER};
use crate::chain::tagged;
use crate::endpoints::LogHandle;
use crate::line::{is_iri, shown, Entry, Timestamp};
use crate::tracer::{bare_iri_column, ColumnRefusal};
use crate::vocabulary::{SESSION_KEY, TOOL_CALL_CLASS};
use crate::WriteError;

/// The namespace a tool's name is written under as the subject of a
/// `log:ToolCall` line: `urn:tool:Bash`, `urn:tool:mcp__github__create_issue`.
///
/// ```
/// assert_eq!(ikigai_log::TOOL_NS, "urn:tool:");
/// ```
pub const TOOL_NS: &str = "urn:tool:";

/// The longest a session IRI may be, in bytes: core's principal bound, for the
/// same reason it bounds a principal. A session is refused rather than cut.
pub const MAX_SESSION_LEN: usize = ikigai_core::MAX_PRINCIPAL_LEN;

/// The longest an opted-in `args-text=` or `result-text=` column is written,
/// in bytes, before it is cut.
///
/// ```
/// assert_eq!(ikigai_log::MAX_TOOL_TEXT, 4096);
/// ```
pub const MAX_TOOL_TEXT: usize = 4096;

/// The session a line belongs to, as an IRI that can be written as a bare
/// `session=` column and read back as itself.
///
/// ```
/// use ikigai_log::Session;
///
/// assert!(Session::new("urn:claude:session:4f1c").is_ok());
/// assert!(Session::new("not a session").is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Session(String);

impl Session {
    /// The session named by `iri`, or why it cannot be written.
    pub fn new(iri: impl Into<String>) -> Result<Session, ToolCallError> {
        let iri = iri.into();
        let detail = match bare_iri_column(SESSION_KEY, &iri, MAX_SESSION_LEN) {
            Ok(()) => return Ok(Session(iri)),
            Err(ColumnRefusal::TooLong) => format!(
                "a session may be at most {MAX_SESSION_LEN} bytes and this one is {}",
                iri.len()
            ),
            Err(ColumnRefusal::NotAColumn(detail)) => detail,
            Err(ColumnRefusal::NotAnRdfIri) => "it is not an IRI RDF will accept".to_string(),
        };
        Err(ToolCallError::Session {
            offered: iri,
            detail,
        })
    }

    /// The IRI, as it is written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a tool call ended: the `outcome=` column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolOutcome {
    /// The tool ran and answered: `ok`.
    Ok,
    /// The call was refused before the tool ran (a permission rule, a hook, a
    /// person saying no): `refused`.
    Refused,
    /// The tool ran and failed: `failed`.
    Failed,
}

impl ToolOutcome {
    /// The token written in the `outcome=` column.
    pub fn token(self) -> &'static str {
        match self {
            ToolOutcome::Ok => "ok",
            ToolOutcome::Refused => "refused",
            ToolOutcome::Failed => "failed",
        }
    }
}

/// Why a tool-call line was not written.
#[derive(Debug)]
pub enum ToolCallError {
    /// The session cannot be written as a bare IRI column.
    Session {
        /// What was offered.
        offered: String,
        /// Why not, in one clause.
        detail: String,
    },
    /// The tool's name is empty, or is not an IRI even percent-encoded.
    Tool {
        /// What was offered.
        offered: String,
    },
    /// The writer did not land the entry.
    Write(WriteError),
}

impl std::fmt::Display for ToolCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolCallError::Session { offered, detail } => write!(
                f,
                "{} cannot be written as a session: {detail}",
                shown(offered)
            ),
            ToolCallError::Tool { offered } if offered.is_empty() => {
                write!(
                    f,
                    "a tool-call line needs a tool name and this one is empty"
                )
            }
            ToolCallError::Tool { offered } => write!(
                f,
                "{} cannot name the tool of a tool-call line",
                shown(offered)
            ),
            ToolCallError::Write(e) => write!(f, "the tool-call line was not written: {e}"),
        }
    }
}

impl std::error::Error for ToolCallError {}

impl From<WriteError> for ToolCallError {
    fn from(e: WriteError) -> Self {
        ToolCallError::Write(e)
    }
}

/// One tool call, as the host that observed it knew it. Built once the call
/// has ended, and handed to [`ToolCallLog::record`].
#[derive(Clone, Debug)]
pub struct ToolCall {
    started: Timestamp,
    session: Session,
    tool: String,
    outcome: ToolOutcome,
    duration_ms: Option<u64>,
    arguments: String,
    result: Option<String>,
}

impl ToolCall {
    /// A call to the tool named `tool`, in `session`, begun at `started`, with
    /// `arguments` as the tool received them (a JSON object, a command line),
    /// which ended in `outcome`.
    ///
    /// `arguments` is digested, never written, unless the log opted in
    /// ([`ToolCallLog::with_text`]).
    pub fn new(
        started: Timestamp,
        session: Session,
        tool: impl Into<String>,
        arguments: impl Into<String>,
        outcome: ToolOutcome,
    ) -> ToolCall {
        ToolCall {
            started,
            session,
            tool: tool.into(),
            outcome,
            duration_ms: None,
            arguments: arguments.into(),
            result: None,
        }
    }

    /// How long the call took, in milliseconds.
    #[must_use]
    pub fn duration_ms(mut self, duration_ms: u64) -> ToolCall {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// What the tool answered. Digested as `result=`, and written as text only
    /// when the log opted in.
    #[must_use]
    pub fn result(mut self, result: impl Into<String>) -> ToolCall {
        self.result = Some(result.into());
        self
    }

    /// The subject IRI this call is written under: [`TOOL_NS`] and the tool's
    /// name, percent-encoded to ASCII.
    pub fn tool_iri(&self) -> Result<String, ToolCallError> {
        let iri = cut(format!("{TOOL_NS}{}", encode_text(&self.tool)));
        if self.tool.is_empty() || !is_iri(&iri) || iri.ends_with(CUT_MARKER) {
            return Err(ToolCallError::Tool {
                offered: self.tool.clone(),
            });
        }
        Ok(iri)
    }

    /// The [`Entry`] this call is written as, with no argument or result text:
    /// what [`ToolCallLog::record`] writes unless the log opted in.
    pub fn entry(&self) -> Result<Entry, ToolCallError> {
        self.entry_with(false)
    }

    /// The [`Entry`] this call is written as, with the argument and result text
    /// when `text` is true.
    pub(crate) fn entry_with(&self, text: bool) -> Result<Entry, ToolCallError> {
        let mut entry = Entry::new(self.started, TOOL_CALL_CLASS, self.tool_iri()?)
            .with(SESSION_KEY, self.session.as_str())
            .with("outcome", self.outcome.token());
        if let Some(duration) = self.duration_ms {
            entry = entry.with("dur", duration.to_string());
        }
        entry = entry.with("args", tagged(self.arguments.as_bytes()));
        if let Some(result) = &self.result {
            entry = entry.with("result", tagged(result.as_bytes()));
        }
        if text {
            let mut cuts = Vec::new();
            let (args, was_cut) = cut_text(&self.arguments);
            entry = entry.with("args-text", args);
            if was_cut {
                cuts.push("args-text");
            }
            if let Some(result) = &self.result {
                let (result, was_cut) = cut_text(result);
                entry = entry.with("result-text", result);
                if was_cut {
                    cuts.push("result-text");
                }
            }
            if !cuts.is_empty() {
                entry = entry.with("cut", cuts.join(","));
            }
        }
        Ok(entry)
    }
}

/// Cut `text` at [`MAX_TOOL_TEXT`] bytes on a character boundary and end it
/// with [`CUT_MARKER`]. Says whether it cut.
fn cut_text(text: &str) -> (String, bool) {
    if text.len() <= MAX_TOOL_TEXT {
        return (text.to_string(), false);
    }
    let mut end = MAX_TOOL_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}{CUT_MARKER}", &text[..end]), true)
}

/// The tool-call line's writer.
///
/// ```no_run
/// # use std::sync::Arc;
/// # use ikigai_log::{LogHandle, Session, Timestamp, ToolCall, ToolCallLog, ToolOutcome};
/// # fn hook(handle: Arc<LogHandle>) -> Result<(), Box<dyn std::error::Error>> {
/// let calls = ToolCallLog::new(handle);
/// let session = Session::new("urn:claude:session:4f1c")?;
/// calls.record(
///     &ToolCall::new(Timestamp::from_millis(0), session, "Bash", r#"{"command":"ls"}"#, ToolOutcome::Ok)
///         .duration_ms(184),
/// )?;
/// # Ok(())
/// # }
/// ```
pub struct ToolCallLog {
    handle: Arc<LogHandle>,
    text: bool,
}

impl ToolCallLog {
    /// A tool-call log writing into `handle`, digests only.
    pub fn new(handle: Arc<LogHandle>) -> ToolCallLog {
        ToolCallLog {
            handle,
            text: false,
        }
    }

    /// The same log, writing the argument and result TEXT beside the digests
    /// (`args-text=`, `result-text=`). The writer's opt-in, for every call it
    /// records: take it only where the segment is as private as the arguments.
    #[must_use]
    pub fn with_text(mut self) -> ToolCallLog {
        self.text = true;
        self
    }

    /// Whether this log writes argument and result text.
    pub fn writes_text(&self) -> bool {
        self.text
    }

    /// Write one tool-call line. `Ok(None)` when no segment is open or the
    /// level dial leaves `log:ToolCall` out, as [`LogHandle::write`] answers.
    pub fn record(&self, call: &ToolCall) -> Result<Option<u64>, ToolCallError> {
        Ok(self.handle.write(call.entry_with(self.text)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_cut_lands_on_a_character_boundary() {
        let text = "é".repeat(MAX_TOOL_TEXT);
        let (out, was_cut) = cut_text(&text);
        assert!(was_cut);
        let body = out.strip_suffix(CUT_MARKER).expect("marked");
        assert!(body.len() <= MAX_TOOL_TEXT);
        assert_eq!(cut_text("short"), ("short".to_string(), false));
    }
}
