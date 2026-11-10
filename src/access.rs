//! The door line: one `log:Access` entry per request a host's door served.
//!
//! "Who did what", written the same way by every host, into the same
//! hash-chained segment as everything else the process logs:
//!
//! ```text
//! 2026-11-10T22:41:06.120Z log:Access urn:cms:page:home door=web verb=GET outcome=ok bytes=5120 dur=12 principal=urn:agent:alice credential=https://ikigai-rs.dev/ns/log#passkey grant=urn:grant:cms:read q=lang=en
//! ```
//!
//! gonk's door line (ledger #739), generalized (ledger #3390). Every column is
//! declared in `vocabulary.ttl`, so a segment transrepts to Turtle with no
//! host-specific parsing, and a host adopts this helper instead of keeping a
//! private access log.
//!
//! ## Attribution is per request
//!
//! A door hands [`AccessLog::tracer_for`] the caller it authenticated and
//! issues the request through
//! [`Kernel::issue_traced`](ikigai_core::Kernel::issue_traced) with that
//! tracer, so the kernel's own entries for the request carry the same
//! `principal=` as its `log:Access` line. Never `set_tracer`: the global slot
//! holds one tracer for the whole process, and a principal on it would credit
//! every tenant's work to one of them.
//!
//! ## What is never written
//!
//! The rules are this helper's, so no host has to remember them:
//!
//! * **No cookie, no `Authorization` header, no session or wire token.** There
//!   is nowhere to put one: an [`Access`] has no header field, and an argument
//!   named for a secret is left out ([`is_withheld`]).
//! * **No form body and no `content` argument**, for the same reason.
//! * **Nothing that identifies an anonymous caller.** [`Caller::Anonymous`]
//!   carries no data, so its line holds `principal=anon` and
//!   `credential=…#anonymous` and nothing more: no address, no fingerprint. Keep
//!   the door's own name ([`Access::new`]'s `door`) to a name for the door.
//!
//! ## Long fields are cut, and the cut is marked
//!
//! Every free-text column (`door`, `verb`, `outcome`, `q`) and the subject are
//! percent-encoded to ASCII, then cut at [`MAX_FIELD`] bytes and ended with
//! [`CUT_MARKER`], `…`. Percent-encoding never writes `…`, so a `…` in one of
//! these columns is always a cut and never part of a value.

use std::sync::Arc;

use ikigai_core::Clock;

use crate::endpoints::LogHandle;
use crate::line::{is_iri, shown, Entry, Timestamp};
use crate::tracer::{bare_iri_column, ColumnRefusal, LogTracer, Principal, ANONYMOUS_PRINCIPAL};
use crate::vocabulary::{ACCESS_CLASS, PRINCIPAL_KEY};
use crate::WriteError;

/// The longest a free-text column or the subject of a `log:Access` line is
/// written, in bytes, before it is cut and marked with [`CUT_MARKER`].
///
/// ```
/// assert_eq!(ikigai_log::MAX_FIELD, 256);
/// ```
pub const MAX_FIELD: usize = 256;

/// What ends a column [`MAX_FIELD`] cut: `…`, U+2026. Columns are
/// percent-encoded to ASCII first, so this is never part of a value.
pub const CUT_MARKER: &str = "\u{2026}";

/// The longest grant IRI written: core's principal bound, for the same reason
/// it bounds a principal. A grant is an IRI and is refused rather than cut.
pub const MAX_GRANT_LEN: usize = ikigai_core::MAX_PRINCIPAL_LEN;

/// `log:passkey`.
pub const PASSKEY_CREDENTIAL: &str = "https://ikigai-rs.dev/ns/log#passkey";
/// `log:clientCertificate`.
pub const CLIENT_CERTIFICATE_CREDENTIAL: &str = "https://ikigai-rs.dev/ns/log#clientCertificate";
/// `log:socketOwner`.
pub const SOCKET_OWNER_CREDENTIAL: &str = "https://ikigai-rs.dev/ns/log#socketOwner";
/// `log:anonymous`.
pub const ANONYMOUS_CREDENTIAL: &str = "https://ikigai-rs.dev/ns/log#anonymous";

/// The argument names a door line never writes, compared without regard to
/// case, `-` or `_`. A name that CONTAINS one of the last six is withheld too,
/// so `access_token`, `X-Session-Id` and `new-password` are.
pub const WITHHELD_ARGUMENTS: [&str; 9] = [
    "content",
    "body",
    "form",
    "cookie",
    "authorization",
    "session",
    "token",
    "password",
    "secret",
];

/// Whether an argument named `name` is left out of a door line's `q=`.
///
/// ```
/// use ikigai_log::is_withheld;
///
/// assert!(is_withheld("content"));
/// assert!(is_withheld("Authorization"));
/// assert!(is_withheld("access_token"));
/// assert!(is_withheld("X-Session-Id"));
/// assert!(!is_withheld("lang"));
/// ```
pub fn is_withheld(name: &str) -> bool {
    let folded: String = name
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect();
    WITHHELD_ARGUMENTS
        .iter()
        .enumerate()
        .any(|(i, withheld)| folded == *withheld || (i >= 3 && folded.contains(withheld)))
}

/// How a door knew who its caller was: a `log:CredentialKind`. The kind, never
/// the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credential {
    /// A WebAuthn passkey assertion: `log:passkey`.
    Passkey,
    /// A TLS client certificate: `log:clientCertificate`.
    ClientCertificate,
    /// The owner of a local socket's peer process: `log:socketOwner`.
    SocketOwner,
}

impl Credential {
    /// The `log:CredentialKind` IRI written in the `credential=` column.
    pub fn iri(self) -> &'static str {
        match self {
            Credential::Passkey => PASSKEY_CREDENTIAL,
            Credential::ClientCertificate => CLIENT_CERTIFICATE_CREDENTIAL,
            Credential::SocketOwner => SOCKET_OWNER_CREDENTIAL,
        }
    }
}

/// Who made a request, as the door established it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// A caller the door authenticated, and how.
    Authenticated {
        /// Who.
        principal: Principal,
        /// How the door knew.
        credential: Credential,
    },
    /// A caller the door did not authenticate. It carries nothing, so nothing
    /// that identifies the caller can be written: the line says
    /// `principal=anon` and `credential=…#anonymous`.
    Anonymous,
}

impl Caller {
    /// An authenticated caller.
    pub fn authenticated(principal: Principal, credential: Credential) -> Caller {
        Caller::Authenticated {
            principal,
            credential,
        }
    }

    /// What `principal=` says: the principal's IRI, or `anon`.
    pub fn principal(&self) -> &str {
        match self {
            Caller::Authenticated { principal, .. } => principal.as_str(),
            Caller::Anonymous => ANONYMOUS_PRINCIPAL,
        }
    }

    /// What `credential=` says: a `log:CredentialKind` IRI.
    pub fn credential(&self) -> &'static str {
        match self {
            Caller::Authenticated { credential, .. } => credential.iri(),
            Caller::Anonymous => ANONYMOUS_CREDENTIAL,
        }
    }
}

/// The grant that authorized a request, as an IRI that can be written as a
/// bare column: the policy the door applied, never a token that carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant(String);

impl Grant {
    /// The grant named by `iri`, or why it cannot be written.
    ///
    /// ```
    /// use ikigai_log::Grant;
    ///
    /// assert!(Grant::new("urn:grant:cms:read").is_ok());
    /// assert!(Grant::new("not a grant").is_err());
    /// ```
    pub fn new(iri: impl Into<String>) -> Result<Grant, AccessError> {
        let iri = iri.into();
        let detail = match bare_iri_column("grant", &iri, MAX_GRANT_LEN) {
            Ok(()) => return Ok(Grant(iri)),
            Err(ColumnRefusal::TooLong) => format!(
                "a grant may be at most {MAX_GRANT_LEN} bytes and this one is {}",
                iri.len()
            ),
            Err(ColumnRefusal::NotAColumn(detail)) => detail,
            Err(ColumnRefusal::NotAnRdfIri) => "it is not an IRI RDF will accept".to_string(),
        };
        Err(AccessError::Grant {
            offered: iri,
            detail,
        })
    }

    /// The IRI, as it is written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a door line was not written.
#[derive(Debug)]
pub enum AccessError {
    /// The grant cannot be written as a bare IRI column.
    Grant {
        /// What was offered.
        offered: String,
        /// Why not, in one clause.
        detail: String,
    },
    /// The subject is not an absolute IRI, even percent-encoded and cut.
    Subject {
        /// What was offered.
        offered: String,
    },
    /// A column every door line carries was empty.
    Empty {
        /// Which column.
        key: &'static str,
    },
    /// The writer did not land the entry.
    Write(WriteError),
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessError::Grant { offered, detail } => {
                write!(
                    f,
                    "{} cannot be written as a grant: {detail}",
                    shown(offered)
                )
            }
            AccessError::Subject { offered } => write!(
                f,
                "{} cannot be the subject of a door line: it is not an absolute IRI",
                shown(offered)
            ),
            AccessError::Empty { key } => {
                write!(f, "a door line needs a {key}= column and this one is empty")
            }
            AccessError::Write(e) => write!(f, "the door line was not written: {e}"),
        }
    }
}

impl std::error::Error for AccessError {}

impl From<WriteError> for AccessError {
    fn from(e: WriteError) -> Self {
        AccessError::Write(e)
    }
}

/// One request, as its door knew it. Built once the door has answered, and
/// handed to [`AccessLog::record`].
#[derive(Clone, Debug)]
pub struct Access {
    started: Timestamp,
    subject: String,
    door: String,
    verb: String,
    outcome: String,
    caller: Caller,
    bytes: Option<u64>,
    duration_ms: Option<u64>,
    grant: Option<Grant>,
    arguments: Vec<(String, String)>,
}

impl Access {
    /// A request to `subject`, received by `door` with `verb` from `caller` at
    /// `started`, which ended in `outcome` (`ok`, or one error-kind token).
    ///
    /// `started` is read from the same clock the kernel runs on, so the line
    /// sits on one timeline with the resolutions it caused. `door` names the
    /// door (`web`, `wire`, `cli`) and never the caller's address.
    pub fn new(
        started: Timestamp,
        subject: impl Into<String>,
        door: impl Into<String>,
        verb: impl Into<String>,
        outcome: impl Into<String>,
        caller: Caller,
    ) -> Access {
        Access {
            started,
            subject: subject.into(),
            door: door.into(),
            verb: verb.into(),
            outcome: outcome.into(),
            caller,
            bytes: None,
            duration_ms: None,
            grant: None,
            arguments: Vec::new(),
        }
    }

    /// How many bytes the door sent back.
    #[must_use]
    pub fn bytes(mut self, bytes: u64) -> Access {
        self.bytes = Some(bytes);
        self
    }

    /// How long the request took, in milliseconds.
    #[must_use]
    pub fn duration_ms(mut self, duration_ms: u64) -> Access {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// The grant that authorized the request.
    #[must_use]
    pub fn grant(mut self, grant: Grant) -> Access {
        self.grant = Some(grant);
        self
    }

    /// One argument the door served. An argument [`is_withheld`] names is kept
    /// out of the line.
    #[must_use]
    pub fn argument(mut self, name: impl Into<String>, value: impl Into<String>) -> Access {
        self.arguments.push((name.into(), value.into()));
        self
    }

    /// The [`Entry`] this request is written as.
    pub fn entry(&self) -> Result<Entry, AccessError> {
        let subject = cut(encode_iri(&self.subject));
        if !is_iri(&subject) {
            return Err(AccessError::Subject {
                offered: self.subject.clone(),
            });
        }
        let mut entry = Entry::new(self.started, ACCESS_CLASS, subject);
        for (key, value) in [
            ("door", &self.door),
            ("verb", &self.verb),
            ("outcome", &self.outcome),
        ] {
            if value.is_empty() {
                return Err(AccessError::Empty { key });
            }
            entry = entry.with(key, cut(encode_text(value)));
        }
        if let Some(bytes) = self.bytes {
            entry = entry.with("bytes", bytes.to_string());
        }
        if let Some(duration) = self.duration_ms {
            entry = entry.with("dur", duration.to_string());
        }
        entry = entry
            .with(PRINCIPAL_KEY, self.caller.principal())
            .with("credential", self.caller.credential());
        if let Some(grant) = &self.grant {
            entry = entry.with("grant", grant.as_str());
        }
        let served: Vec<String> = self
            .arguments
            .iter()
            .filter(|(name, _)| !is_withheld(name))
            .map(|(name, value)| format!("{}={}", encode_text(name), encode_text(value)))
            .collect();
        if !served.is_empty() {
            entry = entry.with("q", cut(served.join("&")));
        }
        Ok(entry)
    }
}

/// The door line's writer: the one place a host's doors record who did what.
///
/// Holds a base [`LogTracer`] and derives one per caller, sharing its handle,
/// clock and drop ledger, so the access line and the kernel's entries for the
/// same request land in the same segment under the same principal.
///
/// ```no_run
/// # use std::sync::Arc;
/// # use ikigai_core::{Capability, Clock, Kernel, Request, SystemClock};
/// # use ikigai_log::{Access, AccessLog, Caller, Credential, LogHandle, Principal, Timestamp};
/// # async fn door(kernel: &Kernel, handle: Arc<LogHandle>, request: Request,
/// #               capability: &Capability) -> Result<(), Box<dyn std::error::Error>> {
/// let clock: Arc<dyn Clock> = Arc::new(SystemClock);
/// let doors = AccessLog::new(handle, Arc::clone(&clock));
/// // Per request: the caller this door authenticated.
/// let caller = Caller::authenticated(Principal::new("urn:agent:alice")?, Credential::Passkey);
/// let started = clock.now().as_millis();
/// let answer = kernel
///     .issue_traced(request, capability, doors.tracer_for(&caller))
///     .await?;
/// let ended = clock.now().as_millis();
/// doors.record(
///     &Access::new(Timestamp::from_millis(started), "urn:cms:page:home", "web", "GET", "ok", caller)
///         .bytes(answer.bytes.len() as u64)
///         .duration_ms(ended - started),
/// )?;
/// # Ok(())
/// # }
/// ```
pub struct AccessLog {
    base: LogTracer,
}

impl AccessLog {
    /// A door log writing into `handle`. `clock` must be the kernel's own.
    pub fn new(handle: Arc<LogHandle>, clock: Arc<dyn Clock>) -> AccessLog {
        AccessLog {
            base: LogTracer::new(handle, clock),
        }
    }

    /// A door log sharing `tracer`'s handle, clock and drop ledger: what a host
    /// that already installed a process tracer builds, so a loss either one
    /// counts is marked by the next entry either one lands.
    pub fn sharing(tracer: &LogTracer) -> AccessLog {
        AccessLog {
            base: tracer.derive(None),
        }
    }

    /// The tracer to hand [`Kernel::issue_traced`](ikigai_core::Kernel::issue_traced)
    /// for one request from `caller`: every entry it records that the
    /// capability names no principal for is attributed to `caller`, `anon`
    /// included. Never install it with `set_tracer`.
    pub fn tracer_for(&self, caller: &Caller) -> Arc<LogTracer> {
        Arc::new(self.base.derive(Some(match caller {
            Caller::Authenticated { principal, .. } => principal.clone(),
            Caller::Anonymous => Principal::anonymous(),
        })))
    }

    /// Write one door line. `Ok(None)` when no segment is open or the level
    /// dial leaves `log:Access` out, as [`LogHandle::write`] answers.
    pub fn record(&self, access: &Access) -> Result<Option<u64>, AccessError> {
        Ok(self.base.handle().write(access.entry()?)?)
    }
}

/// Percent-encode everything but RFC 3986's unreserved characters and the
/// sub-delimiters and separators that read plainly in a bare column. `&`, `=`
/// and `%` are always encoded, so `q=`'s pairs split back unambiguously. ASCII
/// out, whatever came in.
fn encode_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~:/@!$'()*+,;".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Map an IRI to the URI it stands for (RFC 3987 §3.1): every byte that is not
/// printable ASCII, or that an IRI column cannot hold bare, is percent-encoded,
/// and a `%` that does not start an escape becomes `%25`. ASCII out.
fn encode_iri(iri: &str) -> String {
    let bytes = iri.as_bytes();
    let mut out = String::with_capacity(iri.len());
    for (i, &byte) in bytes.iter().enumerate() {
        let escape_start = byte == b'%'
            && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit);
        if byte.is_ascii_graphic() && !b"<>\"{}|\\^`%".contains(&byte) || escape_start {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Cut an ASCII value at [`MAX_FIELD`] bytes, never inside a `%XX` escape, and
/// end it with [`CUT_MARKER`]. Shorter values are returned as they are.
fn cut(value: String) -> String {
    if value.len() <= MAX_FIELD {
        return value;
    }
    let bytes = value.as_bytes();
    let mut end = MAX_FIELD;
    // Back off from a split escape: a `%` in either of the last two places.
    for back in 1..=2 {
        if bytes[end - back] == b'%' {
            end -= back;
            break;
        }
    }
    let mut out = value[..end].to_string();
    out.push_str(CUT_MARKER);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_writes_ascii_only_so_the_marker_is_never_a_value() {
        for value in [
            "caf\u{e9}",
            "a\u{2026}b",
            "two words",
            "a&b=c%d",
            "\u{202e}x",
        ] {
            let text = encode_text(value);
            let iri = encode_iri(&format!("urn:x:{value}"));
            assert!(text.is_ascii(), "{text}");
            assert!(iri.is_ascii(), "{iri}");
            assert!(!text.contains(CUT_MARKER) && !iri.contains(CUT_MARKER));
        }
        assert_eq!(encode_text("a&b=c%d"), "a%26b%3Dc%25d");
        assert_eq!(encode_iri("urn:x:a%2Fb%zz c"), "urn:x:a%2Fb%25zz%20c");
    }

    #[test]
    fn a_cut_never_splits_an_escape() {
        for pad in 0..3 {
            let value = format!(
                "{}{}",
                "a".repeat(MAX_FIELD - 3 + pad),
                "%E2%80%A6".repeat(4)
            );
            let out = cut(value);
            let body = out.strip_suffix(CUT_MARKER).expect("it is cut and marked");
            assert!(body.len() <= MAX_FIELD);
            let tail = &body[body.rfind('%').unwrap_or(0)..];
            assert!(
                !tail.starts_with('%') || tail.len() == 3,
                "{tail} is a split escape"
            );
        }
        assert_eq!(
            cut("short".to_string()),
            "short",
            "short values are untouched"
        );
    }
}
