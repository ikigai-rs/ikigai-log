//! The tool-call line and the session trail (ledger #3962): one `log:ToolCall`
//! per tool call, a `session=` column any line may carry, and
//! `urn:log:trail:session:{session}` reading one session's trail under its own
//! capability, within a retention limit the host sets.
//!
//! Each test parses or transrepts what was written rather than matching
//! strings, except where the claim IS about the bytes: that a default line
//! does not contain the argument text anywhere.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ikigai_core::{
    Capability, Clock, EndpointSpace, Error, Iri, Kernel, Request, Time, UriTemplate, Verb,
};
use ikigai_log::{
    session_capability, tagged, to_triples, Access, AccessLog, Caller, ClosureSink, Destination,
    Entry, Header, Line, LogConfig, LogHandle, Options, SegmentEndpoint, Session,
    SessionTrailEndpoint, Timestamp, ToolCall, ToolCallError, ToolCallLog, ToolOutcome, Vocabulary,
    CAP_READ, CUT_MARKER, LOG_NS, MAX_TOOL_TEXT, SEGMENT_TEMPLATE, SESSION_KEY, SESSION_TEMPLATE,
    TOOL_CALL_CLASS, VOCABULARY_TTL,
};
use oxrdf::{NamedOrBlankNode, Term, Triple};

const T0: u64 = 1_700_000_000_000;
const SESSION_A: &str = "urn:claude:session:4f1c";
const SESSION_B: &str = "urn:claude:session:9e2d";
/// What a tool call's arguments might carry, and a line must not.
const SECRET: &str = "hunter2-very-secret";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

fn at(ms: u64) -> Timestamp {
    Timestamp::from_millis(ms)
}

fn log(local: &str) -> String {
    format!("{LOG_NS}{local}")
}

struct Fixed(u64);

impl Clock for Fixed {
    fn now(&self) -> Time {
        Time::from_millis(self.0)
    }
}

/// A handle writing into memory, and the lines it wrote.
fn open() -> (Arc<LogHandle>, Arc<Mutex<Vec<String>>>) {
    let config = LogConfig::default()
        .with_instance("bug:agent")
        .with_level("info")
        .expect("a real level");
    let handle = Arc::new(LogHandle::new(None, None, config));
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    handle
        .open_with_sink(
            Vocabulary::shared_builtin(),
            at(T0),
            Box::new(ClosureSink(move |line: &str| {
                sink.lock().unwrap().push(line.to_string())
            })),
        )
        .expect("the segment opens");
    (handle, lines)
}

fn text(lines: &Mutex<Vec<String>>) -> String {
    let mut out = lines.lock().unwrap().join("\n");
    out.push('\n');
    out
}

/// The `log:ToolCall` entries written, parsed back, without `seq=`.
fn tool_calls(lines: &Mutex<Vec<String>>) -> Vec<Entry> {
    let text = text(lines);
    let (header, _) = Header::parse(&text).expect("the header parses");
    text.lines()
        .filter_map(|l| match Line::parse(l, &header.prefixes) {
            Ok(Line::Entry(entry)) if entry.class == TOOL_CALL_CLASS => Some(entry),
            _ => None,
        })
        .map(|mut e| {
            assert_eq!(e.fields.first().map(|(k, _)| k.as_str()), Some("seq"));
            e.fields.remove(0);
            e
        })
        .collect()
}

fn session(iri: &str) -> Session {
    Session::new(iri).expect("a session IRI")
}

/// A call whose arguments and result both carry [`SECRET`].
fn secret_call() -> ToolCall {
    ToolCall::new(
        at(T0 + 5),
        session(SESSION_A),
        "Bash",
        format!(r#"{{"command":"echo {SECRET}"}}"#),
        ToolOutcome::Ok,
    )
    .duration_ms(184)
    .result(format!("{SECRET}\n"))
}

#[test]
fn a_default_line_carries_no_argument_or_result_text() {
    let (handle, lines) = open();
    let calls = ToolCallLog::new(handle);
    assert!(
        !calls.writes_text(),
        "digests only, unless the writer opts in"
    );
    calls
        .record(&secret_call())
        .expect("it writes")
        .expect("info admits log:ToolCall");

    // The bytes: nowhere in the segment, not even escaped or quoted.
    let written = text(&lines);
    assert!(
        !written.contains(SECRET) && !written.contains("hunter2"),
        "a default line holds no argument text:\n{written}"
    );
    assert!(!written.contains("args-text") && !written.contains("result-text"));

    // The columns: exactly these, in this order.
    let entries = tool_calls(&lines);
    assert_eq!(entries.len(), 1);
    let args = format!(r#"{{"command":"echo {SECRET}"}}"#);
    assert_eq!(
        entries[0],
        Entry::new(at(T0 + 5), TOOL_CALL_CLASS, "urn:log:tool:name:Bash")
            .with(SESSION_KEY, SESSION_A)
            .with("outcome", "ok")
            .with("dur", "184")
            .with("args", tagged(args.as_bytes()))
            .with("result", tagged(format!("{SECRET}\n").as_bytes()))
    );
}

#[test]
fn the_line_is_one_greppable_line_with_a_bare_session_column() {
    let (handle, lines) = open();
    ToolCallLog::new(handle)
        .record(&secret_call())
        .unwrap()
        .unwrap();
    let line = lines
        .lock()
        .unwrap()
        .iter()
        .find(|l| l.contains(" log:ToolCall "))
        .cloned()
        .expect("a tool-call line");
    assert!(!line.contains('\n'));
    assert!(
        line.starts_with("2023-11-14T22:13:20.005Z log:ToolCall urn:log:tool:name:Bash "),
        "time, class, subject: {line}"
    );
    assert!(line.contains(&format!(" session={SESSION_A} ")), "{line}");
    assert!(line.contains(" outcome=ok dur=184 args=sha256:"), "{line}");
}

#[test]
fn text_is_written_only_when_the_writer_opts_in_and_a_cut_is_named() {
    let (handle, lines) = open();
    let calls = ToolCallLog::new(handle).with_text();
    assert!(calls.writes_text());
    let long = "x".repeat(MAX_TOOL_TEXT + 10);
    calls.record(&secret_call()).unwrap().unwrap();
    calls
        .record(
            &ToolCall::new(
                at(T0 + 6),
                session(SESSION_A),
                "Read",
                long.clone(),
                ToolOutcome::Failed,
            )
            .result("short"),
        )
        .unwrap()
        .unwrap();

    let entries = tool_calls(&lines);
    assert_eq!(
        entries[0].get("args-text"),
        Some(format!(r#"{{"command":"echo {SECRET}"}}"#).as_str()),
        "the text, round-tripped through quoting and escaping"
    );
    assert_eq!(
        entries[0].get("result-text"),
        Some(format!("{SECRET}\n").as_str())
    );
    assert_eq!(entries[0].get("cut"), None, "nothing was cut");
    // The escaped newline keeps the entry on one line.
    assert_eq!(
        text(&lines)
            .lines()
            .filter(|l| l.contains("log:ToolCall"))
            .count(),
        2
    );

    let cut = entries[1].get("args-text").expect("the text");
    assert!(cut.ends_with(CUT_MARKER));
    assert_eq!(cut.len(), MAX_TOOL_TEXT + CUT_MARKER.len());
    assert_eq!(entries[1].get("cut"), Some("args-text"));
    assert_eq!(entries[1].get("outcome"), Some("failed"));
    assert_eq!(
        entries[1].get("args"),
        Some(tagged(long.as_bytes()).as_str()),
        "the digest covers the whole text"
    );
}

#[test]
fn every_outcome_has_its_token() {
    assert_eq!(ToolOutcome::Ok.token(), "ok");
    assert_eq!(ToolOutcome::Refused.token(), "refused");
    assert_eq!(ToolOutcome::Failed.token(), "failed");
}

#[test]
fn a_tool_name_is_percent_encoded_into_its_subject() {
    let call = ToolCall::new(
        at(T0),
        session(SESSION_A),
        "mcp__git hub__issue",
        "{}",
        ToolOutcome::Refused,
    );
    assert_eq!(
        call.tool_iri().unwrap(),
        "urn:log:tool:name:mcp__git%20hub__issue"
    );
    let empty = ToolCall::new(at(T0), session(SESSION_A), "", "{}", ToolOutcome::Ok);
    assert!(matches!(empty.entry(), Err(ToolCallError::Tool { .. })));
}

#[test]
fn a_session_that_cannot_be_a_bare_column_is_refused_and_shown_escaped() {
    for bad in ["two words", "no-scheme", "urn:x:\u{202e}evil"] {
        let err = Session::new(bad).expect_err(bad);
        let message = err.to_string();
        assert!(!message.contains('\u{202e}'), "{message}");
        assert!(
            message.contains("cannot be written as a session"),
            "{message}"
        );
    }
    let long = format!("urn:x:{}", "a".repeat(ikigai_log::MAX_SESSION_LEN));
    assert!(Session::new(long).is_err());
}

#[test]
fn the_graph_states_the_call_in_declared_terms() {
    let (handle, lines) = open();
    ToolCallLog::new(handle)
        .record(&secret_call())
        .unwrap()
        .unwrap();
    let triples =
        to_triples(&text(&lines), Vocabulary::builtin(), &Options::all()).expect("it transrepts");
    let node = node_of(&triples, TOOL_CALL_CLASS);
    let object = |p: &str| -> Vec<&Term> {
        triples
            .iter()
            .filter(|t| matches!(&t.subject, NamedOrBlankNode::NamedNode(n) if n.as_str() == node))
            .filter(|t| t.predicate.as_str() == p)
            .map(|t| &t.object)
            .collect()
    };
    let named = |iri: &str| Term::NamedNode(oxrdf::NamedNode::new(iri).unwrap());
    assert_eq!(
        object(&log("calledTool")),
        [&named("urn:log:tool:name:Bash")]
    );
    assert_eq!(object(&log("session")), [&named(SESSION_A)]);
    assert_eq!(
        object(&log("outcome")),
        [&Term::Literal(oxrdf::Literal::new_simple_literal("ok"))]
    );
    assert_eq!(
        object(&log("durationMs")),
        [&Term::Literal(oxrdf::Literal::new_typed_literal(
            "184",
            oxrdf::NamedNode::new("http://www.w3.org/2001/XMLSchema#integer").unwrap()
        ))]
    );
    assert_eq!(object(&log("argumentsDigest")).len(), 1);
    assert_eq!(object(&log("resultDigest")).len(), 1);
    assert!(
        object(&log("undeclaredKey")).is_empty(),
        "every column is declared"
    );
    // PROV: the entry is an activity of the instance that wrote it.
    assert_eq!(object("http://www.w3.org/ns/prov#startedAtTime").len(), 1);
    assert_eq!(
        object("http://www.w3.org/ns/prov#wasAssociatedWith").len(),
        1
    );
    // Every log: term the graph uses is one the vocabulary defines.
    for t in &triples {
        let p = t.predicate.as_str();
        if let Some(local) = p.strip_prefix(LOG_NS) {
            assert!(
                VOCABULARY_TTL.contains(&format!("log:{local} a ")),
                "log:{local}"
            );
        }
    }
}

#[test]
fn outcome_no_longer_types_a_tool_call_as_a_door_request() {
    // `outcome=` is written by both classes, so its domain is log:Entry: with
    // log:Access, a reasoner would have called every tool call a door request.
    let ttl = VOCABULARY_TTL;
    let start = ttl.find("log:outcome a rdf:Property").expect("declared");
    let end = start + ttl[start..].find(" .\n").expect("ends");
    assert!(
        ttl[start..end].contains("rdfs:domain log:Entry ;"),
        "{}",
        &ttl[start..end]
    );
    let vocab = Vocabulary::builtin();
    assert!(vocab.is_a(TOOL_CALL_CLASS, &log("Entry")));
    assert!(!vocab.is_a(TOOL_CALL_CLASS, &log("Access")));
}

fn node_of(triples: &[Triple], class: &str) -> String {
    let nodes: Vec<String> = triples
        .iter()
        .filter(|t| t.predicate.as_str() == RDF_TYPE)
        .filter(|t| matches!(&t.object, Term::NamedNode(n) if n.as_str() == class))
        .filter_map(|t| match &t.subject {
            NamedOrBlankNode::NamedNode(n) => Some(n.as_str().to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(nodes.len(), 1, "{nodes:?}");
    nodes.into_iter().next().unwrap()
}

// =====================================================================================
// urn:log:trail:session:{session}
// =====================================================================================

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ikigai-log-tool-call-{}-{}-{tag}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A file-backed log holding calls in two sessions, an hour apart, and a door
/// line in session A; and a kernel over the trail and segment endpoints whose
/// trail reads at `now`.
fn trail_fixture(tag: &str, now: u64) -> (Kernel, Arc<LogHandle>, Scratch) {
    let scratch = Scratch::new(tag);
    let config = LogConfig::default()
        .with_instance("bug:trail")
        .with_level("info")
        .expect("a real level")
        .with_destination(Destination::File)
        .with_directory(scratch.0.clone());
    let handle = Arc::new(LogHandle::new(Some(scratch.0.clone()), None, config));
    assert!(handle
        .open(Vocabulary::shared_builtin(), at(T0))
        .expect("the segment opens"));
    let calls = ToolCallLog::new(handle.clone());
    let hour = 3_600_000;
    for (t, s, tool) in [
        (T0 + 1, SESSION_A, "Read"),
        (T0 + 2, SESSION_B, "Bash"),
        (T0 + hour, SESSION_A, "Edit"),
    ] {
        calls
            .record(&ToolCall::new(
                at(t),
                session(s),
                tool,
                SECRET,
                ToolOutcome::Ok,
            ))
            .unwrap()
            .unwrap();
    }
    AccessLog::new(handle.clone(), Arc::new(Fixed(T0)))
        .record(
            &Access::new(
                at(T0 + hour + 1),
                "urn:cms:page:home",
                "web",
                "GET",
                "ok",
                Caller::Anonymous,
            )
            .session(session(SESSION_A)),
        )
        .unwrap()
        .unwrap();
    let space = EndpointSpace::new()
        .bind(
            UriTemplate::parse(SESSION_TEMPLATE).unwrap(),
            SessionTrailEndpoint::new(
                handle.clone(),
                Vocabulary::shared_builtin(),
                Arc::new(Fixed(now)),
            ),
        )
        .bind(
            UriTemplate::parse(SEGMENT_TEMPLATE).unwrap(),
            SegmentEndpoint::new(handle.clone(), Vocabulary::shared_builtin()),
        );
    let kernel = Kernel::new(Arc::new(space)).with_clock(Arc::new(Fixed(now)));
    (kernel, handle, scratch)
}

fn read_trail(
    kernel: &Kernel,
    of: &str,
    capability: &Capability,
) -> ikigai_core::Result<Vec<Triple>> {
    let request = Request::new(
        Verb::Source,
        Iri::parse(format!("urn:log:trail:session:{of}")).expect("an IRI"),
    );
    let repr = futures::executor::block_on(kernel.issue(request, capability))?;
    let turtle = String::from_utf8(repr.bytes.to_vec()).expect("utf-8");
    Ok(oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle)
        .for_slice(turtle.as_bytes())
        .map(|q| Triple::from(q.expect("the trail is Turtle")))
        .collect())
}

/// The subjects of `log:calledTool` (tool calls) and `log:requested` (door
/// lines) in a trail, sorted.
fn steps(triples: &[Triple]) -> Vec<String> {
    let mut out: Vec<String> = triples
        .iter()
        .filter(|t| {
            [log("calledTool"), log("requested")].contains(&t.predicate.as_str().to_string())
        })
        .map(|t| t.object.to_string())
        .collect();
    out.sort();
    out
}

#[test]
fn a_trail_is_one_sessions_entries_under_its_own_capability() {
    let (kernel, _handle, _scratch) = trail_fixture("own", T0 + 7_200_000);
    let own = Capability::scoped([session_capability(SESSION_A)]);
    let triples = read_trail(&kernel, SESSION_A, &own).expect("the session's own scope reads it");
    assert_eq!(
        steps(&triples),
        [
            "<urn:cms:page:home>",
            "<urn:log:tool:name:Edit>",
            "<urn:log:tool:name:Read>"
        ],
        "A's two calls and its door line, and none of B's"
    );
    let sessions: Vec<String> = triples
        .iter()
        .filter(|t| t.predicate.as_str() == log("session"))
        .map(|t| t.object.to_string())
        .collect();
    assert_eq!(sessions, vec![format!("<{SESSION_A}>"); 3]);
    // The entries keep the IRIs they have in their segment.
    assert!(triples
        .iter()
        .any(|t| t.predicate.as_str() == log("segment")));
    // No argument text reaches the trail either.
    assert!(!triples
        .iter()
        .any(|t| t.object.to_string().contains(SECRET)));

    let b = read_trail(
        &kernel,
        SESSION_B,
        &Capability::scoped([session_capability(SESSION_B)]),
    )
    .expect("B reads B");
    assert_eq!(steps(&b), ["<urn:log:tool:name:Bash>"]);
}

#[test]
fn another_sessions_scope_and_the_whole_log_scope_do_not_read_a_trail() {
    let (kernel, _handle, _scratch) = trail_fixture("denied", T0 + 7_200_000);
    for capability in [
        Capability::scoped([session_capability(SESSION_B)]),
        Capability::scoped([CAP_READ]),
    ] {
        let err = read_trail(&kernel, SESSION_A, &capability).expect_err("refused");
        assert!(matches!(err, Error::Denied(_)), "{err}");
    }
    // Root reads it.
    assert_eq!(
        steps(&read_trail(&kernel, SESSION_A, &Capability::root()).unwrap()).len(),
        3
    );
}

#[test]
fn the_host_sets_how_far_back_a_trail_reads() {
    let (kernel, handle, _scratch) = trail_fixture("retention", T0 + 3_600_000 + 10);
    let own = Capability::scoped([session_capability(SESSION_A)]);
    assert_eq!(handle.session_retention_ms(), None, "unlimited by default");
    assert_eq!(
        steps(&read_trail(&kernel, SESSION_A, &own).unwrap()).len(),
        3
    );

    // One minute back: the first call, an hour old, is no longer served.
    handle.set_session_retention_ms(Some(60_000));
    assert_eq!(
        steps(&read_trail(&kernel, SESSION_A, &own).unwrap()),
        ["<urn:cms:page:home>", "<urn:log:tool:name:Edit>"]
    );
    // And the segment itself is untouched.
    let segment = futures::executor::block_on(
        kernel.issue(
            Request::new(
                Verb::Source,
                Iri::parse(handle.open_segment().unwrap().0).unwrap(),
            )
            .with_arg(
                "as",
                ikigai_core::ArgRef::Inline(b"text/x-ikigai-log".to_vec()),
            ),
            &Capability::root(),
        ),
    )
    .expect("the segment reads");
    let segment = String::from_utf8(segment.bytes.to_vec()).unwrap();
    assert_eq!(
        segment
            .lines()
            .filter(|l| l.contains("log:ToolCall"))
            .count(),
        3
    );
}

#[test]
fn the_space_binds_the_trail_above_the_segment_template() {
    let scratch = Scratch::new("space");
    let config = LogConfig::default()
        .with_instance("bug:space")
        .with_destination(Destination::File)
        .with_directory(scratch.0.clone());
    let handle = Arc::new(LogHandle::new(Some(scratch.0.clone()), None, config));
    assert!(handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap());
    ToolCallLog::new(handle.clone())
        .record(&ToolCall::new(
            at(T0 + 1),
            session(SESSION_A),
            "Read",
            "{}",
            ToolOutcome::Ok,
        ))
        .unwrap()
        .unwrap();
    let kernel = Kernel::new(Arc::new(ikigai_log::endpoints::space(handle)));
    let triples = read_trail(
        &kernel,
        SESSION_A,
        &Capability::scoped([session_capability(SESSION_A)]),
    )
    .expect("resolved as a trail, not as a segment named `trail:session:…`");
    assert_eq!(steps(&triples), ["<urn:log:tool:name:Read>"]);
}
