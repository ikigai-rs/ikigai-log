//! The door line (ledger #3390): one `log:Access` entry per request a host's
//! door served, written through the log's writer into a hash-chained segment.
//!
//! Each test parses or transrepts what was written rather than matching
//! strings in it: a line that does not parse back would pass a `contains`.

use std::sync::{Arc, Mutex};

use ikigai_core::{
    Capability, Clock, EndpointSpace, Exact, FnEndpoint, Iri, Kernel, ReprType, Representation,
    Request, Time, Verb,
};
use ikigai_log::{
    to_triples, verify_chain, Access, AccessLog, Caller, ClosureSink, Credential, Entry, Grant,
    Header, Line, LogConfig, LogHandle, Options, Principal, Vocabulary, ACCESS_CLASS,
    ANONYMOUS_CREDENTIAL, ANONYMOUS_PRINCIPAL, CUT_MARKER, LOG_NS, MAX_FIELD, PASSKEY_CREDENTIAL,
    PRINCIPAL_KEY, RESOLUTION_CLASS,
};
use oxrdf::{NamedOrBlankNode, Term, Triple};

const T0: u64 = 1_700_000_000_000;
const ALICE: &str = "urn:agent:alice";
const PROV: &str = "http://www.w3.org/ns/prov#";

fn at(ms: u64) -> ikigai_log::Timestamp {
    ikigai_log::Timestamp::from_millis(ms)
}

struct Fixed(u64);

impl Clock for Fixed {
    fn now(&self) -> Time {
        Time::from_millis(self.0)
    }
}

/// A handle writing into memory at `level`, and the lines it wrote.
fn open(level: &str) -> (Arc<LogHandle>, Arc<Mutex<Vec<String>>>) {
    let config = LogConfig::default()
        .with_instance("bug:door")
        .with_level(level)
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

/// Every entry written, parsed back through the grammar.
fn entries(lines: &Mutex<Vec<String>>) -> Vec<Entry> {
    let text = text(lines);
    let (header, _) = Header::parse(&text).expect("the header parses");
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('@') && !l.starts_with('#'))
        .filter_map(|l| match Line::parse(l, &header.prefixes) {
            Ok(Line::Entry(entry)) => Some(entry),
            Ok(_) => None,
            Err(e) => panic!("{l}\ndoes not parse: {e}"),
        })
        .collect()
}

/// The entries of `class`, without the `seq=` the writer numbers every line
/// with: what remains is what the door line itself wrote.
fn of_class(lines: &Mutex<Vec<String>>, class: &str) -> Vec<Entry> {
    entries(lines)
        .into_iter()
        .filter(|e| e.class == class)
        .map(|mut e| {
            assert_eq!(e.fields.first().map(|(k, _)| k.as_str()), Some("seq"));
            e.fields.remove(0);
            e
        })
        .collect()
}

fn graph(lines: &Mutex<Vec<String>>) -> Vec<Triple> {
    to_triples(&text(lines), Vocabulary::builtin(), &Options::all()).expect("it transrepts")
}

/// The objects of `predicate` on `node`.
fn objects<'a>(triples: &'a [Triple], node: &str, predicate: &str) -> Vec<&'a Term> {
    triples
        .iter()
        .filter(|t| matches!(&t.subject, NamedOrBlankNode::NamedNode(n) if n.as_str() == node))
        .filter(|t| t.predicate.as_str() == predicate)
        .map(|t| &t.object)
        .collect()
}

/// The node of the one entry of `class` in the graph.
fn node_of(triples: &[Triple], class: &str) -> String {
    let nodes: Vec<String> = triples
        .iter()
        .filter(|t| t.predicate.as_str() == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
        .filter(|t| matches!(&t.object, Term::NamedNode(n) if n.as_str() == class))
        .filter_map(|t| match &t.subject {
            NamedOrBlankNode::NamedNode(n) => Some(n.as_str().to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(nodes.len(), 1, "{nodes:?}");
    nodes.into_iter().next().unwrap()
}

fn alice() -> Caller {
    Caller::authenticated(Principal::new(ALICE).unwrap(), Credential::Passkey)
}

#[test]
fn a_door_line_round_trips_to_turtle_with_every_key_declared() {
    let (handle, lines) = open("info");
    let doors = AccessLog::new(handle, Arc::new(Fixed(T0)));
    let access = Access::new(at(T0 + 5), "urn:cms:page:home", "web", "GET", "ok", alice())
        .bytes(5120)
        .duration_ms(12)
        .grant(Grant::new("urn:grant:cms:read").unwrap())
        .argument("lang", "en")
        .argument("view", "two words&more");
    doors.record(&access).expect("it writes").expect("it lands");

    let written = of_class(&lines, ACCESS_CLASS);
    assert_eq!(written.len(), 1);
    assert_eq!(
        written[0],
        access.entry().unwrap(),
        "the line reads back as the entry"
    );
    let keys: Vec<&str> = written[0].fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        [
            "door",
            "verb",
            "outcome",
            "bytes",
            "dur",
            "principal",
            "credential",
            "grant",
            "q"
        ]
    );
    assert_eq!(written[0].get("q"), Some("lang=en&view=two%20words%26more"));

    let triples = graph(&lines);
    let node = node_of(&triples, ACCESS_CLASS);
    let log = |term: &str| format!("{LOG_NS}{term}");
    assert!(
        objects(&triples, &node, &log("undeclaredKey")).is_empty(),
        "every column is declared: {:?}",
        objects(&triples, &node, &log("undeclaredKey"))
    );
    // `None` is an IRI; `Some(v)` a literal reading `v`.
    for (property, expected) in [
        ("requested", None),
        ("door", Some("web")),
        ("verb", Some("GET")),
        ("outcome", Some("ok")),
        ("byteCount", Some("5120")),
        ("durationMs", Some("12")),
        ("onBehalfOf", None),
        ("credentialKind", None),
        ("grant", None),
        ("servedQuery", Some("lang=en&view=two%20words%26more")),
    ] {
        let found = objects(&triples, &node, &log(property));
        assert_eq!(found.len(), 1, "log:{property}: {found:?}");
        let holds = match (expected, found[0]) {
            (None, Term::NamedNode(_)) => true,
            (Some(value), Term::Literal(l)) => l.value() == value,
            _ => false,
        };
        assert!(holds, "log:{property}: {:?}", found[0]);
    }
    assert_eq!(
        objects(&triples, &node, &log("credentialKind")),
        [&Term::NamedNode(
            oxrdf::NamedNode::new(PASSKEY_CREDENTIAL).unwrap()
        )]
    );
    assert_eq!(
        objects(&triples, &node, &format!("{PROV}startedAtTime")).len(),
        1
    );
    // The principal is stated in PROV's own terms as well.
    assert!(
        triples
            .iter()
            .any(|t| t.predicate.as_str() == format!("{PROV}hadActivity")
                && t.object == Term::NamedNode(oxrdf::NamedNode::new(&node).unwrap())),
        "a prov:Delegation for the request"
    );
    let report = verify_chain(&[("door".to_string(), text(&lines))], Vocabulary::builtin());
    assert_eq!(report.broken(), 0, "{}", report.render());
}

#[test]
fn an_anonymous_request_carries_no_identifier() {
    let (handle, lines) = open("info");
    let doors = AccessLog::new(handle, Arc::new(Fixed(T0)));
    doors
        .record(
            &Access::new(
                at(T0),
                "urn:cms:page:home",
                "web",
                "GET",
                "ok",
                Caller::Anonymous,
            )
            .bytes(10)
            .duration_ms(1),
        )
        .unwrap()
        .expect("it lands");

    let written = of_class(&lines, ACCESS_CLASS);
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].get(PRINCIPAL_KEY), Some(ANONYMOUS_PRINCIPAL));
    assert_eq!(written[0].get(PRINCIPAL_KEY), Some("anon"));
    assert_eq!(written[0].get("credential"), Some(ANONYMOUS_CREDENTIAL));
    let keys: Vec<&str> = written[0].fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        [
            "door",
            "verb",
            "outcome",
            "bytes",
            "dur",
            "principal",
            "credential"
        ],
        "the principal is `anon` and nothing more: no address, fingerprint or session"
    );

    let triples = graph(&lines);
    assert!(
        !triples.iter().any(
            |t| t.predicate.as_str() == format!("{PROV}qualifiedDelegation")
                || t.predicate.as_str() == format!("{PROV}actedOnBehalfOf")
        ),
        "no agent is named, so no delegation is stated: {triples:#?}"
    );
}

#[test]
fn secrets_and_bodies_are_never_written() {
    let (handle, lines) = open("info");
    let doors = AccessLog::new(handle, Arc::new(Fixed(T0)));
    let mut access = Access::new(at(T0), "urn:cms:page:home", "web", "POST", "ok", alice());
    for name in [
        "content",
        "body",
        "form",
        "cookie",
        "Authorization",
        "session",
        "token",
        "access_token",
        "X-Session-Id",
        "password",
    ] {
        access = access.argument(name, "hunter2");
    }
    doors
        .record(&access.argument("lang", "en"))
        .unwrap()
        .expect("it lands");
    let written = text(&lines);
    assert!(!written.contains("hunter2"), "{written}");
    assert_eq!(of_class(&lines, ACCESS_CLASS)[0].get("q"), Some("lang=en"));
}

#[test]
fn a_cut_field_is_marked_with_what_the_encoding_never_writes() {
    let (handle, lines) = open("info");
    let doors = AccessLog::new(handle, Arc::new(Fixed(T0)));
    let long = "x".repeat(4 * MAX_FIELD);
    let subject = format!("urn:cms:page:{long}");
    doors
        .record(
            &Access::new(at(T0), &subject, "web", "GET", "ok", alice())
                .argument("q", &long)
                // A value holding the marker itself is encoded, not mistaken.
                .argument("ellipsis", "\u{2026}"),
        )
        .unwrap()
        .expect("it lands");
    doors
        .record(
            &Access::new(at(T0), "urn:cms:page:short", "web", "GET", "ok", alice())
                .argument("ellipsis", "\u{2026}"),
        )
        .unwrap()
        .expect("it lands");

    let written = of_class(&lines, ACCESS_CLASS);
    let q = written[0].get("q").unwrap();
    let body = q.strip_suffix(CUT_MARKER).expect("the cut q= is marked");
    assert_eq!(body.len(), MAX_FIELD);
    let cut_subject = written[0]
        .subject
        .strip_suffix(CUT_MARKER)
        .expect("the cut subject is marked");
    assert_eq!(cut_subject.len(), MAX_FIELD);
    assert!(subject.starts_with(cut_subject));

    let uncut = written[1].get("q").unwrap();
    assert_eq!(uncut, "ellipsis=%E2%80%A6");
    assert!(
        !uncut.contains(CUT_MARKER) && !written[1].subject.contains(CUT_MARKER),
        "an uncut line holds no marker, whatever its values held"
    );
    // And the cut line still transrepts, its subject still an IRI.
    let triples = graph(&lines);
    assert!(triples
        .iter()
        .any(|t| t.predicate.as_str() == format!("{LOG_NS}requested")
            && matches!(&t.object, Term::NamedNode(n) if n.as_str() == written[0].subject)));
}

/// A space whose page issues a sub-request, so a request's attribution can be
/// seen on more than its own line.
fn door_kernel() -> Kernel {
    let part = FnEndpoint::new("doorPart", |_inv| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"part".to_vec(),
        ))
    });
    let page = || {
        ikigai_core::AsyncFnEndpoint::new("doorPage", |inv| {
            Box::pin(async move {
                inv.issue(get("urn:door:part")).await?;
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"page".to_vec(),
                ))
            })
        })
    };
    let space = EndpointSpace::new()
        .bind(Exact::new("urn:door:alice"), page())
        .bind(Exact::new("urn:door:anon"), page())
        .bind(Exact::new("urn:door:part"), part);
    Kernel::new(Arc::new(space)).with_clock(Arc::new(Fixed(T0)))
}

fn get(iri: &str) -> Request {
    Request::new(Verb::Source, Iri::parse(iri).unwrap())
}

#[test]
fn two_callers_through_one_kernel_get_two_principals() {
    // Per request, not per process: no tracer is installed with `set_tracer`,
    // and each request is issued with the tracer for its own caller.
    let (handle, lines) = open("debug");
    let doors = AccessLog::new(handle, Arc::new(Fixed(T0)));
    let kernel = door_kernel();
    let anyone = Capability::scoped(Vec::<String>::new());

    for (target, caller) in [
        ("urn:door:alice", alice()),
        ("urn:door:anon", Caller::Anonymous),
    ] {
        let answer = futures::executor::block_on(kernel.issue_traced(
            get(target),
            &anyone,
            doors.tracer_for(&caller),
        ))
        .expect("it resolves");
        doors
            .record(
                &Access::new(at(T0), target, "web", "GET", "ok", caller)
                    .bytes(answer.bytes.len() as u64),
            )
            .unwrap()
            .expect("it lands");
    }

    let resolutions = of_class(&lines, RESOLUTION_CLASS);
    assert_eq!(resolutions.len(), 4, "{resolutions:#?}");
    let principal_of = |entries: &[Entry], subject: &str| -> Vec<Option<String>> {
        entries
            .iter()
            .filter(|e| e.subject == subject)
            .map(|e| e.get(PRINCIPAL_KEY).map(str::to_string))
            .collect()
    };
    assert_eq!(
        principal_of(&resolutions, "urn:door:alice"),
        [Some(ALICE.to_string())]
    );
    assert_eq!(
        principal_of(&resolutions, "urn:door:anon"),
        [Some("anon".to_string())]
    );
    assert_eq!(
        principal_of(&resolutions, "urn:door:part"),
        [Some(ALICE.to_string()), Some("anon".to_string())],
        "each sub-request is credited to the caller whose request issued it"
    );
    let accesses = of_class(&lines, ACCESS_CLASS);
    assert_eq!(
        principal_of(&accesses, "urn:door:alice"),
        [Some(ALICE.to_string())]
    );
    assert_eq!(
        principal_of(&accesses, "urn:door:anon"),
        [Some("anon".to_string())]
    );
    assert_eq!(
        accesses[0].get("credential"),
        Some(PASSKEY_CREDENTIAL),
        "{accesses:#?}"
    );
}

#[test]
fn the_dial_decides_whether_a_door_line_lands() {
    let (handle, lines) = open("warn");
    let doors = AccessLog::new(handle, Arc::new(Fixed(T0)));
    let landed = doors
        .record(&Access::new(at(T0), "urn:x:y", "web", "GET", "ok", alice()))
        .unwrap();
    assert_eq!(landed, None, "log:Access is at info, below warn");
    assert!(of_class(&lines, ACCESS_CLASS).is_empty());
}

#[test]
fn a_request_with_no_door_is_refused_and_says_so() {
    let (handle, _lines) = open("info");
    let doors = AccessLog::new(handle, Arc::new(Fixed(T0)));
    let error = doors
        .record(&Access::new(at(T0), "urn:x:y", "", "GET", "ok", alice()))
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "a door line needs a door= column and this one is empty"
    );
    let error = Grant::new("two words").unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("two words cannot be written as a grant: "),
        "{error}"
    );
}

#[test]
fn an_access_error_shows_what_it_quotes_escaped() {
    let error = Grant::new("urn:grant:\u{202e}x").unwrap_err().to_string();
    assert!(
        error.starts_with("urn:grant:\\u{202e}x cannot be written as a grant: "),
        "{error}"
    );
    assert!(
        !error.chars().any(|c| c == '\u{202e}' || c.is_control()),
        "{error:?}"
    );
    let (handle, _lines) = open("info");
    let doors = AccessLog::new(handle, Arc::new(Fixed(T0)));
    let error = doors
        .record(&Access::new(
            at(T0),
            "no\u{202e}scheme",
            "web",
            "GET",
            "ok",
            alice(),
        ))
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "no\\u{202e}scheme cannot be the subject of a door line: it is not an absolute IRI"
    );
}
