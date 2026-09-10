//! The module recipe as one test: `ikigai-conformance` walks the six endpoints
//! [`ikigai_log::endpoints::space`] binds and reports every violation at once.
//!
//! ## The fixture is a log directory, and the walk WRITES to it
//!
//! The suite fires the actions it checks — `urn:log:write` included — so the
//! kernel under test is built over a scratch directory holding one segment this
//! file opens, with the kernel's clock fixed (an entry is stamped from the
//! kernel's clock and nowhere else). Two walks, because a segment has two lives:
//!
//! - **live** ([`conforms`]): the handle is open, so `urn:log:{segment}` serves
//!   the tail of a file that is still being appended to — uncacheable, but
//!   carrying the file's golden thread (`urn:file:<path>`) so a reader that
//!   caches downstream of it is cut by a watcher on the log directory;
//! - **finished** ([`a_finished_segment_conforms_and_caches_under_its_file`]):
//!   the handle was closed, the segment ends in `log:ProcessStop` and a `#seal`,
//!   and the same endpoint serves it `.cacheable()` under that thread. The walk
//!   cannot append to it (the Sink answers `closed:`), and the file is
//!   byte-identical afterwards.
//!
//! `urn:log:transrept` is the one pure function here — Turtle from bytes, no
//! file, no clock — so it is declared `pure` and `cacheable`. Everything else
//! that reads is live by design (`urn:log:config` carries process state no
//! thread tracks; `urn:log:segments` and `urn:log:verify` read a directory
//! nothing cuts a thread on), and the suite has no declaration for "live on
//! purpose", so those decisions are stated here and in the module docs rather
//! than held by a check.
//!
//! ## What the suite cannot hold and this file pins by hand
//!
//! - **A finished segment's Source is cacheable under its file; its Exists is
//!   not.** `Suite::cacheable(id)` is per ENDPOINT and holds every cacheable
//!   verb to it, and `Exists` is deliberately live (the directory changes under
//!   rotation and retention). So the declaration cannot be made for `Source`
//!   alone; the second test resolves the segment by hand, asserts the thread
//!   name and the cache hit, then makes the declaration anyway to show the one
//!   finding it produces — `Exists`, and nothing else.
//! - **Declared outputs are the media types served, both directions, with `as`
//!   omitted** ([`declared_outputs_are_the_media_types_served`]): the suite
//!   compares the two only for RDF faces.
//! - **The registered namespace is a promise**
//!   ([`the_faces_emit_only_terms_the_vocabulary_defines`]): `Suite::namespace`
//!   waives VOCABULARY for every `log:` term, so this file parses both Turtle
//!   faces and requires every `log:` term to be a subject of
//!   [`ikigai_log::VOCABULARY_TTL`]. `sig:` is `ikigai-sign`'s namespace,
//!   defined in that crate's prose; the three terms a seal carries are held to
//!   that list.
//! - **The Sink is fired exactly once under root, and a refused write lands
//!   nowhere** (in [`conforms`]): the kernel refuses `ENFORCED`'s no-grants call
//!   before dispatch and this kernel has no tracer, so the only entry the walk
//!   adds is PIPELINE's `log:Message msg=x`.
//!
//! ## Names
//!
//! The six ids (`logWrite`, `logConfig`, `logSegments`, `logVerify`,
//! `logSegment`, `logTransrept`) are camelCase, and NAMES says so. They are live
//! MCP tool names, renamed in one coordinated pass across every module (wave
//! two — see `ikigai-core-PENDING.md` §1), so NAMES is skipped here rather than
//! six ids renamed out of step. No opt-outs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ikigai_conformance::{rdf, Check, Checks, Fixture, Report, Suite};
use ikigai_core::{ArgRef, Capability, Clock, Iri, Kernel, Representation, Request, Time, Verb};
use ikigai_log::{
    Destination, LogConfig, LogHandle, Timestamp, Vocabulary, CAP_READ, CONFIG_IRI, LOG_NS,
    SEGMENTS_IRI, SIG_NS, TRANSREPT_IRI, VERIFY_IRI, VOCABULARY_TTL, WRITE_IRI,
};

/// The six endpoints `space()` binds, by description id — pinned against the
/// kernel in [`the_fixture_ids_are_the_description_ids`], because a `Fixture`
/// is matched BY ID and one that drifts is silently never applied.
const WRITE: &str = "logWrite";
const TRANSREPT: &str = "logTransrept";
const CONFIG: &str = "logConfig";
const SEGMENTS: &str = "logSegments";
const VERIFY: &str = "logVerify";
const SEGMENT: &str = "logSegment";

/// The instance every fixture segment is attributed to.
const INSTANCE: &str = "conformance";

/// When the segment opens; the kernel's clock sits a little after it.
const T0: u64 = 1_700_000_000_000;

/// The `sig:` terms a `#seal` line becomes — `ikigai-sign`'s, defined in that
/// crate's README and nowhere machine-readable, so this is the list the face is
/// held to.
const SIG_TERMS: [&str; 3] = ["contentHash", "algorithm", "value"];

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "ikigai-log-conformance-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock is after the epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A clock that does not move — the only kind a test should reason against.
struct Fixed(u64);

impl Clock for Fixed {
    fn now(&self) -> Time {
        Time::from_millis(self.0)
    }
}

/// The fixture: one segment in a scratch directory, and the module's space over
/// it. Held together so the directory outlives the kernel.
struct Log {
    kernel: Kernel,
    /// The segment's IRI, `urn:log:conformance:<stamp>`.
    iri: String,
    /// The segment file — the golden thread a read declares.
    path: PathBuf,
    _scratch: Scratch,
}

impl Log {
    /// Open a segment under `INSTANCE`; `finished` closes it again so it ends in
    /// `log:ProcessStop` and a final seal.
    fn new(finished: bool) -> Log {
        let scratch = Scratch::new(if finished { "finished" } else { "live" });
        let dir = scratch.0.clone();
        let config = LogConfig::default()
            .with_instance(INSTANCE)
            .with_level("info")
            .expect("a real level")
            .with_destination(Destination::File)
            .with_directory(dir.clone());
        let handle = Arc::new(LogHandle::new(Some(dir.clone()), None, config));
        let opened = handle
            .open(Vocabulary::shared_builtin(), Timestamp::from_millis(T0))
            .expect("the segment opens");
        assert!(opened, "destination = file opens a segment");
        let (iri, _) = handle.open_segment().expect("a segment is open");
        if finished {
            handle
                .close(Timestamp::from_millis(T0 + 1_000))
                .expect("the segment closes");
        }
        let path = segment_file(&dir);
        let kernel = Kernel::new(Arc::new(ikigai_log::endpoints::space(handle)))
            .with_clock(Arc::new(Fixed(T0 + 2_000)));
        Log {
            kernel,
            iri,
            path,
            _scratch: scratch,
        }
    }

    /// The `{segment}` a fixture binds: the IRI without `urn:log:`.
    fn tail(&self) -> &str {
        self.iri
            .strip_prefix("urn:log:")
            .expect("a segment IRI is under urn:log:")
    }

    /// The segment's bytes right now.
    fn text(&self) -> String {
        std::fs::read_to_string(&self.path).expect("the segment file reads")
    }

    /// The golden thread every read of this segment declares.
    fn thread(&self) -> String {
        format!("urn:file:{}", self.path.display())
    }
}

/// The one `.log` file in `dir`.
fn segment_file(dir: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("the scratch dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .collect();
    assert_eq!(files.len(), 1, "exactly one segment: {files:?}");
    files.pop().expect("one file")
}

fn request(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Request {
    let mut request = Request::new(verb, Iri::parse(iri).expect("a valid IRI"));
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    request
}

fn issue(kernel: &Kernel, request: Request, capability: &Capability) -> Representation {
    futures::executor::block_on(kernel.issue(request, capability))
        .unwrap_or_else(|e| panic!("resolution failed: {e}"))
}

/// A reader's capability: `urn:cap:log:read` and nothing else — a different cache
/// key from the root the suite walks under, so a hand check starts cold.
fn reader() -> Capability {
    Capability::scoped([CAP_READ])
}

/// The suite, configured for this module (the file docs say why each line): the
/// two namespaces the faces use beside the well-known ones, a real segment for
/// the transreptor and the segment's own tail for the template, and the one pure
/// function declared as such.
fn suite(log: &Log) -> Suite {
    Suite::new()
        .checks(Checks::all() - Checks::NAMES)
        .namespace(LOG_NS)
        .namespace(SIG_NS)
        .fixture(Fixture::new(TRANSREPT, Verb::Source).arg("content", log.text()))
        .fixture(Fixture::new(SEGMENT, Verb::Source).binding("segment", log.tail()))
        .fixture(Fixture::new(SEGMENT, Verb::Exists).binding("segment", log.tail()))
        .pure(TRANSREPT)
        .cacheable(TRANSREPT)
}

/// The walk saw the six endpoints and their eight actions (config and the
/// segment declare two each), and skipped NAMES and nothing else. A seventh
/// endpoint bound without a line here would be held to a weaker standard; a
/// declared action that binds nothing is a stale list.
fn assert_shape(report: &Report) {
    assert_eq!(
        report.endpoints, 6,
        "write, transrept, config, segments, verify, segment: {report}"
    );
    assert_eq!(
        report.actions, 8,
        "one action each, two for config (Source/Sink) and the segment (Exists/Source): {report}"
    );
    let skipped: Vec<Check> = report.checks.skipped().collect();
    assert_eq!(
        skipped,
        [Check::Names],
        "wave two, and nothing else: {report}"
    );
}

#[test]
fn conforms() {
    let log = Log::new(false);
    let report = suite(&log).run_blocking(&log.kernel);
    // Printed even when clean (`--nocapture`): the report is the record.
    eprintln!("[live segment]\n{report}");
    assert!(report.is_clean(), "{report}");
    assert_shape(&report);

    // The live tail is never served from the cache — the walk resolved it under
    // root more than once, and nothing stuck.
    assert!(
        !log.kernel
            .is_cached(&request(Verb::Source, &log.iri, &[]), &Capability::root()),
        "a live segment is uncacheable"
    );

    // The Sink was fired exactly once under root (PIPELINE, `content=x`), and
    // ENFORCED's refused call reached nothing: the kernel denies before dispatch,
    // this kernel has no tracer, so no `log:CapabilityDenied` can land — the one
    // entry the walk added is the message.
    let after = log.text();
    let messages: Vec<&str> = after
        .lines()
        .filter(|line| line.contains(" log:Message "))
        .collect();
    assert_eq!(
        messages.len(),
        1,
        "one message from the pipeline probe:\n{after}"
    );
    assert!(
        messages[0].contains("msg=x") || messages[0].contains("msg=\"x\""),
        "the piped `content` is the message: {}",
        messages[0]
    );
    assert!(
        !after.contains("log:CapabilityDenied"),
        "a pre-dispatch refusal with no tracer lands nowhere:\n{after}"
    );
}

/// The other life of a segment: closed, sealed, immutable. The walk is clean
/// over it too, cannot change it, and the segment's Source is cached under its
/// file — which the suite can only be told per endpoint (PENDING #1), so the
/// cache facts are pinned by hand and the declaration is then made to show the
/// exact finding it costs.
#[test]
fn a_finished_segment_conforms_and_caches_under_its_file() {
    let log = Log::new(true);
    let before = log.text();
    assert!(
        before.contains(" log:ProcessStop ") && before.contains("\n#seal "),
        "closed: a stop marker and a final seal:\n{before}"
    );

    let report = suite(&log).run_blocking(&log.kernel);
    eprintln!("[finished segment]\n{report}");
    assert!(report.is_clean(), "{report}");
    assert_shape(&report);
    assert_eq!(
        log.text(),
        before,
        "a finished segment is immutable under the walk: the Sink answers `closed:` and writes nothing"
    );

    // By hand: the Source is cached under exactly the file's IRI — the name a
    // watcher on the log directory must cut.
    let source = request(Verb::Source, &log.iri, &[]);
    assert!(
        !log.kernel.is_cached(&source, &reader()),
        "cold under a fresh key"
    );
    let repr = issue(&log.kernel, source.clone(), &reader());
    let threads: Vec<String> = repr.threads().iter().map(|t| t.to_string()).collect();
    assert_eq!(threads, [log.thread()], "the thread is the segment file");
    assert!(
        log.kernel.is_cached(&source, &reader()),
        "a finished segment is served from the cache the second time"
    );

    // Exists stays live by design (the directory changes under rotation and
    // retention), though a found segment declares the same thread.
    let exists = issue(&log.kernel, request(Verb::Exists, &log.iri, &[]), &reader());
    assert_eq!(String::from_utf8(exists.bytes.clone()).unwrap(), "true");
    assert!(
        exists
            .threads()
            .iter()
            .any(|t| t.to_string() == log.thread()),
        "a found segment names its file"
    );
    assert!(
        !log.kernel
            .is_cached(&request(Verb::Exists, &log.iri, &[]), &reader()),
        "Exists is not cached"
    );

    // Declared, the suite holds BOTH cacheable verbs to it: Source passes, and
    // the one finding is Exists — the per-endpoint limit, shown rather than
    // worked around.
    let report = suite(&log).cacheable(SEGMENT).run_blocking(&log.kernel);
    eprintln!("[finished segment, logSegment declared cacheable]\n{report}");
    let findings: Vec<(&str, Option<Verb>, Check)> = report
        .findings
        .iter()
        .map(|f| (f.endpoint.as_str(), f.verb, f.check))
        .collect();
    assert_eq!(
        findings,
        [(SEGMENT, Some(Verb::Exists), Check::Cacheable)],
        "{report}"
    );
    assert!(
        report.findings[0].detail.contains("declared cacheable"),
        "the finding names the declaration: {report}"
    );
}

/// One action to fire: its IRI, its verb, and the arguments that make the call
/// valid with `as` omitted.
type Case<'a> = (&'a str, Verb, Vec<(&'a str, &'a str)>);

/// What `ikigai-conformance` 0.1.0 does not check (its PENDING #11/#31): a
/// declared output that is not an RDF face is never compared with what the
/// action serves. Both directions, by hand, for every action: resolved with `as`
/// omitted the served type is one of the declared outputs, and each declared
/// output is what `as=<output>` serves. `urn:log:config`'s Sink is the one
/// action the suite never fires (no `content`, PENDING #4); it is fired here,
/// with a level it already has, so the layer file is written and nothing is
/// recorded.
#[test]
fn declared_outputs_are_the_media_types_served() {
    let log = Log::new(false);
    let text = log.text();
    let cases: [Case<'_>; 8] = [
        (WRITE_IRI, Verb::Sink, vec![("content", "served")]),
        (
            TRANSREPT_IRI,
            Verb::Source,
            vec![("content", text.as_str())],
        ),
        (CONFIG_IRI, Verb::Source, vec![]),
        (CONFIG_IRI, Verb::Sink, vec![("level", "info")]),
        (SEGMENTS_IRI, Verb::Source, vec![]),
        (VERIFY_IRI, Verb::Source, vec![]),
        (log.iri.as_str(), Verb::Source, vec![]),
        (log.iri.as_str(), Verb::Exists, vec![]),
    ];
    for (iri, verb, args) in cases {
        let description = log
            .kernel
            .describe(&Iri::parse(iri).unwrap())
            .unwrap_or_else(|| panic!("{iri} describes itself"));
        let spec = description
            .action_specs()
            .into_iter()
            .find(|a| a.verb == verb)
            .unwrap_or_else(|| panic!("{iri} declares {verb:?}"));
        let declared: BTreeSet<String> = spec
            .outputs
            .iter()
            .map(|o| rdf::bare_media_type(o))
            .collect();
        assert!(!declared.is_empty(), "{iri} {verb:?} declares an output");

        let served = issue(&log.kernel, request(verb, iri, &args), &Capability::root());
        let got = rdf::bare_media_type(&served.repr_type.media_type);
        assert!(
            declared.contains(&got),
            "{iri} {verb:?} served `{got}` with `as` omitted, declared only {declared:?}"
        );

        for output in &declared {
            let mut with_as = args.clone();
            with_as.push(("as", output));
            let served = issue(
                &log.kernel,
                request(verb, iri, &with_as),
                &Capability::root(),
            );
            let got = rdf::bare_media_type(&served.repr_type.media_type);
            assert_eq!(&got, output, "{iri} {verb:?} as={output}");
        }
    }
}

/// `Suite::namespace(LOG_NS)` waives VOCABULARY for every `log:` term, defined
/// or not, so the promise it makes is checked here: every `log:` predicate and
/// class either Turtle face emits is a subject of [`VOCABULARY_TTL`], every
/// `sig:` term is one of the three a seal carries, and everything else is
/// well-known. Over the finished segment, so the face has a seal in it.
#[test]
fn the_faces_emit_only_terms_the_vocabulary_defines() {
    let log = Log::new(true);
    let defined: BTreeSet<String> = rdf::parse("text/turtle", VOCABULARY_TTL.as_bytes())
        .expect("vocabulary.ttl parses")
        .iter()
        .filter_map(|t| match &t.subject {
            oxrdf::NamedOrBlankNode::NamedNode(n) if n.as_str().starts_with(LOG_NS) => {
                Some(n.as_str().to_string())
            }
            _ => None,
        })
        .collect();
    assert!(
        defined.len() > 20,
        "the vocabulary defines its terms: {defined:?}"
    );

    let faces = [
        (
            "config",
            issue(
                &log.kernel,
                request(Verb::Source, CONFIG_IRI, &[("as", "text/turtle")]),
                &Capability::root(),
            ),
        ),
        (
            "segment",
            issue(
                &log.kernel,
                request(Verb::Source, &log.iri, &[]),
                &Capability::root(),
            ),
        ),
    ];
    for (name, repr) in faces {
        let triples = rdf::parse(&repr.repr_type.media_type, &repr.bytes)
            .unwrap_or_else(|e| panic!("the {name} face parses: {e}"));
        assert!(
            !triples.is_empty(),
            "the {name} face has triples (PENDING #26)"
        );
        assert!(rdf::blank_nodes(&triples).is_empty(), "{name}: skolemized");
        let terms = rdf::terms(&triples);
        for term in &terms {
            if let Some(local) = term.strip_prefix(LOG_NS) {
                assert!(
                    defined.contains(term),
                    "the {name} face emits log:{local}, which vocabulary.ttl does not define"
                );
            } else if let Some(local) = term.strip_prefix(SIG_NS) {
                assert!(
                    SIG_TERMS.contains(&local),
                    "the {name} face emits sig:{local}, which ikigai-sign does not define"
                );
            } else {
                assert!(rdf::is_defined(term, &[]), "{name}: `{term}` is nobody's");
            }
        }
        if name == "segment" {
            assert!(
                terms.contains(&format!("{SIG_NS}contentHash")),
                "a sealed segment's face carries the seal's digest: {terms:?}"
            );
        }
    }
}

/// `Fixture::new(id, …)` is looked up by description id, and an id that does not
/// match any description is not an error — the fixture is silently unused and
/// the action runs with the derived minimal inputs instead. So the ids this file
/// uses are held to what the kernel serves, exact IRIs and the template alike.
#[test]
fn the_fixture_ids_are_the_description_ids() {
    let log = Log::new(false);
    for (iri, id) in [
        (WRITE_IRI, WRITE),
        (TRANSREPT_IRI, TRANSREPT),
        (CONFIG_IRI, CONFIG),
        (SEGMENTS_IRI, SEGMENTS),
        (VERIFY_IRI, VERIFY),
        (log.iri.as_str(), SEGMENT),
    ] {
        let description = log
            .kernel
            .describe(&Iri::parse(iri).unwrap())
            .unwrap_or_else(|| panic!("{iri} describes itself"));
        assert_eq!(description.id, id, "{iri}");
    }
}
