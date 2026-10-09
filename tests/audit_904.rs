//! Regression tests for audit round 6 (ledger #904, ikigai-log @ 76ef41e).
//!
//! Two blind auditors reproduced fifteen root causes on that commit: Claude's
//! reproductions (`R*`) and Hermes's probes (`H*`). Each test below started as one
//! of them and FAILED on 76ef41e because of the defect it names; it now pins the
//! fix. Where the fix changed the door the reproduction walked through (a write
//! that is now refused, say), the test asserts the refusal AND what the
//! reproduction cared about, rather than the old precondition.
//!
//! Public API only, so this is what a consumer of the crate can rely on.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ikigai_core::{ArgRef, Capability, Clock, Expiry, Iri, Kernel, Request, Time, Verb};
use ikigai_log::{
    head_of, to_triples, verify_chain, ClosureSink, Destination, Entry, Finding, LogConfig,
    LogHandle, Options, Prev, SealPolicy, SealSigner, Timestamp, Vocabulary, Writer, WriterOptions,
    LEVEL_CHANGE_CLASS, MESSAGE_CLASS, VERIFY_IRI,
};

const T0: u64 = 1_700_000_000_000; // 2023-11-14T22:13:20.000Z

struct Fixed(u64);
impl Clock for Fixed {
    fn now(&self) -> Time {
        Time::from_millis(self.0)
    }
}

/// A scratch directory under the system temp dir, removed on drop. Unique per
/// process AND per call, so parallel tests never share one.
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Scratch {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ikl-904-{}-{}-{tag}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn at(ms: u64) -> Timestamp {
    Timestamp::from_millis(ms)
}

fn log(term: &str) -> String {
    format!("https://ikigai-rs.dev/ns/log#{term}")
}

fn file_config(dir: &Path, level: &str) -> LogConfig {
    LogConfig::default()
        .with_instance("bug:seg")
        .with_level(level)
        .unwrap()
        .with_destination(Destination::File)
        .with_directory(dir)
}

fn kernel(handle: Arc<LogHandle>) -> Kernel {
    Kernel::new(Arc::new(ikigai_log::endpoints::space(handle))).with_clock(Arc::new(Fixed(T0)))
}

fn req(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Request {
    let mut r = Request::new(verb, Iri::parse(iri).unwrap());
    for (k, v) in args {
        r = r.with_arg(*k, ArgRef::Inline(v.as_bytes().to_vec()));
    }
    r
}

fn issue(k: &Kernel, r: Request, cap: &Capability) -> ikigai_core::Result<String> {
    futures::executor::block_on(k.issue(r, cap))
        .map(|repr| String::from_utf8(repr.bytes.to_vec()).unwrap())
}

/// Every `*.log` file in `dir`, sorted by file name.
fn segment_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "log"))
        .collect();
    v.sort();
    v
}

fn name_of(text: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix("@name"))
        .unwrap()
        .trim()
        .to_string()
}

fn msg(ms: u64, text: &str) -> Entry {
    Entry::new(at(ms), MESSAGE_CLASS, "urn:ikigai:instance:bug:seg").with("msg", text)
}

fn breaking(report: &ikigai_log::SegmentReport) -> Vec<&Finding> {
    report.findings.iter().filter(|f| f.is_breaking()).collect()
}

/// A writer onto a captured buffer, chained from `prev` — the sink path, where
/// nothing is discovered and nothing is bracketed for the caller.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);
impl Captured {
    fn writer(&self, level: &str, now: u64, prev: Prev, seals: SealPolicy) -> Writer {
        let lines = self.0.clone();
        let config = LogConfig::default()
            .with_instance("bug:seg")
            .with_level(level)
            .unwrap();
        Writer::open_with_sink_and(
            &config,
            Vocabulary::shared_builtin(),
            at(now),
            Box::new(ClosureSink(move |l: &str| {
                lines.lock().unwrap().push(l.to_string())
            })),
            WriterOptions {
                seals,
                prev: Some(prev),
                ..WriterOptions::default()
            },
        )
        .unwrap()
    }
    fn text(&self) -> String {
        self.0.lock().unwrap().join("\n") + "\n"
    }
}

struct FakeSigner;
impl SealSigner for FakeSigner {
    fn algorithm(&self) -> &str {
        "Ed25519"
    }
    fn sign(&self, tagged_hash: &str) -> Option<String> {
        // Deterministic stand-in: the point is that the signature covers the HASH
        // ONLY, so a tamperer never has to touch it.
        Some(format!("SIGNED{}", &tagged_hash[7..19]))
    }
}

// =====================================================================================
// #904 item 1 — the seal's range and the tail after it are inside the evidence
// =====================================================================================

/// [C-R1] Entries forged after the final seal of a signed MIDDLE segment, with the
/// seal's range widened and its hash and signature left alone.
#[test]
fn r1_entries_forged_after_the_final_seal_of_a_middle_segment_are_breaking() {
    let dir = Scratch::new("r1");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "info")));
    handle.set_signer(Some(Box::new(FakeSigner)));
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    handle.write(msg(T0 + 10, "real one")).unwrap();
    handle.write(msg(T0 + 20, "real two")).unwrap();
    handle.rotate(at(T0 + 1_000)).unwrap().expect("rotated");
    handle.write(msg(T0 + 1_010, "in the successor")).unwrap();
    handle.close(at(T0 + 1_020)).unwrap();

    let files = segment_files(dir.path());
    assert_eq!(files.len(), 2);
    let a = std::fs::read_to_string(&files[0]).unwrap();
    let b = std::fs::read_to_string(&files[1]).unwrap();

    let honest = verify_chain(
        &[(name_of(&a), a.clone()), (name_of(&b), b.clone())],
        Vocabulary::builtin(),
    );
    assert!(honest.ok(), "{}", honest.render());
    assert!(
        honest.segments[0].findings.is_empty(),
        "{}",
        honest.render()
    );

    let lines: Vec<&str> = a.lines().collect();
    let seal_at = lines.iter().rposition(|l| l.starts_with("#seal ")).unwrap();
    let rotation = lines[..seal_at]
        .iter()
        .rev()
        .find(|l| l.contains(" log:Rotation "))
        .unwrap()
        .to_string();
    let last: u64 = rotation
        .split_whitespace()
        .find_map(|t| t.strip_prefix("seq="))
        .unwrap()
        .parse()
        .unwrap();
    let seal_tokens: Vec<&str> = lines[seal_at].split_whitespace().collect();
    let first = seal_tokens[1].split_once('-').unwrap().0;
    let widened = format!(
        "#seal {first}-{} {} {}",
        last + 2,
        seal_tokens[2],
        seal_tokens[3]
    );
    let forged = format!(
        "2023-11-14T22:13:20.900Z log:Message urn:ikigai:instance:bug:seg seq={} msg=FORGED",
        last + 1
    );
    let rotation_again = rotation.replace(&format!("seq={last}"), &format!("seq={}", last + 2));
    let mut tampered: Vec<String> = lines[..seal_at].iter().map(|s| s.to_string()).collect();
    tampered.push(widened);
    tampered.push(forged);
    tampered.push(rotation_again);
    let tampered = tampered.join("\n") + "\n";

    let graph = to_triples(&tampered, Vocabulary::builtin(), &Options::all()).unwrap();
    assert!(graph.iter().any(|t| t.to_string().contains("FORGED")));

    let report = verify_chain(
        &[(name_of(&tampered), tampered), (name_of(&b), b)],
        Vocabulary::builtin(),
    );
    let found = breaking(&report.segments[0]);
    assert!(
        !report.ok()
            && found
                .iter()
                .any(|f| matches!(f, Finding::SealRangeMismatch { .. }))
            && found
                .iter()
                .any(|f| matches!(f, Finding::AfterTheEnd { .. })),
        "the widened range and the entries past the end must both be breaking:\n{}",
        report.render()
    );
}

/// [H-3] Inflating a crashed segment's final seal `last` must not erase the
/// unsealed tail: the range is checked against the dense run the hash covers.
#[test]
fn h3_a_seal_range_that_disagrees_with_the_entries_is_breaking() {
    let captured = Captured::default();
    let mut writer = captured.writer(
        "info",
        T0,
        Prev::Genesis,
        SealPolicy {
            every_entries: 3,
            every_millis: u64::MAX,
        },
    );
    writer.write(msg(T0 + 100, "one")).unwrap(); // seq 2
    writer.write(msg(T0 + 200, "two")).unwrap(); // seq 3 -> #seal 1-3
    writer.write(msg(T0 + 300, "three")).unwrap(); // seq 4, unsealed
    drop(writer); // a crash

    let original = captured.text();
    let before = ikigai_log::verify_segment(&original, Vocabulary::builtin(), None);
    assert!(before.ok(), "{}", before.render_findings());
    assert!(before
        .findings
        .iter()
        .any(|f| matches!(f, Finding::UnsealedTail { from: 4, to: 4 })));

    let tampered = original.replace("#seal 1-3 ", "#seal 1-999 ");
    assert_ne!(tampered, original);
    let after = ikigai_log::verify_segment(&tampered, Vocabulary::builtin(), None);
    assert!(
        !after.ok()
            && after.findings.iter().any(|f| matches!(
                f,
                Finding::SealRangeMismatch {
                    last: 999,
                    covered: 3,
                    ..
                }
            )),
        "a seal range no entry run supports is breaking:\n{}",
        after.render_findings()
    );
    assert!(
        after
            .findings
            .iter()
            .any(|f| matches!(f, Finding::UnsealedTail { from: 4, to: 4 })),
        "and the tail the range tried to hide is still reported:\n{}",
        after.render_findings()
    );
}

/// [H-4] A forged log:ProcessStop after a sealed segment's final seal: breaking,
/// and the segment is not served cacheable.
#[test]
fn h4_a_forged_stop_after_the_final_seal_is_breaking_and_not_cached() {
    let dir = Scratch::new("h4");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "info")));
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    handle.write(msg(T0 + 100, "real")).unwrap();
    let (segment, _) = handle.open_segment().unwrap();
    handle.close(at(T0 + 200)).unwrap();

    let path = segment_files(dir.path())[0].clone();
    let original = std::fs::read_to_string(&path).unwrap();
    let k = kernel(handle.clone());
    let honest =
        futures::executor::block_on(k.issue(req(Verb::Source, &segment, &[]), &Capability::root()))
            .unwrap();
    assert_eq!(
        honest.expiry,
        Expiry::Never,
        "precondition: a finished segment caches"
    );

    let appended = format!(
        "{original}2023-11-14T22:13:21.000Z log:Message urn:probe:subject seq=4 msg=phantom\n\
         2023-11-14T22:13:22.000Z log:ProcessStop urn:ikigai:instance:bug:seg seq=5\n"
    );
    std::fs::write(&path, &appended).unwrap();

    let report = ikigai_log::verify_segment(&appended, Vocabulary::builtin(), None);
    assert!(
        !report.ok()
            && report
                .findings
                .iter()
                .any(|f| matches!(f, Finding::AfterTheEnd { .. })),
        "{}",
        report.render_findings()
    );

    // A fresh kernel, so nothing cached above answers for the edited file.
    let k = kernel(handle);
    let served =
        futures::executor::block_on(k.issue(req(Verb::Source, &segment, &[]), &Capability::root()))
            .unwrap();
    assert_ne!(
        served.expiry,
        Expiry::Never,
        "a segment with a tail past its end is not finished, so it is not cached"
    );
}

/// [H-4, widened] The same append WITHOUT a forged end marker: entries after an
/// orderly end are breaking whatever class the last one is, or a tamperer simply
/// leaves the marker off and the append reads as a crash.
#[test]
fn h4b_any_entry_after_an_orderly_end_is_breaking() {
    let captured = Captured::default();
    let writer = captured.writer("info", T0, Prev::Genesis, SealPolicy::default());
    writer.close(at(T0 + 10)).unwrap();
    let appended = format!(
        "{}2023-11-14T22:13:21.000Z log:Message urn:probe:subject seq=3 msg=phantom\n",
        captured.text()
    );
    let report = ikigai_log::verify_segment(&appended, Vocabulary::builtin(), None);
    assert!(
        !report.ok()
            && report.findings.iter().any(|f| matches!(
                f,
                Finding::AfterTheEnd {
                    ended_at: 2,
                    from: 3,
                    to: 3
                }
            )),
        "{}",
        report.render_findings()
    );
}

// =====================================================================================
// #904 item 3 — a level bracket says WHICH change it records, and only a sealed one
// counts
// =====================================================================================

fn level_change(ms: u64, from: &str, to: &str) -> Entry {
    Entry::new(at(ms), LEVEL_CHANGE_CLASS, "urn:log:config")
        .with("key", "level")
        .with("from", from)
        .with("to", to)
        .with("effective", "next-segment")
}

fn any_unbracketed(report: &ikigai_log::ChainReport) -> bool {
    report.segments.iter().any(|s| {
        s.findings
            .iter()
            .any(|f| matches!(f, Finding::UnbracketedLevelChange { .. }))
    })
}

/// [H-5a] A recorded change about one transition does not explain a different,
/// unrecorded one at the same boundary.
#[test]
fn h5a_one_bracket_does_not_mask_a_different_change() {
    let a = Captured::default();
    let mut writer = a.writer("debug", T0, Prev::Genesis, SealPolicy::default());
    writer
        .write(level_change(T0 + 150, &log("info"), &log("debug")))
        .unwrap();
    let closed = writer.close(at(T0 + 200)).unwrap();

    let b = Captured::default();
    let writer = b.writer(
        "error",
        T0 + 500_000,
        Prev::Seal(closed.head.clone()),
        SealPolicy::default(),
    );
    writer.close(at(T0 + 500_200)).unwrap();

    let report = verify_chain(
        &[
            (name_of(&a.text()), a.text()),
            (name_of(&b.text()), b.text()),
        ],
        Vocabulary::builtin(),
    );
    assert!(
        any_unbracketed(&report) && !report.ok(),
        "debug -> error was recorded nowhere:\n{}",
        report.render()
    );
}

/// A run of recorded changes explains where it ends, in whatever order they were
/// recorded across the two segments.
#[test]
fn a_recorded_run_of_changes_brackets_the_level_it_reaches() {
    let a = Captured::default();
    let mut writer = a.writer("info", T0, Prev::Genesis, SealPolicy::default());
    writer
        .write(level_change(T0 + 100, &log("info"), &log("debug")))
        .unwrap();
    // The CURIE spelling an operator might write by hand reads the same.
    writer
        .write(level_change(T0 + 200, "log:debug", "log:error"))
        .unwrap();
    let closed = writer.close(at(T0 + 300)).unwrap();

    let b = Captured::default();
    let writer = b.writer(
        "error",
        T0 + 1_000,
        Prev::Seal(closed.head.clone()),
        SealPolicy::default(),
    );
    writer.close(at(T0 + 1_100)).unwrap();

    let report = verify_chain(
        &[
            (name_of(&a.text()), a.text()),
            (name_of(&b.text()), b.text()),
        ],
        Vocabulary::builtin(),
    );
    assert!(report.ok(), "{}", report.render());
}

/// [H-5b] A log:LevelChange forged into a crashed segment's UNSEALED tail does not
/// turn a broken boundary into a clean one.
#[test]
fn h5b_a_bracket_in_an_unsealed_tail_is_not_trusted() {
    let a = Captured::default();
    let mut writer = a.writer("debug", T0, Prev::Genesis, SealPolicy::manual());
    writer.write(msg(T0 + 100, "debug era")).unwrap();
    drop(writer); // a crash: nothing sealed
    let a_text = a.text();

    let b = Captured::default();
    let writer = b.writer(
        "info",
        T0 + 500_000,
        Prev::Seal(head_of(&a_text).unwrap()),
        SealPolicy::default(),
    );
    writer.close(at(T0 + 500_200)).unwrap();
    let b_text = b.text();

    let before = verify_chain(
        &[
            (name_of(&a_text), a_text.clone()),
            (name_of(&b_text), b_text.clone()),
        ],
        Vocabulary::builtin(),
    );
    assert!(
        any_unbracketed(&before) && !before.ok(),
        "{}",
        before.render()
    );

    let forged = format!(
        "{a_text}2023-11-14T22:13:25.000Z log:LevelChange urn:log:config key=level \
         from=log:debug to=log:info effective=next-segment seq=3\n"
    );
    let after = verify_chain(
        &[(name_of(&forged), forged), (name_of(&b_text), b_text)],
        Vocabulary::builtin(),
    );
    assert!(
        any_unbracketed(&after) && !after.ok(),
        "a bracket no seal covers is not evidence:\n{}",
        after.render()
    );
}

// =====================================================================================
// #904 item 12 — verify reports what it cannot read
// =====================================================================================

/// [C-R8] A segment whose header will not parse is reported, not skipped.
#[test]
fn r8_a_damaged_segment_in_the_directory_is_reported() {
    let dir = Scratch::new("r8");
    for start in [T0, T0 + 5_000] {
        let h = LogHandle::new(None, None, file_config(dir.path(), "info"));
        h.open(Vocabulary::shared_builtin(), at(start)).unwrap();
        h.write(msg(start + 1, "work")).unwrap();
        h.close(at(start + 2)).unwrap();
    }
    let files = segment_files(dir.path());
    assert_eq!(files.len(), 2);
    let newest = std::fs::read_to_string(&files[1]).unwrap();
    std::fs::write(
        &files[1],
        newest.replacen("# ikigai-log v1", "# ikigai-log v9", 1),
    )
    .unwrap();

    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "info")));
    let body = issue(
        &kernel(handle),
        req(Verb::Source, VERIFY_IRI, &[]),
        &Capability::root(),
    )
    .unwrap();
    let damaged = files[1].display().to_string();
    assert!(
        body.lines()
            .any(|l| l.starts_with("segment ") && l.contains(&damaged) && l.contains("BROKEN")),
        "a damaged segment sits in the directory and verify must name it:\n{body}"
    );
}

// =====================================================================================
// #904 item 4 — a segment is what its @name says
// =====================================================================================

/// [C-R7] An IRI that names no segment does not exist, even when its fast-path
/// file name collides with a real segment's (`bug-seg` and `bug:seg` slug alike).
#[test]
fn r7_an_iri_that_names_no_segment_does_not_exist() {
    let dir = Scratch::new("r7");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "info")));
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let (real, _) = handle.open_segment().unwrap();
    assert_eq!(real, "urn:log:bug:seg:2023-11-14T22-13-20Z");
    let k = kernel(handle.clone());
    let alias = "urn:log:bug-seg:2023-11-14T22-13-20Z";
    let exists = issue(&k, req(Verb::Exists, alias, &[]), &Capability::root()).unwrap();
    assert_eq!(exists.trim(), "false", "<{alias}> names no segment");
    let served = issue(&k, req(Verb::Source, alias, &[]), &Capability::root());
    assert!(
        matches!(served, Err(ikigai_core::Error::NotFound(_))),
        "{served:?}"
    );
    // And the real one still resolves, by the fast path or the slow one.
    assert_eq!(
        issue(&k, req(Verb::Exists, &real, &[]), &Capability::root())
            .unwrap()
            .trim(),
        "true"
    );
}

/// [H-6] A renamed (or planted) file does not answer for the IRI its file name
/// suggests; the file's own @name is the authority.
#[test]
fn h6_a_renamed_file_answers_only_for_its_own_name() {
    let dir = Scratch::new("h6");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "info")));
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    handle.write(msg(T0 + 100, "real")).unwrap();
    let (real, _) = handle.open_segment().unwrap();
    handle.close(at(T0 + 200)).unwrap();

    let real_path = segment_files(dir.path())[0].clone();
    std::fs::rename(
        &real_path,
        dir.path().join("bug-seg-2030-01-01T00-00-00Z.log"),
    )
    .unwrap();

    let k = kernel(Arc::new(LogHandle::new(
        None,
        None,
        file_config(dir.path(), "info"),
    )));
    let asked = "urn:log:bug:seg:2030-01-01T00-00-00Z";
    let served = issue(&k, req(Verb::Source, asked, &[]), &Capability::root());
    assert!(
        matches!(served, Err(ikigai_core::Error::NotFound(_))),
        "<{asked}> names no segment; got {served:?}"
    );
    // The file is still found by what it says it is.
    let found = issue(&k, req(Verb::Source, &real, &[]), &Capability::root()).unwrap();
    assert!(found.contains(&real), "{found}");
}

// =====================================================================================
// #904 item 2 — urn:log:write cannot speak for anyone
// =====================================================================================

fn sink_as(k: &Kernel, args: &[(&str, &str)], cap: &Capability) -> ikigai_core::Result<String> {
    issue(k, req(Verb::Sink, ikigai_log::WRITE_IRI, args), cap)
}

fn refused_as_argument(result: &ikigai_core::Result<String>, name: &str) -> bool {
    matches!(result, Err(ikigai_core::Error::InvalidArgument { name: n, .. }) if n == name)
}

/// [C-R4, H-2] One tenant cannot attribute an entry to another through `fields=`.
#[test]
fn r4_one_tenant_cannot_attribute_an_entry_to_another() {
    use ikigai_core::Tracer;
    let dir = Scratch::new("r4");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "debug")));
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let k = kernel(handle.clone());
    let bob: Arc<dyn Tracer> = Arc::new(
        ikigai_log::LogTracer::new(handle.clone(), Arc::new(Fixed(T0)))
            .on_behalf_of(ikigai_log::Principal::new("urn:tenant:bob").unwrap()),
    );
    let wrote = futures::executor::block_on(k.issue_traced(
        req(
            Verb::Sink,
            ikigai_log::WRITE_IRI,
            &[
                ("msg", "alice approved the transfer"),
                ("fields", "principal=urn:tenant:alice"),
            ],
        ),
        &Capability::scoped([ikigai_log::CAP_WRITE]),
        bob,
    ));
    assert!(
        matches!(&wrote, Err(ikigai_core::Error::InvalidArgument { name, .. }) if name == "fields"),
        "{wrote:?}"
    );
    handle.close(at(T0 + 10)).unwrap();

    let text = std::fs::read_to_string(&segment_files(dir.path())[0]).unwrap();
    assert!(
        !text.contains("alice"),
        "nothing about alice landed:\n{text}"
    );
    let graph = to_triples(&text, Vocabulary::builtin(), &Options::all()).unwrap();
    assert!(
        !graph
            .iter()
            .any(|t| t.object.to_string() == "<urn:tenant:alice>"),
        "the graph attributes nothing to alice"
    );
}

/// [C-R4b, H-1, H-2] Every column the log writes itself is refused from a caller —
/// including a principal `Principal::new` would refuse outright.
#[test]
fn r4b_a_caller_cannot_restate_reserved_columns() {
    let dir = Scratch::new("r4b");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "info")));
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let k = kernel(handle.clone());
    let only_write = Capability::scoped([ikigai_log::CAP_WRITE]);
    for fields in [
        "seq=1",
        "seq=99",
        "cap=urn:cap:root",
        "denied=urn:cap:secret:read",
        "principal=urn:agent:tenant-b",
        r#"principal="urn:agent:x y""#,
        "pid=1",
        "configured=urn:ikigai:instance:other",
        "next=urn:log:bug:seg:2030-01-01T00-00-00Z",
        "dur=1 cap=urn:cap:fs",
    ] {
        let wrote = sink_as(&k, &[("msg", "x"), ("fields", fields)], &only_write);
        assert!(refused_as_argument(&wrote, "fields"), "{fields}: {wrote:?}");
    }
    // Ordinary columns still land, repeated keys included.
    let wrote = sink_as(
        &k,
        &[("msg", "x"), ("fields", "span=7 dur=12 tag=a tag=b")],
        &only_write,
    )
    .unwrap();
    assert!(wrote.ends_with(":2"), "{wrote}");
    handle.close(at(T0 + 1)).unwrap();
    let text = std::fs::read_to_string(&segment_files(dir.path())[0]).unwrap();
    assert_eq!(
        text.lines().filter(|l| l.contains(" log:Message ")).count(),
        1,
        "only the clean write landed:\n{text}"
    );
}

/// The always-land markers are the log's own: a caller cannot append a stop, a
/// rotation, a level change, a seal or a denial.
#[test]
fn the_logs_own_markers_cannot_be_written_through_the_door() {
    let dir = Scratch::new("markers");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "debug")));
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let k = kernel(handle.clone());
    for class in [
        "log:ProcessStart",
        "log:ProcessStop",
        "log:Rotation",
        "log:LevelChange",
        "log:ConfigChange",
        "log:Seal",
        "log:ChainBroken",
        "log:Dropped",
        "log:CapabilityDenied",
        "https://ikigai-rs.dev/ns/log#ProcessStop",
    ] {
        let wrote = sink_as(&k, &[("class", class)], &Capability::root());
        assert!(refused_as_argument(&wrote, "class"), "{class}: {wrote:?}");
    }
    for class in ["log:Message", "log:Warning", "log:Error", "log:Resolution"] {
        sink_as(&k, &[("class", class)], &Capability::root())
            .unwrap_or_else(|e| panic!("{class} is a caller's class: {e}"));
    }
}

// =====================================================================================
// #904 item 6 — one bad IRI cannot take down a segment's graph
// =====================================================================================

/// [C-R3] The door refuses a subject RDF would reject, and a segment that holds
/// one anyway (hand-written, or from an older writer) still transrepts, with the
/// odd entry degraded and flagged rather than the whole graph refused.
#[test]
fn r3_one_odd_subject_cannot_make_the_whole_segment_unreadable_as_a_graph() {
    let dir = Scratch::new("r3");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "info")));
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let k = kernel(handle.clone());
    for (name, args) in [
        ("subject", [("subject", "urn:x:{a}"), ("msg", "hello")]),
        ("class", [("class", "urn:x:{Odd}"), ("msg", "hello")]),
    ] {
        let wrote = sink_as(&k, &args, &Capability::root());
        assert!(refused_as_argument(&wrote, name), "{wrote:?}");
    }

    // The same lines, written by hand into a sealed segment.
    let captured = Captured::default();
    let mut writer = captured.writer("info", T0, Prev::Genesis, SealPolicy::manual());
    writer.write(msg(T0 + 1, "before")).unwrap();
    writer
        .write(Entry::new(at(T0 + 2), MESSAGE_CLASS, "urn:x:{a}").with("msg", "odd subject"))
        .unwrap();
    writer
        .write(Entry::new(at(T0 + 3), "urn:x:{Odd}", "urn:x:fine").with("msg", "odd class"))
        .unwrap();
    writer.write(msg(T0 + 4, "after")).unwrap();
    writer.close(at(T0 + 5)).unwrap();
    let text = captured.text();

    let graph = to_triples(&text, Vocabulary::builtin(), &Options::all())
        .expect("one odd line does not take the segment's graph down");
    let rendered: Vec<String> = graph.iter().map(|t| t.to_string()).collect();
    for kept in [
        "\"before\"",
        "\"after\"",
        "\"odd subject\"",
        "\"odd class\"",
    ] {
        assert!(
            rendered.iter().any(|t| t.contains(kept)),
            "{kept} is in the graph"
        );
    }
    let flags: Vec<String> = graph
        .iter()
        .filter(|t| t.predicate.as_str() == log("unreadableIri"))
        .map(|t| t.object.to_string())
        .collect();
    assert_eq!(
        flags,
        vec![
            "\"subject=urn:x:{a}\"".to_string(),
            "\"class=urn:x:{Odd}\"".to_string()
        ],
        "each degradation is reported in the graph"
    );
    // And it is still Turtle a parser takes.
    let turtle = ikigai_log::to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap();
    let parsed: Result<Vec<_>, _> = oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle)
        .for_slice(turtle.as_bytes())
        .collect();
    assert!(parsed.is_ok(), "{parsed:?}");
}

/// [C-R3b] An instance name RDF would refuse is refused where it enters: by
/// log.toml, by urn:log:config, and by the writer that would put it in a header.
#[test]
fn r3b_an_instance_name_rdf_refuses_cannot_reach_a_header() {
    let patch = ikigai_log::config::Patch::parse("instance = \"bug{1}\"\n", None);
    assert!(patch.is_err(), "log.toml refuses it: {patch:?}");

    let config = LogConfig::default()
        .with_instance("bug{1}")
        .with_level("info")
        .unwrap();
    let opened = Writer::open_with_sink(
        &config,
        Vocabulary::shared_builtin(),
        at(T0),
        Box::new(ClosureSink(|_: &str| {})),
    );
    assert!(
        matches!(opened, Err(ikigai_log::WriteError::Render(_))),
        "the writer refuses a header RDF would refuse"
    );

    let home = Scratch::new("r3bhome");
    let dir = Scratch::new("r3b");
    let handle = Arc::new(LogHandle::new(
        Some(home.path().to_path_buf()),
        None,
        file_config(dir.path(), "info"),
    ));
    let wrote = issue(
        &kernel(handle),
        req(
            Verb::Sink,
            ikigai_log::CONFIG_IRI,
            &[("instance", "bug{1}")],
        ),
        &Capability::scoped([ikigai_log::CAP_CONFIG]),
    );
    assert!(
        matches!(wrote, Err(ikigai_core::Error::InvalidArgument { .. })),
        "{wrote:?}"
    );
}

// =====================================================================================
// #904 item 14 — the IRI a write returns names the segment the entry is in
// =====================================================================================

/// [H-7] A write that triggers a rotation returns the entry's IRI in the segment
/// it landed in, not in the successor that is open by the time it returns.
#[test]
fn h7_a_write_returns_the_iri_of_the_segment_the_entry_landed_in() {
    let dir = Scratch::new("h7");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "info")));
    handle.set_policies(
        SealPolicy::default(),
        ikigai_log::RotationPolicy {
            max_entries: Some(2),
            max_age_millis: None,
        },
    );
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let (first, _) = handle.open_segment().unwrap();
    let wrote = sink_as(
        &kernel(handle.clone()),
        &[("msg", "rotates")],
        &Capability::root(),
    )
    .unwrap();
    let (now_open, _) = handle.open_segment().unwrap();
    assert_ne!(
        now_open, first,
        "precondition: the write rotated the segment"
    );
    assert_eq!(wrote.trim(), format!("{first}:2"));
    let landed = segment_files(dir.path())
        .into_iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .find(|t| name_of(t) == first)
        .unwrap();
    assert!(
        landed
            .lines()
            .any(|l| l.contains("msg=rotates") && l.contains("seq=2")),
        "{landed}"
    );
}

// =====================================================================================
// #904 items 5, 9, 10 — the log keeps logging
// =====================================================================================

/// [C-R2] A level the vocabulary does not define is refused at urn:log:config
/// (and the refusal lands), instead of closing the log at the next rotation.
#[test]
fn r2_a_typoed_level_is_refused_where_it_is_typed() {
    let dir = Scratch::new("r2");
    let home = Scratch::new("r2home");
    let handle = Arc::new(LogHandle::new(
        Some(home.path().to_path_buf()),
        None,
        file_config(dir.path(), "info"),
    ));
    handle.set_policies(
        SealPolicy::default(),
        ikigai_log::RotationPolicy {
            max_entries: Some(4),
            max_age_millis: None,
        },
    );
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let said = issue(
        &kernel(handle.clone()),
        req(Verb::Sink, ikigai_log::CONFIG_IRI, &[("level", "infoo")]),
        &Capability::scoped([ikigai_log::CAP_CONFIG]),
    );
    assert!(
        matches!(&said, Err(ikigai_core::Error::InvalidArgument { name, .. }) if name == "level"),
        "{said:?}"
    );
    assert!(
        !home.path().join("log.toml").exists()
            || !std::fs::read_to_string(home.path().join("log.toml"))
                .unwrap()
                .contains("infoo"),
        "nothing was persisted"
    );
    for i in 0..6 {
        handle.write(msg(T0 + 100 + i, "after the typo")).unwrap();
    }
    assert!(handle.is_open());
    let all: String = segment_files(dir.path())
        .into_iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect();
    assert!(
        all.contains("log:LevelChangeRejected") && all.contains("to=infoo"),
        "the rejection is in the record:\n{all}"
    );
}

/// [C-R2, the other half] A rotation that cannot open its successor leaves the
/// predecessor writing: a level set behind the endpoint's back (the host API)
/// fails the rotation BEFORE the predecessor is sealed.
#[test]
fn r2b_a_rotation_that_cannot_open_its_successor_leaves_the_predecessor_writing() {
    let dir = Scratch::new("r2b");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "info")));
    handle.set_policies(
        SealPolicy::default(),
        ikigai_log::RotationPolicy {
            max_entries: Some(3),
            max_age_millis: None,
        },
    );
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let (segment, _) = handle.open_segment().unwrap();
    let mut config = handle.config();
    config.level = log("infoo");
    handle.set_config(config);

    for i in 0..5 {
        let landed = handle.write(msg(T0 + 100 + i, "keeps landing"));
        assert!(
            matches!(landed, Ok(Some(_))),
            "an entry that landed is Ok: {landed:?}"
        );
    }
    assert!(handle.is_open(), "the log is still logging");
    assert_eq!(
        handle.open_segment().unwrap().0,
        segment,
        "into the predecessor"
    );
    assert!(
        handle.rotation_error().is_some_and(|e| e.contains("infoo")),
        "{:?}",
        handle.rotation_error()
    );
    let files = segment_files(dir.path());
    assert_eq!(files.len(), 1, "no orphaned successor file: {files:?}");
    let text = std::fs::read_to_string(&files[0]).unwrap();
    assert_eq!(
        text.matches(r#"msg="keeps landing""#).count(),
        5,
        "every entry landed once:\n{text}"
    );
    assert_eq!(
        text.matches("reason=rotation-failed").count(),
        1,
        "the failure is recorded once, not once per write:\n{text}"
    );
    assert!(
        ikigai_log::verify_segment(&text, Vocabulary::builtin(), None).ok(),
        "the predecessor was never sealed off, so nothing after it is out of place"
    );
}

/// [C-R5a] `Err` from `Writer::write` means the entry did not land: a seal that
/// fails after the line is written does not turn a landed entry into an error.
#[test]
fn r5a_an_err_from_write_means_the_entry_was_not_written() {
    #[derive(Clone, Default)]
    struct FailSeals(Arc<Mutex<Vec<String>>>);
    impl ikigai_log::LineSink for FailSeals {
        fn write_line(&mut self, line: &str) -> std::io::Result<()> {
            if line.starts_with("#seal") {
                return Err(std::io::Error::other("no space left on device"));
            }
            self.0.lock().unwrap().push(line.to_string());
            Ok(())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = FailSeals::default();
    let lines = sink.0.clone();
    let config = LogConfig::default()
        .with_instance("bug:seg")
        .with_level("info")
        .unwrap();
    let mut writer = Writer::open_with_sink_and(
        &config,
        Vocabulary::shared_builtin(),
        at(T0),
        Box::new(sink),
        WriterOptions {
            seals: SealPolicy {
                every_entries: 2,
                every_millis: u64::MAX,
            },
            ..WriterOptions::default()
        },
    )
    .unwrap();
    let result = writer.write(msg(T0 + 1, "payment 42"));
    let landed = lines
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("payment"))
        .count();
    assert_eq!(landed, 1);
    assert!(
        matches!(result, Ok(Some(2))),
        "the entry landed, so the write is not an error: {result:?}"
    );
    assert_eq!(writer.sequence(), 2);
    // The seal is owed, not forgotten: closing still tries it, and says so.
    assert!(writer.close(at(T0 + 2)).is_err());
}

/// [C-R5b] A failing ROTATION does not make landed entries count as drops.
#[cfg(unix)]
#[test]
fn r5b_a_landed_entry_is_not_counted_as_dropped() {
    use ikigai_core::{TraceEvent, Tracer};
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new("r5b");
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir.path(), "debug")));
    handle.set_policies(
        SealPolicy::default(),
        ikigai_log::RotationPolicy {
            max_entries: Some(2),
            max_age_millis: None,
        },
    );
    handle.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let file = segment_files(dir.path())[0].clone();
    let tracer = ikigai_log::LogTracer::new(handle.clone(), Arc::new(Fixed(T0)));

    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    if std::fs::write(dir.path().join("probe"), b"").is_ok() {
        // Running as a user the mode does not bind (root, in some CI
        // containers): there is no failing rotation to observe here.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        eprintln!("skipped: the directory stayed writable at mode 0555");
        return;
    }
    for span in 0..3u64 {
        tracer.record(TraceEvent {
            target: format!("urn:traced:{span}"),
            thread: "w".to_string(),
            started: Some(Time::from_millis(T0 + span)),
            ended: Some(Time::from_millis(T0 + span + 1)),
            cache_hit: false,
            span,
            parent: None,
            capability: None,
            notes: Vec::new(),
        });
    }
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let text = std::fs::read_to_string(&file).unwrap();
    let landed = (0..3)
        .filter(|s| text.contains(&format!(" urn:traced:{s} ")))
        .count();
    assert_eq!(landed, 3, "precondition: every entry landed:\n{text}");
    assert_eq!(tracer.pending_drops(), [0; 4]);
    assert!(!text.contains("log:Dropped"), "{text}");
    assert!(handle.rotation_error().is_some());
}

// =====================================================================================
// #904 items 7 and 8, ledger #159 — time and instances
// =====================================================================================

fn verify_dir(dir: &Path) -> String {
    let handle = Arc::new(LogHandle::new(None, None, file_config(dir, "info")));
    issue(
        &kernel(handle),
        req(Verb::Source, VERIFY_IRI, &[]),
        &Capability::root(),
    )
    .unwrap()
}

/// [C-R9] A clock step back across restarts (NTP, a VM restore) cannot fork the
/// chain: the predecessor is chosen by the chain, and the stamp is clamped so the
/// names still sort the way the chain runs.
#[test]
fn r9_an_honest_log_across_a_clock_step_back_verifies() {
    let dir = Scratch::new("r9");
    let hour = 3_600_000;
    for start in [T0 + hour, T0, T0 + hour / 2] {
        let h = LogHandle::new(None, None, file_config(dir.path(), "info"));
        h.open(Vocabulary::shared_builtin(), at(start)).unwrap();
        h.write(msg(start + 1, "work")).unwrap();
        h.close(at(start + 2)).unwrap();
    }
    let body = verify_dir(dir.path());
    assert!(
        !body.contains("BROKEN"),
        "nothing was tampered with:\n{body}"
    );
    let names: Vec<String> = body
        .lines()
        .filter_map(|l| l.strip_prefix("segment "))
        .map(|l| l.split_whitespace().next().unwrap().to_string())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "chain order is name order again:\n{body}");
}

/// [ledger #159] A restart chains from the TAIL of the chain, even where a
/// segment written before the clamp sorts out of order by name.
#[test]
fn a_restart_chains_from_the_chain_tail_not_the_largest_name() {
    let dir = Scratch::new("tail");
    let hour = 3_600_000;
    // S1, an ordinary segment.
    let h = LogHandle::new(None, None, file_config(dir.path(), "info"));
    h.open(Vocabulary::shared_builtin(), at(T0 + hour)).unwrap();
    h.close(at(T0 + hour + 1)).unwrap();
    let s1 = std::fs::read_to_string(&segment_files(dir.path())[0]).unwrap();
    // S2 follows S1 but is stamped an hour EARLIER — what an unclamped writer
    // left on disk before this fix.
    let s2 = Captured::default();
    let writer = s2.writer(
        "info",
        T0,
        Prev::Seal(head_of(&s1).unwrap()),
        SealPolicy::default(),
    );
    writer.close(at(T0 + 1)).unwrap();
    let s2_text = s2.text();
    std::fs::write(
        dir.path().join("bug-seg-2023-11-14T22-13-20Z.log"),
        &s2_text,
    )
    .unwrap();
    assert!(
        name_of(&s2_text) < name_of(&s1),
        "precondition: S2 sorts first"
    );

    let h = LogHandle::new(None, None, file_config(dir.path(), "info"));
    h.open(Vocabulary::shared_builtin(), at(T0 + 2 * hour))
        .unwrap();
    let (s3, _) = h.open_segment().unwrap();
    h.close(at(T0 + 2 * hour + 1)).unwrap();
    let s3_text = segment_files(dir.path())
        .into_iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .find(|t| name_of(t) == s3)
        .unwrap();
    let prev = s3_text
        .lines()
        .find_map(|l| l.strip_prefix("@prev"))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(
        prev,
        head_of(&s2_text).unwrap(),
        "S3 follows S2, the chain's tail"
    );
    let body = verify_dir(dir.path());
    assert!(!body.contains("BROKEN"), "{body}");
}

/// [C-R10] A `directory` change takes effect at the next process start, as its
/// documentation says: a rotation stays where the writer and its instance lock
/// are, so no second writer can take the same name in the new directory while
/// this one is writing there.
#[test]
fn r10_a_directory_change_waits_for_the_next_process_start() {
    let old = Scratch::new("r10old");
    let new = Scratch::new("r10new");
    let home = Scratch::new("r10home");
    let h1 = Arc::new(LogHandle::new(
        Some(home.path().to_path_buf()),
        None,
        file_config(old.path(), "info"),
    ));
    h1.open(Vocabulary::shared_builtin(), at(T0)).unwrap();
    let new_dir = new.path().display().to_string();
    let said = issue(
        &kernel(h1.clone()),
        req(
            Verb::Sink,
            ikigai_log::CONFIG_IRI,
            &[("directory", new_dir.as_str())],
        ),
        &Capability::scoped([ikigai_log::CAP_CONFIG]),
    )
    .unwrap();
    assert!(
        said.contains("directory: effective at the next process start"),
        "{said}"
    );
    h1.rotate(at(T0 + 1_000)).unwrap().expect("rotated");
    h1.write(msg(T0 + 1_001, "still here")).unwrap();
    assert!(
        segment_files(new.path()).is_empty(),
        "the running writer did not move"
    );
    assert_eq!(segment_files(old.path()).len(), 2);
    let all: String = segment_files(old.path())
        .into_iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect();
    assert!(
        all.contains("key=directory") && all.contains("effective=next-process-start"),
        "{all}"
    );

    // A second process in the new directory has it to itself.
    let h2 = Arc::new(LogHandle::new(None, None, file_config(new.path(), "info")));
    h2.open(Vocabulary::shared_builtin(), at(T0 + 2_000))
        .unwrap();
    assert_eq!(segment_files(new.path()).len(), 1);
}

// =====================================================================================
// #904 item 13 — an operator's level edit is bracketed where it takes effect
// =====================================================================================

/// [C-R11] A level changed in log.toml between runs (raised, here) verifies: the
/// writer that opens at a level its predecessor did not run at records the
/// change itself, and seals it at once.
#[test]
fn r11_an_operator_level_edit_does_not_break_verification() {
    let dir = Scratch::new("r11");
    let home = Scratch::new("r11home");
    for (start, level) in [(T0, "info"), (T0 + 5_000, "debug")] {
        std::fs::write(
            home.path().join("log.toml"),
            format!("level = \"{level}\"\n"),
        )
        .unwrap();
        let base = LogConfig::default()
            .with_instance("bug:seg")
            .with_destination(Destination::File)
            .with_directory(dir.path());
        let config = ikigai_log::load::complete_in(home.path(), None, base).unwrap();
        let h = LogHandle::new(Some(home.path().to_path_buf()), None, config);
        h.open(Vocabulary::shared_builtin(), at(start)).unwrap();
        h.write(msg(start + 1, "work")).unwrap();
        // A crash, not a close: the bracket must not wait for an orderly end.
        drop(h);
    }
    let body = verify_dir(dir.path());
    assert!(
        !body.contains("BROKEN"),
        "an operator raised the level:\n{body}"
    );
    let newest = std::fs::read_to_string(&segment_files(dir.path())[1]).unwrap();
    let bracket = newest
        .lines()
        .position(|l| l.contains("log:LevelChange") && l.contains("effective=this-segment"))
        .unwrap_or_else(|| panic!("the writer recorded the change:\n{newest}"));
    assert!(
        newest
            .lines()
            .skip(bracket)
            .any(|l| l.starts_with("#seal ")),
        "and sealed it at once:\n{newest}"
    );
}
