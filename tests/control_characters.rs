//! Control characters in logged values (ledger #2732).
//!
//! One entry is one PRINTABLE line: a value holding a control character (C0,
//! DEL, C1) or a line or paragraph separator is written as an escape that the
//! parser reads back, never as the raw character, whether the value would
//! otherwise have been written bare or quoted. The hash chain folds in the line
//! as written and the transreptor reads the value as parsed, so the two must
//! agree on the escaped form. And a segment written before the escape existed,
//! with the raw characters in it, still parses, verifies and transrepts.
//!
//! Public API only, so this is what a consumer of the crate can rely on.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ikigai_log::{
    parse_fields, to_triples, verify_chain, ClosureSink, Entry, LogConfig, Options, Prev,
    RenderError, SealPolicy, Timestamp, Vocabulary, Writer, WriterOptions, MESSAGE_CLASS,
};
use oxrdf::Term;

const T0: u64 = 1_700_000_000_000; // 2023-11-14T22:13:20.000Z
const SUBJECT: &str = "urn:ikigai:instance:bug:seg";

fn at(ms: u64) -> Timestamp {
    Timestamp::from_millis(ms)
}

fn prefixes() -> BTreeMap<String, String> {
    BTreeMap::from([(
        "log".to_string(),
        "https://ikigai-rs.dev/ns/log#".to_string(),
    )])
}

/// Whether `c` may not appear raw on a written line: every Unicode control
/// character (C0, DEL, C1), and the two separators some readers break a line on.
fn forbidden(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}'
}

/// Every forbidden character, one at a time.
fn every_forbidden() -> Vec<char> {
    (0u32..=0x9f)
        .chain([0x2028, 0x2029])
        .filter_map(char::from_u32)
        .filter(|&c| forbidden(c))
        .collect()
}

/// Values shaped to take each rendering path: no whitespace and no quote (the
/// BARE path, before this fix), and with a space (the QUOTED path).
fn payloads() -> Vec<String> {
    let mut values = vec![
        // A color change, a window-title change and a screen clear.
        "red\u{1b}[31mtext\u{1b}[0m".to_string(),
        "\u{1b}]0;title\u{7}".to_string(),
        "two words\u{1b}]0;title\u{7} and more".to_string(),
        "\u{9b}2J\u{7f}\u{0}".to_string(),
        "line\u{2028}separator and\u{2029}paragraph".to_string(),
        // Text that already looks like an escape must stay that text.
        "literal \\u{1b} stays literal".to_string(),
        "\\u{1b}".to_string(),
    ];
    for c in every_forbidden() {
        values.push(format!("bare{c}value"));
        values.push(format!("quoted {c} value"));
        values.push(c.to_string());
    }
    values
}

fn assert_printable(line: &str) {
    if let Some(c) = line.chars().find(|&c| forbidden(c)) {
        panic!("raw U+{:04X} on a written line: {line:?}", c as u32);
    }
}

#[test]
fn a_rendered_entry_holds_no_raw_control_character_and_reads_back() {
    let prefixes = prefixes();
    for value in payloads() {
        let entry = Entry::new(at(T0), MESSAGE_CLASS, SUBJECT).with("msg", value.clone());
        let line = entry.render(&prefixes).unwrap();
        assert_printable(&line);
        let back = Entry::parse(&line, &prefixes).unwrap();
        assert_eq!(back, entry, "round trip of {value:?} through {line:?}");
    }
}

#[test]
fn the_field_syntax_reads_the_escape_and_refuses_a_malformed_one() {
    let fields = parse_fields(r#"msg="a\u{1b}b" bell="\u{7}" sep="\u{2028}""#).unwrap();
    assert_eq!(fields[0].1, "a\u{1b}b");
    assert_eq!(fields[1].1, "\u{7}");
    assert_eq!(fields[2].1, "\u{2028}");
    for bad in [
        r#"msg="\u1b""#,
        r#"msg="\u{}""#,
        r#"msg="\u{zz}""#,
        r#"msg="\u{1b""#,
        r#"msg="\u{1234567}""#,
        r#"msg="\u{d800}""#,
    ] {
        assert!(parse_fields(bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn a_control_character_in_an_iri_column_is_refused_not_written() {
    let prefixes = prefixes();
    for c in every_forbidden() {
        let subject = format!("urn:x:a{c}b");
        let entry = Entry::new(at(T0), MESSAGE_CLASS, subject.clone());
        assert_eq!(
            entry.render(&prefixes),
            Err(RenderError::NotAnIri(subject)),
            "U+{:04X} in the subject",
            c as u32
        );
        let class = format!("urn:x:Class{c}");
        let entry = Entry::new(at(T0), class.clone(), SUBJECT);
        assert_eq!(
            entry.render(&prefixes),
            Err(RenderError::NotAnIri(class)),
            "U+{:04X} in the class",
            c as u32
        );
    }
}

/// A writer onto a captured buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);
impl Captured {
    fn writer(&self) -> Writer {
        let lines = self.0.clone();
        let config = LogConfig::default()
            .with_instance("bug:seg")
            .with_level("info")
            .unwrap();
        Writer::open_with_sink_and(
            &config,
            Vocabulary::shared_builtin(),
            at(T0),
            Box::new(ClosureSink(move |l: &str| {
                lines.lock().unwrap().push(l.to_string())
            })),
            WriterOptions {
                seals: SealPolicy {
                    every_entries: 7,
                    every_millis: 60_000,
                },
                prev: Some(Prev::Genesis),
                ..WriterOptions::default()
            },
        )
        .unwrap()
    }
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    fn text(&self) -> String {
        self.lines().join("\n") + "\n"
    }
}

/// Every literal object in the graph, as its lexical form.
fn literals(text: &str) -> Vec<String> {
    to_triples(text, Vocabulary::builtin(), &Options::all())
        .unwrap()
        .into_iter()
        .filter_map(|t| match t.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
        .collect()
}

fn name_of(text: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix("@name"))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn a_written_segment_is_printable_verifies_and_transrepts_the_original_values() {
    let captured = Captured::default();
    let mut writer = captured.writer();
    let values = payloads();
    for (i, value) in values.iter().enumerate() {
        writer
            .write(Entry::new(at(T0 + 1 + i as u64), MESSAGE_CLASS, SUBJECT).with("msg", value))
            .unwrap();
    }
    writer.close(at(T0 + 10_000)).unwrap();

    // Each write is one sink line, and none holds a raw control character.
    for line in captured.lines() {
        assert!(!line.contains('\n'), "{line:?}");
        assert_printable(&line);
    }
    let text = captured.text();

    // The chain hashes the escaped bytes as written; a verifier reads the same.
    let report = verify_chain(&[(name_of(&text), text.clone())], Vocabulary::builtin());
    assert!(report.ok(), "{}", report.render());
    assert!(
        report.segments[0].findings.is_empty(),
        "{}",
        report.render()
    );
    assert!(report.segments[0].seals > 1);

    // The transreptor yields the ORIGINAL value, decoded, for every entry.
    let found = literals(&text);
    for value in &values {
        assert!(
            found.contains(value),
            "transreption lost {value:?}; the graph holds no such literal"
        );
    }
}

/// The exact bytes `ikigai-log` 0.9.1 wrote for three messages carrying raw
/// control characters, one bare (seq 2) and one quoted (seq 3), with its seals.
/// Captured from the 0.9.1 writer, not composed by hand.
const WRITTEN_BY_0_9_1: &str = "# ikigai-log v1\n@prefix log:  <https://ikigai-rs.dev/ns/log#> .\n@prefix prov: <http://www.w3.org/ns/prov#> .\n@name     urn:log:bug:seg:2023-11-14T22-13-20Z\n@instance urn:ikigai:instance:bug:seg\n@level    log:info\n@started  2023-11-14T22:13:20.000Z\n@prev     genesis\n\n\n2023-11-14T22:13:20.000Z log:ProcessStart urn:ikigai:instance:bug:seg seq=1 pid=87148\n2023-11-14T22:13:20.010Z log:Message urn:ikigai:instance:bug:seg seq=2 msg=red\u{1b}[31mtext\u{7}\u{7f}\n#seal 1-2 sha256:20a4611c84620c75ad8b794f5e5b4694ccb122a5f7eb641cbb3318f86ef1fee6\n2023-11-14T22:13:20.020Z log:Message urn:ikigai:instance:bug:seg seq=3 msg=\"two words\u{1b}]0;title\u{7} \u{9b}2J\0\"\n2023-11-14T22:13:20.030Z log:Message urn:ikigai:instance:bug:seg seq=4 msg=plain\n#seal 3-4 sha256:7400c1441b038f6230c722626533c7a113a6d53cb4c41f728f1e286b8428b01f\n2023-11-14T22:13:20.040Z log:ProcessStop urn:ikigai:instance:bug:seg seq=5\n#seal 5-5 sha256:1b36f879eb59e068c9544aff85d59f890f7e29f8b213103b20f782a458d1c424\n";

#[test]
fn a_segment_written_before_the_escape_still_parses_verifies_and_transrepts() {
    let text = WRITTEN_BY_0_9_1;
    let report = verify_chain(&[(name_of(text), text.to_string())], Vocabulary::builtin());
    assert!(report.ok(), "{}", report.render());
    assert!(
        report.segments[0].findings.is_empty(),
        "{}",
        report.render()
    );
    assert_eq!(report.segments[0].entries, 5);
    assert_eq!(report.segments[0].seals, 3);

    let found = literals(text);
    for value in [
        "red\u{1b}[31mtext\u{7}\u{7f}",
        "two words\u{1b}]0;title\u{7} \u{9b}2J\u{0}",
    ] {
        assert!(found.contains(&value.to_string()), "lost {value:?}");
    }
}

/// The incremental `urn:log:transrept` body path reads lines one at a time, so
/// it must decode an escape exactly as the bytes path does, for a segment
/// written with escapes and for one written before them.
#[cfg(not(target_family = "wasm"))]
#[test]
fn the_incremental_transreptor_agrees_with_the_bytes_path_on_escaped_values() {
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, EndpointSpace, Exact, Iri, Kernel, Request, Verb};

    let captured = Captured::default();
    let mut writer = captured.writer();
    for (i, value) in payloads().iter().enumerate() {
        writer
            .write(Entry::new(at(T0 + 1 + i as u64), MESSAGE_CLASS, SUBJECT).with("msg", value))
            .unwrap();
    }
    writer.close(at(T0 + 10_000)).unwrap();
    let escaped = captured.text();

    let kernel = Kernel::new(Arc::new(EndpointSpace::new().bind(
        Exact::new(ikigai_log::TRANSREPT_IRI),
        ikigai_log::segments::TransreptEndpoint::new(Vocabulary::shared_builtin()),
    )));
    for text in [escaped.as_str(), WRITTEN_BY_0_9_1] {
        let expected = ikigai_log::to_turtle(text, Vocabulary::builtin(), &Options::all()).unwrap();
        let request = Request::new(Verb::Source, Iri::parse(ikigai_log::TRANSREPT_IRI).unwrap())
            .with_arg("content", ArgRef::Inline(text.as_bytes().to_vec()));
        let answer = block_on(kernel.issue_body(request, &Capability::root())).unwrap();
        assert_eq!(
            block_on(answer.collect(1 << 22)).unwrap().bytes,
            expected.as_bytes()
        );
    }
}
