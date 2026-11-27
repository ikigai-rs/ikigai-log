//! Ledger #4510: link verification alone passes any valid prefix of a chain.
//!
//! A chain cut back to an earlier seal is still a chain whose every link holds,
//! so `verify_chain` reports it `ok()`: the cut tail reads as a crash (`noted`,
//! never `BROKEN`). Only a head the verifier holds from somewhere else, a seal
//! hash or a stated length, can say the chain ends too soon.

use std::sync::{Arc, Mutex};

use ikigai_log::{
    verify_chain, verify_chain_to, ClosureSink, Entry, ExpectedHead, Finding, LogConfig, Prev,
    SealPolicy, Timestamp, Vocabulary, Writer, WriterOptions, MESSAGE_CLASS,
};

fn at(seconds: u64) -> Timestamp {
    let base = Timestamp::parse("2026-11-27T10:00:00.000Z")
        .unwrap()
        .as_millis();
    Timestamp::from_millis(base + seconds * 1_000)
}

/// One closed segment: two entries, a seal, two more entries, then the close
/// (which writes a stop and seals it). Returns its name, its lines and its head.
fn closed_segment() -> (String, Vec<String>, String) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    let mut w = Writer::open_with_sink_and(
        &LogConfig::default().with_instance("bug:truncate"),
        Vocabulary::shared_builtin(),
        at(0),
        Box::new(ClosureSink(move |l: &str| {
            sink.lock().unwrap().push(l.to_string())
        })),
        WriterOptions {
            seals: SealPolicy::manual(),
            prev: Some(Prev::Genesis),
            ..WriterOptions::default()
        },
    )
    .unwrap();
    for n in 1..=2 {
        w.write(Entry::new(at(n), MESSAGE_CLASS, "urn:subject").with("msg", "early"))
            .unwrap();
    }
    w.seal(at(3)).unwrap();
    for n in 4..=5 {
        w.write(Entry::new(at(n), MESSAGE_CLASS, "urn:subject").with("msg", "late"))
            .unwrap();
    }
    let name = w.segment().to_string();
    let head = w.close(at(6)).unwrap().head;
    let lines = lines.lock().unwrap().clone();
    (name, lines, head)
}

/// The segment cut back to just after its first seal: a valid prefix.
fn truncated(name: &str, lines: &[String]) -> Vec<(String, String)> {
    let first_seal = lines.iter().position(|l| l.starts_with("#seal")).unwrap();
    let kept = lines[..=first_seal].join("\n") + "\n";
    vec![(name.to_string(), kept)]
}

fn entries_in(segments: &[(String, String)]) -> u64 {
    verify_chain(segments, Vocabulary::builtin())
        .segments
        .iter()
        .map(|s| s.entries)
        .sum()
}

#[test]
fn a_truncated_chain_passes_link_verification() {
    let (name, lines, _) = closed_segment();
    let cut = truncated(&name, &lines);
    let report = verify_chain(&cut, Vocabulary::builtin());
    // The defect: the prefix verifies. Its cut tail is only `noted`.
    assert!(report.ok(), "{}", report.render());
}

#[test]
fn an_expected_head_refuses_a_truncated_chain() {
    let (name, lines, head) = closed_segment();
    let whole = vec![(name.clone(), lines.join("\n") + "\n")];
    let expected = ExpectedHead::seal(head.clone());
    let report = verify_chain_to(&whole, Vocabulary::builtin(), &expected);
    assert!(report.ok(), "{}", report.render());

    let cut = truncated(&name, &lines);
    let report = verify_chain_to(&cut, Vocabulary::builtin(), &expected);
    assert!(!report.ok(), "{}", report.render());
    assert_eq!(
        report.findings,
        vec![Finding::ExpectedHeadMissing { head: head.clone() }]
    );
    let text = report.render();
    assert!(
        text.contains(&format!(
            "BROKEN no seal in this chain states its expected head {head}: \
             the chain ends before it, or was rewritten before it"
        )),
        "{text}"
    );
    assert!(
        text.ends_with("verified 1 segment(s), 0 broken, expected head not reached\n"),
        "{text}"
    );
}

#[test]
fn an_earlier_expected_head_accepts_a_chain_that_grew_past_it() {
    let (name, lines, _) = closed_segment();
    let first_seal = lines.iter().find(|l| l.starts_with("#seal")).unwrap();
    let earlier = first_seal.split_whitespace().nth(2).unwrap().to_string();
    let whole = vec![(name, lines.join("\n") + "\n")];
    let report = verify_chain_to(&whole, Vocabulary::builtin(), &ExpectedHead::seal(earlier));
    assert!(report.ok(), "{}", report.render());
    assert!(report.findings.is_empty());
}

#[test]
fn a_stated_length_refuses_a_truncated_chain() {
    let (name, lines, _) = closed_segment();
    let whole = vec![(name.clone(), lines.join("\n") + "\n")];
    let length = entries_in(&whole);
    let expected = ExpectedHead::entries(length);
    assert!(verify_chain_to(&whole, Vocabulary::builtin(), &expected).ok());

    let cut = truncated(&name, &lines);
    let found = entries_in(&cut);
    let report = verify_chain_to(&cut, Vocabulary::builtin(), &expected);
    assert!(!report.ok(), "{}", report.render());
    assert_eq!(
        report.findings,
        vec![Finding::ShortOfExpectedLength {
            expected: length,
            found
        }]
    );
    let text = report.render();
    assert!(
        text.contains(&format!(
            "BROKEN the chain holds {found} entries but {length} were expected: \
             it ends before its expected head, so entries were removed from its end"
        )),
        "{text}"
    );
}

#[test]
fn an_expected_head_refuses_an_empty_walk() {
    let report = verify_chain_to(&[], Vocabulary::builtin(), &ExpectedHead::entries(1));
    assert!(!report.ok());
}
