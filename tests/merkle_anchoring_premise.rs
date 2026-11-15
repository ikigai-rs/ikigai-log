//! Ledger #3642: the fact `docs/design/merkle-anchoring.md` is built on.
//!
//! The chain walk cannot see history removed from its old end. Deleting the
//! oldest segment of a rotated chain leaves a chain that verifies `OK`; the only
//! trace is that the first remaining segment's `@prev` names a seal no segment
//! holds. A root over seals, held outside the operator's control, is the design's
//! answer. If this test starts failing because the walk learned to catch the
//! deletion, the note's premise has changed and the note must change with it.

use std::sync::{Arc, Mutex};

use ikigai_log::{
    verify_chain, ClosureSink, Entry, LogConfig, Prev, SealPolicy, Timestamp, Vocabulary, Writer,
    WriterOptions, MESSAGE_CLASS,
};

fn at(minutes: u64) -> Timestamp {
    let base = Timestamp::parse("2026-11-15T10:00:00.000Z")
        .unwrap()
        .as_millis();
    Timestamp::from_millis(base + minutes * 60_000)
}

fn writer(lines: &Arc<Mutex<Vec<String>>>, minutes: u64, prev: Prev) -> Writer {
    let lines = lines.clone();
    Writer::open_with_sink_and(
        &LogConfig::default().with_instance("bug:premise"),
        Vocabulary::shared_builtin(),
        at(minutes),
        Box::new(ClosureSink(move |l: &str| {
            lines.lock().unwrap().push(l.to_string())
        })),
        WriterOptions {
            seals: SealPolicy::manual(),
            prev: Some(prev),
            ..WriterOptions::default()
        },
    )
    .unwrap()
}

fn text(lines: &Arc<Mutex<Vec<String>>>) -> String {
    lines.lock().unwrap().join("\n") + "\n"
}

#[test]
fn deleting_the_oldest_segment_still_verifies() {
    let first = Arc::new(Mutex::new(Vec::new()));
    let mut w = writer(&first, 0, Prev::Genesis);
    w.write(Entry::new(at(1), MESSAGE_CLASS, "urn:subject").with("msg", "hello"))
        .unwrap();
    w.seal(at(2)).unwrap();
    let first_name = w.segment().to_string();
    let second_name = "urn:log:bug:premise:2026-11-15T11-00-00Z";
    let closed = w.rotate_out(at(60), Some(second_name)).unwrap();

    let second = Arc::new(Mutex::new(Vec::new()));
    let mut w = writer(&second, 60, Prev::Seal(closed.head.clone()));
    w.write(Entry::new(at(61), MESSAGE_CLASS, "urn:subject").with("msg", "hello"))
        .unwrap();
    w.close(at(62)).unwrap();

    let whole = vec![
        (first_name, text(&first)),
        (second_name.to_string(), text(&second)),
    ];
    assert!(verify_chain(&whole, Vocabulary::builtin()).ok());

    // The old end is gone. The walk still says OK.
    let remaining = &whole[1..];
    let report = verify_chain(remaining, Vocabulary::builtin());
    assert!(report.ok(), "{report:?}");

    // What is left points at a seal nobody holds: the head the deleted segment
    // ended on, which a root held elsewhere would have counted.
    let prev = format!("@prev     {}", closed.head);
    assert!(
        remaining[0].1.lines().any(|l| l == prev),
        "{}",
        remaining[0].1
    );
}
