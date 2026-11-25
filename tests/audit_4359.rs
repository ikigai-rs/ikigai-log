//! Reproductions for the unled correctness audit of the hash chain, ledger #4359.

use std::io;
use std::sync::{Arc, Mutex};

use ikigai_log::{
    verify_segment, Entry, LineSink, LogConfig, SealPolicy, Timestamp, Vocabulary, Writer,
    WriterOptions, MESSAGE_CLASS,
};

#[derive(Clone, Default)]
struct Sink {
    lines: Arc<Mutex<Vec<String>>>,
}

impl LineSink for Sink {
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.lines.lock().unwrap().push(line.to_string());
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A closed segment, sealed after its second message and again at the close.
fn sealed_lines() -> Vec<String> {
    let sink = Sink::default();
    let mut writer = Writer::open_with_sink_and(
        &LogConfig::default().with_instance("audit:4359"),
        Vocabulary::shared_builtin(),
        Timestamp::from_millis(0),
        Box::new(sink.clone()),
        WriterOptions {
            seals: SealPolicy::manual(),
            ..WriterOptions::default()
        },
    )
    .unwrap();
    for i in 0..4u64 {
        writer
            .write(
                Entry::new(Timestamp::from_millis(1 + i), MESSAGE_CLASS, "urn:subject")
                    .with("msg", format!("message {i}")),
            )
            .unwrap();
        if i == 1 {
            writer.seal(Timestamp::from_millis(2)).unwrap();
        }
    }
    writer.close(Timestamp::from_millis(9)).unwrap();
    let lines = sink.lines.lock().unwrap().clone();
    lines
}

fn joined(lines: &[String]) -> String {
    lines.join("\n") + "\n"
}

#[test]
fn the_pristine_segment_verifies() {
    let report = verify_segment(&joined(&sealed_lines()), Vocabulary::builtin(), None);
    assert!(report.ok(), "{}", report.render_findings());
}

/// The writer never puts a raw carriage return on a line: a `\r` in a value is
/// written as the escape `\r`. So a raw `\r` left at the end of a sealed entry
/// line, once the line ending (`\n` or `\r\n`) is taken off, is a byte someone
/// added after the seal, and the chain hashes "the entry line exactly as it
/// appears". The verifier used to trim EVERY trailing `\r` before hashing, so
/// the edited segment was reported intact.
#[test]
fn carriage_returns_added_to_a_sealed_entry_are_breaking() {
    for added in ["\r\r", "\r\r\r"] {
        let mut lines = sealed_lines();
        let at = lines
            .iter()
            .position(|line| line.contains("message 0"))
            .expect("the first message was written");
        lines[at].push_str(added);
        let report = verify_segment(&joined(&lines), Vocabulary::builtin(), None);
        assert!(
            !report.ok(),
            "a segment with {added:?} added to a sealed line verified as intact"
        );
    }
}

/// A CRLF line ending changes no line's content: the line ending is not part of
/// the line, and the parser reads `\r\n` as one. A whole file converted to CRLF
/// still verifies, and so does one line whose ending became `\r\n`.
#[test]
fn crlf_line_endings_still_verify() {
    let text = joined(&sealed_lines()).replace('\n', "\r\n");
    let report = verify_segment(&text, Vocabulary::builtin(), None);
    assert!(report.ok(), "{}", report.render_findings());

    let mut lines = sealed_lines();
    let at = lines
        .iter()
        .position(|line| line.contains("message 0"))
        .expect("the first message was written");
    lines[at].push('\r');
    let report = verify_segment(&joined(&lines), Vocabulary::builtin(), None);
    assert!(report.ok(), "{}", report.render_findings());
}
