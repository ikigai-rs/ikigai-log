//! Reproductions for the unled correctness audit, ledger #3436.

use std::io;
use std::sync::{Arc, Mutex};

use ikigai_log::{
    verify_segment, Entry, Header, LineSink, LogConfig, Prev, SealPolicy, Timestamp, Vocabulary,
    Writer, WriterOptions, MESSAGE_CLASS,
};

#[derive(Clone, Default)]
struct Sink {
    lines: Arc<Mutex<Vec<String>>>,
    fail_flush: Arc<Mutex<bool>>,
}

impl LineSink for Sink {
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.lines.lock().unwrap().push(line.to_string());
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if std::mem::take(&mut *self.fail_flush.lock().unwrap()) {
            Err(io::Error::other("injected flush failure"))
        } else {
            Ok(())
        }
    }
}

impl Sink {
    fn writer(&self) -> Writer {
        Writer::open_with_sink_and(
            &LogConfig::default().with_instance("audit:3436"),
            Vocabulary::shared_builtin(),
            Timestamp::from_millis(0),
            Box::new(self.clone()),
            WriterOptions {
                seals: SealPolicy::manual(),
                ..WriterOptions::default()
            },
        )
        .unwrap()
    }

    fn text(&self) -> String {
        self.lines.lock().unwrap().join("\n") + "\n"
    }
}

fn message(text: &str) -> Entry {
    Entry::new(Timestamp::from_millis(1), MESSAGE_CLASS, "urn:subject").with("msg", text)
}

#[test]
fn entry_flush_failure_does_not_reuse_a_written_sequence() {
    let sink = Sink::default();
    let mut writer = sink.writer();
    *sink.fail_flush.lock().unwrap() = true;
    assert!(writer.write(message("before the flush failure")).is_err());
    assert_eq!(writer.sequence(), 2);
    assert_eq!(
        writer.write(message("after the flush failure")).unwrap(),
        Some(3)
    );
    writer.close(Timestamp::from_millis(2)).unwrap();
    let report = verify_segment(&sink.text(), Vocabulary::builtin(), None);
    assert!(report.ok(), "{}", report.render_findings());
}

#[test]
fn seal_flush_failure_does_not_repeat_a_written_seal() {
    let sink = Sink::default();
    let mut writer = sink.writer();
    *sink.fail_flush.lock().unwrap() = true;
    assert!(writer.seal(Timestamp::from_millis(1)).is_err());
    // Retrying must flush the already accepted seal, without appending it again.
    *sink.fail_flush.lock().unwrap() = true;
    assert!(writer.seal(Timestamp::from_millis(2)).is_err());
    assert!(writer.seal(Timestamp::from_millis(2)).unwrap().is_none());
    writer.close(Timestamp::from_millis(3)).unwrap();
    let report = verify_segment(&sink.text(), Vocabulary::builtin(), None);
    assert!(report.ok(), "{}", report.render_findings());
}

fn header() -> Header {
    Header {
        version: 1,
        prefixes: Default::default(),
        name: "urn:segment".into(),
        instance: "urn:instance".into(),
        level: "https://ikigai-rs.dev/ns/log#info".into(),
        started: Timestamp::from_millis(0),
        prev: Prev::Genesis,
    }
}

#[test]
fn out_of_format_timestamps_are_refused_before_writing() {
    let last = Timestamp::parse("9999-12-31T23:59:59.999Z").unwrap();
    for millis in [last.as_millis() + 1, u64::MAX] {
        let time = Timestamp::from_millis(millis);
        let mut entry = message("out of range");
        entry.time = time;
        let error = entry.render(&Default::default()).unwrap_err();
        assert!(matches!(error, ikigai_log::RenderError::Timestamp(n) if n == millis));
        assert_eq!(
            error.to_string(),
            format!(
                "timestamp {millis} milliseconds since the Unix epoch is outside 1970 through 9999"
            )
        );
        let mut header = header();
        header.started = time;
        assert!(header.render().is_err());
        let sink = Sink::default();
        let mut writer = sink.writer();
        let before = sink.text();
        assert!(writer.write(entry).is_err());
        assert_eq!(writer.sequence(), 1);
        assert_eq!(sink.text(), before);
    }
}

#[test]
fn timestamp_endpoints_and_payloads_survive_lines_and_turtle() {
    let last = Timestamp::parse("9999-12-31T23:59:59.999Z").unwrap();
    let values = [
        "two words".to_string(),
        "a=b=c".to_string(),
        "\"quoted\" and \\backslash\nnew line\r\ttab".to_string(),
        "日本語 café 🦀".to_string(),
        "é= ".repeat(32_768),
    ];
    for time in [Timestamp::from_millis(0), last] {
        let mut header = header();
        header.started = time;
        let block = header.render().unwrap();
        assert_eq!(Header::parse(&block).unwrap().0, header);
        for value in &values {
            let entry = Entry::new(time, MESSAGE_CLASS, "urn:subject").with("msg", value);
            let line = entry.render(&header.prefixes).unwrap();
            assert_eq!(Entry::parse(&line, &header.prefixes).unwrap(), entry);
            let triples = ikigai_log::to_triples(
                &format!("{block}{line}\n"),
                Vocabulary::builtin(),
                &ikigai_log::Options::all(),
            )
            .unwrap();
            assert!(triples.iter().any(|triple| {
                triple.predicate.as_str() == "https://ikigai-rs.dev/ns/log#text"
                    && matches!(&triple.object, oxrdf::Term::Literal(lit) if lit.value() == value)
            }));
            let turtle = ikigai_log::to_turtle(
                &format!("{block}{line}\n"),
                Vocabulary::builtin(),
                &ikigai_log::Options::all(),
            )
            .unwrap();
            let parsed: Vec<_> = oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle)
                .for_reader(turtle.as_bytes())
                .map(Result::unwrap)
                .collect();
            assert!(parsed.iter().any(|quad| {
                matches!(&quad.object, oxrdf::Term::Literal(lit) if lit.value() == value)
            }));
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn invalid_file_timestamp_does_not_reserve_a_damaged_segment() {
    let directory = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!("audit-3436-invalid-time-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let config = LogConfig::default()
        .with_instance("audit:3436")
        .with_destination(ikigai_log::Destination::File)
        .with_directory(&directory);
    let result = Writer::open(
        &config,
        Vocabulary::shared_builtin(),
        Timestamp::from_millis(u64::MAX),
    );
    assert!(matches!(
        result,
        Err(ikigai_log::WriteError::Render(
            ikigai_log::RenderError::Timestamp(u64::MAX)
        ))
    ));
    assert!(std::fs::read_dir(&directory).unwrap().all(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_none_or(|ext| ext != "log")
    }));
    std::fs::remove_dir_all(directory).unwrap();
}

fn sealed_segment(name: &str, instance: &str, prev: Prev) -> (String, String) {
    let mut header = header();
    header.name = name.into();
    header.instance = instance.into();
    header.prev = prev;
    let mut text = header.render().unwrap();
    let mut chain = ikigai_log::Chain::open(&header);
    for entry in [
        message("original").with("seq", "1"),
        Entry::new(
            Timestamp::from_millis(2),
            ikigai_log::PROCESS_STOP_CLASS,
            &header.instance,
        )
        .with("seq", "2"),
    ] {
        let line = entry.render(&header.prefixes).unwrap();
        chain.advance(&line);
        text.push_str(&line);
        text.push('\n');
    }
    text.push_str(
        &ikigai_log::Seal {
            first: 1,
            last: 2,
            hash: chain.head().into(),
            signature: None,
        }
        .render(),
    );
    text.push('\n');
    (name.into(), text)
}

#[test]
fn chain_probes_detect_edits_deletions_reordering_truncation_and_foreign_splices() {
    let first = sealed_segment("urn:segment:first", "urn:instance", Prev::Genesis);
    let second = sealed_segment(
        "urn:segment:second",
        "urn:instance",
        Prev::Seal(ikigai_log::head_of(&first.1).unwrap()),
    );
    let original = vec![first.clone(), second.clone()];
    assert!(ikigai_log::verify_chain(&original, Vocabulary::builtin()).ok());

    let mut edited = original.clone();
    edited[0].1 = edited[0].1.replace("msg=original", "msg=changed");
    let mut deleted = original.clone();
    deleted[0].1 = deleted[0]
        .1
        .lines()
        .filter(|line| !line.contains("msg=original"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let mut reordered = original.clone();
    reordered.reverse();
    let mut truncated = original.clone();
    let cut = truncated[1].1.len() - 12;
    truncated[1].1.truncate(cut);
    let foreign = sealed_segment("urn:segment:foreign", "urn:other-instance", Prev::Genesis);
    assert!(verify_segment(&foreign.1, Vocabulary::builtin(), None).ok());
    let spliced = vec![first, foreign, second];

    for (probe, chain) in [
        ("edited entry", edited),
        ("deleted entry", deleted),
        ("reordered segments", reordered),
        ("truncated final seal", truncated),
        ("foreign instance segment", spliced),
    ] {
        let report = ikigai_log::verify_chain(&chain, Vocabulary::builtin());
        assert!(!report.ok(), "{probe}: {}", report.render());
        assert!(report.segments.iter().any(|segment| {
            segment
                .findings
                .iter()
                .any(ikigai_log::Finding::is_breaking)
        }));
    }
}
