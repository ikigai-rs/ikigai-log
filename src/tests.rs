//! Tests for the grammar and the vocabulary.
//!
//! Two claims carry most of the weight and are tested directly: that the term
//! table is DATA (an extension adds classes and keys with no code change), and
//! that one entry is one line (nothing rendered can contain a raw newline).

use std::collections::BTreeMap;

use crate::config::ConfigError;
use crate::line::{Entry, Header, Line, ParseError, Prev, Seal, Timestamp};
use crate::vocabulary::{Vocabulary, DEFAULT_MIN_LEVEL, ENTRY_CLASS, LOG_NS};

fn log(term: &str) -> String {
    format!("{LOG_NS}{term}")
}

fn prefixes() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("log".to_string(), LOG_NS.to_string()),
        ("prov".to_string(), "http://www.w3.org/ns/prov#".to_string()),
    ])
}

fn rank(vocab: &Vocabulary, level: &str) -> i64 {
    vocab
        .rank(&log(level))
        .unwrap_or_else(|| panic!("level {level} has a rank"))
}

// =====================================================================================
// The vocabulary
// =====================================================================================

#[test]
fn the_embedded_vocabulary_parses_and_is_prov_rooted() {
    let vocab = Vocabulary::builtin();
    let entry = vocab.class(ENTRY_CLASS).expect("log:Entry is declared");
    assert!(
        entry
            .super_classes
            .contains(&"http://www.w3.org/ns/prov#Activity".to_string()),
        "log:Entry is a prov:Activity: {:?}",
        entry.super_classes
    );
    let segment = vocab
        .class(&log("Segment"))
        .expect("log:Segment is declared");
    assert!(
        segment
            .super_classes
            .contains(&"http://www.w3.org/ns/prov#Bundle".to_string()),
        "a segment is a prov:Bundle — PROV's own word for a named set of provenance descriptions"
    );
}

#[test]
fn the_ladder_is_ordered_and_always_sits_below_it() {
    let vocab = Vocabulary::builtin();
    let ladder = ["error", "warn", "info", "debug", "trace"];
    for pair in ladder.windows(2) {
        assert!(
            rank(vocab, pair[0]) < rank(vocab, pair[1]),
            "{} ranks below {}",
            pair[0],
            pair[1]
        );
    }
    assert!(
        rank(vocab, "always") < rank(vocab, "error"),
        "log:always ranks below every settable level, which is what makes the \
         always-land set arithmetic instead of a list in code"
    );
}

#[test]
fn the_dial_includes_what_the_vocabulary_says_it_includes() {
    let vocab = Vocabulary::builtin();
    let (info, debug, trace) = (
        rank(vocab, "info"),
        rank(vocab, "debug"),
        rank(vocab, "trace"),
    );

    assert!(
        !vocab.emits(&log("Resolution"), info),
        "info: no resolutions"
    );
    assert!(vocab.emits(&log("Resolution"), debug));

    assert!(
        !vocab.emits(&log("CacheHit"), debug),
        "debug: resolutions but not cache hits — the highest-volume, \
         lowest-information events sit at the top of the dial"
    );
    assert!(vocab.emits(&log("CacheHit"), trace));

    assert!(vocab.emits(&log("Message"), info));
    assert!(!vocab.emits(&log("Message"), rank(vocab, "warn")));
    assert!(
        vocab.emits(&log("Warning"), rank(vocab, "warn")),
        "severity is carried by subclass, so the class alone decides emission"
    );

    for always in [
        "Seal",
        "ChainBroken",
        "Rotation",
        "Tombstone",
        "Dropped",
        "LevelChange",
        "ConfigChange",
        "CapabilityDenied",
        "KeyChange",
        "ProcessStart",
        "ProcessStop",
    ] {
        assert!(
            vocab.emits(&log(always), rank(vocab, "error")),
            "{always} lands whatever the dial says: every legitimate source of \
             absence must leave a marker in the chain"
        );
    }
}

#[test]
fn the_key_table_types_its_values() {
    let vocab = Vocabulary::builtin();

    let cap = vocab.key("cap").expect("cap is declared");
    assert_eq!(cap.property, log("capability"));
    assert_eq!(
        cap.range.as_deref(),
        Some("http://www.w3.org/2000/01/rdf-schema#Resource"),
        "a capability column transrepts to an IRI, not a string — otherwise no \
         entry joins to any other entry"
    );

    let dur = vocab.key("dur").expect("dur is declared");
    assert_eq!(
        dur.range.as_deref(),
        Some("http://www.w3.org/2001/XMLSchema#integer")
    );

    assert_eq!(
        vocab.key("msg").map(|k| k.property.clone()),
        Some(log("text"))
    );
    assert!(
        vocab.key("nonesuch").is_none(),
        "an unclaimed key is not an error here — it lands losslessly and \
         flagged, so drift is measurable"
    );
}

#[test]
fn every_declared_key_types_its_range() {
    let vocab = Vocabulary::builtin();
    for key in vocab.keys() {
        assert!(
            key.range.is_some(),
            "{} has no rdfs:range, so the transreptor cannot type its value",
            key.key
        );
    }
}

#[test]
fn every_class_is_placeable_on_the_dial() {
    let vocab = Vocabulary::builtin();
    let structural = [
        log("Segment"),
        log("Instance"),
        log("Level"),
        log("Config"),
        log("Destination"),
    ];
    for class in vocab.classes() {
        if structural.contains(&class.iri) {
            continue;
        }
        assert!(
            vocab.is_a(&class.iri, ENTRY_CLASS),
            "{} is neither an entry class nor a declared structural class",
            class.iri
        );
        let min = vocab.min_level(&class.iri).to_string();
        assert!(
            vocab.rank(&min).is_some(),
            "{} declares log:minLevel {min}, which no level defines",
            class.iri
        );
    }
}

#[test]
fn the_subject_column_is_refined_per_class_and_inherited() {
    let vocab = Vocabulary::builtin();
    assert_eq!(
        vocab.subject_predicate(&log("Resolution")),
        Some(log("resolved")).as_deref(),
        "a resolution's subject is what it resolved"
    );
    assert_eq!(
        vocab.subject_predicate(&log("CacheHit")),
        Some(log("resolved")).as_deref(),
        "and a cache hit inherits that reading from its superclass"
    );
    assert_eq!(
        vocab.subject_predicate(&log("ProcessStart")),
        Some("http://www.w3.org/ns/prov#wasAssociatedWith"),
        "a liveness event is about the agent it attributes to"
    );
}

#[test]
fn a_module_extends_the_table_without_touching_code() {
    // Exactly what a module ships: a subclass, a minimum, and its own keys.
    // Nothing in this crate knows these terms exist.
    let extension = r#"
        @prefix log:  <https://ikigai-rs.dev/ns/log#> .
        @prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
        @prefix ex:   <https://example.org/sync#> .

        ex:SyncRun a rdfs:Class ;
            rdfs:subClassOf log:Entry ;
            log:minLevel log:warn ;
            log:subjectPredicate log:subject .

        ex:SyncFailed a rdfs:Class ;
            rdfs:subClassOf ex:SyncRun .

        ex:peer a rdf:Property ;
            log:keyName "peer" ;
            rdfs:range rdfs:Resource .
    "#;
    let mut vocab = Vocabulary::parse(crate::VOCABULARY_TTL).expect("builtin parses");
    vocab.extend(extension).expect("the extension parses");

    let warn = rank(&vocab, "warn");
    assert!(vocab.emits("https://example.org/sync#SyncRun", warn));
    assert!(
        !vocab.emits("https://example.org/sync#SyncRun", rank(&vocab, "error")),
        "the extension's own minimum is respected"
    );
    assert_eq!(
        vocab.min_level("https://example.org/sync#SyncFailed"),
        log("warn"),
        "a subclass that declares no minimum inherits its parent's"
    );
    assert!(
        vocab.is_a("https://example.org/sync#SyncFailed", ENTRY_CLASS),
        "and it is still an entry, two hops up"
    );

    let peer = vocab
        .key("peer")
        .expect("the extension's key is in the table");
    assert_eq!(peer.property, "https://example.org/sync#peer");
    assert_eq!(
        peer.range.as_deref(),
        Some("http://www.w3.org/2000/01/rdf-schema#Resource")
    );
}

#[test]
fn an_undeclared_class_still_lands_at_the_default() {
    let vocab = Vocabulary::builtin();
    assert_eq!(
        vocab.min_level("https://example.org/unknown#Thing"),
        DEFAULT_MIN_LEVEL,
        "a class nothing declares is visible at the day-to-day default rather \
         than silently invisible"
    );
}

// =====================================================================================
// Time
// =====================================================================================

#[test]
fn timestamps_are_fixed_width_utc_and_round_trip() {
    assert_eq!(
        Timestamp::from_millis(0).render(),
        "1970-01-01T00:00:00.000Z"
    );
    let stamp = Timestamp::parse("2026-08-23T09:14:22.031Z").expect("parses");
    assert_eq!(stamp.render(), "2026-08-23T09:14:22.031Z");
    // A leap day, and the day after it.
    for text in ["2024-02-29T23:59:59.999Z", "2024-03-01T00:00:00.000Z"] {
        assert_eq!(Timestamp::parse(text).expect("parses").render(), text);
    }
    // Lexical order is chronological order — the reason the column is fixed
    // width and always UTC.
    let mut rendered = [
        Timestamp::from_millis(2_000).render(),
        Timestamp::from_millis(1_000).render(),
        Timestamp::from_millis(1_500).render(),
    ];
    rendered.sort();
    assert_eq!(rendered[0], Timestamp::from_millis(1_000).render());
    assert_eq!(rendered[2], Timestamp::from_millis(2_000).render());
}

#[test]
fn impossible_and_loose_timestamps_are_refused() {
    for bad in [
        "2026-02-30T00:00:00.000Z", // no such day
        "2026-13-01T00:00:00.000Z", // no such month
        "2026-08-23T24:00:00.000Z", // no such hour
        "2026-08-23T09:14:22Z",     // no millis
        "2026-08-23T09:14:22.031",  // no zone
        "2026-08-23T09:14:22.031+01:00",
        "2026-8-23T09:14:22.031Z",
    ] {
        assert!(
            matches!(Timestamp::parse(bad), Err(ParseError::Timestamp(_))),
            "{bad} must not parse"
        );
    }
}

// =====================================================================================
// Entries
// =====================================================================================

#[test]
fn an_entry_round_trips_through_its_line() {
    let entry = Entry::new(
        Timestamp::parse("2026-08-23T09:14:22.031Z").unwrap(),
        log("Resolution"),
        "urn:calendar:today",
    )
    .with("worker", "ikigai-sched-2")
    .with("span", "7")
    .with("cap", "urn:cap:fs:read")
    .with("cap", "urn:cap:net:api.example.com");

    let line = entry.render(&prefixes()).expect("renders");
    assert_eq!(
        line,
        "2026-08-23T09:14:22.031Z log:Resolution urn:calendar:today \
         worker=ikigai-sched-2 span=7 cap=urn:cap:fs:read cap=urn:cap:net:api.example.com"
    );
    assert_eq!(Entry::parse(&line, &prefixes()).expect("parses"), entry);
    assert_eq!(
        entry.all("cap").collect::<Vec<_>>(),
        vec!["urn:cap:fs:read", "urn:cap:net:api.example.com"],
        "a repeated key is a repeated column: attenuation is multi-valued"
    );
}

#[test]
fn one_entry_is_one_line_whatever_the_payload() {
    let entry = Entry::new(
        Timestamp::from_millis(0),
        log("Error"),
        "urn:agent:calendar",
    )
    .with("msg", "sync failed:\n  connection refused\tafter 3 retries")
    .with("detail", r#"he said "no""#);

    let line = entry.render(&prefixes()).expect("renders");
    assert!(
        !line.contains('\n') && !line.contains('\r'),
        "a raw newline would break grep, the per-line hash chain, and any \
         rotation reasoning about a prefix of the file: {line}"
    );
    assert!(line.contains(r#"msg="sync failed:\n  connection refused\tafter 3 retries""#));
    assert_eq!(
        Entry::parse(&line, &prefixes()).expect("parses"),
        entry,
        "and the escapes come back as the characters they stood for"
    );
}

#[test]
fn a_class_from_an_unbound_vocabulary_still_renders() {
    let entry = Entry::new(
        Timestamp::from_millis(0),
        "https://example.org/sync#SyncRun",
        "urn:peer:plasma",
    );
    let line = entry.render(&prefixes()).expect("renders");
    assert!(
        line.contains("<https://example.org/sync#SyncRun>"),
        "the CURIE is a convenience for readers, not a constraint on what can \
         be logged: {line}"
    );
    assert_eq!(Entry::parse(&line, &prefixes()).expect("parses"), entry);
}

#[test]
fn columns_that_would_parse_back_as_something_else_are_refused() {
    let stamp = Timestamp::from_millis(0);

    // A subject that is not an IRI.
    let entry = Entry::new(stamp, log("Message"), "not an iri");
    assert!(entry.render(&prefixes()).is_err());

    // A key with a space in it would split into two columns on the way back.
    let entry = Entry::new(stamp, log("Message"), "urn:x:y").with("two words", "v");
    assert!(entry.render(&prefixes()).is_err());

    // A CURIE whose prefix the header never bound.
    assert!(matches!(
        Entry::parse("1970-01-01T00:00:00.000Z nope:Thing urn:x:y", &prefixes()),
        Err(ParseError::UnboundPrefix(_))
    ));

    // A subject column that is not an absolute IRI.
    assert!(matches!(
        Entry::parse("1970-01-01T00:00:00.000Z log:Message plain", &prefixes()),
        Err(ParseError::NotAnIri(_))
    ));

    // A trailing column that is not key=value.
    assert!(matches!(
        Entry::parse(
            "1970-01-01T00:00:00.000Z log:Message urn:x:y stray",
            &prefixes()
        ),
        Err(ParseError::Field(_))
    ));
}

// =====================================================================================
// Seals, headers, whole segments
// =====================================================================================

#[test]
fn a_seal_round_trips_signed_and_unsigned() {
    let sealed = Seal {
        first: 1,
        last: 42,
        hash: "sha256:4c1e".to_string(),
        signature: Some("sig:MEUCIQD".to_string()),
    };
    assert_eq!(sealed.render(), "#seal 1-42 sha256:4c1e sig:MEUCIQD");
    assert_eq!(Seal::parse(&sealed.render()).expect("parses"), sealed);

    let unsigned = Seal {
        signature: None,
        ..sealed
    };
    assert_eq!(
        Seal::parse(&unsigned.render()).expect("parses"),
        unsigned,
        "an unsigned seal still localizes tampering to a range"
    );
}

fn header() -> Header {
    Header {
        version: crate::FORMAT_VERSION,
        prefixes: prefixes(),
        name: "urn:log:bug:daemon:2026-08-23T09-00-00Z".to_string(),
        instance: "urn:ikigai:instance:bug:daemon".to_string(),
        level: log("info"),
        started: Timestamp::parse("2026-08-23T09:00:00.000Z").unwrap(),
        prev: Prev::Genesis,
    }
}

#[test]
fn a_header_round_trips_and_carries_the_chain_across_the_rotation() {
    let genesis = header();
    let text = genesis.render().expect("renders");
    assert!(text.contains("@prev     genesis"));
    let (parsed, offset) = Header::parse(&text).expect("parses");
    assert_eq!(parsed, genesis);
    assert_eq!(
        offset,
        text.len(),
        "the header block ends at the blank line"
    );

    let next = Header {
        prev: Prev::Seal("sha256:9f3a".to_string()),
        ..header()
    };
    let (parsed, _) = Header::parse(&next.render().expect("renders")).expect("parses");
    assert_eq!(
        parsed.prev,
        Prev::Seal("sha256:9f3a".to_string()),
        "without this link, rotation is the seam at which a whole file can be \
         replaced and nothing detects it"
    );
}

#[test]
fn an_incomplete_or_foreign_header_is_an_error_not_a_default() {
    let full = header().render().expect("renders");

    for directive in ["@name", "@instance", "@level", "@started", "@prev"] {
        let pruned: String = full
            .lines()
            .filter(|line| !line.starts_with(directive))
            .map(|line| format!("{line}\n"))
            .collect();
        assert!(
            Header::parse(&pruned).is_err(),
            "a missing {directive} must fail loudly: a level or a destination \
             that silently defaults is a hole nothing brackets"
        );
    }

    let wrong_version = full.replacen("v1", "v2", 1);
    assert!(matches!(
        Header::parse(&wrong_version),
        Err(ParseError::Version(_))
    ));

    assert!(
        Header::parse(&full.replacen("# ikigai-log v1\n", "", 1)).is_err(),
        "and a segment with no version line is not a segment"
    );
}

#[test]
fn a_whole_segment_reads_back_line_by_line() {
    let header = header();
    let entries = [
        Entry::new(
            Timestamp::parse("2026-08-23T09:00:00.000Z").unwrap(),
            log("ProcessStart"),
            "urn:ikigai:instance:bug:daemon",
        ),
        Entry::new(
            Timestamp::parse("2026-08-23T09:14:22.031Z").unwrap(),
            log("Message"),
            "urn:agent:calendar",
        )
        .with("msg", "sync started"),
    ];
    let seal = Seal {
        first: 1,
        last: 2,
        hash: "sha256:4c1e".to_string(),
        signature: None,
    };

    let mut file = header.render().expect("renders");
    for entry in &entries {
        file.push_str(&entry.render(&header.prefixes).expect("renders"));
        file.push('\n');
    }
    file.push_str(&seal.render());
    file.push('\n');

    let (parsed_header, offset) = Header::parse(&file).expect("header parses");
    assert_eq!(parsed_header, header);

    let body: Vec<Line> = file[offset..]
        .lines()
        .map(|line| Line::parse(line, &parsed_header.prefixes).expect("line parses"))
        .collect();
    assert_eq!(
        body,
        vec![
            Line::Entry(entries[0].clone()),
            Line::Entry(entries[1].clone()),
            Line::Seal(seal),
        ]
    );
}

#[test]
fn lines_are_classified_by_shape() {
    let p = prefixes();
    assert_eq!(Line::parse("   ", &p).unwrap(), Line::Blank);
    assert_eq!(
        Line::parse("# a note", &p).unwrap(),
        Line::Comment("a note".to_string()),
        "a seal reads as a comment to anything that does not know the format"
    );
    assert!(matches!(
        Line::parse("#seal 1-2 sha256:ab", &p).unwrap(),
        Line::Seal(_)
    ));
    assert_eq!(
        Line::parse("@name urn:log:x", &p).unwrap(),
        Line::Directive {
            name: "name".to_string(),
            value: "urn:log:x".to_string()
        }
    );
}

// =====================================================================================
// The writer
// =====================================================================================
//
// Hermetic by construction, not by redirection: every path below is either an
// explicit scratch directory or a caller-supplied sink, and every config home
// is passed in. Nothing here consults `$HOME`, so nothing can read or write the
// real `~/.ikigai` — and no test has to fight the process-global environment to
// stay honest about it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ikigai_core::{
    ArgRef, Capability, Clock, Endpoint, Error, Iri, Kernel, Representation, Request, Time, Verb,
};

use crate::config::{Destination, LogConfig, Patch};
use crate::endpoints::{LogHandle, CAP_CONFIG, CAP_READ, CAP_WRITE, CONFIG_IRI, WRITE_IRI};
use crate::vocabulary::{
    CONFIG_CHANGE_CLASS, LEVEL_CHANGE_CLASS, MESSAGE_CLASS, PROCESS_START_CLASS,
};
use crate::writer::{ClosureSink, WriteError, Writer};

/// A scratch directory that removes itself. No dev-dependency for two
/// directories, and no `$TMPDIR` collision between concurrent tests.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "ikigai-log-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock is after the epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, contents: &str) {
        std::fs::write(self.0.join(name), contents).expect("scratch write");
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.0.join(name)).expect("scratch read")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Lines captured from a writer, without a filesystem.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);

impl Captured {
    fn sink(&self) -> Box<ClosureSink<impl FnMut(&str) + Send>> {
        let lines = self.0.clone();
        Box::new(ClosureSink(move |line: &str| {
            lines.lock().expect("captured").push(line.to_string())
        }))
    }

    fn text(&self) -> String {
        let lines = self.0.lock().expect("captured");
        let mut out = lines.join("\n");
        out.push('\n');
        out
    }
}

fn at(millis: u64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn config_at(level: &str) -> LogConfig {
    LogConfig::default()
        .with_instance("bug:test")
        .with_level(level)
        .expect("a level this vocabulary defines")
}

/// Open a writer onto a capture buffer at `level`, and hand back both.
fn writer_at(level: &str) -> (Writer, Captured) {
    let captured = Captured::default();
    let writer = Writer::open_with_sink(
        &config_at(level),
        Vocabulary::shared_builtin(),
        at(1_700_000_000_000),
        captured.sink(),
    )
    .expect("the segment opens");
    (writer, captured)
}

#[test]
fn a_written_segment_reparses_and_yields_back_what_went_in() {
    let (mut writer, captured) = writer_at("debug");
    writer
        .write(
            Entry::new(
                at(1_700_000_001_000),
                log("Resolution"),
                "urn:calendar:today",
            )
            .with("worker", "ikigai-sched-2")
            .with("dur", "12"),
        )
        .expect("the entry writes")
        .expect("and is not filtered");
    writer
        .write(
            Entry::new(at(1_700_000_002_000), MESSAGE_CLASS, "urn:agent:calendar")
                .with("msg", "sync started"),
        )
        .expect("the entry writes")
        .expect("and is not filtered");

    let text = captured.text();
    let (header, offset) = Header::parse(&text).expect("the header this writer wrote parses");
    assert_eq!(header.level, log("debug"));
    assert_eq!(header.instance, "urn:ikigai:instance:bug:test");
    assert_eq!(
        header.prev,
        Prev::Genesis,
        "T4 owns the chain; T2 claims nothing"
    );
    assert_eq!(header.started, at(1_700_000_000_000));

    let entries: Vec<Entry> = text[offset..]
        .lines()
        .map(|line| Line::parse(line, &header.prefixes).expect("every line parses"))
        .filter_map(|line| match line {
            Line::Entry(entry) => Some(entry),
            _ => None,
        })
        .collect();

    // The liveness marker the writer laid down first, then the two entries.
    assert_eq!(entries.len(), 3, "{entries:#?}");
    assert_eq!(entries[0].class, PROCESS_START_CLASS);
    assert_eq!(entries[0].get("seq"), Some("1"));
    assert_eq!(entries[1].class, log("Resolution"));
    assert_eq!(entries[1].subject, "urn:calendar:today");
    assert_eq!(
        entries[1].get("seq"),
        Some("2"),
        "seq is written EXPLICITLY"
    );
    assert_eq!(entries[1].get("worker"), Some("ikigai-sched-2"));
    assert_eq!(entries[1].get("dur"), Some("12"));
    assert_eq!(entries[2].get("msg"), Some("sync started"));
}

#[test]
fn the_level_dial_excludes_resolutions_at_info_and_never_the_always_land_set() {
    let (mut info, captured) = writer_at("info");
    assert!(!info.emits(&log("Resolution")), "no resolutions at info");
    assert!(!info.emits(&log("CacheHit")), "and certainly no cache hits");
    assert!(info.emits(MESSAGE_CLASS));
    let filtered = info
        .write(Entry::new(at(1), log("Resolution"), "urn:calendar:today"))
        .expect("a filtered entry is not an error");
    assert_eq!(filtered, None);
    assert!(
        !captured.text().contains("Resolution"),
        "and nothing reached the file"
    );

    // At the bottom of the dial, every always-land class still lands: rank -1
    // sorts below every settable level, so the set needs no list in code.
    let (mut error, captured) = writer_at("error");
    for class in [
        "ProcessStart",
        "ProcessStop",
        "ConfigChange",
        "LevelChange",
        "LevelChangeRejected",
        "Rotation",
        "Seal",
        "ChainBroken",
        "Tombstone",
        "Dropped",
        "CapabilityDenied",
        "KeyChange",
    ] {
        assert!(
            error.emits(&log(class)),
            "log:{class} lands at every level or the chain blesses a hole"
        );
        error
            .write(Entry::new(at(2), log(class), "urn:log:test"))
            .expect("it writes")
            .unwrap_or_else(|| panic!("log:{class} must not be filtered"));
    }
    assert!(!error.emits(MESSAGE_CLASS), "but ordinary prose does not");
    let text = captured.text();
    for class in ["ProcessStart", "Dropped", "CapabilityDenied"] {
        assert!(text.contains(&format!("log:{class}")), "{text}");
    }
}

#[test]
fn a_level_the_vocabulary_does_not_define_fails_at_open() {
    let mut config = config_at("info");
    // Shape-valid, so the config layer accepts it — and meaningless, so the
    // writer must not.
    config.level = log("verbose");
    let opened = Writer::open_with_sink(
        &config,
        Vocabulary::shared_builtin(),
        at(0),
        Captured::default().sink(),
    );
    match opened
        .err()
        .expect("a level nothing can place on the dial is a hard stop")
    {
        WriteError::UnknownLevel { level, known } => {
            assert_eq!(level, log("verbose"));
            assert!(known.contains(&log("info")), "{known:?}");
        }
        other => panic!("expected UnknownLevel, got {other}"),
    }
}

#[test]
fn prose_with_a_newline_survives_escaped_on_one_line() {
    let (mut writer, captured) = writer_at("info");
    writer
        .write(
            Entry::new(at(3), MESSAGE_CLASS, "urn:agent:calendar")
                .with("msg", "first\nsecond\ttabbed"),
        )
        .expect("it writes")
        .expect("and is not filtered");
    let text = captured.text();
    assert!(text.contains(r#"msg="first\nsecond\ttabbed""#), "{text}");

    let (header, offset) = Header::parse(&text).expect("header");
    let entries: Vec<Entry> = text[offset..]
        .lines()
        .filter_map(|line| match Line::parse(line, &header.prefixes) {
            Ok(Line::Entry(entry)) => Some(entry),
            _ => None,
        })
        .collect();
    assert_eq!(
        entries.last().expect("the message").get("msg"),
        Some("first\nsecond\ttabbed"),
        "one entry is one line on the way out AND the way back"
    );
}

#[test]
fn the_file_destination_writes_a_segment_and_a_second_process_does_not_interleave() {
    let scratch = Scratch::new("segments");
    let config = LogConfig::default()
        .with_destination(Destination::File)
        .with_directory(scratch.path())
        .with_instance("serve");

    let first = Writer::open(&config, Vocabulary::shared_builtin(), at(1_700_000_000_000))
        .expect("the first segment opens")
        .expect("a file destination is a writer");
    assert_eq!(first.instance(), "urn:ikigai:instance:serve");
    assert!(
        first.configured_instance().is_none(),
        "no disambiguation yet"
    );
    assert_eq!(
        first.segment(),
        "urn:log:serve:2023-11-14T22-13-20Z",
        "the segment IRI carries the instant, so two runs of one name stay apart"
    );

    // The same name, in the same process, while the first writer still holds
    // the lock: this is what a second `ikigai serve` looks like from here. It
    // does NOT refuse — a logging subsystem that takes out the second server on
    // the box is backwards — it disambiguates, and it records that it did.
    let second = Writer::open(&config, Vocabulary::shared_builtin(), at(1_700_000_060_000))
        .expect("the second segment opens too")
        .expect("a writer");
    assert_ne!(second.instance(), first.instance());
    assert!(
        second
            .instance()
            .ends_with(&format!("-{}", std::process::id())),
        "the pid is the token: unique among LIVE processes, and it points at one"
    );
    assert_eq!(
        second.configured_instance(),
        Some("urn:ikigai:instance:serve"),
        "what was asked for is in the record, not lost"
    );
    assert_ne!(second.path(), first.path(), "two names, two files");

    let text = std::fs::read_to_string(first.path().expect("a file")).expect("the segment");
    let (header, offset) = Header::parse(&text).expect("the header parses");
    assert_eq!(header.name, first.segment());
    let start = text[offset..]
        .lines()
        .find_map(|line| match Line::parse(line, &header.prefixes) {
            Ok(Line::Entry(entry)) if entry.class == PROCESS_START_CLASS => Some(entry),
            _ => None,
        })
        .expect("every segment opens with liveness");
    assert_eq!(
        start.get("pid"),
        Some(std::process::id().to_string()).as_deref()
    );

    let second_text =
        std::fs::read_to_string(second.path().expect("a file")).expect("the second segment");
    let (_, second_offset) = Header::parse(&second_text).expect("header");
    assert!(
        second_text[second_offset..].contains("configured=urn:ikigai:instance:serve"),
        "{second_text}"
    );
}

#[test]
fn an_orderly_close_writes_a_stop_marker_and_a_drop_does_not() {
    let (writer, captured) = writer_at("error");
    writer.close(at(9)).expect("the close writes");
    assert!(
        captured.text().contains("log:ProcessStop"),
        "{}",
        captured.text()
    );

    let (writer, captured) = writer_at("error");
    drop(writer);
    assert!(
        !captured.text().contains("log:ProcessStop"),
        "a segment that ends without one ended because the process DIED — which \
         is exactly what the absence query will want to see"
    );
}

// =====================================================================================
// The layered config
// =====================================================================================

#[test]
fn no_files_at_all_is_the_host_defaults_not_an_error() {
    let home = Scratch::new("empty-config");
    let base = LogConfig::default().with_destination(Destination::Console);
    let effective = crate::load::complete_in(home.path(), Some("serve"), base.clone())
        .expect("an absent file is a layer that states nothing");
    assert_eq!(effective.destination, Destination::Console);
    assert_eq!(effective.level, log("info"));
    assert!(effective.layers.is_empty());
}

#[test]
fn the_app_layer_overrides_the_shared_one_key_wise() {
    let home = Scratch::new("layered-config");
    home.write("log.toml", "level = \"debug\"\ndestination = \"file\"\n");
    home.write("serve.log.toml", "instance = \"bug:serve\"\n");

    let effective = crate::load::complete_in(home.path(), Some("serve"), LogConfig::default())
        .expect("both layers parse");
    assert_eq!(effective.instance, "urn:ikigai:instance:bug:serve");
    assert_eq!(effective.level, log("debug"), "the shared level SURVIVES");
    assert_eq!(effective.destination, Destination::File);
    assert_eq!(effective.layers.len(), 2);

    // Another application sees the shared file only.
    let other = crate::load::complete_in(home.path(), Some("web"), LogConfig::default())
        .expect("the shared layer parses");
    assert_eq!(other.instance, "urn:ikigai:instance:repl");
    assert_eq!(other.level, log("debug"));
    assert_eq!(other.layers.len(), 1);
}

#[test]
fn a_present_but_wrong_key_fails_loudly_and_names_itself() {
    let home = Scratch::new("bad-config");
    home.write("log.toml", "destination = \"flie\"\n");
    let error = crate::load::complete_in(home.path(), None, LogConfig::default())
        .expect_err("a typo that silently does nothing is the defect this prevents");
    assert!(matches!(error, ConfigError::Parse { .. }), "{error:?}");

    let home = Scratch::new("unknown-key");
    home.write("log.toml", "levle = \"debug\"\n");
    assert!(
        crate::load::complete_in(home.path(), None, LogConfig::default()).is_err(),
        "an unknown key is the same defect as a misspelled value"
    );

    let home = Scratch::new("bad-level");
    home.write("log.toml", "level = \"not a level\"\n");
    let error = crate::load::complete_in(home.path(), None, LogConfig::default())
        .expect_err("a level that is not even IRI-shaped stops at the layer");
    assert!(
        matches!(error, ConfigError::BadValue { key: "level", .. }),
        "{error:?}"
    );
}

#[test]
fn the_threads_name_every_candidate_including_the_ones_not_created_yet() {
    let threads = crate::load::threads_in(Path::new("/cfg/ikigai"), Some("serve"));
    assert_eq!(
        threads,
        vec![
            "urn:file:/cfg/ikigai/log.toml".to_string(),
            "urn:file:/cfg/ikigai/serve.log.toml".to_string(),
        ],
        "a config that named only the files it READ would never notice an \
         override being created"
    );
}

// =====================================================================================
// The endpoints
// =====================================================================================

/// A clock that does not move — the only kind a test should reason against.
struct Fixed(u64);

impl Clock for Fixed {
    fn now(&self) -> Time {
        Time::from_millis(self.0)
    }
}

/// A kernel over the log's own space, with a fixed clock. Entries are stamped
/// from the KERNEL's clock and nowhere else — a caller-supplied timestamp would
/// be a forgery surface on a record whose whole value is that it can be trusted.
fn kernel(handle: Arc<LogHandle>) -> Kernel {
    Kernel::new(Arc::new(crate::endpoints::space(handle)))
        .with_clock(Arc::new(Fixed(1_700_000_000_000)))
}

fn sink_request(iri: &str, args: &[(&str, &str)]) -> Request {
    let mut request = Request::new(Verb::Sink, Iri::parse(iri).expect("a valid IRI"));
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    request
}

fn text(repr: &Representation) -> String {
    String::from_utf8(repr.bytes.to_vec()).expect("utf-8")
}

/// A handle with a segment open onto a capture buffer.
fn open_handle(home: &Path, app: Option<&str>, level: &str) -> (Arc<LogHandle>, Captured) {
    let config = crate::load::complete_in(
        home,
        app,
        LogConfig::default()
            .with_instance("bug:test")
            .with_level(level)
            .expect("a real level"),
    )
    .expect("the layers parse");
    let handle = Arc::new(LogHandle::new(
        Some(home.to_path_buf()),
        app.map(str::to_string),
        config,
    ));
    let captured = Captured::default();
    handle
        .open_with_sink(
            Vocabulary::shared_builtin(),
            at(1_700_000_000_000),
            captured.sink(),
        )
        .expect("the segment opens");
    (handle, captured)
}

#[test]
fn binding_the_endpoints_starts_nothing() {
    let home = Scratch::new("closed");
    let handle = Arc::new(LogHandle::new(
        Some(home.path().to_path_buf()),
        None,
        LogConfig::default(),
    ));
    let _space = crate::endpoints::space(handle.clone());
    assert!(
        !handle.is_open(),
        "the module cannot judge what it is inside; the HOST decides who logs"
    );

    // And a write against a closed log says so rather than pretending.
    let kernel = kernel(handle);
    let repr = futures::executor::block_on(kernel.issue(
        sink_request(WRITE_IRI, &[("msg", "nothing to see")]),
        &Capability::root(),
    ))
    .expect("a closed log is not an error");
    assert!(text(&repr).starts_with("closed:"), "{}", text(&repr));
}

#[test]
fn the_convenience_write_normalizes_to_log_message() {
    let home = Scratch::new("convenience");
    let (handle, captured) = open_handle(home.path(), None, "info");
    let kernel = kernel(handle);

    // Piped content, no class, no subject — the whole convenience path.
    let repr = futures::executor::block_on(kernel.issue(
        sink_request(WRITE_IRI, &[("content", "sync started\nand continued")]),
        &Capability::root(),
    ))
    .expect("the write lands");
    assert!(
        text(&repr).starts_with("urn:log:bug:test:"),
        "the entry's IRI comes back, so it pipes: {}",
        text(&repr)
    );

    let written = captured.text();
    assert!(written.contains("log:Message"), "{written}");
    assert!(
        written.contains(r#"msg="sync started\nand continued""#),
        "prose survives a newline ESCAPED, on one line: {written}"
    );
    assert!(
        written.contains("urn:ikigai:instance:bug:test"),
        "an entry with no stated subject is about the process that wrote it"
    );
    assert_eq!(
        written
            .lines()
            .filter(|l| l.contains("log:Message"))
            .count(),
        1,
        "one entry is one line"
    );
    assert!(
        !written.contains("level="),
        "severity is carried by SUBCLASS, never by a level= column"
    );
}

#[test]
fn the_typed_write_takes_its_fields_in_the_lines_own_tail_syntax() {
    let home = Scratch::new("typed");
    let (handle, captured) = open_handle(home.path(), None, "debug");
    let kernel = kernel(handle);

    futures::executor::block_on(kernel.issue(
        sink_request(
            WRITE_IRI,
            &[
                ("class", "log:Resolution"),
                ("subject", "urn:calendar:today"),
                (
                    "fields",
                    r#"span=7 dur=12 cap=urn:cap:fs cap=urn:cap:net msg="two words""#,
                ),
            ],
        ),
        &Capability::root(),
    ))
    .expect("the write lands");

    let written = captured.text();
    let (header, offset) = Header::parse(&written).expect("header");
    let entry = written[offset..]
        .lines()
        .find_map(|line| match Line::parse(line, &header.prefixes) {
            Ok(Line::Entry(entry)) if entry.class == log("Resolution") => Some(entry),
            _ => None,
        })
        .expect("the resolution");
    assert_eq!(entry.get("span"), Some("7"));
    assert_eq!(entry.get("dur"), Some("12"));
    assert_eq!(
        entry.all("cap").collect::<Vec<_>>(),
        vec!["urn:cap:fs", "urn:cap:net"],
        "a repeated key is a list — one resolution under two capability scopes"
    );
    assert_eq!(
        entry.get("msg"),
        Some("two words"),
        "the same scanner as the file, so quoting behaves identically"
    );
}

#[test]
fn a_write_without_the_capability_is_denied_before_the_endpoint_is_entered() {
    let home = Scratch::new("denied");
    let (handle, captured) = open_handle(home.path(), None, "error");
    let kernel = kernel(handle.clone());

    let error = futures::executor::block_on(kernel.issue(
        sink_request(WRITE_IRI, &[("msg", "forged")]),
        &Capability::scoped(["urn:cap:something:else"]),
    ))
    .expect_err("a forged entry is the threat this gate exists for");
    assert!(matches!(error, Error::Denied(_)), "{error:?}");
    assert!(
        !captured.text().contains("forged"),
        "and the payload does not land"
    );

    // ★ The kernel refuses BEFORE dispatch (core 0.1.49 onward), so the entry
    // that would record the refusal is written by the action that was refused —
    // and never runs. `log:CapabilityDenied` is always-land and this is a real
    // hole in T2: the fact can only be recorded by a HOST that catches the
    // Denied, through `record_denial`. Closing it properly needs a kernel seam
    // for pre-dispatch denials, which is core's decision and not this crate's.
    assert!(
        !captured.text().contains("log:CapabilityDenied"),
        "if this ever starts passing, the kernel grew the seam and the module \
         docs need rewriting: {}",
        captured.text()
    );

    // The door that IS available to a host, at the bottom of the dial.
    handle
        .record_denial(at(1_700_000_000_500), CAP_WRITE, "appending a log entry")
        .expect("a refused authority is a security fact, so it lands at EVERY level");
    let written = captured.text();
    assert!(written.contains("log:CapabilityDenied"), "{written}");
    assert!(written.contains(&format!("cap={CAP_WRITE}")), "{written}");

    // The declared requirement and the enforced one are the same string.
    let described =
        crate::endpoints::write(Arc::new(LogHandle::new(None, None, LogConfig::default())))
            .describe();
    let sink = described
        .action_specs()
        .into_iter()
        .find(|a| a.verb == Verb::Sink)
        .expect("a Sink action");
    assert_eq!(sink.requires, vec![CAP_WRITE.to_string()]);
}

#[test]
fn the_config_source_serves_the_effective_config_and_whether_a_segment_is_open() {
    let home = Scratch::new("config-source");
    home.write("log.toml", "level = \"debug\"\n");
    let (handle, _captured) = open_handle(home.path(), None, "info");
    let kernel = kernel(handle);

    let plain = futures::executor::block_on(kernel.issue(
        Request::new(Verb::Source, Iri::parse(CONFIG_IRI).expect("iri")),
        &Capability::scoped([CAP_READ]),
    ))
    .expect("the read lands");
    let body = text(&plain);
    assert!(body.contains("level = \"debug\""), "{body}");
    assert!(body.contains("# open = true"), "{body}");
    assert!(body.contains("# segment = urn:log:bug:test:"), "{body}");
    assert!(
        Patch::parse(&body, None).is_ok(),
        "the plain face round-trips as a config file — the live state is comments: {body}"
    );

    let turtle = futures::executor::block_on(
        kernel.issue(
            Request::new(Verb::Source, Iri::parse(CONFIG_IRI).expect("iri"))
                .with_arg("as", ArgRef::Inline(b"text/turtle".to_vec())),
            &Capability::scoped([CAP_READ]),
        ),
    )
    .expect("the graph face lands");
    let graph = text(&turtle);
    assert!(graph.contains("a log:Config"), "{graph}");
    assert!(
        graph.contains("log:currentSegment <urn:log:bug:test:"),
        "{graph}"
    );
    assert!(!graph.contains("[]"), "skolemized; no blank nodes: {graph}");

    // Reading where the log lives is itself gated.
    let denied = futures::executor::block_on(kernel.issue(
        Request::new(Verb::Source, Iri::parse(CONFIG_IRI).expect("iri")),
        &Capability::scoped([CAP_WRITE]),
    ))
    .expect_err("a write grant is not a read grant");
    assert!(matches!(denied, Error::Denied(_)), "{denied:?}");
}

#[test]
fn a_config_write_lands_its_always_land_entry_at_every_level_and_persists() {
    // `error` is the bottom of the dial: if the bracket lands here it lands
    // everywhere, which is the whole point of log:always.
    let home = Scratch::new("config-sink");
    let (handle, captured) = open_handle(home.path(), Some("serve"), "error");
    let kernel = kernel(handle.clone());

    let repr = futures::executor::block_on(kernel.issue(
        sink_request(CONFIG_IRI, &[("level", "debug"), ("destination", "file")]),
        &Capability::scoped([CAP_CONFIG]),
    ))
    .expect("the change lands");
    let body = text(&repr);
    assert!(
        body.contains("serve.log.toml"),
        "the file it touched: {body}"
    );
    assert!(
        body.contains("effective at next process start"),
        "T2 has no rotation, and a segment's level is fixed for its life: {body}"
    );

    // Persisted to the HIGHEST-precedence layer, or the change could be
    // silently overridden by a file the writer never mentioned.
    let written = home.read("serve.log.toml");
    assert!(written.contains("level = \"debug\""), "{written}");
    assert!(written.contains("destination = \"file\""), "{written}");

    // And in memory, for the next segment.
    assert_eq!(handle.config().level, log("debug"));
    assert_eq!(handle.config().destination, Destination::File);

    let log_text = captured.text();
    let (header, offset) = Header::parse(&log_text).expect("header");
    assert_eq!(
        header.level,
        log("error"),
        "the OPEN segment keeps its level"
    );
    let entries: Vec<Entry> = log_text[offset..]
        .lines()
        .filter_map(|line| match Line::parse(line, &header.prefixes) {
            Ok(Line::Entry(entry)) => Some(entry),
            _ => None,
        })
        .collect();
    let level_change = entries
        .iter()
        .find(|e| e.class == LEVEL_CHANGE_CLASS)
        .expect("a level change brackets the hole it creates");
    assert_eq!(level_change.get("from"), Some(log("error")).as_deref());
    assert_eq!(level_change.get("to"), Some(log("debug")).as_deref());
    assert_eq!(level_change.get("effective"), Some("next-segment"));
    let config_change = entries
        .iter()
        .find(|e| e.class == CONFIG_CHANGE_CLASS)
        .expect("a destination change matters MORE than a level change");
    assert_eq!(config_change.get("key"), Some("destination"));

    // A change nobody is entitled to make does not touch the file.
    let error = futures::executor::block_on(kernel.issue(
        sink_request(CONFIG_IRI, &[("level", "trace")]),
        &Capability::scoped([CAP_READ]),
    ))
    .expect_err("reading the config is not changing it");
    assert!(matches!(error, Error::Denied(_)), "{error:?}");
    assert!(
        !home.read("serve.log.toml").contains("trace"),
        "a denied change is not a change"
    );
}

#[test]
fn a_level_the_config_write_cannot_parse_is_rejected_and_the_rejection_lands() {
    let home = Scratch::new("rejected");
    let (handle, captured) = open_handle(home.path(), None, "error");
    let kernel = kernel(handle);

    let error = futures::executor::block_on(kernel.issue(
        sink_request(CONFIG_IRI, &[("level", "not a level")]),
        &Capability::scoped([CAP_CONFIG]),
    ))
    .expect_err("a level that is not even IRI-shaped is refused");
    assert!(
        matches!(error, Error::InvalidArgument { ref name, .. } if name == "level"),
        "{error:?}"
    );
    assert!(
        captured.text().contains("log:LevelChangeRejected"),
        "the evidence that the change did NOT take: {}",
        captured.text()
    );
    assert!(
        !home.path().join("log.toml").exists(),
        "and nothing was written"
    );
}
