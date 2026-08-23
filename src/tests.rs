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

// =====================================================================================
// The transreptor, and the named-graph story
// =====================================================================================

use oxrdf::{NamedNodeRef, NamedOrBlankNode, Term as OxTerm, Triple};
use oxrdfio::{RdfFormat, RdfParser};

use crate::graph::{to_triples, to_turtle, GraphError, Options, LOG_MEDIA_TYPE, SIG_NS};
use crate::segments::{SegmentEndpoint, TransreptEndpoint, SEGMENTS_IRI, TRANSREPT_IRI};

const PROV: &str = "http://www.w3.org/ns/prov#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const TURTLE: &str = "text/turtle";

/// Re-parse a serialization as RDF and hand back its triples.
///
/// Every assertion below goes through this: asserting on the Turtle TEXT would
/// test the serializer's whitespace, not the mapping, and would pass on a graph
/// that no parser accepts.
fn reparse(turtle: &str) -> Vec<Triple> {
    RdfParser::from_format(RdfFormat::Turtle)
        .for_slice(turtle.as_bytes())
        .map(|quad| quad.expect("the emitted Turtle re-parses").into())
        .collect()
}

/// Whether `triples` states `subject predicate object`.
fn states(triples: &[Triple], subject: &str, predicate: &str, object: OxTerm) -> bool {
    let subject =
        NamedOrBlankNode::NamedNode(NamedNodeRef::new(subject).expect("an IRI").into_owned());
    let predicate = NamedNodeRef::new(predicate).expect("an IRI").into_owned();
    triples
        .iter()
        .any(|t| t.subject == subject && t.predicate == predicate && t.object == object)
}

fn node(iri: &str) -> OxTerm {
    OxTerm::NamedNode(NamedNodeRef::new(iri).expect("an IRI").into_owned())
}

fn string(value: &str) -> OxTerm {
    OxTerm::Literal(oxrdf::Literal::new_simple_literal(value))
}

fn typed(value: &str, datatype: &str) -> OxTerm {
    OxTerm::Literal(oxrdf::Literal::new_typed_literal(
        value,
        NamedNodeRef::new(datatype).expect("an IRI").into_owned(),
    ))
}

fn objects<'a>(triples: &'a [Triple], subject: &str, predicate: &str) -> Vec<&'a OxTerm> {
    let subject =
        NamedOrBlankNode::NamedNode(NamedNodeRef::new(subject).expect("an IRI").into_owned());
    let predicate = NamedNodeRef::new(predicate).expect("an IRI").into_owned();
    triples
        .iter()
        .filter(|t| t.subject == subject && t.predicate == predicate)
        .map(|t| &t.object)
        .collect()
}

/// A segment written by the WRITER, not by hand — so the transreptor is tested
/// against the bytes the rest of the crate actually produces.
fn written_segment(level: &str, write: impl FnOnce(&mut Writer)) -> (String, String) {
    let (mut writer, captured) = writer_at(level);
    let name = writer.segment().to_string();
    write(&mut writer);
    (name, captured.text())
}

#[test]
fn a_written_segment_becomes_a_graph_that_reparses_as_rdf() {
    let (segment, text) = written_segment("debug", |writer| {
        writer
            .write(
                Entry::new(
                    at(1_700_000_001_000),
                    log("Resolution"),
                    "urn:calendar:today",
                )
                .with("span", "7")
                .with("dur", "12")
                .with("worker", "ikigai-sched-2")
                .with("cap", "urn:cap:personal:calendar"),
            )
            .expect("a resolution at debug");
    });

    let turtle = to_turtle(&text, Vocabulary::builtin(), &Options::all()).expect("it transrepts");
    let triples = reparse(&turtle);

    // The header became a segment node.
    assert!(states(&triples, &segment, RDF_TYPE, node(&log("Segment"))));
    assert!(states(
        &triples,
        &segment,
        &log("level"),
        node(&log("debug"))
    ));
    assert!(states(
        &triples,
        &segment,
        &format!("{PROV}startedAtTime"),
        typed(
            "2023-11-14T22:13:20.000Z",
            "http://www.w3.org/2001/XMLSchema#dateTime"
        )
    ));
    // `genesis` is STATED, not omitted: an absent @prev is unambiguously an
    // error, and a graph that dropped the token would give that away.
    assert!(states(
        &triples,
        &segment,
        &log("prevSeal"),
        string("genesis")
    ));

    let instance = "urn:ikigai:instance:bug:test";
    assert!(states(&triples, instance, RDF_TYPE, node(&log("Instance"))));
    assert!(
        states(
            &triples,
            instance,
            RDF_TYPE,
            node(&format!("{PROV}SoftwareAgent"))
        ),
        "a consumer of this graph alone has no reasoner and no copy of the log \
         vocabulary, so the PROV type is stated rather than inferred"
    );

    // seq=1 is log:ProcessStart, seq=2 the resolution.
    let entry = format!("{segment}:2");
    assert!(states(&triples, &entry, RDF_TYPE, node(&log("Resolution"))));
    assert!(states(
        &triples,
        &entry,
        &format!("{PROV}wasAssociatedWith"),
        node(instance)
    ));
    assert!(
        states(
            &triples,
            &entry,
            &log("span"),
            typed("7", "http://www.w3.org/2001/XMLSchema#integer")
        ),
        "an xsd:integer range makes a typed literal, so a threshold query can compare"
    );
    assert!(states(
        &triples,
        &entry,
        &log("worker"),
        string("ikigai-sched-2")
    ));

    // The subject column emits TWICE: log:subject always, plus the class's
    // declared log:subjectPredicate. Two triples, both true, no reasoner.
    assert!(states(
        &triples,
        &entry,
        &log("subject"),
        node("urn:calendar:today")
    ));
    assert!(
        states(
            &triples,
            &entry,
            &log("resolved"),
            node("urn:calendar:today")
        ),
        "log:Resolution declares log:subjectPredicate log:resolved"
    );
}

#[test]
fn a_range_typed_key_lands_as_an_iri_and_not_as_a_string() {
    let (segment, text) = written_segment("info", |writer| {
        writer
            .write(
                Entry::new(at(1_700_000_001_000), log("Message"), "urn:agent:calendar")
                    .with("cap", "urn:cap:personal:calendar")
                    .with("cap", "urn:cap:fs:read")
                    .with("msg", "sync started"),
            )
            .expect("a message at info");
    });
    let triples = reparse(&to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap());
    let entry = format!("{segment}:2");

    // `cap` is rdfs:range rdfs:Resource. As a string it would join to nothing,
    // and the whole capability axis is a join.
    let caps = objects(&triples, &entry, &log("capability"));
    assert_eq!(caps.len(), 2, "a key may repeat: two scopes, two triples");
    for cap in caps {
        assert!(
            matches!(cap, OxTerm::NamedNode(_)),
            "an rdfs:Resource range makes an IRI: {cap:?}"
        );
    }

    // `configured` is rdfs:range log:Instance — a CLASS, not an XSD datatype,
    // and it must be an IRI for the same reason. The rule is one rule: XSD
    // datatype ⇒ typed literal, anything else ⇒ IRI.
    let (_, start_text) = written_segment("info", |_| {});
    let started = reparse(&to_turtle(&start_text, Vocabulary::builtin(), &Options::all()).unwrap());
    assert!(
        started.iter().all(
            |t| t.predicate.as_str() != format!("{LOG_NS}configuredInstance")
                || matches!(t.object, OxTerm::NamedNode(_))
        ),
        "a class-ranged key is an IRI"
    );

    // And prose stays prose.
    assert!(states(
        &triples,
        &entry,
        &log("text"),
        string("sync started")
    ));
}

#[test]
fn an_undeclared_key_lands_losslessly_and_flagged() {
    let (segment, text) = written_segment("info", |writer| {
        writer
            .write(
                Entry::new(at(1_700_000_001_000), log("Message"), "urn:agent:calendar")
                    .with("nonesuch", "42")
                    .with("nonesuch", "43"),
            )
            .expect("a message at info");
    });
    let triples = reparse(&to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap());
    let entry = format!("{segment}:2");

    // Lossless: both values, on log:{key}, as plain literals — never guessed
    // into a range nobody declared.
    let values = objects(&triples, &entry, &log("nonesuch"));
    assert_eq!(values.len(), 2, "{values:?}");
    assert!(values.contains(&&string("42")) && values.contains(&&string("43")));

    // AND flagged, once — the hygiene signal the design counts, not a
    // per-occurrence rash.
    let flags = objects(&triples, &entry, &log("undeclaredKey"));
    assert_eq!(flags, vec![&string("nonesuch")], "{flags:?}");
}

#[test]
fn log_segment_is_on_every_entry_so_a_flattened_triple_keeps_its_attribution() {
    let (segment, text) = written_segment("debug", |writer| {
        for n in 0..3 {
            writer
                .write(Entry::new(
                    at(1_700_000_001_000 + n),
                    log("Message"),
                    "urn:agent:calendar",
                ))
                .expect("a message at debug");
        }
    });
    let triples = reparse(&to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap());

    // urn:rdf:union is triple-only and loses graph names, so this is what keeps
    // a triple self-identifying if it is ever flattened into one graph — and it
    // lets a query written against a union keep working on a single segment.
    for seq in 1..=4 {
        assert!(
            states(
                &triples,
                &format!("{segment}:{seq}"),
                &log("segment"),
                node(&segment)
            ),
            "entry {seq} names its segment"
        );
    }
}

#[test]
fn nothing_transrepts_to_a_blank_node() {
    let (_, text) = written_segment("debug", |writer| {
        writer
            .write(
                Entry::new(
                    at(1_700_000_001_000),
                    log("Resolution"),
                    "urn:calendar:today",
                )
                .with("span", "7")
                .with("parent", "1")
                .with("undeclared", "x"),
            )
            .expect("a resolution at debug");
    });
    let mut text = text;
    text.push_str("#seal 1-2 sha256:4c1e sig:MEUCIQD\n");

    let triples = reparse(&to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap());
    assert!(!triples.is_empty());
    for triple in &triples {
        assert!(
            matches!(triple.subject, NamedOrBlankNode::NamedNode(_)),
            "a blank node in a log is a fact you cannot cite: {triple}"
        );
        assert!(
            !matches!(triple.object, OxTerm::BlankNode(_)),
            "a blank node in a log is a fact you cannot cite: {triple}"
        );
    }
}

#[test]
fn a_graph_states_each_fact_once_and_two_runs_are_byte_identical() {
    // log:ProcessStart declares `log:subjectPredicate prov:wasAssociatedWith`,
    // which is also the per-entry attribution — so the naive emission writes
    // that triple twice. A set has no duplicates and neither should the
    // serialization: two runs over one segment agreeing as graphs but differing
    // in bytes costs the artifact its diffability for nothing.
    let (_, text) = written_segment("info", |writer| {
        writer
            .write(
                Entry::new(at(1_700_000_001_000), log("Message"), "urn:agent:calendar")
                    .with("cap", "urn:cap:fs:read")
                    .with("cap", "urn:cap:fs:read"),
            )
            .unwrap();
    });
    let turtle = to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap();
    let triples = reparse(&turtle);
    let mut seen = std::collections::HashSet::new();
    for triple in &triples {
        assert!(seen.insert(triple.to_string()), "stated twice: {triple}");
    }
    assert_eq!(
        turtle,
        to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap(),
        "the same segment serializes to the same bytes"
    );
}

#[test]
fn invoked_is_materialized_within_one_run_and_never_across_a_process_start() {
    // Two runs in one segment — which is what a rotation-free restart looks
    // like from the writer's side, and exactly where a naive span join breaks:
    // the kernel's span counter restarts with the process, so span 7 in run two
    // is a different activity from span 7 in run one.
    let (segment, text) = written_segment("debug", |writer| {
        let resolution = |ms: u64, span: &str| {
            Entry::new(at(ms), log("Resolution"), "urn:calendar:today").with("span", span)
        };
        writer
            .write(resolution(1_700_000_001_000, "9").with("parent", "7"))
            .unwrap();
        writer.write(resolution(1_700_000_002_000, "7")).unwrap();
        // A second run. Its child claims parent 7 — which exists, but in the
        // OTHER run.
        writer
            .write(Entry::new(
                at(1_700_000_003_000),
                log("ProcessStart"),
                "urn:ikigai:instance:bug:test",
            ))
            .unwrap();
        writer
            .write(resolution(1_700_000_004_000, "11").with("parent", "7"))
            .unwrap();
    });

    let triples = reparse(&to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap());
    let invoked = objects(&triples, &format!("{segment}:3"), &log("invoked"));
    assert_eq!(
        invoked,
        vec![&node(&format!("{segment}:2"))],
        "parent → child, and the parent's line is written when it COMPLETES, so \
         the child's line came first: {invoked:?}"
    );

    // The cross-run child got no edge — and kept its literal, so the fact is
    // still recoverable by a union that can see both runs.
    let across = triples
        .iter()
        .filter(|t| t.predicate.as_str() == format!("{LOG_NS}invoked"))
        .count();
    assert_eq!(across, 1, "no edge crosses a log:ProcessStart");
    assert!(states(
        &triples,
        &format!("{segment}:5"),
        &log("parentSpan"),
        typed("7", "http://www.w3.org/2001/XMLSchema#integer")
    ));
}

#[test]
fn a_seal_transrepts_as_what_it_says_and_asserts_nothing_about_its_validity() {
    let (segment, text) = written_segment("info", |_| {});
    let mut text = text;
    text.push_str("#seal 1-42 sha256:4c1e0d sig:MEUCIQD\n");
    text.push_str("#seal 43-99 sha256:9ab7\n");

    let triples = reparse(&to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap());
    let seal = format!("{segment}:seal:1-42");
    assert!(states(&triples, &seal, RDF_TYPE, node(&log("Seal"))));
    assert!(states(&triples, &seal, &log("segment"), node(&segment)));
    assert!(states(
        &triples,
        &seal,
        &log("firstSequence"),
        typed("1", "http://www.w3.org/2001/XMLSchema#integer")
    ));
    assert!(states(
        &triples,
        &seal,
        &log("lastSequence"),
        typed("42", "http://www.w3.org/2001/XMLSchema#integer")
    ));
    // The tokens EXACTLY as the line wrote them. T3 states; T4 verifies.
    assert!(states(
        &triples,
        &seal,
        &format!("{SIG_NS}contentHash"),
        string("sha256:4c1e0d")
    ));
    assert!(states(
        &triples,
        &seal,
        &format!("{SIG_NS}value"),
        string("sig:MEUCIQD")
    ));

    // An unsigned seal still localizes tampering, so it is not an error and it
    // carries no sig:value to imply otherwise.
    let unsigned = format!("{segment}:seal:43-99");
    assert!(states(
        &triples,
        &unsigned,
        &format!("{SIG_NS}contentHash"),
        string("sha256:9ab7")
    ));
    assert!(objects(&triples, &unsigned, &format!("{SIG_NS}value")).is_empty());

    // Nothing anywhere claims a seal is valid, verified, or intact.
    let turtle = to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap();
    for word in ["verif", "valid", "intact"] {
        assert!(
            !turtle.contains(word),
            "a transreptor that implied verification would be worse than one \
             that ignored seals: {turtle}"
        );
    }
}

#[test]
fn a_module_extends_the_mapping_without_touching_the_transreptor() {
    // The same claim T1 tests for the writer, now for the reader: the table is
    // data, so a module's own class and key transrept with no code change here.
    let mut vocab = Vocabulary::builtin().clone();
    vocab
        .extend(
            r#"
            @prefix log:  <https://ikigai-rs.dev/ns/log#> .
            @prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
            @prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
            <urn:demo:Fetch> a rdfs:Class ;
                rdfs:subClassOf log:Entry ;
                log:minLevel log:info ;
                log:subjectPredicate <urn:demo:fetched> .
            <urn:demo:status> a rdf:Property ;
                log:keyName "status" ;
                rdfs:range xsd:integer .
            "#,
        )
        .expect("the extension parses");

    let (mut writer, captured) = {
        let captured = Captured::default();
        let writer = Writer::open_with_sink(
            &config_at("info"),
            Arc::new(vocab.clone()),
            at(1_700_000_000_000),
            captured.sink(),
        )
        .expect("the segment opens");
        (writer, captured)
    };
    let segment = writer.segment().to_string();
    writer
        .write(
            Entry::new(at(1_700_000_001_000), "urn:demo:Fetch", "urn:page:home")
                .with("status", "200"),
        )
        .expect("the extension's class emits at info");

    let triples = reparse(&to_turtle(&captured.text(), &vocab, &Options::all()).unwrap());
    let entry = format!("{segment}:2");
    assert!(states(&triples, &entry, RDF_TYPE, node("urn:demo:Fetch")));
    assert!(
        states(&triples, &entry, "urn:demo:fetched", node("urn:page:home")),
        "the extension's log:subjectPredicate refines the subject column"
    );
    assert!(
        states(
            &triples,
            &entry,
            "urn:demo:status",
            typed("200", "http://www.w3.org/2001/XMLSchema#integer")
        ),
        "and its rdfs:range types the value"
    );
    assert!(
        objects(&triples, &entry, &log("undeclaredKey")).is_empty(),
        "a key the EXTENDED table claims is not undeclared"
    );
}

#[test]
fn the_window_narrows_the_entries_and_never_the_header() {
    let (segment, text) = written_segment("info", |writer| {
        for n in 1..=5 {
            writer
                .write(Entry::new(
                    at(1_700_000_000_000 + n * 1000),
                    log("Message"),
                    "urn:agent:calendar",
                ))
                .unwrap();
        }
    });
    let window = Options {
        from_seq: Some(3),
        to_seq: Some(4),
        ..Options::default()
    };
    let triples = reparse(&to_turtle(&text, Vocabulary::builtin(), &window).unwrap());

    // O(segment) is the design's own first stated weakness, and the window is
    // how a long segment stays affordable — so it must narrow before the graph
    // is built, not after.
    for seq in [3, 4] {
        assert!(states(
            &triples,
            &format!("{segment}:{seq}"),
            &log("segment"),
            node(&segment)
        ));
    }
    for seq in [1, 2, 5] {
        assert!(
            objects(&triples, &format!("{segment}:{seq}"), &log("segment")).is_empty(),
            "entry {seq} is outside the window"
        );
    }
    // The header always lands: a segment node with no level and no start time
    // would be a graph that cannot say what it is a window into.
    assert!(states(&triples, &segment, RDF_TYPE, node(&log("Segment"))));
    assert!(states(
        &triples,
        &segment,
        &log("level"),
        node(&log("info"))
    ));

    let by_time = Options {
        since: Some(at(1_700_000_004_000)),
        ..Options::default()
    };
    let triples = reparse(&to_turtle(&text, Vocabulary::builtin(), &by_time).unwrap());
    assert!(objects(&triples, &format!("{segment}:4"), &log("segment")).is_empty());
    assert!(!objects(&triples, &format!("{segment}:5"), &log("segment")).is_empty());
}

#[test]
fn a_corrupt_line_names_its_position_rather_than_saying_invalid() {
    let (_, text) = written_segment("info", |_| {});
    let mut text = text;
    text.push_str("2026-13-45T99:99:99.999Z log:Message urn:agent:calendar\n");
    match to_triples(&text, Vocabulary::builtin(), &Options::all()) {
        // The corrupt line is the last one, and the error says so — "line N" is
        // what an operator can act on; "invalid" is not.
        Err(GraphError::Parse { line, .. }) => assert_eq!(line, text.lines().count(), "{text}"),
        other => panic!("a corrupt line is located, not shrugged at: {other:?}"),
    }
}

// =====================================================================================
// The addressable space
// =====================================================================================

use ikigai_core::{Expiry, Fallback, Space};

/// A handle writing real segment files into `dir`.
fn file_handle(dir: &Path, level: &str) -> Arc<LogHandle> {
    let config = LogConfig::default()
        .with_instance("bug:seg")
        .with_level(level)
        .expect("a real level")
        .with_destination(Destination::File)
        .with_directory(dir);
    let handle = Arc::new(LogHandle::new(Some(dir.to_path_buf()), None, config));
    handle
        .open(Vocabulary::shared_builtin(), at(1_700_000_000_000))
        .expect("the segment opens");
    handle
}

fn source_request(iri: &str, args: &[(&str, &str)]) -> Request {
    let mut request = Request::new(Verb::Source, Iri::parse(iri).expect("a valid IRI"));
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    request
}

fn source(kernel: &Kernel, iri: &str, args: &[(&str, &str)]) -> Representation {
    futures::executor::block_on(kernel.issue(source_request(iri, args), &Capability::root()))
        .unwrap_or_else(|e| panic!("<{iri}> resolves: {e}"))
}

#[test]
fn the_transreptor_declares_its_conversion_and_runs_over_piped_bytes() {
    let (segment, text) = written_segment("info", |writer| {
        writer
            .write(Entry::new(
                at(1_700_000_001_000),
                log("Message"),
                "urn:agent:calendar",
            ))
            .unwrap();
    });

    // Declared, so the shipped sniff-and-dispatch machinery can SELECT it —
    // `Description::transreptor` is what puts it in the transreptor graph, and
    // an undeclared converter is invisible to every caller that does not name
    // it directly.
    let described = TransreptEndpoint::new(Vocabulary::shared_builtin()).describe();
    let conversion = described
        .transreption()
        .expect("it is a transreptor, not an endpoint that happens to convert");
    assert_eq!(conversion.from, vec![LOG_MEDIA_TYPE.to_string()]);
    assert_eq!(conversion.to, vec![TURTLE.to_string()]);

    let home = Scratch::new("transrept");
    let handle = Arc::new(LogHandle::new(
        Some(home.path().to_path_buf()),
        None,
        LogConfig::default(),
    ));
    let kernel = kernel(handle);
    let repr = source(&kernel, TRANSREPT_IRI, &[("content", &text)]);
    assert_eq!(repr.repr_type.media_type.as_str(), TURTLE);
    assert!(states(
        &reparse(&text_of(&repr)),
        &format!("{segment}:2"),
        RDF_TYPE,
        node(&log("Message"))
    ));
}

fn text_of(repr: &Representation) -> String {
    String::from_utf8(repr.bytes.clone()).expect("utf-8")
}

#[test]
fn a_segment_resolves_to_turtle_at_its_own_iri_and_the_file_face_is_opt_in() {
    let dir = Scratch::new("segment-face");
    let handle = file_handle(dir.path(), "info");
    let (segment, _) = handle.open_segment().expect("a segment is open");
    handle
        .write(Entry::new(
            at(1_700_000_001_000),
            MESSAGE_CLASS,
            "urn:agent:calendar",
        ))
        .expect("a message at info");
    let kernel = kernel(handle);

    // ★ Turtle is the DEFAULT, and that is not a preference. `urn:sparql:*`
    // issues a bare Source with no `as=`, so a segment that answered it with log
    // lines would not be a graph source and the whole named-graph story would
    // need a second mechanism.
    let repr = source(&kernel, &segment, &[]);
    assert_eq!(repr.repr_type.media_type.as_str(), TURTLE);
    let triples = reparse(&text_of(&repr));
    assert!(states(&triples, &segment, RDF_TYPE, node(&log("Segment"))));
    assert!(states(
        &triples,
        &format!("{segment}:2"),
        &log("subject"),
        node("urn:agent:calendar")
    ));

    // The file itself is still addressable — it is the thing you grep.
    let raw = source(&kernel, &segment, &[("as", LOG_MEDIA_TYPE)]);
    assert_eq!(raw.repr_type.media_type.as_str(), LOG_MEDIA_TYPE);
    assert!(text_of(&raw).starts_with("# ikigai-log v1"));

    // A window over the raw face would hand back something that is not a
    // segment, so it is refused rather than silently truncated.
    let error = futures::executor::block_on(kernel.issue(
        source_request(&segment, &[("as", LOG_MEDIA_TYPE), ("from_seq", "2")]),
        &Capability::root(),
    ))
    .expect_err("a windowed segment file is not a segment");
    assert!(matches!(error, Error::InvalidArgument { .. }), "{error:?}");

    // On the graph face it narrows.
    let windowed = source(&kernel, &segment, &[("from_seq", "2")]);
    let triples = reparse(&text_of(&windowed));
    assert!(objects(&triples, &format!("{segment}:1"), &log("segment")).is_empty());
    assert!(!objects(&triples, &format!("{segment}:2"), &log("segment")).is_empty());
}

#[test]
fn the_segment_template_is_bound_last_so_the_exact_iris_still_win() {
    // `urn:log:{segment}` matches EVERY IRI in this space. The exact bindings
    // are registered first and the template last, and if that ever inverts,
    // `urn:log:write` becomes a segment named "write" — which fails as "no
    // segment" rather than as an unbound IRI, so nothing else would catch it.
    let dir = Scratch::new("binding-order");
    let handle = file_handle(dir.path(), "info");
    let kernel = kernel(handle);

    let written = futures::executor::block_on(kernel.issue(
        sink_request(WRITE_IRI, &[("msg", "still the writer")]),
        &Capability::root(),
    ))
    .expect("urn:log:write is not a segment named `write`");
    assert!(
        text(&written).starts_with("urn:log:bug:seg:"),
        "{}",
        text(&written)
    );

    assert!(text_of(&source(&kernel, CONFIG_IRI, &[])).contains("destination"));
    assert!(!source(&kernel, SEGMENTS_IRI, &[]).bytes.is_empty());
}

#[test]
fn a_finished_segment_caches_and_a_live_one_does_not() {
    // ★ The trap in this task. Effective expiry PROPAGATES from dependencies, so
    // a live source joined into a cached graph silently un-caches it and NO test
    // fails. The rule is therefore asserted directly rather than trusted.
    let dir = Scratch::new("cacheability");
    let handle = file_handle(dir.path(), "info");
    let (segment, _) = handle.open_segment().expect("a segment is open");
    let kernel = kernel(handle.clone());

    let live = source(&kernel, &segment, &[]);
    assert_eq!(
        live.expiry,
        Expiry::Always,
        "this process is appending to it right now; a cached tail would be a lie \
         about the one fact a reader came for"
    );
    // And the thread is declared anyway — the read did not go through
    // `urn:file:`, but what the kernel needs from it is the dependency.
    assert!(
        live.threads()
            .iter()
            .any(|t| t.as_str().starts_with("urn:file:")),
        "{:?}",
        live.threads()
    );

    // An orderly close writes log:ProcessStop, which is what makes the segment
    // FINISHED — nothing will append to it again.
    handle
        .close(at(1_700_000_009_000))
        .expect("an orderly close");
    let finished = source(&kernel, &segment, &[]);
    assert_eq!(
        finished.expiry,
        Expiry::Never,
        "a rotated segment is immutable, and it is the common case for analysis"
    );
    assert!(finished
        .threads()
        .iter()
        .any(|t| t.as_str().starts_with("urn:file:")));

    // A segment that ends WITHOUT a stop marker ended because the process died,
    // and a dead process's segment is indistinguishable from a running one's —
    // so it stays live rather than being guessed finished.
    let orphan = dir.path().join("bug-orphan-2023-11-14T22-13-20Z.log");
    let mut truncated = std::fs::read_to_string(
        std::fs::read_dir(dir.path())
            .expect("the scratch dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "log"))
            .expect("a segment file"),
    )
    .expect("readable");
    truncated = truncated
        .lines()
        .filter(|l| !l.contains("ProcessStop"))
        .collect::<Vec<_>>()
        .join("\n")
        .replace("urn:log:bug:seg:", "urn:log:bug:orphan:")
        .replace("instance:bug:seg", "instance:bug:orphan");
    std::fs::write(&orphan, format!("{truncated}\n")).expect("writable");
    let orphaned = source(&kernel, "urn:log:bug:orphan:2023-11-14T22-13-20Z", &[]);
    assert_eq!(orphaned.expiry, Expiry::Always);
}

#[test]
fn the_listing_reads_each_file_s_own_name_and_is_never_cached() {
    let dir = Scratch::new("listing");
    let handle = file_handle(dir.path(), "info");
    let (segment, _) = handle.open_segment().expect("a segment is open");
    let kernel = kernel(handle);

    let listing = source(&kernel, SEGMENTS_IRI, &[]);
    assert_eq!(text_of(&listing), format!("{segment}\n"));
    assert_eq!(
        listing.expiry,
        Expiry::Always,
        "the directory changes under rotation and nothing cuts a thread on a \
         directory, so a cached listing would send a chain walk after a segment \
         that is no longer there"
    );

    // The `@name` in the file is the authority; the filename is a convenience.
    // A renamed file is still found, and still found by what it says it is.
    let path = std::fs::read_dir(dir.path())
        .expect("the scratch dir")
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "log"))
        .expect("a segment file");
    std::fs::rename(&path, dir.path().join("renamed-by-an-operator.log")).expect("renamable");
    assert_eq!(
        text_of(&source(&kernel, SEGMENTS_IRI, &[])),
        format!("{segment}\n")
    );
    assert!(text_of(&source(&kernel, &segment, &[])).contains("log:Segment"));
}

#[test]
fn reading_a_segment_without_the_capability_is_refused() {
    let dir = Scratch::new("segment-denied");
    let handle = file_handle(dir.path(), "info");
    let (segment, _) = handle.open_segment().expect("a segment is open");
    let kernel = kernel(handle);

    for iri in [segment.as_str(), SEGMENTS_IRI] {
        let error = futures::executor::block_on(
            kernel.issue(source_request(iri, &[]), &Capability::scoped([CAP_WRITE])),
        )
        .expect_err("segment content is at least as sensitive as the log's whereabouts");
        assert!(matches!(error, Error::Denied(_)), "<{iri}>: {error:?}");
    }

    // Declared == enforced: the manifold says exactly what the body checks.
    let described = SegmentEndpoint::new(
        Arc::new(LogHandle::new(None, None, LogConfig::default())),
        Vocabulary::shared_builtin(),
    )
    .describe();
    let read = described
        .action_specs()
        .into_iter()
        .find(|a| a.verb == Verb::Source)
        .expect("a Source action");
    assert_eq!(read.requires, vec![CAP_READ.to_string()]);
}

#[test]
fn a_segment_is_a_named_graph_to_sparql_because_it_resolves_to_turtle() {
    // ★ THE test. Everything else in this file asserts what this crate does;
    // this asserts what it BUYS — that resolving to Turtle at your own IRI is
    // the entire named-graph story, with no N-Quads, no TriG and no union
    // machinery, because `urn:sparql:*` already loads each `graph=` source
    // "through the kernel and loaded as a named graph (named by its URI)".
    let dir = Scratch::new("named-graph");
    let handle = file_handle(dir.path(), "info");
    let (segment, _) = handle.open_segment().expect("a segment is open");
    handle
        .record_denial(at(1_700_000_002_000), "urn:cap:fs:write", "writing a file")
        .expect("a refused authority lands at every level");

    let space = Fallback::new(vec![
        Arc::new(crate::endpoints::space(handle)) as Arc<dyn Space>,
        Arc::new(ikigai_sparql::space()) as Arc<dyn Space>,
    ]);
    let kernel = Kernel::new(Arc::new(space)).with_clock(Arc::new(Fixed(1_700_000_000_000)));

    let results = source(
        &kernel,
        "urn:sparql:select",
        &[
            (
                "query",
                "SELECT ?g ?e WHERE { GRAPH ?g { ?e a \
                 <https://ikigai-rs.dev/ns/log#CapabilityDenied> } }",
            ),
            ("graph", &segment),
        ],
    );
    let body = text_of(&results);
    assert!(
        body.contains(&segment),
        "the graph is named by the IRI it was dereferenced at: {body}"
    );
    assert!(
        body.contains(&format!("{segment}:2")),
        "and the entry is in it: {body}"
    );

    // Golden threads reach through too, so an analysis result dies when a
    // segment it read changes. Verified, not assumed — this is the "alerting =
    // golden threads" line of the design working through shipped machinery.
    assert!(
        results
            .threads()
            .iter()
            .any(|t| t.as_str().starts_with("urn:file:")),
        "the segment's thread reached the query result: {:?}",
        results.threads()
    );
    // The live segment un-caches the query over it. That is expiry PROPAGATING,
    // and it is correct: a cached answer about a log that is still being written
    // is a stale answer.
    assert_eq!(results.expiry, Expiry::Always);
}
