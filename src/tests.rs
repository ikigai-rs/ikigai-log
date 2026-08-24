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
        "the header carries the chain link explicitly — genesis is WRITTEN, so a \
         missing @prev is unambiguously an error rather than an ambiguous \
         \"maybe first\""
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
    text.push_str("#seal 1-42 sha256:4c1e0d Ed25519:MEUCIQD\n");
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
    // The digest EXACTLY as the line wrote it — tagged, which is the same
    // lexical form ikigai-sign writes on the same predicate, so the two producers
    // join instead of silently never matching.
    assert!(states(
        &triples,
        &seal,
        &format!("{SIG_NS}contentHash"),
        string("sha256:4c1e0d")
    ));
    // The signature column is SPLIT: a line has columns and a graph does not, and
    // a graph that kept the packing would make sig:value mean something different
    // here than in a signature-graph — which is exactly the join being bought.
    assert!(states(
        &triples,
        &seal,
        &format!("{SIG_NS}algorithm"),
        string("Ed25519")
    ));
    assert!(states(
        &triples,
        &seal,
        &format!("{SIG_NS}value"),
        string("MEUCIQD")
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

// =====================================================================================
// The chain, the seal, the rotation, and verify
//
// Four layers, tested as one piece — because a partial chain is worse than none:
// it looks verifiable. Each test below names which layer it is defending, and the
// forged-segment test is the one a naive implementation passes silently.
// =====================================================================================

use crate::chain::{
    head_of, split_signature, verify_chain, verify_segment, Chain, Finding, RotationPolicy,
    SealPolicy, SealSigner,
};
use crate::endpoints::CONFIG_IRI as CONFIG;
use crate::segments::VERIFY_IRI;
use crate::vocabulary::{CHAIN_BROKEN_CLASS, ROTATION_CLASS};

/// A signer that is not cryptography — it is the SEAM. What is asserted is that
/// the seam is reached with the tagged chain hash and that its answer round-trips
/// through the line and into the graph; whether Ed25519 works is `ikigai-sign`'s
/// test, and duplicating it here would test that crate from this one.
struct TestSigner;

impl SealSigner for TestSigner {
    fn algorithm(&self) -> &str {
        "Ed25519"
    }

    fn sign(&self, tagged_hash: &str) -> Option<String> {
        // Deterministic and dependent on the input, so a seal signed over the
        // wrong hash would show up as the wrong token rather than as no token.
        Some(format!("SIG{}", &tagged_hash[tagged_hash.len() - 8..]))
    }
}

/// A file-destination handle over `dir`, at `level`, under `instance`.
fn chained_handle(dir: &Path, instance: &str, level: &str, now: u64) -> Arc<LogHandle> {
    let config = LogConfig::default()
        .with_instance(instance)
        .with_level(level)
        .expect("a real level")
        .with_destination(Destination::File)
        .with_directory(dir);
    let handle = Arc::new(LogHandle::new(Some(dir.to_path_buf()), None, config));
    handle
        .open(Vocabulary::shared_builtin(), at(now))
        .expect("the segment opens");
    handle
}

fn message(now: u64, text: &str) -> Entry {
    Entry::new(at(now), MESSAGE_CLASS, "urn:agent:test").with("msg", text)
}

/// Every segment file in `dir`, as `(IRI, bytes)`, oldest first.
fn segments_on_disk(dir: &Path) -> Vec<(String, String)> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("the scratch dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .collect();
    paths.sort();
    let mut found: Vec<(String, String)> = paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("readable");
            let (header, _) = Header::parse(&text).expect("a segment");
            (header.name, text)
        })
        .collect();
    found.sort_by(|(a, _), (b, _)| a.cmp(b));
    found
}

fn path_of(dir: &Path, segment: &str) -> PathBuf {
    std::fs::read_dir(dir)
        .expect("the scratch dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .find(|p| {
            let text = std::fs::read_to_string(p).unwrap_or_default();
            Header::parse(&text).is_ok_and(|(h, _)| h.name == segment)
        })
        .unwrap_or_else(|| panic!("a file for <{segment}>"))
}

#[test]
fn a_segment_chains_and_seals_and_the_seal_is_the_chain_head() {
    // Layers 1 and 2. The seal is not decoration over the entries: it states the
    // running hash, which is what makes "between seal K and K+1" a range that
    // means something.
    let (mut writer, captured) = writer_at("info");
    writer.write(message(1, "one")).expect("writes");
    writer.write(message(2, "two")).expect("writes");
    let seal = writer
        .seal(at(3))
        .expect("the seal lands")
        .expect("there was something to seal");
    assert_eq!((seal.first, seal.last), (1, 3), "ProcessStart is seq 1");

    let text = captured.text();
    let (header, offset) = Header::parse(&text).expect("a segment");
    let mut recomputed = Chain::open(&header);
    for raw in text[offset..].lines() {
        if let Ok(Line::Entry(_)) = Line::parse(raw, &header.prefixes) {
            recomputed.advance(raw);
        }
    }
    assert_eq!(
        seal.hash,
        recomputed.head(),
        "a reader recomputes exactly what the writer committed — the same two \
         functions, not two implementations of one rule"
    );
    assert!(
        seal.hash.starts_with("sha256:"),
        "tagged at the boundary: {}",
        seal.hash
    );
    assert_eq!(
        seal.signature, None,
        "no signer was installed, and that is a supported posture — an unsigned \
         seal still localizes tampering"
    );
    assert!(
        !text
            .lines()
            .filter(|l| !l.starts_with("#seal"))
            .any(|l| l.contains("sha256:")),
        "NOT a hash per line: that column is exactly the noise that would wreck \
         grep, which is a first-order requirement of this format\n{text}"
    );
}

#[test]
fn the_seal_cadence_fires_on_entries_and_on_time_and_both_are_needed() {
    // The time bound is not optional. N alone leaves a quiet log unsealed for
    // days, and the unsealed tail is precisely what an attacker rewrites for free.
    let captured = Captured::default();
    let mut writer = Writer::open_with_sink_and(
        &config_at("info"),
        Vocabulary::shared_builtin(),
        at(0),
        captured.sink(),
        crate::writer::WriterOptions {
            seals: SealPolicy {
                every_entries: 3,
                every_millis: 10_000,
            },
            rotation: RotationPolicy::manual(),
            prev: None,
            signer: None,
        },
    )
    .expect("the segment opens");

    // Three entries including the ProcessStart: the count bound fires.
    writer.write(message(1, "a")).expect("writes");
    writer.write(message(2, "b")).expect("writes");
    let seals: Vec<Seal> = captured
        .text()
        .lines()
        .filter_map(|l| Seal::parse(l).ok())
        .collect();
    assert_eq!(seals.len(), 1, "3 entries reached the count bound");
    assert_eq!((seals[0].first, seals[0].last), (1, 3));

    // One more entry, far too few for the count bound — but past the time bound.
    writer.write(message(20_000, "c")).expect("writes");
    let seals: Vec<Seal> = captured
        .text()
        .lines()
        .filter_map(|l| Seal::parse(l).ok())
        .collect();
    assert_eq!(
        seals.len(),
        2,
        "the TIME bound sealed a tail the count bound would have left open for \
         as long as the log stayed quiet"
    );
    assert_eq!((seals[1].first, seals[1].last), (4, 4));
}

#[test]
fn a_signer_signs_the_tagged_hash_and_the_token_splits_into_the_graph() {
    let captured = Captured::default();
    let mut writer = Writer::open_with_sink_and(
        &config_at("info"),
        Vocabulary::shared_builtin(),
        at(0),
        captured.sink(),
        crate::writer::WriterOptions {
            seals: SealPolicy::manual(),
            rotation: RotationPolicy::manual(),
            prev: None,
            signer: Some(Box::new(TestSigner)),
        },
    )
    .expect("the segment opens");
    writer.write(message(1, "signed")).expect("writes");
    let seal = writer
        .seal(at(2))
        .expect("seals")
        .expect("something to seal");

    let token = seal.signature.clone().expect("the signer was reached");
    let (algorithm, value) = split_signature(&token).expect("the token is tagged");
    assert_eq!(algorithm, "Ed25519");
    assert_eq!(
        value,
        format!("SIG{}", &seal.hash[seal.hash.len() - 8..]),
        "what was signed is the TAGGED CHAIN HASH — which is what a verifier \
         reconstructs, and what `urn:sign:verify in=<that>` would be handed"
    );

    // And the graph splits it, so a seal's signature joins with a signature-graph
    // written by ikigai-sign rather than meaning something different here.
    let triples = reparse(
        &crate::graph::to_turtle(
            &captured.text(),
            Vocabulary::builtin(),
            &crate::graph::Options::all(),
        )
        .expect("the segment transrepts"),
    );
    let (segment, _) = Header::parse(&captured.text())
        .map(|(h, _)| (h.name, ()))
        .expect("a segment");
    let node = format!("{segment}:seal:1-2");
    assert!(
        states(
            &triples,
            &node,
            "https://ikigai-rs.dev/ns/sign#algorithm",
            string("Ed25519")
        ),
        "sig:algorithm, split out of the line's packed column"
    );
    assert!(
        states(
            &triples,
            &node,
            "https://ikigai-rs.dev/ns/sign#value",
            string(value)
        ),
        "sig:value is the signature ALONE, as it is in a signature-graph"
    );
    assert!(
        states(
            &triples,
            &node,
            "https://ikigai-rs.dev/ns/sign#contentHash",
            string(&seal.hash)
        ),
        "sig:contentHash is tagged at both ends, so the two producers join"
    );
}

#[test]
fn a_tampered_entry_inside_a_sealed_range_fails_and_the_failure_names_the_range() {
    // ★ The localization claim, which IS the product. "This segment is broken" is
    // not an answer; "between sequence 1 and 5 of this segment" is.
    let dir = Scratch::new("tamper");
    let handle = chained_handle(dir.path(), "bug:tamper", "info", 1_700_000_000_000);
    let (segment, _) = handle.open_segment().expect("a segment is open");
    handle.write(message(1_700_000_001_000, "before")).ok();
    handle.write(message(1_700_000_002_000, "middle")).ok();
    handle.write(message(1_700_000_003_000, "after")).ok();
    handle
        .close(at(1_700_000_004_000))
        .expect("an orderly close");

    let path = path_of(dir.path(), &segment);
    let honest = std::fs::read_to_string(&path).expect("readable");
    assert!(
        verify_segment(&honest, Vocabulary::builtin(), None).ok(),
        "the untampered segment verifies"
    );

    // The attacker rewrites one message and leaves everything else alone — the
    // subtlest edit there is, and the one a log's own reader would never notice.
    let tampered = honest.replace(r#"msg=middle"#, r#"msg=innocent"#);
    assert_ne!(tampered, honest, "the tamper actually applied");
    std::fs::write(&path, &tampered).expect("writable");

    let report = verify_segment(&tampered, Vocabulary::builtin(), None);
    assert!(!report.ok(), "a tampered entry does not verify");
    let named = report
        .findings
        .iter()
        .find_map(|f| match f {
            Finding::SealMismatch { first, last, .. } => Some((*first, *last)),
            _ => None,
        })
        .expect("the failure is a seal mismatch");
    assert_eq!(
        named,
        (1, 5),
        "and it NAMES the range: ProcessStart, three messages, ProcessStop"
    );
    assert!(
        report
            .render_findings()
            .contains("between sequence 1 and 5"),
        "the range is in the words, not only in the struct: {}",
        report.render_findings()
    );
}

#[test]
fn a_forged_replacement_segment_fails_because_at_prev_does_not_match() {
    // ★★ LAYER 3, and the test a naive implementation passes silently. Every
    // other check here is satisfied by the forgery — its chain recomputes, its
    // seals agree, its sequences are dense, it ends on a rotation marker. A
    // per-file chain would call it perfect. What it cannot forge is the
    // SUCCESSOR's @prev, which was written before the forgery existed.
    let dir = Scratch::new("forge");
    let handle = chained_handle(dir.path(), "bug:forge", "info", 1_700_000_000_000);
    let (first, _) = handle.open_segment().expect("a segment is open");
    handle.write(message(1_700_000_001_000, "damning")).ok();
    handle.write(message(1_700_000_002_000, "ordinary")).ok();
    handle
        .rotate(at(1_700_000_060_000))
        .expect("the rotation completes")
        .expect("a file destination rotates");
    handle.write(message(1_700_000_061_000, "later")).ok();
    handle
        .close(at(1_700_000_062_000))
        .expect("an orderly close");

    let on_disk = segments_on_disk(dir.path());
    assert_eq!(on_disk.len(), 2, "one rotation makes two segments");
    assert!(
        verify_chain(&on_disk, Vocabulary::builtin()).ok(),
        "the honest chain verifies:\n{}",
        verify_chain(&on_disk, Vocabulary::builtin()).render()
    );

    // The forgery: the damning entry is gone, and everything a per-file check
    // could look at has been made consistent again.
    let path = path_of(dir.path(), &first);
    let honest = std::fs::read_to_string(&path).expect("readable");
    let forged = forge_without(&honest, "damning");
    std::fs::write(&path, &forged).expect("writable");

    assert!(
        verify_segment(&forged, Vocabulary::builtin(), None).ok(),
        "the forgery is INTERNALLY perfect — this is the point of the test:\n{}",
        verify_segment(&forged, Vocabulary::builtin(), None).render_findings()
    );
    assert!(
        !forged.contains("damning"),
        "and the entry is genuinely gone"
    );

    let report = verify_chain(&segments_on_disk(dir.path()), Vocabulary::builtin());
    assert!(
        !report.ok(),
        "★ the chain spans the rotation, so the forgery is caught:\n{}",
        report.render()
    );
    let successor = report
        .segments
        .iter()
        .find(|s| s.name != first)
        .expect("the successor is in the report");
    assert!(
        successor
            .findings
            .iter()
            .any(|f| matches!(f, Finding::PrevMismatch { .. })),
        "and it is caught at the SEAM — @prev, and nowhere a per-file chain \
         would look: {:?}",
        successor.findings
    );
}

/// Rebuild a segment without the entries matching `drop`, as a competent forger
/// would: sequences renumbered densely, every seal recomputed over the surviving
/// chain, header untouched.
///
/// In the tests rather than in the crate, obviously — but written from the crate's
/// OWN primitives, because a forgery built by a weaker method would prove nothing
/// about what the verifier catches.
fn forge_without(text: &str, drop: &str) -> String {
    let (header, offset) = Header::parse(text).expect("a segment");
    let mut out = header.render().expect("the header renders");
    let mut chain = Chain::open(&header);
    let mut seq = 0u64;
    let mut sealed = 0u64;
    for raw in text[offset..].lines() {
        match Line::parse(raw, &header.prefixes) {
            Ok(Line::Entry(entry)) => {
                if raw.contains(drop) {
                    continue;
                }
                seq += 1;
                let mut fields = vec![("seq".to_string(), seq.to_string())];
                fields.extend(
                    entry
                        .fields
                        .iter()
                        .filter(|(k, _)| k != "seq")
                        .cloned()
                        .collect::<Vec<_>>(),
                );
                let line = Entry {
                    time: entry.time,
                    class: entry.class,
                    subject: entry.subject,
                    fields,
                }
                .render(&header.prefixes)
                .expect("renders");
                chain.advance(&line);
                out.push_str(&line);
                out.push('\n');
            }
            Ok(Line::Seal(_)) if seq > sealed => {
                out.push_str(
                    &Seal {
                        first: sealed + 1,
                        last: seq,
                        hash: chain.head().to_string(),
                        signature: None,
                    }
                    .render(),
                );
                out.push('\n');
                sealed = seq;
            }
            _ => {}
        }
    }
    out
}

#[test]
fn a_rotation_that_cannot_verify_its_predecessor_lands_chain_broken_and_does_not_panic() {
    // Layer 4. The failure belongs in the record it is a failure of — an entry,
    // not an exception, because an exception would be caught by whatever was
    // rotating and the fact would leave no trace at all.
    let dir = Scratch::new("broken");
    let handle = chained_handle(dir.path(), "bug:broken", "info", 1_700_000_000_000);
    let (first, _) = handle.open_segment().expect("a segment is open");
    handle.write(message(1_700_000_001_000, "one")).ok();
    handle
        .rotate(at(1_700_000_060_000))
        .expect("the first rotation completes")
        .expect("a file destination rotates");

    // Tamper the now-sealed first segment while the process runs on. This is the
    // realistic attack: nobody edits a file the writer holds open.
    let path = path_of(dir.path(), &first);
    let text = std::fs::read_to_string(&path).expect("readable");
    std::fs::write(&path, text.replace("msg=one", "msg=two")).expect("writable");

    handle.write(message(1_700_000_061_000, "second")).ok();
    let third = handle
        .rotate(at(1_700_000_120_000))
        .expect("the rotation completes rather than throwing")
        .expect("a file destination rotates");

    let opened = std::fs::read_to_string(path_of(dir.path(), &third)).expect("readable");
    assert!(
        opened.contains("log:ChainBroken"),
        "the rotation recorded what it found, in the log:\n{opened}"
    );
    assert!(
        opened.contains(&first),
        "and it names the segment that failed, not merely that something did"
    );
    assert!(
        opened.contains("finding="),
        "with what was wrong, in the words verify uses:\n{opened}"
    );

    // Not fatal, and that is deliberate: a rotation that refused to complete
    // because a predecessor was tampered with would stop the log, which is
    // exactly what a tamperer wants.
    assert!(handle.is_open(), "the log kept logging");
    handle.close(at(1_700_000_121_000)).expect("closes");
}

#[test]
fn the_chain_survives_a_restart_and_a_different_instance_starts_its_own() {
    // The chain spans process RESTARTS as well as rotations: a writer opening on
    // a file destination reads the newest segment of its own instance and chains
    // from its head. Per INSTANCE, because the instance is the attribution key.
    let dir = Scratch::new("restart");
    let first = chained_handle(dir.path(), "bug:restart", "info", 1_700_000_000_000);
    let (first_segment, _) = first.open_segment().expect("open");
    first.write(message(1_700_000_001_000, "run one")).ok();
    first.close(at(1_700_000_002_000)).expect("closes");
    let head = head_of(&std::fs::read_to_string(path_of(dir.path(), &first_segment)).unwrap())
        .expect("a chain head");

    let second = chained_handle(dir.path(), "bug:restart", "info", 1_700_000_060_000);
    let (second_segment, _) = second.open_segment().expect("open");
    second.close(at(1_700_000_061_000)).expect("closes");
    let (header, _) = Header::parse(
        &std::fs::read_to_string(path_of(dir.path(), &second_segment)).expect("readable"),
    )
    .expect("a segment");
    assert_eq!(
        header.prev,
        Prev::Seal(head),
        "a new PROCESS continues the chain — @prev names the predecessor's final \
         seal, so a segment cannot be dropped between two runs either"
    );

    // A different instance is a different chain, and starts at genesis. That is
    // the right reading rather than a limitation: it is a different process, and
    // it never claimed to continue anyone.
    let other = chained_handle(dir.path(), "bug:other", "info", 1_700_000_120_000);
    let (other_segment, _) = other.open_segment().expect("open");
    other.close(at(1_700_000_121_000)).expect("closes");
    let (header, _) = Header::parse(
        &std::fs::read_to_string(path_of(dir.path(), &other_segment)).expect("readable"),
    )
    .expect("a segment");
    assert_eq!(header.prev, Prev::Genesis);
}

#[test]
fn a_bracketed_gap_verifies_and_an_unexplained_one_does_not() {
    // ★ THE omission check, and the reason verify is not just a hash walk. A hash
    // chain is tamper-evident and NOT omission-evident: it proves nothing was
    // ALTERED and cannot prove nothing was LEFT OUT. Lowering the level is
    // sanctioned omission, and the chain would bless the hole as perfectly intact.
    for bracketed in [true, false] {
        let dir = Scratch::new(if bracketed {
            "bracketed"
        } else {
            "unexplained"
        });
        let handle = chained_handle(dir.path(), "bug:level", "debug", 1_700_000_000_000);
        handle.write(message(1_700_000_001_000, "at debug")).ok();
        if bracketed {
            // What a `urn:log:config` write lands: always-land, in the segment
            // that was open when the change was made, effective at the next one.
            handle
                .write(
                    Entry::new(at(1_700_000_002_000), LEVEL_CHANGE_CLASS, CONFIG)
                        .with("key", "level")
                        .with("from", "https://ikigai-rs.dev/ns/log#debug")
                        .with("to", "https://ikigai-rs.dev/ns/log#info")
                        .with("effective", "next-segment"),
                )
                .expect("an always-land entry lands at every level");
        }
        handle.set_config(
            handle
                .config()
                .with_level("info")
                .expect("a level the vocabulary defines"),
        );
        handle
            .rotate(at(1_700_000_060_000))
            .expect("rotates")
            .expect("a file destination rotates");
        handle.close(at(1_700_000_061_000)).expect("closes");

        let report = verify_chain(&segments_on_disk(dir.path()), Vocabulary::builtin());
        let unbracketed = report.segments.iter().any(|s| {
            s.findings
                .iter()
                .any(|f| matches!(f, Finding::UnbracketedLevelChange { .. }))
        });
        if bracketed {
            assert!(
                report.ok() && !unbracketed,
                "a level change that left a marker is EXPLAINED absence:\n{}",
                report.render()
            );
        } else {
            assert!(
                unbracketed && !report.ok(),
                "★ the level dropped from debug to info and nothing recorded it — \
                 the hashes all agree, and that is exactly the point:\n{}",
                report.render()
            );
        }
    }
}

#[test]
fn a_removed_entry_is_caught_by_the_sequence_even_where_a_level_would_not_explain_it() {
    // Emission advances the counter only for entries actually WRITTEN, so a
    // level-filtered entry consumes no sequence number. That is what makes a jump
    // mean "removed" rather than "filtered", and it is why the check is worth
    // making at all.
    let (mut writer, captured) = writer_at("info");
    writer.write(message(1, "kept")).expect("writes");
    writer
        .write(Entry::new(at(2), log("Resolution"), "urn:x"))
        .expect("filtered at info");
    writer.write(message(3, "also kept")).expect("writes");
    let text = captured.text();
    assert!(
        text.contains("seq=2") && text.contains("seq=3") && !text.contains("Resolution"),
        "the filtered entry consumed no sequence number:\n{text}"
    );

    let gutted = text
        .lines()
        .filter(|l| !l.contains("msg=kept"))
        .collect::<Vec<_>>()
        .join("\n");
    let report = verify_segment(&format!("{gutted}\n"), Vocabulary::builtin(), None);
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, Finding::SequenceGap { after: 1, next: 3 })),
        "{:?}",
        report.findings
    );
}

#[test]
fn a_crashed_tail_is_noted_and_not_called_broken() {
    // The split that decides whether anyone reads this verifier. A daemon that
    // was killed leaves an unmarked end on every restart, and a tool that called
    // that BROKEN would train its operator to disregard the word.
    let (mut writer, captured) = writer_at("info");
    writer
        .write(message(1, "and then nothing"))
        .expect("writes");
    let report = verify_segment(&captured.text(), Vocabulary::builtin(), None);
    assert!(
        report.ok(),
        "a crash is not tampering:\n{}",
        report.render_findings()
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, Finding::UnmarkedEnd { .. })),
        "but it is REPORTED — silence about it would be the other failure: {:?}",
        report.findings
    );
    assert!(report
        .findings
        .iter()
        .any(|f| matches!(f, Finding::UnsealedTail { from: 1, to: 2 })));
}

#[test]
fn a_rotated_segment_is_finished_and_therefore_cacheable() {
    // ★★ THE cacheability trap, and the single highest-value line in this
    // milestone. `is_finished` keyed on log:ProcessStop ALONE leaves every
    // ROTATED segment — the common case for analysis, since a daemon writes one
    // stop marker in its life and a rotation every day — permanently uncacheable,
    // at 196 ms live versus 40 µs cached, ~4,900×, with NO test failing either
    // way, because expiry is not something an assertion about the graph can see.
    let dir = Scratch::new("rotated-cacheable");
    let handle = chained_handle(dir.path(), "bug:rot", "info", 1_700_000_000_000);
    let (first, _) = handle.open_segment().expect("a segment is open");
    handle.write(message(1_700_000_001_000, "before")).ok();
    let second = handle
        .rotate(at(1_700_000_060_000))
        .expect("rotates")
        .expect("a file destination rotates");
    assert_ne!(first, second, "a rotation opens a new segment");

    let kernel = kernel(handle.clone());
    let rotated = source(&kernel, &first, &[]);
    assert_eq!(
        rotated.expiry,
        Expiry::Never,
        "a ROTATED segment is as immutable as a stopped one, and nothing will \
         ever append to it again"
    );
    assert!(rotated
        .threads()
        .iter()
        .any(|t| t.as_str().starts_with("urn:file:")));

    // The successor is live, and stays uncached — this process is appending to it.
    assert_eq!(source(&kernel, &second, &[]).expiry, Expiry::Always);

    // And the rotation marker is the LAST entry, which is what `is_finished`
    // reads: a rotation is followed by its final seal and nothing else.
    let text = std::fs::read_to_string(path_of(dir.path(), &first)).expect("readable");
    let last_entry = text
        .lines()
        .rfind(|l| Line::parse(l, &prefixes()).is_ok_and(|l| matches!(l, Line::Entry(_))))
        .expect("entries");
    assert!(last_entry.contains("log:Rotation"), "{text}");
    assert!(
        text.lines().last().is_some_and(|l| l.starts_with("#seal")),
        "and the seal covers it — a rotation marker outside every checkpoint \
         would be the one entry removable for free:\n{text}"
    );
    handle.close(at(1_700_000_120_000)).expect("closes");
}

#[test]
fn the_rotation_marker_names_its_successor() {
    let dir = Scratch::new("successor");
    let handle = chained_handle(dir.path(), "bug:next", "info", 1_700_000_000_000);
    let (first, _) = handle.open_segment().expect("open");
    let second = handle
        .rotate(at(1_700_000_060_000))
        .expect("rotates")
        .expect("rotates");
    let text = std::fs::read_to_string(path_of(dir.path(), &first)).expect("readable");
    assert!(
        text.contains(&format!("next={second}")),
        "the successor's IRI is derivable at the moment of rotation, which is the \
         only reason it can be named before the segment exists:\n{text}"
    );
    handle.close(at(1_700_000_061_000)).expect("closes");

    // And it transrepts as an edge, not as a string — log:successor's range is
    // log:Segment, so the forward link joins.
    let triples = reparse(
        &crate::graph::to_turtle(&text, Vocabulary::builtin(), &crate::graph::Options::all())
            .expect("transrepts"),
    );
    assert!(
        objects(
            &triples,
            &format!("{first}:2"),
            "https://ikigai-rs.dev/ns/log#successor"
        )
        .contains(&&node(&second)),
        "log:successor is an IRI"
    );
}

#[test]
fn a_rotation_policy_rolls_the_segment_over_without_being_asked() {
    let dir = Scratch::new("auto-rotate");
    let config = LogConfig::default()
        .with_instance("bug:auto")
        .with_level("info")
        .expect("a real level")
        .with_destination(Destination::File)
        .with_directory(dir.path());
    let handle = Arc::new(LogHandle::new(Some(dir.path().to_path_buf()), None, config));
    handle.set_policies(
        SealPolicy::default(),
        RotationPolicy {
            max_entries: Some(3),
            max_age_millis: None,
        },
    );
    handle
        .open(Vocabulary::shared_builtin(), at(1_700_000_000_000))
        .expect("opens");

    // ProcessStart is seq 1; two more reaches the bound and rolls over.
    handle
        .write(message(1_700_000_001_000, "a"))
        .expect("writes");
    handle
        .write(message(1_700_000_002_000, "b"))
        .expect("writes");
    assert_eq!(
        segments_on_disk(dir.path()).len(),
        2,
        "the segment rolled over on its own — a log has no tick of its own, so \
         the write is the only moment there is to judge the policy at"
    );
    handle.close(at(1_700_000_003_000)).expect("closes");
    let report = verify_chain(&segments_on_disk(dir.path()), Vocabulary::builtin());
    assert!(
        report.ok(),
        "and the chain is intact across it:\n{}",
        report.render()
    );
}

#[test]
fn verify_binds_above_the_template_and_reports_through_the_kernel() {
    // ★ `urn:log:{segment}` is a template that matches EVERY urn:log: IRI. Bound
    // below it, `urn:log:verify` resolves as a segment named `verify` and the
    // failure is "no segment <urn:log:verify>" — an error that says nothing about
    // what actually went wrong, so nothing but this test would catch it.
    let dir = Scratch::new("verify-endpoint");
    let handle = chained_handle(dir.path(), "bug:vrfy", "info", 1_700_000_000_000);
    let (segment, _) = handle.open_segment().expect("open");
    handle.write(message(1_700_000_001_000, "one")).ok();
    handle.close(at(1_700_000_002_000)).expect("closes");

    let kernel = kernel(handle);
    let body = text_of(&source(&kernel, VERIFY_IRI, &[]));
    assert!(
        !body.contains("no segment"),
        "resolved as the verifier, not as a segment named `verify`: {body}"
    );
    assert!(
        body.contains(&format!("segment {segment} OK")),
        "one greppable line per segment: {body}"
    );
    assert!(body.contains("verified 1 segment(s), 0 broken"), "{body}");

    // The piped face verifies a blob in isolation — everything except the link,
    // because a segment arriving over a wire has no predecessor to check against.
    let honest = std::fs::read_to_string(path_of(dir.path(), &segment)).expect("readable");
    let piped = text_of(&source(&kernel, VERIFY_IRI, &[("content", &honest)]));
    assert!(piped.contains("OK"), "{piped}");
    let tampered = honest.replace("msg=one", "msg=two");
    let piped = text_of(&source(&kernel, VERIFY_IRI, &[("content", &tampered)]));
    assert!(piped.contains("BROKEN"), "{piped}");
}

#[test]
fn verifying_without_the_capability_is_refused() {
    let dir = Scratch::new("verify-cap");
    let handle = chained_handle(dir.path(), "bug:cap", "info", 1_700_000_000_000);
    let described =
        crate::segments::VerifyEndpoint::new(handle, Vocabulary::shared_builtin()).describe();
    let read = described
        .action_specs()
        .into_iter()
        .find(|a| a.verb == Verb::Source)
        .expect("a Source action");
    assert_eq!(
        read.requires,
        vec![CAP_READ.to_string()],
        "declared = enforced: a verdict about the log is at least as sensitive as \
         the log"
    );
}

#[test]
fn the_always_land_classes_the_chain_depends_on_are_all_declared() {
    // Every legitimate source of absence must leave a marker, and rotation and
    // chain breaks are two of them. Asserted because the emission rule is
    // arithmetic over the vocabulary — a class that lost its log:always would go
    // quiet at `error` and nothing else would say so.
    let vocab = Vocabulary::builtin();
    for class in [ROTATION_CLASS, CHAIN_BROKEN_CLASS] {
        assert!(
            vocab.emits(class, rank(vocab, "error")),
            "{class} lands whatever the dial says"
        );
    }
    assert_eq!(
        vocab.key("next").map(|k| k.property.as_str()),
        Some("https://ikigai-rs.dev/ns/log#successor")
    );
    assert_eq!(
        vocab.key("next").and_then(|k| k.range.clone()),
        Some("https://ikigai-rs.dev/ns/log#Segment".to_string()),
        "the forward link is an EDGE, so it joins"
    );
}

/// The measurement behind [`a_rotated_segment_is_finished_and_therefore_cacheable`]
/// and behind the ★ note in [`crate::segments`], kept so the number can be
/// re-derived rather than believed.
///
/// `#[ignore]`d because it is a measurement and not an assertion: a timing
/// threshold in CI is a flake generator, and the thing worth asserting — that a
/// rotated segment is `Expiry::Never` — is asserted in the test above, where it
/// cannot be flaky. Run it with
/// `cargo test measure_rotated -- --ignored --nocapture`.
///
/// Debug build, so read the RATIO and not the absolute numbers. Measured
/// 2026-08-23 over a 585 KB / 5,002-entry rotated segment: **133 ms** to
/// transrept, which is what an uncached read pays EVERY time, against **29 µs**
/// served from cache — ~4,600×, matching T3's ~4,900× on a comparable segment.
#[test]
#[ignore = "measurement, not an assertion — see the doc comment"]
fn measure_rotated_segment_read_either_side_of_the_is_finished_fix() {
    let dir = Scratch::new("measure");
    let handle = chained_handle(dir.path(), "bug:measure", "info", 1_700_000_000_000);
    let (first, _) = handle.open_segment().expect("open");
    for i in 0..5_000u64 {
        handle
            .write(message(
                1_700_000_000_000 + i,
                "a representative line of prose about a resolution",
            ))
            .expect("writes");
    }
    let second = handle
        .rotate(at(1_700_001_000_000))
        .expect("rotates")
        .expect("rotates");
    let path = path_of(dir.path(), &first);
    let bytes = std::fs::metadata(&path).unwrap().len();
    let text = std::fs::read_to_string(&path).unwrap();
    let entries = text.lines().filter(|l| l.starts_with("20")).count();
    println!("segment: {bytes} bytes, {entries} entries, successor {second}");

    let kernel = kernel(handle.clone());

    // BEFORE the fix: `is_finished` keyed on log:ProcessStop alone, so a ROTATED
    // segment read as live and EVERY read re-transrepted it. That per-read cost
    // is exactly `to_turtle` over the whole segment — the same work the cold
    // read below does once and then never again.
    let start = std::time::Instant::now();
    let turtle =
        crate::graph::to_turtle(&text, Vocabulary::builtin(), &crate::graph::Options::all())
            .expect("transrepts");
    let live = start.elapsed();
    println!(
        "BEFORE (uncached, every read): {live:?} -> {} bytes",
        turtle.len()
    );

    // AFTER: the rotation marker ends the segment, so it is cacheable.
    let first_read = std::time::Instant::now();
    let cold = source(&kernel, &first, &[]);
    let cold_time = first_read.elapsed();
    // Best of ten: the first cached read pays allocation the later ones do not,
    // and what is being measured is the steady state a query hits.
    let mut warm_time = std::time::Duration::MAX;
    let mut warm = cold.clone();
    for _ in 0..10 {
        let read = std::time::Instant::now();
        warm = source(&kernel, &first, &[]);
        warm_time = warm_time.min(read.elapsed());
    }
    println!("AFTER  (cold): {cold_time:?}  expiry={:?}", cold.expiry);
    println!("AFTER  (cached): {warm_time:?}  expiry={:?}", warm.expiry);
    println!(
        "ratio: {:.0}x",
        live.as_secs_f64() / warm_time.as_secs_f64()
    );
    handle.close(at(1_700_002_000_000)).expect("closes");
}

#[test]
fn exists_answers_a_chain_walk_without_reading_a_segment() {
    let dir = Scratch::new("exists");
    let handle = chained_handle(dir.path(), "bug:exists", "info", 1_700_000_000_000);
    let (segment, _) = handle.open_segment().expect("open");
    let kernel = kernel(handle.clone());

    let found = futures::executor::block_on(kernel.issue(
        Request::new(Verb::Exists, Iri::parse(&segment).expect("a valid IRI")),
        &Capability::root(),
    ))
    .expect("Exists resolves");
    assert_eq!(text_of(&found), "true");
    assert!(
        found
            .threads()
            .iter()
            .any(|t| t.as_str().starts_with("urn:file:")),
        "a found segment declares its file's thread, so a caller caching \
         downstream of this is not caching a stale yes"
    );

    let absent = futures::executor::block_on(kernel.issue(
        Request::new(
            Verb::Exists,
            Iri::parse("urn:log:bug:exists:1999-01-01T00-00-00Z").expect("a valid IRI"),
        ),
        &Capability::root(),
    ))
    .expect("Exists resolves for an absent segment too");
    assert_eq!(
        text_of(&absent),
        "false",
        "an absent segment is an ANSWER, not an error: following a @prev into a \
         segment retention removed should say so"
    );
    handle.close(at(1_700_000_001_000)).expect("closes");
}

#[test]
fn deleting_the_newest_segment_is_caught_by_the_rotation_marker() {
    // The hole @prev cannot close. @prev catches a segment removed from the
    // MIDDLE — the one after it still points at what should have been there. But
    // nothing points forward at the LAST segment, so truncating the chain at its
    // head would be free, and the head is the recent past: the part worth
    // erasing. The rotation marker's `next=` is the forward link that notices.
    let dir = Scratch::new("truncate");
    let handle = chained_handle(dir.path(), "bug:trunc", "info", 1_700_000_000_000);
    let (first, _) = handle.open_segment().expect("open");
    let second = handle
        .rotate(at(1_700_000_060_000))
        .expect("rotates")
        .expect("rotates");
    handle.write(message(1_700_000_061_000, "recent")).ok();
    handle.close(at(1_700_000_062_000)).expect("closes");
    assert!(
        verify_chain(&segments_on_disk(dir.path()), Vocabulary::builtin()).ok(),
        "the intact chain verifies"
    );

    std::fs::remove_file(path_of(dir.path(), &second)).expect("the attacker deletes it");
    let report = verify_chain(&segments_on_disk(dir.path()), Vocabulary::builtin());
    assert!(!report.ok(), "{}", report.render());
    assert!(
        report.segments.iter().any(|s| s.findings.iter().any(|f| {
            matches!(f, Finding::MissingSuccessor { after, successor }
                if after == &first && successor == &second)
        })),
        "and it names both ends of the cut:\n{}",
        report.render()
    );
}
