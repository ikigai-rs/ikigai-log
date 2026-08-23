//! Tests for the grammar and the vocabulary.
//!
//! Two claims carry most of the weight and are tested directly: that the term
//! table is DATA (an extension adds classes and keys with no code change), and
//! that one entry is one line (nothing rendered can contain a raw newline).

use std::collections::BTreeMap;

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
    let structural = [log("Segment"), log("Instance"), log("Level")];
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
