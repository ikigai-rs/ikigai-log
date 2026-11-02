//! Error and report text show the offending text escaped (ledger #2911, #2913).
//!
//! An error that quotes its input stays one printable line: every character a
//! written line never carries raw (C0, DEL, C1, the line and paragraph
//! separators) is shown as the line writes it, `\n`, `\r`, `\t` or `\u{hex}`,
//! and so are the bidirectional format characters, which would reorder the
//! rest of the sentence on screen. Everything else, a backslash included, is
//! shown as it is.
//!
//! Public API only, so this is what a consumer of the crate can rely on.

use std::collections::BTreeMap;

use std::path::PathBuf;

use ikigai_log::{
    to_triples, verify_chain, ConfigError, Entry, Finding, GraphError, Options, ParseError, Prev,
    Principal, RenderError, SegmentReport, Timestamp, VocabError, Vocabulary, WriteError,
    MESSAGE_CLASS,
};

/// Whether `c` may not appear raw in an error sentence.
fn unprintable(c: char) -> bool {
    c.is_control()
        || c == '\u{2028}'
        || c == '\u{2029}'
        || ('\u{202a}'..='\u{202e}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
}

/// Every character an error must not show raw, one at a time.
fn every_unprintable() -> Vec<char> {
    (0u32..=0x9f)
        .chain([0x2028, 0x2029])
        .chain(0x202a..=0x202e)
        .chain(0x2066..=0x2069)
        .filter_map(char::from_u32)
        .filter(|&c| unprintable(c))
        .collect()
}

fn assert_one_printable_line(message: &str) {
    if let Some(c) = message.chars().find(|&c| unprintable(c)) {
        panic!("raw U+{:04X} in an error message: {message:?}", c as u32);
    }
}

/// How an error shows `c`: the short escape for the three a line abbreviates,
/// `\u{hex}` for the rest.
fn escaped(c: char) -> String {
    match c {
        '\n' => "\\n".to_string(),
        '\r' => "\\r".to_string(),
        '\t' => "\\t".to_string(),
        c => c.escape_unicode().to_string(),
    }
}

#[test]
fn every_parse_and_render_error_shows_its_text_escaped() {
    for c in every_unprintable() {
        let text = format!("urn:x{c}y");
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ParseError::Timestamp(text.clone())),
            Box::new(ParseError::Field(text.clone())),
            Box::new(ParseError::UnboundPrefix(text.clone())),
            Box::new(ParseError::NotAnIri(text.clone())),
            Box::new(ParseError::Header(text.clone())),
            Box::new(ParseError::Seal(text.clone())),
            Box::new(ParseError::Version(text.clone())),
            Box::new(RenderError::NotAnIri(text.clone())),
            Box::new(RenderError::Key(text.clone())),
            Box::new(GraphError::Iri(text.clone())),
        ];
        let want = format!("urn:x{}y", escaped(c));
        for error in errors {
            let message = error.to_string();
            assert_one_printable_line(&message);
            assert!(
                message.ends_with(&want),
                "U+{:04X} shown as {message:?}, not ending {want:?}",
                c as u32
            );
        }
    }
}

#[test]
fn printable_text_and_a_backslash_are_shown_as_they_are() {
    let text = r#"urn:x "quoted" \u{1b} é ü 日本"#;
    assert_eq!(
        ParseError::Field(text.to_string()).to_string(),
        format!("bad key=value column: {text}")
    );
}

#[test]
fn a_refused_subject_is_shown_escaped() {
    let entry = Entry::new(
        Timestamp::from_millis(0),
        MESSAGE_CLASS,
        "urn:agent:x\u{1b}]0;title\u{7}\u{202e}",
    );
    let error = entry
        .render(&BTreeMap::new())
        .expect_err("a control character in the subject is refused");
    assert_eq!(
        error.to_string(),
        "not an absolute IRI: urn:agent:x\\u{1b}]0;title\\u{7}\\u{202e}"
    );
}

#[test]
fn a_line_that_does_not_parse_is_shown_escaped() {
    // An unterminated quote, carrying raw characters a segment written before
    // 0.9.2 can hold.
    let line = "2023-11-14T22:13:20.000Z log:Message urn:s msg=\"red\u{1b}[31m\u{9b}2J";
    let prefixes = BTreeMap::from([(
        "log".to_string(),
        "https://ikigai-rs.dev/ns/log#".to_string(),
    )]);
    let error = Entry::parse(line, &prefixes).expect_err("an unterminated quote");
    let message = error.to_string();
    assert_one_printable_line(&message);
    assert!(message.contains("red\\u{1b}[31m\\u{9b}2J"), "{message}");
}

#[test]
fn a_refused_principal_is_shown_escaped() {
    let error = Principal::new("urn:agent:x\u{1b}[2J").expect_err("not a bare column");
    let message = error.to_string();
    assert_one_printable_line(&message);
    assert!(message.starts_with("urn:agent:x\\u{1b}[2J "), "{message}");
}

/// A segment written before 0.9.2, with a raw control character in its header.
fn old_segment(name: &str) -> String {
    [
        "# ikigai-log v1",
        "@prefix log: <https://ikigai-rs.dev/ns/log#> .",
        &format!("@name {name}"),
        "@instance urn:ikigai:instance:bug:old",
        "@level log:info",
        "@started 2023-11-14T22:13:20.000Z",
        "@prev genesis",
        "",
        "2023-11-14T22:13:20.000Z log:Message urn:s msg=hello",
        "@late\u{1b}[2J directive",
        "",
    ]
    .join("\n")
}

#[test]
fn a_segment_the_graph_face_refuses_is_reported_escaped() {
    let text = old_segment("urn:log:old:x\u{1b}[31m");
    let error = to_triples(&text, Vocabulary::builtin(), &Options::all())
        .expect_err("oxrdf refuses the header IRI");
    let message = error.to_string();
    assert_one_printable_line(&message);
    assert!(message.contains("\\u{1b}"), "{message}");
}

#[test]
fn a_verify_report_shows_a_late_directive_escaped() {
    let text = old_segment("urn:log:old:2023-11-14T22-13-20Z");
    let report = verify_chain(
        &[("urn:log:old:2023-11-14T22-13-20Z".to_string(), text)],
        Vocabulary::builtin(),
    );
    let rendered = report.render();
    for line in rendered.lines() {
        assert_one_printable_line(line);
    }
    assert!(rendered.contains("@late\\u{1b}[2J"), "{rendered}");
}

/// Every finding that names something it read: a segment, a level, a class,
/// a stated hash, a successor.
fn findings_naming(text: &str) -> Vec<Finding> {
    let t = || text.to_string();
    vec![
        Finding::Malformed {
            line: 9,
            detail: t(),
        },
        Finding::SealMismatch {
            first: 1,
            last: 2,
            stated: t(),
            recomputed: t(),
        },
        Finding::PrevMismatch {
            predecessor: t(),
            stated: t(),
            expected: t(),
        },
        Finding::UnexpectedGenesis { predecessor: t() },
        Finding::MissingSuccessor {
            after: t(),
            successor: t(),
        },
        Finding::UnbracketedLevelChange {
            from_segment: t(),
            from: t(),
            to_segment: t(),
            to: t(),
        },
        Finding::UnmarkedEnd {
            last_class: Some(t()),
        },
    ]
}

#[test]
fn every_finding_shows_the_names_it_read_escaped() {
    for c in every_unprintable() {
        let text = format!("urn:x{c}y");
        let want = format!("urn:x{}y", escaped(c));
        for finding in findings_naming(&text) {
            let message = finding.to_string();
            assert_one_printable_line(&message);
            assert!(
                message.contains(&want),
                "U+{:04X} shown as {message:?}, not holding {want:?}",
                c as u32
            );
        }
    }
}

#[test]
fn a_verify_report_shows_every_name_it_read_escaped() {
    for c in every_unprintable() {
        let text = format!("urn:x{c}y");
        let want = format!("urn:x{}y", escaped(c));
        let read = SegmentReport {
            name: text.clone(),
            instance: text.clone(),
            level: text.clone(),
            prev: Prev::Seal(text.clone()),
            head: text.clone(),
            entries: 1,
            seals: 1,
            signed_with: vec![text.clone()],
            successor: None,
            level_changes: Vec::new(),
            findings: findings_naming(&text),
        };
        // No header was read, so the report names it by what the caller called it.
        let unreadable = SegmentReport {
            name: text.clone(),
            instance: String::new(),
            level: String::new(),
            prev: Prev::Genesis,
            head: String::new(),
            entries: 0,
            seals: 0,
            signed_with: Vec::new(),
            successor: None,
            level_changes: Vec::new(),
            findings: Vec::new(),
        };
        let rendered = ikigai_log::ChainReport {
            segments: vec![read, unreadable],
        }
        .render();
        for line in rendered.lines() {
            assert_one_printable_line(line);
        }
        let segment_line = rendered.lines().next().expect("a segment line");
        // name, level, prev, signed and head.
        assert_eq!(
            segment_line.matches(&want).count(),
            5,
            "U+{:04X}: {segment_line:?}",
            c as u32
        );
        assert!(
            rendered.contains(&format!("segment {want} BROKEN unreadable")),
            "U+{:04X}: {rendered:?}",
            c as u32
        );
    }
}

/// A segment as a writer before 0.9.2 could leave it, a raw control character
/// in its name, its level, its `@prev` and the class it ends on.
fn raw_segment(name: &str, level: &str, prev: &str, last_class: &str) -> String {
    [
        "# ikigai-log v1",
        "@prefix log: <https://ikigai-rs.dev/ns/log#> .",
        &format!("@name {name}"),
        "@instance urn:ikigai:instance:bug:old",
        &format!("@level {level}"),
        "@started 2023-11-14T22:13:20.000Z",
        &format!("@prev {prev}"),
        "",
        &format!("2023-11-14T22:13:20.000Z {last_class} urn:s seq=1"),
        "",
    ]
    .join("\n")
}

#[test]
fn verifying_a_segment_with_raw_names_reports_them_escaped() {
    let first = raw_segment(
        "urn:log:old:a\u{1b}[31m",
        "log:info\u{202e}",
        "genesis",
        "<urn:class:x\u{9b}2J>",
    );
    let second = raw_segment(
        "urn:log:old:b\u{7}",
        "log:debug",
        "sha256:\u{1b}]0;t",
        "log:Message",
    );
    let report = verify_chain(
        &[
            ("urn:log:old:a".to_string(), first),
            ("urn:log:old:b".to_string(), second),
        ],
        Vocabulary::builtin(),
    );
    let rendered = report.render();
    for line in rendered.lines() {
        assert_one_printable_line(line);
    }
    for want in [
        "urn:log:old:a\\u{1b}[31m",
        "log#info\\u{202e}",
        "urn:class:x\\u{9b}2J",
        "urn:log:old:b\\u{7}",
        "sha256:\\u{1b}]0;t",
    ] {
        assert!(rendered.contains(want), "{want} not in {rendered}");
    }
}

#[test]
fn every_write_error_shows_the_names_it_read_escaped() {
    for c in every_unprintable() {
        let text = format!("urn:x{c}y");
        let want = format!("urn:x{}y", escaped(c));
        let errors = [
            WriteError::UnknownLevel {
                level: text.clone(),
                known: vec![text.clone()],
            },
            WriteError::InstanceInUse {
                name: text.clone(),
                tried: text.clone(),
            },
            WriteError::SegmentExists(PathBuf::from(&text)),
            WriteError::Io {
                path: Some(PathBuf::from(&text)),
                message: text.clone(),
            },
        ];
        for error in errors {
            let message = error.to_string();
            assert_one_printable_line(&message);
            assert!(
                message.contains(&want),
                "U+{:04X} shown as {message:?}",
                c as u32
            );
        }
    }
}

#[test]
fn every_config_and_vocabulary_error_shows_its_text_escaped() {
    for c in every_unprintable() {
        let text = format!("urn:x{c}y");
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ConfigError::Parse {
                path: Some(PathBuf::from(&text)),
                message: text.clone(),
            }),
            Box::new(ConfigError::BadValue {
                key: "level",
                value: text.clone(),
                expected: "a level".to_string(),
            }),
            Box::new(ConfigError::Unreadable {
                path: PathBuf::from(&text),
                message: text.clone(),
            }),
            Box::new(ConfigError::Unwritable {
                path: PathBuf::from(&text),
                message: text.clone(),
            }),
            Box::new(VocabError(text.clone())),
        ];
        for error in errors {
            let message = error.to_string();
            assert_one_printable_line(&message);
            assert!(
                message.contains(&format!("urn:x{}y", escaped(c)))
                    // A config value is quoted the way Rust quotes a string.
                    || message.contains(&format!("urn:x{}y", c.escape_debug())),
                "U+{:04X} shown as {message:?}",
                c as u32
            );
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn the_streaming_transreptor_shows_a_late_directive_escaped() {
    use std::sync::Arc;

    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, EndpointSpace, Exact, Iri, Kernel, Request, Verb};

    let kernel = Kernel::new(Arc::new(EndpointSpace::new().bind(
        Exact::new(ikigai_log::TRANSREPT_IRI),
        ikigai_log::segments::TransreptEndpoint::new(Vocabulary::shared_builtin()),
    )));
    let text = old_segment("urn:log:old:2023-11-14T22-13-20Z");
    let request = Request::new(Verb::Source, Iri::parse(ikigai_log::TRANSREPT_IRI).unwrap())
        .with_arg("content", ArgRef::Inline(text.into_bytes()));
    let error = block_on(async {
        let answer = kernel.issue_body(request, &Capability::root()).await?;
        answer.collect(1 << 20).await
    })
    .expect_err("a directive after the header block");
    let message = error.to_string();
    assert_one_printable_line(&message);
    assert!(message.contains("@late\\u{1b}[2J"), "{message}");
}

/// A kernel over a log that was never opened, its directory a fresh empty one.
#[cfg(not(target_family = "wasm"))]
fn unopened_log() -> (std::sync::Arc<ikigai_core::Kernel>, PathBuf) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let directory = std::env::temp_dir().join(format!(
        "ikigai-log-error-text-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    let config = ikigai_log::LogConfig::default()
        .with_instance("errors")
        .with_destination(ikigai_log::Destination::File)
        .with_directory(&directory);
    let handle = Arc::new(ikigai_log::LogHandle::new(
        Some(directory.clone()),
        None,
        config,
    ));
    let kernel = Arc::new(
        ikigai_core::Kernel::new(Arc::new(ikigai_log::endpoints::space(handle)))
            .with_clock(Arc::new(Fixed)),
    );
    (kernel, directory)
}

#[cfg(not(target_family = "wasm"))]
struct Fixed;

#[cfg(not(target_family = "wasm"))]
impl ikigai_core::Clock for Fixed {
    fn now(&self) -> ikigai_core::Time {
        ikigai_core::Time::from_millis(1_700_000_000_000)
    }
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn endpoint_answers_show_a_requested_name_escaped() {
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, Iri, Request, Verb};

    // A request IRI may carry a bidirectional format character.
    let (kernel, directory) = unopened_log();
    let missing = Request::new(
        Verb::Source,
        Iri::parse("urn:log:x\u{202e}y:2023-11-14T22-13-20Z").unwrap(),
    );
    let refused = block_on(kernel.issue(missing, &Capability::root()))
        .expect_err("no such segment")
        .to_string();
    let written = Request::new(Verb::Sink, Iri::parse(ikigai_log::WRITE_IRI).unwrap())
        .with_arg(
            "class",
            ArgRef::Inline(b"urn:class:x\xe2\x80\xaey".to_vec()),
        )
        .with_arg("msg", ArgRef::Inline(b"hello".to_vec()));
    let answer = block_on(kernel.issue(written, &Capability::root())).expect("answered");
    let answer = String::from_utf8(answer.bytes).unwrap();
    let _ = std::fs::remove_dir_all(&directory);

    for message in [&refused, &answer] {
        assert_one_printable_line(message);
        assert!(message.contains("x\\u{202e}y"), "{message}");
    }
}
