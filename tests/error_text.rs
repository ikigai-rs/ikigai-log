//! Error messages show the offending text escaped (ledger #2911).
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

use ikigai_log::{
    to_triples, verify_chain, Entry, GraphError, Options, ParseError, Principal, RenderError,
    Timestamp, Vocabulary, MESSAGE_CLASS,
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
