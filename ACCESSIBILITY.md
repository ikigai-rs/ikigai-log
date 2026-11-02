# Accessibility

What `ikigai-log` emits that people read, the rules that output follows, how it is tested, and
how to report a barrier. It is not a conformance claim. Adapted from the
[ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA, for any page that presents this output; this repository writes text only (no HTML, SVG or color) |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-log/issues/new?labels=accessibility) with the `accessibility` label; anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-log/security/advisories/new) |
| Last reviewed | 2026-11-02 |

## What it emits that people read

This is a library a host uses to write and read its log. People read its files with `grep`,
`tail` and a pager as often as through the kernel.

- **Log segments** (`src/line.rs`, `src/writer.rs`): a header of `@` directives, then one entry
  per line, `<timestamp> <class> <subject> key=value…`, for example
  `2026-08-23T09:14:22.031Z log:Message urn:agent:calendar seq=2 msg="sync started"`, and
  `#seal` lines carrying hashes and, when signed, a signature.
- **The verify report** from `urn:log:verify` (`ChainReport::render` in `src/chain.rs`,
  `text/plain`): one `segment <iri> OK|BROKEN entries=… seals=… level=… prev=… signed=… head=…`
  line per segment, each finding indented under it and prefixed `BROKEN` or `noted`, and a last
  line `verified N segment(s), M broken`. Each finding is a sentence (`Finding`'s `Display`):
  `sequence jumps from 4 to 7: entries were removed (filtering consumes no sequence number)`.
- **Other text answers**: `urn:log:write` answers the new entry's IRI, or says in words why
  nothing was written (`closed: no segment is open, …`, `filtered: … is below this segment's
  level …`); `urn:log:segments` lists
  segment IRIs, one per line; `urn:log:config` answers the effective configuration as TOML; a
  segment or the transreptor answers Turtle.
- **Errors**: the `Display` of `ParseError` (`bad timestamp: …`, `unbound prefix in CURIE: …`),
  `RenderError`, `WriteError`, `ConfigError` and `VocabError`, and the endpoints' refusals.

Not this repository's: how a host or a terminal shows any of this, and the display of core's
error kinds.

## The rules that output follows

Verified by reading the source:

- **One entry is one printable line that reads in its written order.** A newline, carriage
  return or tab inside a value is written as an escape (`\n`, `\r`, `\t`), and every other
  control character (C0, DEL, C1), the line and paragraph separators, and the bidirectional
  formatting characters (U+202A to U+202E, U+2066 to U+2069, U+200E, U+200F, U+061C) as
  `\u{hex}`, so a reader or a screen reader moving line by line meets whole entries, no value
  reaches the screen as a control sequence, and no value reorders the rest of its line. A
  subject, class or principal holding one is refused rather than written.
- **An error is one printable line.** An error or report line that repeats its input (`ParseError`,
  `RenderError`, `GraphError`, `PrincipalError`, `WriteError`, `ConfigError`, `VocabError`, every
  verify finding and the verify report's segment line, and an endpoint's text naming a requested
  segment, a class, a level or a path) shows those same characters escaped the same way, the
  bidirectional formatting characters included, so quoted text cannot reorder the sentence around
  it on screen.
- Timestamps are fixed-width ISO 8601 in UTC with milliseconds and a `Z`.
- The verify report says its outcome in words: `OK` or `BROKEN` per segment, `BROKEN` or `noted`
  per finding, and a total; an unsigned segment says `signed=none` rather than leaving it out.
  A finding names the sequence numbers or segments involved and says what they mean.
- No color, no terminal control sequences and no markup are written into a segment, its own
  or a logged value's.

## How it is tested

- `src/tests.rs`: `one_entry_is_one_line_whatever_the_payload` and
  `prose_with_a_newline_survives_escaped_on_one_line` pin the escapes;
  `timestamps_are_fixed_width_utc_and_round_trip` pins the timestamp;
  `verify_binds_above_the_template_and_reports_through_the_kernel` pins the report's `OK`,
  `BROKEN` and `verified 1 segment(s), 0 broken`; `a_crashed_tail_is_noted_and_not_called_broken`
  pins that a crash is not reported as breaking.
- `tests/control_characters.rs` pins that no written line holds a raw control character or
  bidirectional formatting character, that each escape reads back to the value logged through
  the parser, the verifier and both transreption paths, that a principal holding one is
  refused, and that segments written before either escape still read and verify.
- `tests/error_text.rs` pins that every error quoting its input, every finding, the verify
  report's segment line, the streaming transreptor's errors and the endpoints' answers naming a
  request show each such character, and each bidirectional format character, escaped, and
  printable text as it is.
- `tests/audit_904.rs`: `r8_a_damaged_segment_in_the_directory_is_reported` pins a
  `segment … BROKEN` line for a damaged file.

These test the format for correctness; none was written as an accessibility test.
**No automated accessibility checker, browser or assistive technology has been used on this
output.**

## Known limitations

Found by reading the source on 2026-10-31 and 2026-11-02:

- **Long opaque strings.** `#seal` lines, `@prev`, and the report's `prev=` and `head=` carry
  full SHA-256 digests, and a seal mismatch finding states two; a screen reader reads them
  character by character.
- **Findings are grouped by indentation.** A finding belongs to the segment line above it only
  because it is indented two spaces, which a screen reader usually does not announce; its own
  `BROKEN` or `noted` word survives.
- **Terse columns.** A line is CURIEs and `key=value` pairs (`dur=12` carries no unit on the
  line); what a key means is in `src/vocabulary.ttl`, not in the file a person is reading.
- **A parenthesized plural** ends the verify report (`verified 1 segment(s), 0 broken`), which a
  screen reader reads with the parentheses.
- Times are always UTC; a reader converts to local time themselves.
- Every message is English only.

## Contributing

Read this file before changing any output listed above: the line grammar, the verify report, a
finding's sentence or an error. Keep one entry to one line, keep outcomes as words, and keep
meaning in words. Say in the pull request what was tested, with what, and what was not.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-log/issues/new?labels=accessibility) with
the `accessibility` label (the link sets it when GitHub lets you add labels; otherwise a
maintainer adds it): what you were doing, what happened, and the host, terminal and any
assistive technology you used, if you are comfortable sharing them. Anything security-sensitive
goes through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-log/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.

## Change history

| Date | Change |
|---|---|
| 2026-10-31 | First version. |
| 2026-11-02 | Control characters in values are escaped; the rule and its test are listed. |
| 2026-11-02 | Errors show quoted input escaped, bidirectional format characters included. |
| 2026-11-02 | The verify report, every finding and every error show the names they repeat escaped. |
| 2026-11-02 | Log lines escape bidirectional formatting characters; the limitation row is removed. |
