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
| Last reviewed | 2026-11-12 |

## What it emits that people read

This is a library a host uses to write and read its log. People read its files with `grep`,
`tail` and a pager as often as through the kernel.

- **Log segments** (`src/line.rs`, `src/writer.rs`): a header of `@` directives, then one entry
  per line, `<timestamp> <class> <subject> key=value…`, for example
  `2026-08-23T09:14:22.031Z log:Message urn:agent:calendar seq=2 msg="sync started"`, and
  `#seal` lines carrying hashes and, when signed, a signature.
- **Door lines** (`src/access.rs`): one `log:Access` entry per request a host's door served,
  `… log:Access <subject> door=… verb=… outcome=… bytes=… dur=… principal=… credential=… grant=… q=…`.
  Its subject and free-text columns are percent-encoded to ASCII, so they hold no control or
  bidirectional formatting character at all, and a column cut at `MAX_FIELD` ends with `…`.
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
  `RenderError`, `WriteError`, `ConfigError`, `VocabError` and `AccessError`, and the endpoints'
  refusals.

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
  `RenderError`, `GraphError`, `PrincipalError`, `AccessError`, `WriteError`, `ConfigError`,
  `VocabError`, every verify finding and the verify report's segment line, and an endpoint's text
  naming a requested segment, a class, a level or a path) shows those same characters escaped the
  same way, the bidirectional formatting characters included, so quoted text cannot reorder the
  sentence around it on screen.
- Timestamps are fixed-width ISO 8601 in UTC with milliseconds and a `Z`.
- The verify report says its outcome in words: `OK` or `BROKEN` per segment, `BROKEN` or `noted`
  per finding, and a total; an unsigned segment says `signed=none` rather than leaving it out.
  A finding names the sequence numbers or segments involved and says what they mean.
- No color, no terminal control sequences and no markup are written into a segment, its own
  or a logged value's.

## How it is tested

Every named check has a result: Pass, Fail or Blocked, with evidence. Pass means only
that the stated check passed, not that this output or a host presenting it is accessible.
Fail means a check found a barrier; Blocked means the check has not been completed.

All Pass rows below were run with `cargo test` on 2026-11-12 against main commit
[`528d8d7`](https://github.com/ikigai-rs/ikigai-log/commit/528d8d75a7764b5549153ea086d5569083ed2909),
using Cargo 1.99.1 and rustc 1.99.1 on macOS. The command runs the unit, integration and
documentation tests, including every test named below. CI repeats these format tests through
[the Rust workflow](.github/workflows/ci.yml); it does not run the manual or assistive
technology checks. These are format-correctness tests, not an accessibility evaluation.
They do not establish usability, pronunciation, reading order in a host, or WCAG conformance.

| Check | Result | Evidence |
|---|---|---|
| One entry stays on one printable line | Pass | `src/tests.rs`: `one_entry_is_one_line_whatever_the_payload` and `prose_with_a_newline_survives_escaped_on_one_line`, run by `cargo test` with the tools and date above. Checks escaped payloads, not how a terminal presents them. |
| Fixed-width UTC timestamps | Pass | `src/tests.rs`: `timestamps_are_fixed_width_utc_and_round_trip`, run by `cargo test` with the tools and date above. Checks timestamp text and round trips, not local-time comprehension. |
| Verify outcomes expressed in words | Pass | `src/tests.rs`: `verify_binds_above_the_template_and_reports_through_the_kernel` checks `OK`, `BROKEN` and `verified 1 segment(s), 0 broken`; `a_crashed_tail_is_noted_and_not_called_broken` checks nonbreaking crash findings. Run by `cargo test` with the tools and date above; no screen reader announcement check. |
| Control and bidirectional formatting characters in log output | Pass | `tests/control_characters.rs`, run by `cargo test` with the tools and date above. Checks escaping, rejection in IRI columns and principals, parser/verifier/transreptor round trips and older-segment compatibility; no terminal or assistive technology session. |
| Door-line encoding, columns and truncation marker | Pass | `tests/access.rs`, run by `cargo test` with the tools and date above. Checks Turtle round trips, anonymous caller fields, the `…` cut marker and escaped `AccessError` text; does not test whether people understand the columns. |
| Quoted input in errors, findings and endpoint answers | Pass | `tests/error_text.rs`, run by `cargo test` with the tools and date above. Checks control/bidirectional character escaping and unchanged printable text, including streaming errors and report segment names; does not evaluate error comprehension. |
| Timestamp bounds and payload round trips | Pass | `tests/audit_3436.rs`: `out_of_format_timestamps_are_refused_before_writing` and `timestamp_endpoints_and_payloads_survive_lines_and_turtle`, run by `cargo test` with the tools and date above. Checks printable rejection beyond year 9999 and supported timestamp/payload round trips; no assistive technology check. |
| Damaged-file report | Pass | `tests/audit_904.rs`: `r8_a_damaged_segment_in_the_directory_is_reported`, run by `cargo test` with the tools and date above. Checks a `segment … BROKEN` line for a damaged file, not its presentation by a host. |
| Automated accessibility checker | Blocked | No automated accessibility checker has been run on this output. No host page or browser checker is configured in this library repository; format tests do not substitute for one. |
| Browser presentation, zoom, reflow and contrast | Blocked | No browser has been used to evaluate this output. This library emits text; a host presentation and browser session were not available for this review. |
| Manual keyboard navigation | Blocked | No person has performed a keyboard pass on a host presenting this output; no interactive host session was available for this review. |
| Screen reader | Blocked | No screen reader has been used on this output; no screen reader session was available for this review. |
| Screen magnifier | Blocked | No screen magnifier has been used on this output; no magnifier session was available for this review. |
| Speech input | Blocked | No speech-input software has been used on this output; no speech-input session was available for this review. |
| Switch access | Blocked | No switch-access software has been used on this output; no switch-access session was available for this review. |
| Braille display | Blocked | No braille display has been used on this output; no braille display was available for this review. |

## Known limitations

Recorded from source review on 2026-10-31 and 2026-11-02, not assistive technology
testing. The user impacts below remain unevaluated:

- **Long opaque strings.** `#seal` lines, `@prev`, and the report's `prev=` and `head=` carry
  full SHA-256 digests, and a seal mismatch finding states two; a screen reader may read them
  as a long sequence of characters, depending on its settings.
- **Findings are grouped by indentation.** A finding belongs to the segment line above it only
  because it is indented two spaces, whose announcement depends on the screen reader and its
  settings; its own `BROKEN` or `noted` word survives.
- **Terse columns.** A line is CURIEs and `key=value` pairs (`dur=12` carries no unit on the
  line); what a key means is in `src/vocabulary.ttl`, not in the file a person is reading.
- **A parenthesized plural** ends the verify report (`verified 1 segment(s), 0 broken`), whose
  punctuation may add speech verbosity depending on screen reader settings.
- Times are always UTC; a reader converts to local time themselves.
- Every message is English only.

## Contributing

Read this file before changing any output listed above: the line grammar, the verify report, a
finding's sentence or an error. Keep one entry to one line, keep outcomes as words, and keep
meaning in words. In the pull request's Accessibility section, give each check a row in a
`Check | Result | Evidence` table: Pass, Fail or Blocked, with the test or command, tool and
version used, or why it could not run. Keep unrun checks as Blocked, including assistive
technology nobody used. A historical run that CI does not repeat is Blocked with its date,
not Pass. Say what each check covers and does not.

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
| 2026-11-12 | Record current format-test results and blocked accessibility checks with evidence and scope. |
