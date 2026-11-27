# Changelog

Earlier releases are described in their commit messages and pull requests; this file starts
with the first release that changes a public name.

## Unreleased

### Added

- `urn:log:verify` checks an instance's chain against an expected head (ledger #4510), hence
  0.15.0. Link verification alone passes any valid prefix: a chain cut back to an earlier
  seal has every link intact, and its missing tail reads as a crash. With `instance=` and
  `head=` (a seal hash published elsewhere) or `entries=` (a stated length), a chain that
  ends before it is `BROKEN`, said in a sentence:
  `no seal in this chain states its expected head sha256:…: the chain ends before it, or was
  rewritten before it`. In the library, `verify_chain_to`, `ExpectedHead` and
  `ChainReport::check_expected`, with two new findings, `Finding::ExpectedHeadMissing` and
  `Finding::ShortOfExpectedLength`.

### Changed

- `ChainReport` gains `expected` and `findings`, and `SegmentReport` gains `seal_hashes` (every
  seal's hash, so a published head is found anywhere in a chain that grew past it). Code that
  builds either with a struct literal adds the fields, or `..ChainReport::default()`; hence
  0.15.0. A report without an expected head renders exactly as before.

- On ikigai-core 0.4.0 (scope opacity, structured denials; the core 0.4.0 cascade,
  ledger #3930), with ikigai-sign 0.6.0, and in tests ikigai-sparql 0.6.0 and
  ikigai-conformance 0.15.0. Refusals are now `Error::Denied(Denial)` carrying the
  same messages as before. A consumer on core 0.3 cannot mix these types, hence 0.13.0.

### Fixed

- `verify` hashes an entry line exactly as it appears once its line ending (`\n` or
  `\r\n`) is taken off (ledger #4359), hence 0.14.3. It used to trim every trailing
  carriage return before hashing, so a sealed line with `\r\r` added to its end was
  reported intact. The writer never writes a raw `\r`, so such a line was edited
  after the seal and is now reported as a seal mismatch. CRLF line endings still
  verify.

- Live segment replays pin file identity and the byte length observed when
  preparing the body (ledger #4141), hence 0.14.2. A host can use the streaming
  body API for its open segment even when it writes an access line before
  streaming the response.

- `urn:log:verify` streams the directory instead of reading it all under a 64 MiB
  total budget (ledger #4099), hence 0.14.1. A host that never prunes had a log over
  64 MiB answer `over budget` to every verify, `segment=` included, for good. Each
  segment is now read under its own 16 MiB bound, verified alone and dropped; the
  links across rotations are checked from the previous segment's report. Memory is
  one segment plus the report, and the directory's total has no bound (no time
  budget either). `segment=` now reads the segment it names and its predecessor,
  plus every other segment's header and last seal, and reports that one segment
  with its link checked, where it used to report the whole chain it belonged to.
  Report wording is unchanged. `MAX_VERIFY_BYTES` now bounds only the session trail.
- A flush failure after a complete entry or seal write no longer makes the writer
  reuse its sequence number or repeat the seal. A later explicit seal retries an
  outstanding flush without appending another checkpoint (ledger #3436). I/O
  errors can occur after bytes were accepted; callers must not blindly retry an entry.
- Entry and header rendering refuse timestamps beyond year 9999 with
  `RenderError::Timestamp`, before writing a line or reserving a segment file.
  Accepted timestamps keep the v1 parser's fixed-width format (ledger #3436).

### Added

- A tool-call line and a session column (ledger #3962), additive, hence 0.14.0.
  `ToolCallLog` writes one `log:ToolCall` per tool call: the tool as its subject
  (`urn:log:tool:name:{name}`), `session=`, `outcome=ok|refused|failed`, `dur=`, and the
  arguments' digest `args=sha256:…` (and `result=` when the host hands the result
  over). Argument and result text (`args-text=`, `result-text=`) are written only
  under the writer's opt-in, `ToolCallLog::with_text`. New public names: `Session`,
  `ToolCall`, `ToolOutcome`, `ToolCallError`, `ToolCallLog`, `TOOL_NS`,
  `MAX_SESSION_LEN`, `MAX_TOOL_TEXT`, `TOOL_CALL_CLASS`, `SESSION_KEY`,
  `SESSION_PROPERTY`, and `Access::session`.
- `urn:log:trail:session:{session}` (`SessionTrailEndpoint`, bound by `space()` above the
  segment template): one session's trail as Turtle across every segment, read under
  `urn:cap:log:read:session:{session}` (`session_capability`,
  `CAP_READ_SESSION_PREFIX`), which `urn:cap:log:read` does not imply. A host limits
  how far back it reads with `LogHandle::set_session_retention_ms`.
- Vocabulary: `log:Session`, `log:session`, `log:ToolCall`, `log:calledTool`,
  `log:argumentsDigest`, `log:resultDigest`, `log:argumentsText`, `log:resultText`,
  `log:cutColumn`. `/ns/log` is deployed by hand and needs a redeploy.

### Changed in the vocabulary

- `log:outcome`'s `rdfs:domain` is `log:Entry`, not `log:Access`: a tool call
  writes the column too, and the narrower domain would type it a door request.

- `Access::needs`, an optional `needs=` column on a door line naming the
  capabilities a refused request lacked, as capability IRIs, space-separated
  (ledger #3829). Written only beside `outcome=denied` (`DENIED_OUTCOME`), and
  encoded and cut at `MAX_FIELD` as `q=` is.
- Vocabulary: `log:neededCapability`, keyed `needs`. `/ns/log` needs a redeploy.
- `AccessLog`, the one door line every host shares (ledger #3390): a `log:Access`
  entry per request with `door=`, `verb=`, `outcome=`, `bytes=`, `dur=`,
  `principal=`, `credential=`, `grant=` and `q=`, written through the log's writer.
  `AccessLog::tracer_for` gives the per-call tracer for `Kernel::issue_traced`, so
  the kernel's entries for a request carry its caller. No cookie, `Authorization`
  header, session or wire token, form body or `content` argument is written, and an
  anonymous caller is `principal=anon` and nothing more. Long fields are cut at
  `MAX_FIELD` and end with `…`.
- Vocabulary: `log:Access`, `log:requested`, `log:door`, `log:verb`, `log:outcome`,
  `log:byteCount`, `log:credentialKind`, `log:grant`, `log:servedQuery`, and the
  `log:CredentialKind` individuals `log:passkey`, `log:clientCertificate`,
  `log:socketOwner` and `log:anonymous`. The version is not bumped here: the release
  that ships these terms needs a crate publish and an `/ns/log` redeploy, both Brian's.

## 0.10.1

### Changed

- Conformance checks signature terms against ikigai-sign's published vocabulary,
  replacing the namespace waiver and local term list (ledger #2370).
- Graph emission uses ikigai-sign's public constants. A byte-for-byte fixture
  preserves the existing signed, unsigned, and legacy seal output.
- The vocabulary version is 0.10.1; no terms changed. This change does not publish
  the crate; publication remains Brian's.

## 0.10.0

### Changed

- Public API types now use ikigai-core 0.3.0 and its scoped content store
  (ledger #2965). Runtime and test dependencies share that core release.
- The content-ID transreption fixture holds content for its deliverer and checks
  that another principal cannot read it.
- The vocabulary version is 0.10.0; Brian must redeploy `/ns/log`.

## 0.9.3

### Fixed

- Rotation no longer writes a false `log:ChainBroken` entry for the segment it
  just sealed (ledger #2951). Rotation verifies a bounded window whose final
  successor is expected outside the walk. Whole-chain verification still reports
  a missing newest segment, and rotation still checks the segments and the link
  between them for tampering.

## 0.9.2

### Fixed

- Escape control characters in log lines so every entry stays one printable line
  (ledger #2732). A value holding a control character (C0, DEL or C1) or a line or
  paragraph separator is now quoted, with the character written as `\u{hex}`;
  before, such a value could be written bare, and a quoted one kept every control
  character but newline, carriage return and tab. The parser reads `\u{hex}` back,
  so the value, the hash chain and the transreptor's graph all agree. A subject,
  class, header IRI or prefix holding one is refused with `RenderError` instead of
  written, as whitespace already was; the tracer counts such an entry as
  unwritable.
- Segments written before this release, raw characters included, still parse,
  verify and transrept unchanged. A reader older than 0.9.2 reads a new escape as
  the text after its backslash, so read new segments with 0.9.2 or later. The
  format version stays v1: the grammar gained one escape, and no line an earlier
  writer produced reads differently.
- Error messages show the offending text escaped, so they stay one printable line
  (ledger #2911). `ParseError`, `RenderError`, `GraphError::Iri` and `PrincipalError`,
  and a verify finding naming a stray directive, write each character a line never
  carries raw as the line writes it (`\n`, `\r`, `\t` or `\u{hex}`), and the
  bidirectional format characters (U+202A to U+202E, U+2066 to U+2069) as `\u{hex}`;
  everything else, a backslash included, is shown as it is. Before, each quoted its
  input raw.
- Log lines escape bidirectional formatting characters so every entry reads in its
  written order (ledger #2917). A value holding one of U+202A to U+202E, U+2066 to
  U+2069, U+200E, U+200F or U+061C is quoted, with the character written as
  `\u{hex}`, exactly as a control character is; a subject, class, header IRI or
  prefix holding one is refused with `RenderError`. `Principal::new` refuses an IRI
  holding one, since it would have to be quoted. A segment written before this
  change, raw characters included, still parses, verifies and transrepts. Error
  text escapes the same set, the marks U+200E, U+200F and U+061C now included.
- Report and error text show names escaped the same way (ledger #2913). The verify
  report's segment line (name, level, `prev=`, `signed=`, `head=`) and every
  `Finding` that names what it read (`Malformed`, `SealMismatch`, `PrevMismatch`,
  `UnexpectedGenesis`, `MissingSuccessor`, `UnbracketedLevelChange`,
  `UnmarkedEnd`); `WriteError` (`UnknownLevel`, `InstanceInUse`, and the path in
  `SegmentExists` and `Io`); `ConfigError`'s paths and messages; `VocabError`; the
  streaming transreptor's stray-directive error; and the endpoints' text that
  repeats a requested segment IRI, a class, a level or a path. A segment written
  before 0.9.2 can carry such a character in its header or a class, and a request
  IRI can carry a bidirectional format character. The entry IRI `urn:log:write`
  answers is unchanged: it is an IRI, not a sentence.

## 0.9.1

### Added

- File-backed segment body reads. The raw face is seekable and carries an exact
  length and content validator; the graph face replays the shared Turtle emitter
  from the file and also carries a measured length and validator. Finished bodies
  cache without retaining their text. A changed file ends a reader with `Conflict`.
- An incremental `urn:log:transrept` body path resolving inline, reference and
  content-id inputs through core 0.2.1. It parses one line at a time, shares the
  existing graph emitter and serializer, and refuses input or working state above
  its bounds with `OverBudget`. Replays use a prefix probe; one-shot inputs buffer
  triples until the `logkey:` prefix decision is known, under the same working
  bound. Span joins, principals and deferred seals are bounded too.
- Native `LogHandle::set_append_cutter` and raw `tail=true` reads: connect the hook
  to `Kernel::cut`, listen to the file thread, and resume each fresh replay with
  `open_at(last_offset)`. This opt-in tail caches live snapshots only while the
  handle owns the open segment and a host cut hook is installed. Rotation, close
  and hook removal invalidate the old tail. External writers need a host watcher.

The bytes entry points retain their existing behavior and 16 MiB input bound;
verification remains a bounded collecting operation. This is an additive patch.

## 0.9.0

### Changed

- Move to `ikigai-core` 0.2.0, the streams release (ledger #2261). Core types
  appear in the public API, so consumers must upgrade together; the old 0.1
  requirement excluded 0.2.0 under Cargo's 0.x rules.
- Update `ikigai-sign` to 0.4.0 and the development dependency `ikigai-sparql`
  to 0.3.0 so the entire dependency graph shares core 0.2.0.
- Update `ikigai-conformance` to 0.11.0, running DATATYPES and FAILURES by
  default. Require every check to run in both live and finished segment walks.

## 0.8.0

A **breaking** change under 0.x, so a minor bump: anything that matches on an endpoint id, a
catalog label or an MCP tool name derived from one must move with it.

### Renamed

Every endpoint id now follows the naming convention `ikigai-core` states: a short `kebab-case`
noun, the bound IRI's own segment plus the module's prefix. The IRIs already conformed and do
not change, so nothing that resolves `urn:log:*` is affected. An id is not an IRI, so there is
no alias: the old ids are gone, not deprecated.

| old id | new id | IRI (unchanged) |
| --- | --- | --- |
| `logWrite` | `log-write` | `urn:log:write` |
| `logConfig` | `log-config` | `urn:log:config` |
| `logSegments` | `log-segments` | `urn:log:segments` |
| `logSegment` | `log-segment` | `urn:log:{segment}` |
| `logTransrept` | `log-transrept` | `urn:log:transrept` |
| `logVerify` | `log-verify` | `urn:log:verify` |

The conformance test no longer skips `NAMES`: every check runs.
