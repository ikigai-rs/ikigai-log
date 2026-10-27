//! Incremental line parsing with the buffered graph emitter's ordering and serializer.
//!
//! A replay gets a bounded prefix probe and is then read row by row. A one-shot
//! producer cannot be probed twice: until its first `logkey:` property (or EOF),
//! output triples wait under the working memory bound so the prefix block stays
//! byte-identical. Deferred span joins, principals and seals are also bounded.
//! None of these paths collects the source text.

use std::io::Write;
use std::sync::{Arc, Mutex};

use futures_util::{stream, StreamExt, TryStreamExt};
use ikigai_core::{Body, ByteStream, Bytes, Error, Replay, Result};
use oxrdf::Triple;
use oxrdfio::WriterQuadSerializer;

use crate::graph::{self, GraphBuilder, Options};
use crate::line::{Entry, Header, Line, Seal};
use crate::segments::MAX_SEGMENT_BYTES;
use crate::vocabulary::{Vocabulary, LOG_KEY_NS, PROCESS_START_CLASS};

fn over() -> Error {
    Error::OverBudget {
        detail: "log transreption exceeds its input or working memory budget".into(),
    }
}

fn graph_error(error: impl std::fmt::Display) -> Error {
    Error::Endpoint(error.to_string())
}

/// Newline framing only; UTF-8, line syntax, RDF and hashes use existing helpers.
struct Lines {
    stream: ByteStream,
    pending: Bytes,
    seen: usize,
    number: usize,
    limit: usize,
    eof: bool,
}

impl Lines {
    fn new(stream: ByteStream, limit: usize) -> Self {
        Self {
            stream,
            pending: Bytes::new(),
            seen: 0,
            number: 0,
            limit,
            eof: false,
        }
    }

    async fn next(&mut self) -> Result<Option<String>> {
        let mut line = Vec::new();
        loop {
            if !self.pending.is_empty() {
                let newline = self.pending.iter().position(|&byte| byte == b'\n');
                let n = newline.map_or(self.pending.len(), |at| at + 1);
                if line.len().saturating_add(n) > self.limit {
                    return Err(over());
                }
                line.extend_from_slice(&self.pending[..n]);
                self.pending = self.pending.slice(n..);
                if newline.is_some() {
                    break;
                }
            }
            if self.eof {
                if line.is_empty() {
                    return Ok(None);
                }
                break;
            }
            match self.stream.next().await {
                Some(chunk) => {
                    let chunk = chunk?;
                    self.seen = self.seen.saturating_add(chunk.len());
                    if self.seen > MAX_SEGMENT_BYTES {
                        return Err(over());
                    }
                    self.pending = chunk;
                }
                None => self.eof = true,
            }
        }
        self.number += 1;
        String::from_utf8(line)
            .map(Some)
            .map_err(|error| Error::InvalidArgument {
                name: "content".into(),
                detail: format!("a segment is UTF-8 text: {error}"),
            })
    }
}

enum Record {
    Entry { entry: Entry, seq: u64, run: usize },
    Seal(Seal),
}

struct Input {
    lines: Lines,
    header: Header,
    vocabulary: Arc<Vocabulary>,
    options: Options,
    ordinal: u64,
    run: usize,
    started: bool,
}

impl Input {
    async fn new(
        stream: ByteStream,
        vocabulary: Arc<Vocabulary>,
        options: Options,
        limit: usize,
    ) -> Result<Self> {
        let mut lines = Lines::new(stream, limit);
        let mut text = String::new();
        while let Some(line) = lines.next().await? {
            if text.len().saturating_add(line.len()) > limit {
                return Err(over());
            }
            let blank = line.trim().is_empty();
            text.push_str(&line);
            if blank {
                break;
            }
        }
        let (header, _) =
            Header::parse(&text).map_err(|error| graph_error(format!("line 1: {error}")))?;
        Ok(Self {
            lines,
            header,
            vocabulary,
            options,
            ordinal: 0,
            run: 0,
            started: false,
        })
    }

    async fn next(&mut self) -> Result<Option<Record>> {
        while let Some(line) = self.lines.next().await? {
            let raw = line.trim_end_matches(['\n', '\r']);
            if graph::outside_window(raw, &self.options) {
                self.ordinal += 1;
                continue;
            }
            let parsed = Line::parse(raw, &self.header.prefixes)
                .map_err(|error| graph_error(format!("line {}: {error}", self.lines.number)))?;
            match parsed {
                Line::Entry(entry) => {
                    if self.vocabulary.is_a(&entry.class, PROCESS_START_CLASS) {
                        if self.started {
                            self.run += 1;
                        }
                        self.started = true;
                    }
                    self.ordinal += 1;
                    let seq = entry
                        .get("seq")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(self.ordinal);
                    if self.options.admits(&entry, seq) {
                        return Ok(Some(Record::Entry {
                            entry,
                            seq,
                            run: self.run,
                        }));
                    }
                }
                Line::Seal(seal) => return Ok(Some(Record::Seal(seal))),
                Line::Blank | Line::Comment(_) => {}
                Line::Directive { name, .. } => {
                    return Err(graph_error(format!(
                        "line {}: @{name} after the header block",
                        self.lines.number
                    )))
                }
            }
        }
        Ok(None)
    }
}

/// A bounded writer drained after each row; Oxigraph owns all Turtle syntax.
#[derive(Clone)]
struct Output {
    bytes: Arc<Mutex<Vec<u8>>>,
    limit: usize,
}

impl Output {
    fn take(&self) -> Result<Bytes> {
        Ok(std::mem::take(&mut *self.bytes.lock().map_err(graph_error)?).into())
    }
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut output = self
            .bytes
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if output.len().saturating_add(bytes.len()) > self.limit {
            return Err(std::io::Error::other(
                "log output exceeds working memory budget",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Emitter {
    input: Input,
    graph: GraphBuilder,
    seals: Vec<Seal>,
    seal_bytes: usize,
    waiting: Vec<Triple>,
    waiting_bytes: usize,
    output: Output,
    serializer: Option<WriterQuadSerializer<Output>>,
    limit: usize,
    done: bool,
}

impl Emitter {
    fn new(input: Input, undeclared: Option<bool>, limit: usize) -> Result<Self> {
        let graph = GraphBuilder::new(input.header.clone()).map_err(graph_error)?;
        let output = Output {
            bytes: Arc::new(Mutex::new(Vec::new())),
            limit,
        };
        let serializer = undeclared
            .map(|yes| graph::serializer(output.clone(), yes))
            .transpose()
            .map_err(graph_error)?;
        Ok(Self {
            input,
            graph,
            seals: Vec::new(),
            seal_bytes: 0,
            waiting: Vec::new(),
            waiting_bytes: 0,
            output,
            serializer,
            limit,
            done: false,
        })
    }

    fn check(&self) -> Result<()> {
        if self
            .graph
            .retained_bytes()
            .saturating_add(self.waiting_bytes)
            .saturating_add(self.seal_bytes)
            > self.limit
        {
            return Err(over());
        }
        Ok(())
    }

    fn emit(&mut self, last: bool) -> Result<()> {
        self.check()?;
        if self.serializer.is_none() {
            let undeclared = self
                .graph
                .out
                .iter()
                .any(|t| t.predicate.as_str().starts_with(LOG_KEY_NS));
            self.waiting_bytes = self
                .waiting_bytes
                .saturating_add(graph::triples_bytes(&self.graph.out));
            self.waiting.append(&mut self.graph.out);
            if !undeclared && !last {
                return Ok(());
            }
            self.serializer =
                Some(graph::serializer(self.output.clone(), undeclared).map_err(graph_error)?);
            std::mem::swap(&mut self.graph.out, &mut self.waiting);
            self.waiting_bytes = 0;
        }
        if let Some(serializer) = &mut self.serializer {
            for triple in self.graph.out.drain(..) {
                serializer.serialize_triple(&triple).map_err(|_| over())?;
            }
        }
        Ok(())
    }

    async fn next(&mut self) -> Result<Option<Bytes>> {
        if self.done {
            return Ok(None);
        }
        loop {
            self.emit(false)?;
            let bytes = self.output.take()?;
            if !bytes.is_empty() {
                return Ok(Some(bytes));
            }
            match self.input.next().await? {
                Some(Record::Entry { entry, seq, run }) => {
                    self.graph
                        .entry(seq, entry, run, &self.input.vocabulary)
                        .map_err(graph_error)?;
                }
                Some(Record::Seal(seal)) => {
                    // Reserve both the retained seal and its final RDF materialization.
                    self.seal_bytes = self.seal_bytes.saturating_add(
                        4096 + 8
                            * (seal.hash.len() + seal.signature.as_ref().map_or(0, String::len)),
                    );
                    self.seals.push(seal);
                    self.check()?;
                }
                None => {
                    self.graph.finish(&self.seals).map_err(graph_error)?;
                    self.seals.clear();
                    self.seal_bytes = 0;
                    self.emit(true)?;
                    if let Some(serializer) = self.serializer.take() {
                        serializer.finish().map_err(|_| over())?;
                    }
                    self.done = true;
                    let bytes = self.output.take()?;
                    return Ok((!bytes.is_empty()).then_some(bytes));
                }
            }
        }
    }
}

async fn reader(
    source: ByteStream,
    vocabulary: Arc<Vocabulary>,
    options: Options,
    limit: usize,
    undeclared: Option<bool>,
) -> Result<ByteStream> {
    let input = Input::new(source, vocabulary, options, limit).await?;
    let emitter = Emitter::new(input, undeclared, limit)?;
    Ok(Box::pin(stream::try_unfold(
        emitter,
        |mut emitter| async move { Ok(emitter.next().await?.map(|bytes| (bytes, emitter))) },
    )))
}

struct Buffer(Bytes);
impl Replay for Buffer {
    fn open(&self) -> ByteStream {
        Body::Bytes(self.0.clone()).into_stream()
    }
}

struct GraphReplay {
    source: Arc<dyn Replay>,
    vocabulary: Arc<Vocabulary>,
    options: Options,
    limit: usize,
}

impl Replay for GraphReplay {
    fn open(&self) -> ByteStream {
        let source = self.source.clone();
        let vocabulary = self.vocabulary.clone();
        let options = self.options;
        let limit = self.limit;
        Box::pin(
            stream::once(async move {
                let mut input =
                    Input::new(source.open(), vocabulary.clone(), options, limit).await?;
                let mut undeclared = false;
                while let Some(record) = input.next().await? {
                    if let Record::Entry { entry, .. } = record {
                        if entry.fields.iter().any(|(key, _)| {
                            vocabulary
                                .key(key)
                                .is_none_or(|def| def.property.starts_with(LOG_KEY_NS))
                        }) {
                            undeclared = true;
                            break;
                        }
                    }
                }
                reader(source.open(), vocabulary, options, limit, Some(undeclared)).await
            })
            .try_flatten(),
        )
    }
}

pub(crate) async fn body(
    source: Body,
    vocabulary: Arc<Vocabulary>,
    options: Options,
    limit: usize,
) -> Result<Body> {
    if source
        .len_hint()
        .is_some_and(|len| len > MAX_SEGMENT_BYTES as u64)
    {
        return Err(over());
    }
    let replay = match source {
        Body::Replay(replay) => replay,
        Body::Bytes(bytes) => Arc::new(Buffer(bytes)),
        Body::Once(stream) => {
            return Ok(Body::Once(
                reader(stream, vocabulary, options, limit, None).await?,
            ))
        }
    };
    Ok(Body::replay(GraphReplay {
        source: replay,
        vocabulary,
        options,
        limit,
    }))
}

/// Measure a derived file replay without retaining its output. Finished segment
/// cache entries then carry framing and a strong content validator, too.
pub(crate) async fn measured(source: Body) -> Result<Body> {
    use ikigai_core::{ContentHasher, ContentId};
    struct Measured {
        source: Arc<dyn Replay>,
        len: u64,
        validator: ContentId,
    }
    impl Replay for Measured {
        fn open(&self) -> ByteStream {
            self.source.open()
        }
        fn len_hint(&self) -> Option<u64> {
            Some(self.len)
        }
        fn validator(&self) -> Option<ContentId> {
            Some(self.validator)
        }
    }
    let Body::Replay(source) = source else {
        return Err(graph_error("a derived segment must be replayable"));
    };
    let mut stream = source.open();
    let mut len = 0u64;
    let mut hash = ContentHasher::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        len = len.checked_add(chunk.len() as u64).ok_or_else(over)?;
        hash.update(&chunk);
    }
    Ok(Body::replay(Measured {
        source,
        len,
        validator: hash.finish(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::line::{Prev, Timestamp};
    use futures::executor::block_on;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn header() -> String {
        Header {
            version: 1,
            prefixes: [("log".into(), crate::LOG_NS.into())].into(),
            name: "urn:log:stream-test".into(),
            instance: "urn:instance:streams".into(),
            level: format!("{}info", crate::LOG_NS),
            started: Timestamp::from_millis(0),
            prev: Prev::Genesis,
        }
        .render()
        .unwrap()
    }

    fn entry(extra: &str) -> String {
        format!("1970-01-01T00:00:00.000Z log:Message urn:subject {extra}\n")
    }

    fn counted(parts: Vec<Vec<u8>>, polls: Arc<AtomicUsize>) -> Body {
        Body::once(stream::iter(parts).map(move |part| {
            polls.fetch_add(1, Ordering::Relaxed);
            Ok(part.into())
        }))
    }

    #[test]
    fn one_shot_emits_before_polling_the_rest_of_the_producer() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut parts = vec![header().into_bytes(), entry("novel=first").into_bytes()];
        parts.extend((0..100).map(|_| entry("novel=later").into_bytes()));
        let answer = block_on(body(
            counted(parts, polls.clone()),
            Vocabulary::shared_builtin(),
            Options::all(),
            64 * 1024,
        ))
        .unwrap();
        let mut stream = answer.into_stream();
        assert!(!block_on(stream.next()).unwrap().unwrap().is_empty());
        assert_eq!(
            polls.load(Ordering::Relaxed),
            2,
            "stop before polling later records"
        );
    }

    #[test]
    fn deferred_prefix_state_refuses_at_budget_and_stops_polling() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut parts = vec![header().into_bytes()];
        parts.extend((0..10_000).map(|_| entry("msg=known").into_bytes()));
        let answer = block_on(body(
            counted(parts, polls.clone()),
            Vocabulary::shared_builtin(),
            Options::all(),
            16 * 1024,
        ))
        .unwrap();
        let mut stream = answer.into_stream();
        assert!(matches!(
            block_on(stream.next()),
            Some(Err(Error::OverBudget { .. }))
        ));
        assert!(polls.load(Ordering::Relaxed) < 100);
        assert!(block_on(stream.next()).is_none());
    }

    struct Generated;
    impl Replay for Generated {
        fn open(&self) -> ByteStream {
            Box::pin(stream::iter(0..20_001).map(|index| {
                Ok(if index == 0 {
                    header()
                } else {
                    entry("msg=repeated")
                }
                .into_bytes()
                .into())
            }))
        }
    }

    #[test]
    fn replay_input_and_output_larger_than_memory_are_never_collected() {
        let answer = block_on(body(
            Body::replay(Generated),
            Vocabulary::shared_builtin(),
            Options::all(),
            16 * 1024,
        ))
        .unwrap();
        let mut stream = answer.into_stream();
        let mut bytes = 0;
        let mut chunks = 0;
        while let Some(chunk) = block_on(stream.next()) {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= 16 * 1024);
            bytes += chunk.len();
            chunks += 1;
        }
        assert!(bytes > 1_000_000);
        assert!(chunks >= 20_000);
    }

    #[test]
    fn every_chunk_boundary_including_utf8_matches_buffered_turtle() {
        let text = header() + &entry("novel=é msg=hello") + &entry("msg=second");
        let expected = graph::to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap();
        for split in 0..=text.len() {
            let source = counted(
                vec![
                    text.as_bytes()[..split].to_vec(),
                    text.as_bytes()[split..].to_vec(),
                ],
                Arc::new(AtomicUsize::new(0)),
            );
            let answer = block_on(body(
                source,
                Vocabulary::shared_builtin(),
                Options::all(),
                64 * 1024,
            ))
            .unwrap();
            assert_eq!(
                block_on(answer.collect(64 * 1024)).unwrap(),
                expected.as_bytes(),
                "split {split}"
            );
        }
    }

    #[test]
    fn streamed_seals_principals_and_cross_run_joins_match_the_bytes_emitter() {
        let mut text = header();
        for (class, fields) in [
            ("ProcessStart", "seq=1"),
            (
                "Message",
                "seq=2 span=1 parent=2 principal=urn:tenant:a principal=urn:tenant:b",
            ),
            (
                "Message",
                "seq=3 span=2 principal=urn:tenant:a cap=urn:cap:x cap=urn:cap:x",
            ),
            ("ProcessStart", "seq=4"),
            (
                "Message",
                "seq=5 span=2 parent=1 principal=urn:tenant:c novel=last",
            ),
        ] {
            text.push_str(&format!(
                "1970-01-01T00:00:00.000Z log:{class} urn:subject {fields}\n"
            ));
        }
        text.push_str("#seal 1-3 sha256:4c1e0d Ed25519:MEUCIQD\n#seal 4-5 sha256:9ab7\n");
        for options in [
            Options::all(),
            Options {
                from_seq: Some(2),
                to_seq: Some(3),
                ..Options::all()
            },
        ] {
            let expected = graph::to_turtle(&text, Vocabulary::builtin(), &options).unwrap();
            let once = counted(
                text.as_bytes().chunks(7).map(<[u8]>::to_vec).collect(),
                Arc::new(AtomicUsize::new(0)),
            );
            for source in [Body::from(text.clone().into_bytes()), once] {
                let answer = block_on(body(
                    source,
                    Vocabulary::shared_builtin(),
                    options,
                    128 * 1024,
                ))
                .unwrap();
                assert_eq!(
                    block_on(answer.collect(128 * 1024)).unwrap(),
                    expected.as_bytes()
                );
            }
        }
    }

    #[test]
    fn producer_failure_and_malformed_utf8_after_output_are_error_items() {
        for utf8 in [false, true] {
            let parts = vec![
                Ok(header().into_bytes().into()),
                Ok(entry("novel=first").into_bytes().into()),
                if utf8 {
                    Ok(Bytes::from_static(b"\xff\n"))
                } else {
                    Err(Error::Unavailable("producer failed".into()))
                },
            ];
            let answer = block_on(body(
                Body::once(stream::iter(parts)),
                Vocabulary::shared_builtin(),
                Options::all(),
                64 * 1024,
            ))
            .unwrap();
            let mut stream = answer.into_stream();
            assert!(block_on(stream.next()).unwrap().is_ok());
            let error = block_on(stream.next()).unwrap().unwrap_err();
            assert!(if utf8 {
                matches!(error, Error::InvalidArgument { .. })
            } else {
                matches!(error, Error::Unavailable(_))
            });
            assert!(block_on(stream.next()).is_none());
        }
    }
}
