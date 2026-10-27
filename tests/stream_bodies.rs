//! File-backed segment body regressions (ledger #2276).
#![cfg(not(target_family = "wasm"))]

use std::path::PathBuf;
use std::sync::Arc;

use futures::executor::block_on;
use ikigai_core::{ArgRef, Body, Capability, ContentId, Iri, Kernel, Request, Verb};
use ikigai_log::{Destination, LogConfig, LogHandle, Timestamp, Vocabulary, LOG_MEDIA_TYPE};

struct Log {
    directory: PathBuf,
    path: PathBuf,
    iri: String,
    kernel: Arc<Kernel>,
    handle: Arc<LogHandle>,
}

impl Log {
    fn new(finished: bool) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "ikigai-log-stream-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let config = LogConfig::default()
            .with_instance("streams")
            .with_destination(Destination::File)
            .with_directory(&directory);
        let handle = Arc::new(LogHandle::new(Some(directory.clone()), None, config));
        handle
            .open(Vocabulary::shared_builtin(), Timestamp::from_millis(0))
            .unwrap();
        let (iri, _) = handle.open_segment().unwrap();
        if finished {
            handle.close(Timestamp::from_millis(1)).unwrap();
        }
        let path = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "log"))
            .unwrap();
        let kernel = Arc::new(Kernel::new(Arc::new(ikigai_log::endpoints::space(
            handle.clone(),
        ))));
        Self {
            directory,
            path,
            iri,
            kernel,
            handle,
        }
    }

    fn request(&self) -> Request {
        Request::new(Verb::Source, Iri::parse(&self.iri).unwrap())
            .with_arg("as", ArgRef::Inline(LOG_MEDIA_TYPE.as_bytes().to_vec()))
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn raw_segment_body_is_seekable_with_exact_length_and_validator() {
    let log = Log::new(true);
    let expected = block_on(log.kernel.issue(log.request(), &Capability::root())).unwrap();
    let answer = block_on(log.kernel.issue_body(log.request(), &Capability::root())).unwrap();
    let Body::Replay(replay) = answer.bytes else {
        panic!("raw segment body must retain a file, not the segment's bytes");
    };
    assert_eq!(replay.len_hint(), Some(expected.bytes.len() as u64));
    assert_eq!(replay.validator(), Some(ContentId::of(&expected.bytes)));
    assert_eq!(
        block_on(Body::Replay(replay.clone()).collect(usize::MAX)).unwrap(),
        expected.bytes
    );
    let offset = expected.bytes.len() / 2;
    let suffix = Body::Once(replay.open_at(offset as u64).expect("seekable"));
    assert_eq!(
        block_on(suffix.collect(usize::MAX)).unwrap(),
        expected.bytes[offset..]
    );
}

#[test]
fn log_transreption_declares_incremental_input() {
    use ikigai_core::Endpoint;
    let endpoint = ikigai_log::segments::TransreptEndpoint::new(Vocabulary::shared_builtin());
    assert!(endpoint.describe().transreption().unwrap().is_incremental());
}

#[test]
fn both_faces_and_windows_equal_the_bytes_path_and_keep_cache_policy() {
    use ikigai_core::{Bindings, Endpoint, Expiry, Invocation};
    for finished in [false, true] {
        let log = Log::new(finished);
        let endpoint = ikigai_log::segments::SegmentEndpoint::new(
            log.handle.clone(),
            Vocabulary::shared_builtin(),
        );
        let mut bindings = Bindings::new();
        bindings.insert("segment", log.iri.strip_prefix("urn:log:").unwrap());
        let cap = Capability::root();
        for args in [
            vec![],
            vec![("as", LOG_MEDIA_TYPE)],
            vec![("as", "text/turtle")],
            vec![("from_seq", "2"), ("to_seq", "2")],
            vec![("since", "1970-01-01T00:00:00.001Z")],
            vec![("until", "1970-01-01T00:00:00.000Z")],
        ] {
            let mut request = Request::new(Verb::Source, Iri::parse(&log.iri).unwrap());
            for (key, value) in args {
                request = request.with_arg(key, ArgRef::Inline(value.as_bytes().to_vec()));
            }
            let inv = Invocation::detached(&request, &bindings, &cap);
            let expected = block_on(endpoint.invoke(&inv)).unwrap();
            let answer = block_on(endpoint.invoke_body(&inv)).unwrap();
            let Body::Replay(replay) = &answer.bytes else {
                panic!("a file-backed replay")
            };
            assert_eq!(replay.len_hint(), Some(expected.bytes.len() as u64));
            assert_eq!(replay.validator(), Some(ContentId::of(&expected.bytes)));
            assert_eq!(
                answer.expiry,
                if finished {
                    Expiry::Never
                } else {
                    Expiry::Always
                }
            );
            let actual = block_on(answer.collect(usize::MAX)).unwrap();
            assert_eq!(actual.bytes, expected.bytes);
            assert_eq!(actual.repr_type, expected.repr_type);
            assert_eq!(actual.threads(), expected.threads());
        }
    }
}

#[test]
fn a_cached_file_body_refuses_a_changed_or_removed_file() {
    use ikigai_core::Error;
    use std::io::Write;
    for removed in [false, true] {
        let log = Log::new(true);
        let answer = block_on(log.kernel.issue_body(log.request(), &Capability::root())).unwrap();
        if removed {
            std::fs::remove_file(&log.path).unwrap();
        } else {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&log.path)
                .unwrap()
                .write_all(b"# changed\n")
                .unwrap();
        }
        assert!(matches!(
            block_on(answer.collect(usize::MAX)),
            Err(Error::Conflict(_))
        ));
    }
}

#[test]
fn a_file_changed_after_a_data_chunk_ends_with_error_then_eof() {
    use futures::StreamExt;
    use ikigai_core::Error;
    use std::io::Write;
    let log = Log::new(false);
    let answer = block_on(log.kernel.issue_body(log.request(), &Capability::root())).unwrap();
    let mut stream = answer.bytes.into_stream();
    assert!(!block_on(stream.next()).unwrap().unwrap().is_empty());
    std::fs::OpenOptions::new()
        .append(true)
        .open(&log.path)
        .unwrap()
        .write_all(b"# changed\n")
        .unwrap();
    assert!(matches!(
        block_on(stream.next()),
        Some(Err(Error::Conflict(_)))
    ));
    assert!(block_on(stream.next()).is_none());
}

#[test]
fn segment_bounds_and_permissions_apply_to_bodies() {
    use ikigai_core::{Error, IssueContext};
    let log = Log::new(false);
    assert!(matches!(
        block_on(
            log.kernel
                .issue_body(log.request(), &Capability::scoped(Vec::<String>::new()))
        ),
        Err(Error::Denied(_))
    ));
    assert!(matches!(
        block_on(log.kernel.issue_body_with_context(
            log.request(),
            &Capability::root(),
            IssueContext::new().with_memory_limit(8)
        )),
        Err(Error::OverBudget { .. })
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .open(&log.path)
        .unwrap()
        .set_len(ikigai_log::segments::MAX_SEGMENT_BYTES as u64 + 1)
        .unwrap();
    assert!(matches!(
        block_on(log.kernel.issue_body(log.request(), &Capability::root())),
        Err(Error::OverBudget { .. })
    ));
}

#[test]
fn transrept_body_resolves_inline_reference_and_content_id() {
    use ikigai_core::{
        EndpointSpace, Exact, FnEndpoint, MemoryContentStore, ReprType, Representation,
    };
    let log = Log::new(true);
    let text = std::fs::read(&log.path).unwrap();
    let expected = ikigai_log::to_turtle(
        std::str::from_utf8(&text).unwrap(),
        Vocabulary::builtin(),
        &ikigai_log::Options::all(),
    )
    .unwrap();
    let store = Arc::new(MemoryContentStore::new(1 << 20));
    let held = store.put(text.clone()).unwrap();
    let source_text = text.clone();
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(
                Exact::new("urn:fixture"),
                FnEndpoint::new("fixture", move |_| {
                    Ok(Representation::new(
                        ReprType::new(LOG_MEDIA_TYPE),
                        source_text.clone(),
                    ))
                }),
            )
            .bind(
                Exact::new(ikigai_log::TRANSREPT_IRI),
                ikigai_log::segments::TransreptEndpoint::new(Vocabulary::shared_builtin()),
            ),
    ))
    .with_content_store(store);
    for arg in [
        ArgRef::Inline(text),
        ArgRef::Reference(Iri::parse("urn:fixture").unwrap()),
        ArgRef::Content(held.id()),
    ] {
        let request = Request::new(Verb::Source, Iri::parse(ikigai_log::TRANSREPT_IRI).unwrap())
            .with_arg("content", arg);
        let answer = block_on(kernel.issue_body(request, &Capability::root())).unwrap();
        assert_eq!(
            block_on(answer.collect(1 << 20)).unwrap().bytes,
            expected.as_bytes()
        );
    }
}

#[test]
fn live_tail_is_cacheable_only_when_append_cuts_are_connected() {
    use ikigai_core::Expiry;
    let log = Log::new(false);
    let weak = Arc::downgrade(&log.kernel);
    log.handle.set_append_cutter(Some(Arc::new(move |thread| {
        if let Some(kernel) = weak.upgrade() {
            kernel.cut(thread);
        }
    })));
    let request = log
        .request()
        .with_arg("tail", ArgRef::Inline(b"true".to_vec()));
    let answer = block_on(log.kernel.issue_body(request, &Capability::root())).unwrap();
    assert_eq!(answer.expiry, Expiry::Never);
}

#[test]
fn append_cut_wakes_a_scoped_listener_and_a_new_range_resumes_at_last_offset() {
    use ikigai_core::{Error, ListenSpec};
    let log = Log::new(false);
    let weak = Arc::downgrade(&log.kernel);
    log.handle.set_append_cutter(Some(Arc::new(move |thread| {
        if let Some(kernel) = weak.upgrade() {
            kernel.cut(thread);
        }
    })));
    let cap = Capability::scoped([ikigai_log::CAP_READ, ikigai_core::CAP_LISTEN]);
    let thread = format!("urn:file:{}", log.path.display());
    let listener = log
        .kernel
        .listen(ListenSpec::new().exact(&thread), &cap)
        .unwrap();
    let request = log
        .request()
        .with_arg("tail", ArgRef::Inline(b"true".to_vec()));
    let first = block_on(log.kernel.issue_body(request.clone(), &cap)).unwrap();
    let offset = first.bytes.len_hint().unwrap();
    let old = first.bytes;
    log.handle
        .write(
            ikigai_log::Entry::new(
                Timestamp::from_millis(2),
                ikigai_log::MESSAGE_CLASS,
                "urn:subject",
            )
            .with("msg", "appended"),
        )
        .unwrap();
    let batch = listener.drain();
    assert_eq!(batch.dropped, 0);
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].thread.as_str(), thread);
    assert_eq!(
        batch.events[0].invalidated.as_slice(),
        std::slice::from_ref(&log.iri)
    );
    assert!(matches!(
        block_on(old.collect(usize::MAX)),
        Err(Error::Conflict(_))
    ));
    let fresh = block_on(log.kernel.issue_body(request.clone(), &cap)).unwrap();
    let Body::Replay(replay) = fresh.bytes else {
        panic!("a file replay")
    };
    let suffix = block_on(Body::Once(replay.open_at(offset).unwrap()).collect(usize::MAX)).unwrap();
    let bytes = std::fs::read(&log.path).unwrap();
    assert_eq!(suffix, bytes[offset as usize..]);
    assert!(std::str::from_utf8(&suffix)
        .unwrap()
        .contains("msg=appended"));
    // Disconnecting cuts the former tail and prevents a stale cache claim.
    log.handle.set_append_cutter(None);
    assert_eq!(listener.drain().events.len(), 1);
    assert!(matches!(
        block_on(log.kernel.issue_body(request, &cap)),
        Err(Error::Unsupported { .. })
    ));
}

#[test]
fn closing_and_rotating_cut_the_old_tail_and_filtered_writes_do_not() {
    use ikigai_core::ListenSpec;
    for rotate in [false, true] {
        let log = Log::new(false);
        let weak = Arc::downgrade(&log.kernel);
        log.handle.set_append_cutter(Some(Arc::new(move |thread| {
            if let Some(kernel) = weak.upgrade() {
                kernel.cut(thread);
            }
        })));
        let listener = log
            .kernel
            .listen(
                ListenSpec::new().exact(format!("urn:file:{}", log.path.display())),
                &Capability::root(),
            )
            .unwrap();
        let request = log
            .request()
            .with_arg("tail", ArgRef::Inline(b"true".to_vec()));
        let before = block_on(log.kernel.issue_body(request.clone(), &Capability::root())).unwrap();
        let offset = before.bytes.len_hint().unwrap();
        assert_eq!(
            log.handle
                .write(ikigai_log::Entry::new(
                    Timestamp::from_millis(1),
                    format!("{}Resolution", ikigai_log::LOG_NS),
                    "urn:subject"
                ))
                .unwrap(),
            None
        );
        assert!(listener.drain().events.is_empty());
        if rotate {
            log.handle.rotate(Timestamp::from_millis(2)).unwrap();
        } else {
            log.handle.close(Timestamp::from_millis(2)).unwrap();
        }
        assert_eq!(listener.drain().events.len(), 1);
        let after = block_on(log.kernel.issue_body(request.clone(), &Capability::root())).unwrap();
        let expected = block_on(log.kernel.issue(request, &Capability::root())).unwrap();
        let Body::Replay(replay) = after.bytes else {
            panic!("a file replay")
        };
        let suffix =
            block_on(Body::Once(replay.open_at(offset).unwrap()).collect(usize::MAX)).unwrap();
        assert_eq!(suffix, expected.bytes[offset as usize..]);
        assert!(std::str::from_utf8(&suffix).unwrap().contains(if rotate {
            "log:Rotation"
        } else {
            "log:ProcessStop"
        }));
    }
}

#[test]
fn live_tail_requires_raw_face_and_a_notifier_for_this_handles_segment() {
    use ikigai_core::Error;
    let log = Log::new(false);
    let request = log
        .request()
        .with_arg("tail", ArgRef::Inline(b"true".to_vec()));
    assert!(matches!(
        block_on(log.kernel.issue_body(request, &Capability::root())),
        Err(Error::Unsupported { .. })
    ));
    let graph = Request::new(Verb::Source, Iri::parse(&log.iri).unwrap())
        .with_arg("tail", ArgRef::Inline(b"true".to_vec()));
    assert!(matches!(
        block_on(log.kernel.issue_body(graph, &Capability::root())),
        Err(Error::InvalidArgument { .. })
    ));
    let bad = log
        .request()
        .with_arg("tail", ArgRef::Inline(b"yes".to_vec()));
    assert!(matches!(
        block_on(log.kernel.issue_body(bad, &Capability::root())),
        Err(Error::InvalidArgument { .. })
    ));
}

#[test]
fn large_file_bodies_run_with_a_working_budget_smaller_than_input_or_output() {
    use futures::StreamExt;
    use ikigai_core::{ContentHasher, Error, IssueContext};
    use std::io::Write;
    let log = Log::new(false);
    let mut file = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log.path)
            .unwrap(),
    );
    for _ in 0..20_000 {
        file.write_all(b"1970-01-01T00:00:00.001Z log:Message urn:subject msg=large\n")
            .unwrap();
    }
    file.flush().unwrap();
    assert!(log.path.metadata().unwrap().len() > 1_000_000);
    for request in [
        log.request(),
        Request::new(Verb::Source, Iri::parse(&log.iri).unwrap()),
    ] {
        let answer = block_on(log.kernel.issue_body_with_context(
            request,
            &Capability::root(),
            IssueContext::new().with_memory_limit(16 * 1024),
        ))
        .unwrap();
        let Body::Replay(replay) = answer.bytes else {
            panic!("a file replay")
        };
        assert!(replay.len_hint().unwrap() > 1_000_000);
        let mut stream = replay.open();
        let mut hash = ContentHasher::new();
        let mut len = 0;
        while let Some(chunk) = block_on(stream.next()) {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= 16 * 1024);
            len += chunk.len() as u64;
            hash.update(&chunk);
        }
        assert_eq!(Some(len), replay.len_hint());
        assert_eq!(Some(hash.finish()), replay.validator());
        assert!(matches!(
            block_on(Body::Replay(replay).collect(16 * 1024)),
            Err(Error::OverBudget { .. })
        ));
    }
}

#[test]
fn the_kernel_plan_hands_one_shot_content_to_the_incremental_step_without_collecting() {
    use futures::{stream, StreamExt};
    use ikigai_core::{
        Description, Endpoint, EndpointSpace, Exact, Invocation, ReprType, Representation, Result,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Plan {
        header: String,
        polls: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl Endpoint for Plan {
        async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
            self.invoke_body(inv).await?.collect(1 << 20).await
        }
        async fn invoke_body(&self, inv: &Invocation<'_>) -> Result<Representation<Body>> {
            let polls = self.polls.clone();
            let mut parts = vec![self.header.clone()];
            parts.extend(
                (0..100).map(|_| {
                    "1970-01-01T00:00:00.001Z log:Message urn:subject novel=stream\n".into()
                }),
            );
            let source = Body::once(stream::iter(parts).map(move |part| {
                polls.fetch_add(1, Ordering::Relaxed);
                Ok(part.into_bytes().into())
            }));
            let plan = inv
                .select_transreptor(LOG_MEDIA_TYPE, "text/turtle")
                .expect("registered transreptor");
            assert!(plan[0].incremental);
            inv.transrept(
                Representation::from_body(ReprType::new(LOG_MEDIA_TYPE), source),
                &plan,
            )
            .await
        }
        fn name(&self) -> &str {
            "plan"
        }
        fn describe(&self) -> Description {
            Description::new("plan").verb(Verb::Source)
        }
    }
    let log = Log::new(false);
    let text = std::fs::read_to_string(&log.path).unwrap();
    let (header, _) = ikigai_log::Header::parse(&text).unwrap();
    let polls = Arc::new(AtomicUsize::new(0));
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(
                Exact::new("urn:plan"),
                Plan {
                    header: header.render().unwrap(),
                    polls: polls.clone(),
                },
            )
            .bind(
                Exact::new(ikigai_log::TRANSREPT_IRI),
                ikigai_log::segments::TransreptEndpoint::new(Vocabulary::shared_builtin()),
            ),
    ));
    let answer = block_on(kernel.issue_body(
        Request::new(Verb::Source, Iri::parse("urn:plan").unwrap()),
        &Capability::root(),
    ))
    .unwrap();
    let mut stream = answer.bytes.into_stream();
    assert!(block_on(stream.next()).unwrap().is_ok());
    assert_eq!(polls.load(Ordering::Relaxed), 2);
}
