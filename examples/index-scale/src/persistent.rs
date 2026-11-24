//! The persistent half of the index-scale measurement (ledger #4218).
//!
//! Every phase is its own process, so "restart" and "first read after open" are what a
//! restarted host would see. Nothing here changes `ikigai-log`'s behavior.
//!
//! ```sh
//! log-index-persistent generate <segments> <dir> [instance]
//! log-index-persistent ingest   <dir> <store>
//! log-index-persistent query    <dir> <store> <reps>
//! log-index-persistent graph    <dir> <reps>
//! log-index-persistent concurrent <extra-dir> <store> <reps>
//! log-index-persistent turtle   <file>
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use ikigai_core::{ArgRef, Capability, Fallback, Iri, Kernel, Request, Space, Verb};
use ikigai_log::{
    to_triples, to_turtle, verify_chain, verify_segment, Destination, Entry, Header, LogConfig,
    LogHandle, Options, RotationPolicy, SealPolicy, SealSigner, Timestamp, Vocabulary, ERROR_CLASS,
    MESSAGE_CLASS, WARNING_CLASS,
};
use ikigai_store::DurableStore;
use oxigraph::model::{NamedNode, Quad};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use oxigraph::store::Store;

/// Entries written per segment, before the rotation marker: the README's reference unit.
const ENTRIES: u64 = 5000;
/// A fixed seed: the key is a fixture, not a secret.
const SEED: [u8; 32] = [7; 32];
const T0: u64 = 1_700_000_000_000;

const PREFIXES: &str = "PREFIX log: <https://ikigai-rs.dev/ns/log#> \
                        PREFIX prov: <http://www.w3.org/ns/prov#> ";

/// The same query text runs on both paths.
const QUERIES: [(&str, &str); 3] = [
    (
        "selective",
        "SELECT ?g ?e WHERE { GRAPH ?g { ?e log:text \"needle\" } }",
    ),
    (
        "broad-wide",
        "SELECT ?g ?e ?p ?o WHERE { GRAPH ?g { ?e a log:Warning ; ?p ?o } }",
    ),
    (
        "broad-join",
        "SELECT ?g ?e ?w ?agent WHERE { GRAPH ?g { ?e a log:Error ; log:subject ?agent . \
         ?w a log:Warning ; log:subject ?agent } }",
    ),
];

struct Ed25519(SigningKey);

impl SealSigner for Ed25519 {
    fn algorithm(&self) -> &str {
        "Ed25519"
    }
    fn sign(&self, tagged_hash: &str) -> Option<String> {
        let signature = self.0.sign(tagged_hash.as_bytes());
        Some(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| {
        args.get(i)
            .unwrap_or_else(|| panic!("argument {i} missing"))
            .clone()
    };
    match arg(0).as_str() {
        "generate" => generate(
            arg(1).parse().unwrap(),
            Path::new(&arg(2)),
            args.get(3).map(String::as_str).unwrap_or("scale"),
        ),
        "ingest" => ingest(Path::new(&arg(1)), Path::new(&arg(2))),
        "query" => query(
            Path::new(&arg(1)),
            Path::new(&arg(2)),
            arg(3).parse().unwrap(),
        ),
        "graph" => graph_path(Path::new(&arg(1)), arg(2).parse().unwrap()),
        "concurrent" => concurrent(
            Path::new(&arg(1)),
            Path::new(&arg(2)),
            arg(3).parse().unwrap(),
        ),
        "turtle" => {
            let text = std::fs::read_to_string(arg(1)).unwrap();
            print!(
                "{}",
                to_turtle(&text, Vocabulary::builtin(), &Options::all()).unwrap()
            );
        }
        other => panic!("unknown phase {other}"),
    }
}

// =====================================================================================
// Segments: written by the real writer, sealed, signed and chained
// =====================================================================================

fn generate(segments: u64, dir: &Path, instance: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let config = LogConfig::default()
        .with_instance(instance)
        .with_destination(Destination::File)
        .with_directory(dir);
    let handle = LogHandle::new(Some(dir.to_path_buf()), None, config);
    handle.set_policies(
        SealPolicy {
            every_entries: 500,
            every_millis: u64::MAX,
        },
        RotationPolicy::manual(),
    );
    handle.set_signer(Some(Box::new(Ed25519(SigningKey::from_bytes(&SEED)))));
    let start = Instant::now();
    let mut now = T0;
    handle
        .open(Vocabulary::shared_builtin(), Timestamp::from_millis(now))
        .unwrap();
    for segment in 0..segments {
        for i in 0..ENTRIES {
            now += 10;
            let class = if i % 1000 == 999 {
                ERROR_CLASS
            } else if i % 100 == 50 {
                WARNING_CLASS
            } else {
                MESSAGE_CLASS
            };
            let msg = if i == ENTRIES - 1 {
                "needle".to_string()
            } else {
                format!("ordinary-{}", (i * 7 + segment) % 97)
            };
            let entry = Entry::new(
                Timestamp::from_millis(now),
                class,
                format!("urn:agent:scale:{}", (i / 7) % 50),
            )
            .with("msg", msg);
            handle.write(entry).unwrap();
        }
        now += 10;
        if segment + 1 < segments {
            handle
                .rotate(Timestamp::from_millis(now))
                .unwrap()
                .expect("a successor");
        } else {
            handle.close(Timestamp::from_millis(now)).unwrap();
        }
    }
    let written = start.elapsed().as_secs_f64();
    let all = read_segments(dir);
    let t = Instant::now();
    let report = verify_chain(&all, Vocabulary::builtin());
    let chain_s = t.elapsed().as_secs_f64();
    assert!(report.ok(), "{}", report.render());
    let (seals, signed) = all.iter().fold((0, 0), |(a, b), (_, text)| {
        let (s, g) = check_signatures(text);
        (a + s, b + g)
    });
    assert_eq!(
        seals, signed,
        "every seal is signed and its signature checks"
    );
    let bytes: usize = all.iter().map(|(_, t)| t.len()).sum();
    println!(
        "generate segments={} bytes={bytes} seals={seals} write_s={written:.3} verify_chain_s={chain_s:.3}",
        all.len()
    );
}

/// Every segment file in `dir` as `(IRI, text)`, in chain order.
fn read_segments(dir: &Path) -> Vec<(String, String)> {
    let mut found: Vec<(u64, String, String)> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap();
            let (header, _) = Header::parse(&text).unwrap();
            (header.started.as_millis(), header.name, text)
        })
        .collect();
    found.sort();
    found
        .into_iter()
        .map(|(_, name, text)| (name, text))
        .collect()
}

/// `(seals, seals whose Ed25519 signature verifies)`.
fn check_signatures(text: &str) -> (usize, usize) {
    let key = VerifyingKey::from(&SigningKey::from_bytes(&SEED));
    let mut seals = 0;
    let mut good = 0;
    for line in text.lines().filter(|l| l.starts_with("#seal ")) {
        seals += 1;
        let columns: Vec<&str> = line.split_whitespace().collect();
        let (Some(hash), Some(token)) = (columns.get(2), columns.get(3)) else {
            continue;
        };
        let Some(b64) = token.strip_prefix("Ed25519:") else {
            continue;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            continue;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&bytes) else {
            continue;
        };
        if key.verify(hash.as_bytes(), &signature).is_ok() {
            good += 1;
        }
    }
    (seals, good)
}

// =====================================================================================
// Ingest: verify on receipt, transrept, one named graph per segment, one transaction each
// =====================================================================================

fn ingest_segments(store: &Store, segments: &[(String, String)]) -> (f64, f64, usize) {
    let mut verify = 0.0;
    let mut transrept = 0.0;
    let mut quads = 0;
    let mut previous: Option<(String, String)> = None;
    for (name, text) in segments {
        let t = Instant::now();
        let report = verify_segment(
            text,
            Vocabulary::builtin(),
            previous.as_ref().map(|(n, h)| (n.as_str(), h.as_str())),
        );
        let (seals, good) = check_signatures(text);
        assert!(report.ok() && seals == good && seals > 0, "{name} verifies");
        verify += t.elapsed().as_secs_f64();
        let t = Instant::now();
        let triples = to_triples(text, Vocabulary::builtin(), &Options::all()).unwrap();
        transrept += t.elapsed().as_secs_f64();
        let graph = NamedNode::new(name.as_str()).unwrap();
        quads += triples.len();
        store
            .extend(
                triples
                    .into_iter()
                    .map(|t| Quad::new(t.subject, t.predicate, t.object, graph.clone())),
            )
            .unwrap();
        previous = Some((name.clone(), report.head));
    }
    (verify, transrept, quads)
}

fn ingest(dir: &Path, store_dir: &Path) {
    let segments = read_segments(dir);
    let bytes: usize = segments.iter().map(|(_, t)| t.len()).sum();
    let start = Instant::now();
    let (_owner, store) = DurableStore::open_shared(store_dir).unwrap();
    let (verify, transrept, quads) = ingest_segments(&store, &segments);
    store.flush().unwrap();
    let ingest_s = start.elapsed().as_secs_f64();
    let len = store.len().unwrap();
    drop(store);
    drop(_owner);
    println!(
        "ingest segments={} bytes={bytes} quads={quads} stored={len} verify_s={verify:.3} transrept_s={transrept:.3} ingest_s={ingest_s:.3} entries_per_s={:.0} disk_bytes={}",
        segments.len(),
        segments.len() as f64 * (ENTRIES as f64 + 1.0) / ingest_s,
        disk_size(store_dir)
    );
}

fn disk_size(path: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![PathBuf::from(path)];
    while let Some(p) = stack.pop() {
        for entry in std::fs::read_dir(&p).unwrap().flatten() {
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    total
}

// =====================================================================================
// Reads
// =====================================================================================

fn run_store(store: &Store, text: &str) -> usize {
    let QueryResults::Solutions(rows) = SparqlEvaluator::new()
        .parse_query(&format!("{PREFIXES}{text}"))
        .unwrap()
        .on_store(store)
        .execute()
        .unwrap()
    else {
        panic!("a SELECT")
    };
    rows.map(|r| r.unwrap()).count()
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let t = Instant::now();
    let out = f();
    (out, t.elapsed().as_secs_f64() * 1000.0)
}

/// `p50/p95/p99/max` in milliseconds, nearest-rank.
fn percentiles(mut ms: Vec<f64>) -> String {
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let at = |p: f64| ms[(((p * ms.len() as f64).ceil() as usize).max(1) - 1).min(ms.len() - 1)];
    format!(
        "n={} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} max_ms={:.3}",
        ms.len(),
        at(0.50),
        at(0.95),
        at(0.99),
        ms[ms.len() - 1]
    )
}

fn query(_dir: &Path, store_dir: &Path, reps: usize) {
    let ((owner, store), open_ms) = timed(|| DurableStore::open_shared(store_dir).unwrap());
    println!("restart open_ms={open_ms:.3}");
    for (label, text) in QUERIES {
        let (rows, first_ms) = timed(|| run_store(&store, text));
        let warm: Vec<f64> = (0..reps)
            .map(|_| {
                let (n, ms) = timed(|| run_store(&store, text));
                assert_eq!(n, rows);
                ms
            })
            .collect();
        println!(
            "store {label} rows={rows} first_ms={first_ms:.3} warm {}",
            percentiles(warm)
        );
    }
    drop(owner);
}

// =====================================================================================
// Today's path: `urn:sparql:select graph=<every segment>` through a kernel
// =====================================================================================

fn graph_path(dir: &Path, reps: usize) {
    let segments = read_segments(dir);
    let names: Vec<&str> = segments.iter().map(|(n, _)| n.as_str()).collect();
    let graphs = names.join(" ");
    drop(segments);
    let config = LogConfig::default()
        .with_destination(Destination::File)
        .with_directory(dir);
    let handle = Arc::new(LogHandle::new(Some(dir.to_path_buf()), None, config));
    let space = Fallback::new(vec![
        Arc::new(ikigai_log::endpoints::space(handle)) as Arc<dyn Space>,
        Arc::new(ikigai_sparql::space()) as Arc<dyn Space>,
    ]);
    let kernel = Kernel::new(Arc::new(space));
    let ask = |text: &str| -> Result<usize, String> {
        let request = Request::new(Verb::Source, Iri::parse("urn:sparql:select").unwrap())
            .with_arg(
                "query",
                ArgRef::Inline(format!("{PREFIXES}{text}").into_bytes()),
            )
            .with_arg("graph", ArgRef::Inline(graphs.clone().into_bytes()));
        let repr = futures::executor::block_on(kernel.issue(request, &Capability::root()))
            .map_err(|e| e.to_string())?;
        let body = String::from_utf8(repr.bytes).unwrap();
        Ok(body.matches("\"e\":").count())
    };
    for (label, text) in QUERIES {
        let (rows, first_ms) = timed(|| ask(text));
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => {
                println!("graph {label} first_ms={first_ms:.3} refused: {e}");
                continue;
            }
        };
        let (_, repeat_ms) = timed(|| ask(text).unwrap());
        // A distinct comment per run misses the result cache and keeps the segment cache.
        let warm: Vec<f64> = (0..reps)
            .map(|i| {
                let (n, ms) = timed(|| ask(&format!("{text} # run {i}")).unwrap());
                assert_eq!(n, rows);
                ms
            })
            .collect();
        println!(
            "graph {label} rows={rows} first_ms={first_ms:.3} identical_repeat_ms={repeat_ms:.3} warm {}",
            percentiles(warm)
        );
    }
}

// =====================================================================================
// Concurrency: ingest more verified segments while reading
// =====================================================================================

fn concurrent(extra: &Path, store_dir: &Path, reps: usize) {
    let (owner, store) = DurableStore::open_shared(store_dir).unwrap();
    let extra = read_segments(extra);
    let before = store.len().unwrap();
    for (label, text) in QUERIES {
        let idle: Vec<f64> = (0..reps)
            .map(|_| timed(|| run_store(&store, text)).1)
            .collect();
        println!("idle {label} {}", percentiles(idle));
    }
    let writer = {
        let store = store.clone();
        std::thread::spawn(move || timed(|| ingest_segments(&store, &extra)))
    };
    let mut loaded: Vec<Vec<f64>> = vec![Vec::new(); QUERIES.len()];
    let mut rows_seen = Vec::new();
    while !writer.is_finished() {
        for (i, (_, text)) in QUERIES.iter().enumerate() {
            let (rows, ms) = timed(|| run_store(&store, text));
            loaded[i].push(ms);
            if i == 0 {
                rows_seen.push(rows);
            }
        }
    }
    let ((_, _, quads), ingest_ms) = writer.join().unwrap();
    for ((label, _), ms) in QUERIES.iter().zip(loaded) {
        if !ms.is_empty() {
            println!("during-ingest {label} {}", percentiles(ms));
        }
    }
    store.flush().unwrap();
    println!(
        "concurrent ingest_ms={ingest_ms:.0} quads={quads} before={before} after={} selective_rows_first={:?} selective_rows_last={:?} disk_bytes={}",
        store.len().unwrap(),
        rows_seen.first(),
        rows_seen.last(),
        disk_size(store_dir)
    );
    drop(owner);
}
