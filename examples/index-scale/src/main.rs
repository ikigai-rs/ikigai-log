use ikigai_log::{to_triples, Options, Vocabulary};
use ikigai_store::DurableStore;
use oxigraph::model::{NamedNode, Quad};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use std::time::Instant;

fn main() {
    let segments: usize = std::env::args()
        .nth(1)
        .expect("segment count")
        .parse()
        .unwrap();
    let (_owner, store) = DurableStore::in_memory_shared().unwrap();
    let start = Instant::now();
    let mut transrept = 0.0;
    let mut input_bytes = 0;
    for segment in 0..segments {
        let name = format!("urn:log:scale:segment:{segment}");
        let mut input = format!("# ikigai-log v1\n@prefix log: <https://ikigai-rs.dev/ns/log#> .\n@name {name}\n@instance urn:ikigai:instance:scale\n@level log:info\n@started 2023-11-14T22:13:20.000Z\n@prev genesis\n\n");
        for seq in 1..=5001 {
            let msg = if seq == 5001 { "needle" } else { "ordinary" };
            input.push_str(&format!(
                "2023-11-14T22:13:20.000Z log:Message urn:subject:scale seq={seq} msg={msg}\n"
            ));
        }
        input_bytes += input.len();
        let t = Instant::now();
        let triples = to_triples(&input, Vocabulary::builtin(), &Options::all()).unwrap();
        transrept += t.elapsed().as_secs_f64();
        let graph = NamedNode::new(name).unwrap();
        for triple in triples {
            store
                .insert(&Quad::new(
                    triple.subject,
                    triple.predicate,
                    triple.object,
                    graph.clone(),
                ))
                .unwrap();
        }
    }
    let ingest = start.elapsed().as_secs_f64();
    let query =
        "SELECT ?g ?e WHERE { GRAPH ?g { ?e <https://ikigai-rs.dev/ns/log#text> \"needle\" } }";
    let t = Instant::now();
    let QueryResults::Solutions(rows) = SparqlEvaluator::new()
        .parse_query(query)
        .unwrap()
        .on_store(&store)
        .execute()
        .unwrap()
    else {
        panic!()
    };
    let count = rows.map(|r| r.unwrap()).count();
    let elapsed = t.elapsed().as_secs_f64();
    println!("segments={segments} entries={} bytes={input_bytes} quads={} transrept_s={transrept:.3} ingest_s={ingest:.3} query_s={elapsed:.6} rows={count}", segments*5001, store.len().unwrap());
    assert_eq!(count, segments);
}
