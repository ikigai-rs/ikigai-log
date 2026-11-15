//! Ledger #3642: an hourly RFC 9162 Merkle root over segment seals, and a key
//! history anchored outside the operator's control.

use std::sync::{Arc, Mutex};

use ikigai_log::anchor::{
    verify_anchored_heads, verify_key_history, Anchor, AnchorCheck, AnchorFinding, Anchored,
    KeyChangeError, KeyHistory, KeyRecord, Receipt, GENESIS, RFC3161,
};
use ikigai_log::merkle::{
    check_heads, consistency_proof, hourly_heads, inclusion_proof, leaf_hash, parse_tagged_node,
    root, seal_leaves, tagged_node, verify_consistency, verify_inclusion, HeadFinding, NodeHash,
    TreeHead, HOUR_MILLIS,
};
use ikigai_log::{
    verify_chain, ClosureSink, Entry, LogConfig, Prev, SealPolicy, Timestamp, Vocabulary, Writer,
    WriterOptions, MESSAGE_CLASS,
};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn node(text: &str) -> NodeHash {
    hex(text).try_into().unwrap()
}

/// The leaves of the RFC 6962 reference tree, as the Certificate Transparency
/// implementations test against them.
const REFERENCE_LEAVES: [&str; 8] = [
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
];

/// The root of the first n reference leaves, n = 1..=8.
const REFERENCE_ROOTS: [&str; 8] = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

fn reference() -> Vec<NodeHash> {
    REFERENCE_LEAVES
        .iter()
        .map(|leaf| leaf_hash(&hex(leaf)))
        .collect()
}

#[test]
fn roots_match_the_rfc_6962_reference_tree() {
    let leaves = reference();
    for (n, expected) in REFERENCE_ROOTS.iter().enumerate() {
        assert_eq!(
            tagged_node(&root(&leaves[..n + 1])),
            format!("sha256:{expected}"),
            "root of {} leaves",
            n + 1
        );
    }
    assert_eq!(
        tagged_node(&root(&[])),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn inclusion_proof_matches_the_reference_path() {
    let leaves = reference();
    let proof = inclusion_proof(&leaves, 0).unwrap();
    assert_eq!(
        proof,
        vec![
            node("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
            node("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
            node("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"),
        ]
    );
}

fn synthetic(n: usize) -> Vec<NodeHash> {
    (0..n)
        .map(|i| leaf_hash(format!("leaf {i}").as_bytes()))
        .collect()
}

#[test]
fn every_inclusion_proof_verifies_and_a_wrong_one_does_not() {
    for n in 1..=40usize {
        let leaves = synthetic(n);
        let r = root(&leaves);
        for i in 0..n {
            let proof = inclusion_proof(&leaves, i).unwrap();
            assert!(verify_inclusion(i as u64, n as u64, &leaves[i], &proof, &r));
            let other = leaf_hash(b"not a leaf");
            assert!(!verify_inclusion(i as u64, n as u64, &other, &proof, &r));
            if n > 1 {
                let wrong = (i + 1) % n;
                assert!(!verify_inclusion(
                    wrong as u64,
                    n as u64,
                    &leaves[i],
                    &proof,
                    &r
                ));
                let mut bent = proof.clone();
                bent[0][0] ^= 1;
                assert!(!verify_inclusion(i as u64, n as u64, &leaves[i], &bent, &r));
            }
        }
        assert!(inclusion_proof(&leaves, n).is_none());
    }
}

#[test]
fn every_consistency_proof_verifies_and_a_rewritten_prefix_does_not() {
    for n in 1..=40usize {
        let leaves = synthetic(n);
        let new_root = root(&leaves);
        for m in 0..=n {
            let old_root = root(&leaves[..m]);
            let proof = consistency_proof(&leaves, m).unwrap();
            assert!(
                verify_consistency(m as u64, n as u64, &old_root, &new_root, &proof),
                "{m} -> {n}"
            );
            if m > 0 && m < n {
                // The same old head, against a tree whose prefix was rewritten.
                let mut rewritten = leaves.clone();
                rewritten[m - 1] = leaf_hash(b"rewritten");
                let forged_root = root(&rewritten);
                let forged = consistency_proof(&rewritten, m).unwrap();
                assert!(
                    !verify_consistency(m as u64, n as u64, &old_root, &forged_root, &forged),
                    "rewritten {m} -> {n}"
                );
            }
        }
        assert!(consistency_proof(&leaves, n + 1).is_none());
    }
}

#[test]
fn tagged_nodes_round_trip_and_refuse_anything_else() {
    let hash = leaf_hash(b"x");
    assert_eq!(parse_tagged_node(&tagged_node(&hash)), Some(hash));
    assert_eq!(parse_tagged_node("sha256:00"), None);
    assert_eq!(parse_tagged_node(&tagged_node(&hash).to_uppercase()), None);
    assert_eq!(
        parse_tagged_node(&tagged_node(&hash).replace("sha256", "sha512")),
        None
    );
}

// =====================================================================================
// Seals as leaves, one head per hour
// =====================================================================================

fn base() -> u64 {
    Timestamp::parse("2026-11-15T10:00:00.000Z")
        .unwrap()
        .as_millis()
}

fn at(minutes: u64) -> Timestamp {
    Timestamp::from_millis(base() + minutes * 60_000)
}

fn message(minutes: u64) -> Entry {
    Entry::new(at(minutes), MESSAGE_CLASS, "urn:subject").with("msg", "hello")
}

fn writer(lines: &Arc<Mutex<Vec<String>>>, minutes: u64, prev: Prev) -> Writer {
    let lines = lines.clone();
    Writer::open_with_sink_and(
        &LogConfig::default().with_instance("bug:merkle"),
        Vocabulary::shared_builtin(),
        at(minutes),
        Box::new(ClosureSink(move |l: &str| {
            lines.lock().unwrap().push(l.to_string())
        })),
        WriterOptions {
            seals: SealPolicy::manual(),
            prev: Some(prev),
            ..WriterOptions::default()
        },
    )
    .unwrap()
}

fn text(lines: &Arc<Mutex<Vec<String>>>) -> String {
    lines.lock().unwrap().join("\n") + "\n"
}

/// Two segments across three hours: seals at 10:01, 11:10 and 12:10 (the
/// rotation) in the first, and 12:20 (the stop) in the second.
fn two_segments() -> Vec<(String, String)> {
    let first = Arc::new(Mutex::new(Vec::new()));
    let mut w = writer(&first, 0, Prev::Genesis);
    w.write(message(1)).unwrap();
    w.seal(at(2)).unwrap();
    w.write(message(70)).unwrap();
    w.seal(at(71)).unwrap();
    let second_name = "urn:log:bug:merkle:2026-11-15T12-10-00Z";
    let first_name = w.segment().to_string();
    let closed = w.rotate_out(at(130), Some(second_name)).unwrap();

    let second = Arc::new(Mutex::new(Vec::new()));
    let mut w = writer(&second, 130, Prev::Seal(closed.head));
    assert_eq!(w.segment(), second_name);
    w.write(message(135)).unwrap();
    w.close(at(140)).unwrap();
    vec![
        (first_name, text(&first)),
        (second_name.to_string(), text(&second)),
    ]
}

fn hour(h: &str) -> Timestamp {
    Timestamp::parse(&format!("2026-11-15T{h}:00:00.000Z")).unwrap()
}

#[test]
fn one_head_per_hour_over_a_cumulative_tree_of_seals() {
    let segments = two_segments();
    assert!(verify_chain(&segments, Vocabulary::builtin()).ok());

    let leaves = seal_leaves(&segments).unwrap();
    assert_eq!(leaves.len(), 4);
    assert_eq!(leaves[0].segment, segments[0].0);
    assert_eq!(leaves[3].segment, segments[1].0);
    // The writer's own `log:ProcessStart` is sequence 1.
    assert!(
        leaves[0]
            .data()
            .starts_with(&format!("{} 1-2 sha256:", segments[0].0)),
        "{}",
        leaves[0].data()
    );

    let heads = hourly_heads(&segments).unwrap();
    let shape: Vec<(Timestamp, u64)> = heads.iter().map(|h| (h.until, h.size)).collect();
    assert_eq!(
        shape,
        vec![(hour("11"), 1), (hour("12"), 2), (hour("13"), 4)]
    );

    let hashes: Vec<NodeHash> = leaves.iter().map(|l| l.leaf_hash()).collect();
    // Each head extends the one before it, provably.
    for pair in heads.windows(2) {
        let (old, new) = (&pair[0], &pair[1]);
        let proof = consistency_proof(&hashes[..new.size as usize], old.size as usize).unwrap();
        assert!(verify_consistency(
            old.size,
            new.size,
            &parse_tagged_node(&old.root).unwrap(),
            &parse_tagged_node(&new.root).unwrap(),
            &proof
        ));
    }
    // And every seal is provably in the last one.
    let last = heads.last().unwrap();
    for (i, hash) in hashes.iter().enumerate() {
        let proof = inclusion_proof(&hashes, i).unwrap();
        assert!(verify_inclusion(
            i as u64,
            last.size,
            hash,
            &proof,
            &parse_tagged_node(&last.root).unwrap()
        ));
    }
    assert!(check_heads(&leaves, &heads).is_empty());
}

#[test]
fn a_head_line_round_trips_and_a_bad_one_is_shown_escaped() {
    let head = hourly_heads(&two_segments()).unwrap().pop().unwrap();
    assert_eq!(TreeHead::parse(&head.render()).unwrap(), head);
    let error = TreeHead::parse("#root \u{202e}soon 1 sha256:00").unwrap_err();
    assert_eq!(
        error.to_string(),
        "bad root line: #root \\u{202e}soon 1 sha256:00"
    );
}

#[test]
fn a_stepped_back_clock_does_not_reopen_an_hour() {
    let mut leaves = seal_leaves(&two_segments()).unwrap();
    // The third seal claims 10:30, after a seal at 11:10. It counts in the
    // hour already open, so no second head lands for the 10:00 hour.
    leaves[2].at = at(30);
    let heads = ikigai_log::merkle::interval_heads(&leaves, HOUR_MILLIS);
    let shape: Vec<(Timestamp, u64)> = heads.iter().map(|h| (h.until, h.size)).collect();
    assert_eq!(
        shape,
        vec![(hour("11"), 1), (hour("12"), 3), (hour("13"), 4)]
    );
}

/// The hole the chain walk leaves: deleting the oldest segment looks like
/// retention. A head taken before the deletion sees it.
#[test]
fn deleting_the_oldest_segment_passes_the_chain_walk_but_not_a_held_head() {
    let segments = two_segments();
    let heads = hourly_heads(&segments).unwrap();

    let remaining = &segments[1..];
    assert!(verify_chain(remaining, Vocabulary::builtin()).ok());

    let findings = check_heads(&seal_leaves(remaining).unwrap(), &heads);
    // One seal is left: the one-seal head no longer matches, and the larger
    // two count seals that are gone.
    assert_eq!(findings.len(), 3, "{findings:?}");
    assert!(matches!(findings[0], HeadFinding::RootMismatch { .. }));
    assert!(matches!(
        findings[1],
        HeadFinding::Truncated { held: 1, .. }
    ));
    assert!(matches!(
        findings[2],
        HeadFinding::Truncated { held: 1, .. }
    ));
    let said = findings[0].to_string();
    assert!(
        said.contains("history before 2026-11-15T11:00:00.000Z was rewritten"),
        "{said}"
    );
}

#[test]
fn a_rewritten_seal_changes_every_root_that_counts_it() {
    let mut segments = two_segments();
    let heads = hourly_heads(&segments).unwrap();
    let leaves = seal_leaves(&segments).unwrap();
    // The operator recomputed the second seal (what any writer of the files can
    // do, since the chain is unkeyed).
    segments[0].1 = segments[0]
        .1
        .replace(&leaves[1].hash, &format!("sha256:{}", "0".repeat(64)));
    let findings = check_heads(&seal_leaves(&segments).unwrap(), &heads);
    // The head until 11:00 counted only the first seal and still stands.
    let mismatched: Vec<u64> = findings
        .iter()
        .map(|f| match f {
            HeadFinding::RootMismatch { head, .. } => head.size,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(mismatched, vec![2, 4]);
}

#[test]
fn heads_that_shrink_are_not_of_one_log() {
    let segments = two_segments();
    let leaves = seal_leaves(&segments).unwrap();
    let mut heads = hourly_heads(&segments).unwrap();
    heads.reverse();
    assert!(check_heads(&leaves, &heads)
        .iter()
        .any(|f| matches!(f, HeadFinding::Shrank { .. })));
}

#[test]
fn an_unreadable_segment_is_an_error_not_a_skipped_leaf() {
    let mut segments = two_segments();
    segments[0].1 = "not a segment\n".into();
    let error = seal_leaves(&segments).unwrap_err();
    assert_eq!(error.segment, segments[0].0);
    assert!(error.to_string().contains("cannot be leaves"));
}

// =====================================================================================
// The anchored key history
// =====================================================================================

/// A stand-in time-stamping authority: its receipt names the digest it saw and
/// the time it saw it. A real one signs both; checking that signature is the
/// host's, through the same seam.
struct Tsa {
    now: Arc<Mutex<u64>>,
}

impl Anchor for Tsa {
    fn kind(&self) -> &str {
        RFC3161
    }
    fn anchor(&self, digest: &str) -> Option<String> {
        Some(format!("t{}-{}", self.now.lock().unwrap(), &digest[7..]))
    }
}

struct TsaCheck;

impl AnchorCheck for TsaCheck {
    fn check(&self, digest: &str, receipt: &Receipt) -> Result<Timestamp, String> {
        if receipt.kind != RFC3161 {
            return Err(format!("not an {RFC3161} token: {}", receipt.kind));
        }
        let (time, seen) = receipt.token[1..]
            .split_once('-')
            .ok_or("unreadable token")?;
        if seen != &digest[7..] {
            return Err("the token's message imprint is another digest".into());
        }
        Ok(Timestamp::from_millis(
            time.parse().map_err(|_| "bad time")?,
        ))
    }
}

const LAG: u64 = 5 * 60_000;

fn honest_history(tsa: &Tsa) -> KeyHistory {
    let mut history = KeyHistory::new();
    *tsa.now.lock().unwrap() = at(0).as_millis() + 1_000;
    history
        .change(at(0), "Ed25519", "urn:key:ops-1", Some(tsa))
        .unwrap();
    *tsa.now.lock().unwrap() = at(600).as_millis() + 2_000;
    history
        .change(at(600), "Ed25519", "urn:key:ops-2", Some(tsa))
        .unwrap();
    history
}

fn tsa() -> Tsa {
    Tsa {
        now: Arc::new(Mutex::new(0)),
    }
}

#[test]
fn an_honest_key_history_verifies_and_round_trips() {
    let tsa = tsa();
    let history = honest_history(&tsa);
    assert_eq!(history.records[0].0.prev, GENESIS);
    assert_eq!(history.records[1].0.prev, history.records[0].0.digest());
    assert!(verify_key_history(&history, &TsaCheck, LAG).is_empty());

    let text = history.render();
    assert!(text.starts_with(
        "#key 2026-11-15T10:00:00.000Z Ed25519 urn:key:ops-1 genesis\n#anchor rfc3161 t"
    ));
    assert_eq!(KeyHistory::parse(&text).unwrap(), history);

    assert_eq!(history.key_at(at(0)).unwrap().key, "urn:key:ops-1");
    assert_eq!(history.key_at(at(599)).unwrap().key, "urn:key:ops-1");
    assert_eq!(history.key_at(at(600)).unwrap().key, "urn:key:ops-2");
    assert!(history.key_at(Timestamp::from_millis(base() - 1)).is_none());
}

/// The rewrite the item names: the operator swaps in a key they hold for the
/// past and re-anchors. The new receipts carry today's time.
#[test]
fn a_rewritten_and_re_anchored_history_is_late_everywhere() {
    let tsa = tsa();
    let honest = honest_history(&tsa);

    let mut forged = KeyHistory::new();
    *tsa.now.lock().unwrap() = at(60 * 24 * 30).as_millis();
    forged
        .change(at(0), "Ed25519", "urn:key:operator", Some(&tsa))
        .unwrap();
    forged
        .change(at(600), "Ed25519", "urn:key:ops-2", Some(&tsa))
        .unwrap();
    assert_ne!(forged, honest);

    let findings = verify_key_history(&forged, &TsaCheck, LAG);
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(findings
        .iter()
        .all(|f| matches!(f, AnchorFinding::Late { .. })));
    assert_eq!(
        findings[0].to_string(),
        "key record 1 (urn:key:operator) says 2026-11-15T10:00:00.000Z but was first anchored \
         at 2026-12-15T10:00:00.000Z, more than 300000 ms later: it may have been written after \
         the fact"
    );
}

#[test]
fn a_rewrite_that_keeps_the_old_receipts_is_rejected_and_unchained() {
    let tsa = tsa();
    let mut history = honest_history(&tsa);
    history.records[0].0.key = "urn:key:operator".into();
    let findings = verify_key_history(&history, &TsaCheck, LAG);
    assert!(matches!(
        &findings[0],
        AnchorFinding::Rejected {
            what: Anchored::Key { index: 0, .. },
            ..
        }
    ));
    assert!(matches!(
        &findings[1],
        AnchorFinding::Unchained { index: 1, .. }
    ));
    assert_eq!(findings.len(), 2, "{findings:?}");
}

#[test]
fn an_unanchored_record_is_reported_until_a_receipt_is_attached() {
    let tsa = tsa();
    let mut history = KeyHistory::new();
    history
        .change(at(0), "Ed25519", "urn:key:ops-1", None)
        .unwrap();
    let findings = verify_key_history(&history, &TsaCheck, LAG);
    assert_eq!(
        findings.iter().map(|f| f.to_string()).collect::<Vec<_>>(),
        vec![
            "key record 1 (urn:key:ops-1) has no anchor receipt: nothing outside the \
              operator's control has seen it"
        ]
    );
    *tsa.now.lock().unwrap() = at(1).as_millis();
    let digest = history.records[0].0.digest();
    let token = tsa.anchor(&digest).unwrap();
    assert!(history.attach(
        0,
        Receipt {
            kind: RFC3161.into(),
            token
        }
    ));
    assert!(verify_key_history(&history, &TsaCheck, LAG).is_empty());
}

#[test]
fn key_changes_are_refused_out_of_order_or_unprintable() {
    let mut history = KeyHistory::new();
    history
        .change(at(10), "Ed25519", "urn:key:a", None)
        .unwrap();
    assert_eq!(
        history
            .change(at(5), "Ed25519", "urn:key:b", None)
            .unwrap_err(),
        KeyChangeError::Time {
            at: at(5),
            last: Some(at(10))
        }
    );
    let error = history
        .change(at(11), "Ed25519", "urn:key:\u{202e}b", None)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "key urn:key:\\u{202e}b is not an absolute IRI without spaces"
    );
    assert!(history
        .change(at(11), "Ed 25519", "urn:key:b", None)
        .is_err());
}

#[test]
fn a_record_edited_out_of_order_is_found() {
    let mut history = KeyHistory::new();
    history.change(at(0), "Ed25519", "urn:key:a", None).unwrap();
    history
        .change(at(10), "Ed25519", "urn:key:b", None)
        .unwrap();
    let mut text = history.render();
    text = text.replace("2026-11-15T10:10:00.000Z", "2026-11-15T09:00:00.000Z");
    let edited = KeyHistory::parse(&text).unwrap();
    assert!(verify_key_history(&edited, &TsaCheck, LAG)
        .iter()
        .any(|f| matches!(f, AnchorFinding::OutOfOrder { index: 1, .. })));
}

#[test]
fn a_stray_anchor_line_is_refused() {
    assert!(KeyHistory::parse("#anchor rfc3161 abc\n").is_err());
    let doubled = "#key 2026-11-15T10:00:00.000Z Ed25519 urn:key:a genesis\n\
                   #anchor rfc3161 abc\n#anchor rfc3161 def\n";
    assert!(KeyHistory::parse(doubled).is_err());
    assert!(KeyRecord::parse("#key 2026-11-15T10:00:00.000Z Ed25519 not-an-iri genesis").is_err());
}

#[test]
fn anchored_heads_catch_both_a_late_anchor_and_a_rewritten_log() {
    let tsa = tsa();
    let segments = two_segments();
    let leaves = seal_leaves(&segments).unwrap();
    let anchored: Vec<(TreeHead, Option<Receipt>)> = hourly_heads(&segments)
        .unwrap()
        .into_iter()
        .map(|head| {
            *tsa.now.lock().unwrap() = head.until.as_millis() + 30_000;
            let token = tsa.anchor(&head.digest()).unwrap();
            (
                head,
                Some(Receipt {
                    kind: RFC3161.into(),
                    token,
                }),
            )
        })
        .collect();
    assert!(verify_anchored_heads(&leaves, &anchored, &TsaCheck, LAG).is_empty());

    // The oldest segment removed after the fact.
    let findings = verify_anchored_heads(
        &seal_leaves(&segments[1..]).unwrap(),
        &anchored,
        &TsaCheck,
        LAG,
    );
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| matches!(f, AnchorFinding::Head(_))));

    // A head computed over the rewritten log and anchored now.
    let mut late = anchored.clone();
    *tsa.now.lock().unwrap() = hour("13").as_millis() + 24 * HOUR_MILLIS;
    let head = &late[0].0;
    late[0].1 = Some(Receipt {
        kind: RFC3161.into(),
        token: tsa.anchor(&head.digest()).unwrap(),
    });
    let findings = verify_anchored_heads(&leaves, &late, &TsaCheck, LAG);
    assert!(matches!(
        &findings[..],
        [AnchorFinding::Late {
            what: Anchored::Head(_),
            ..
        }]
    ));
}
