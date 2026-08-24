//! The vocabulary — which is also the transreptor's term table and the level
//! dial's threshold table.
//!
//! Three things are declared as RDF here rather than written as Rust:
//!
//!   * **what a key means** — `log:keyName` binds a line's bare `key=` column to
//!     a property, and that property's `rdfs:range` decides whether the value
//!     becomes an IRI, an integer, a boolean or a plain literal;
//!   * **what a class is about** — `log:subjectPredicate` refines the subject
//!     column per class (`log:resolved` for a resolution,
//!     `prov:wasAssociatedWith` for a liveness event);
//!   * **when a class is written** — `log:minLevel` per class, `log:rank` per
//!     level, so the emit test is one integer comparison over this graph.
//!
//! The consequence is the extension story: a module introduces entry types with
//! `rdfs:subClassOf` plus its own `log:minLevel` and `log:keyName` bindings,
//! loads them with [`Vocabulary::extend`], and neither the writer nor the
//! transreptor changes. A hard-coded table would have made every new entry type
//! a change to this crate.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, OnceLock};

use oxrdf::Term;
use oxrdfio::{RdfFormat, RdfParser};

/// The log vocabulary namespace. Self-contained in this crate — the `sig:`
/// precedent from ikigai-sign — so no arc here blocks on a `/ns` deploy. A term
/// is promoted into the shared `vocabulary.ttl` when it earns a second
/// consumer; log-specific classes are expected to stay.
pub const LOG_NS: &str = "https://ikigai-rs.dev/ns/log#";

/// The vocabulary source, embedded so the table and its documentation cannot
/// drift apart: there is only one artifact.
pub const VOCABULARY_TTL: &str = include_str!("vocabulary.ttl");

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDFS_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const RDFS_SUBCLASS_OF: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
const RDFS_RANGE: &str = "http://www.w3.org/2000/01/rdf-schema#range";
const LOG_KEY_NAME: &str = "https://ikigai-rs.dev/ns/log#keyName";
const LOG_MIN_LEVEL: &str = "https://ikigai-rs.dev/ns/log#minLevel";
const LOG_RANK: &str = "https://ikigai-rs.dev/ns/log#rank";
const LOG_SUBJECT_PREDICATE: &str = "https://ikigai-rs.dev/ns/log#subjectPredicate";
const LOG_LEVEL_CLASS: &str = "https://ikigai-rs.dev/ns/log#Level";

/// The PROV-O namespace, bound in every segment header alongside `log:`.
pub const PROV_NS: &str = "http://www.w3.org/ns/prov#";

/// `log:Entry` — the root of the entry hierarchy.
pub const ENTRY_CLASS: &str = "https://ikigai-rs.dev/ns/log#Entry";

/// `log:Message` — the convenience write's class, and the root of the prose
/// hierarchy whose SUBCLASSES carry severity.
pub const MESSAGE_CLASS: &str = "https://ikigai-rs.dev/ns/log#Message";
/// `log:Warning`.
pub const WARNING_CLASS: &str = "https://ikigai-rs.dev/ns/log#Warning";
/// `log:Error`.
pub const ERROR_CLASS: &str = "https://ikigai-rs.dev/ns/log#Error";
/// `log:ProcessStart` — always-land liveness, first entry of every segment.
pub const PROCESS_START_CLASS: &str = "https://ikigai-rs.dev/ns/log#ProcessStart";
/// `log:ProcessStop` — always-land, written only by an ORDERLY close.
pub const PROCESS_STOP_CLASS: &str = "https://ikigai-rs.dev/ns/log#ProcessStop";
/// `log:ConfigChange` — always-land.
pub const CONFIG_CHANGE_CLASS: &str = "https://ikigai-rs.dev/ns/log#ConfigChange";
/// `log:LevelChange` — always-land.
pub const LEVEL_CHANGE_CLASS: &str = "https://ikigai-rs.dev/ns/log#LevelChange";
/// `log:LevelChangeRejected` — always-land.
pub const LEVEL_CHANGE_REJECTED_CLASS: &str = "https://ikigai-rs.dev/ns/log#LevelChangeRejected";
/// `log:CapabilityDenied` — always-land.
pub const CAPABILITY_DENIED_CLASS: &str = "https://ikigai-rs.dev/ns/log#CapabilityDenied";
/// `log:Rotation` — always-land, and the OTHER way a segment ends finally.
///
/// A rotated segment is as immutable as a stopped one, so this class is half of
/// what `is_finished` asks: keying that question on `log:ProcessStop` alone
/// leaves every rotated segment uncacheable forever.
pub const ROTATION_CLASS: &str = "https://ikigai-rs.dev/ns/log#Rotation";
/// `log:ChainBroken` — always-land. A rotation that could not verify its
/// predecessor lands one of these: an entry, not an exception, because the
/// failure belongs in the record it is a failure of.
pub const CHAIN_BROKEN_CLASS: &str = "https://ikigai-rs.dev/ns/log#ChainBroken";

/// The level a class is written at when neither it nor any of its superclasses
/// declares one: the day-to-day default, so an undeclared extension is visible
/// rather than silently invisible.
pub const DEFAULT_MIN_LEVEL: &str = "https://ikigai-rs.dev/ns/log#info";

/// A vocabulary that will not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VocabError(pub String);

impl fmt::Display for VocabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vocabulary: {}", self.0)
    }
}

impl std::error::Error for VocabError {}

/// What the graph says about one entry class.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassDef {
    /// The class IRI.
    pub iri: String,
    /// Its declared superclasses, in IRI order.
    pub super_classes: Vec<String>,
    /// Its own `log:minLevel`, if it declares one — otherwise inherited.
    pub min_level: Option<String>,
    /// The precise predicate its subject column means, if declared.
    pub subject_predicate: Option<String>,
}

/// What the graph says about one `key=` column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDef {
    /// The bare key, as written in a line.
    pub key: String,
    /// The property the key binds to.
    pub property: String,
    /// The property's `rdfs:range` — what the value transrepts to.
    pub range: Option<String>,
}

/// The parsed vocabulary graph, indexed for the three questions the writer and
/// the transreptor ask of it.
#[derive(Clone, Debug, Default)]
pub struct Vocabulary {
    classes: BTreeMap<String, ClassDef>,
    keys: BTreeMap<String, KeyDef>,
    levels: BTreeMap<String, i64>,
}

impl Vocabulary {
    /// The built-in vocabulary, parsed once.
    pub fn builtin() -> &'static Vocabulary {
        static BUILTIN: OnceLock<Vocabulary> = OnceLock::new();
        BUILTIN.get_or_init(|| {
            Vocabulary::parse(VOCABULARY_TTL).expect("the embedded vocabulary parses")
        })
    }

    /// The built-in vocabulary as a shared handle — what a writer that has no
    /// module extensions to load takes.
    ///
    /// A `Writer` holds an `Arc<Vocabulary>` rather than a `&'static` one
    /// because the extension story is the point: a host that has loaded a
    /// module's own `rdfs:subClassOf` declarations passes its extended graph,
    /// and it did not come from an `include_str!`.
    pub fn shared_builtin() -> Arc<Vocabulary> {
        static SHARED: OnceLock<Arc<Vocabulary>> = OnceLock::new();
        SHARED
            .get_or_init(|| Arc::new(Vocabulary::builtin().clone()))
            .clone()
    }

    /// Parse a vocabulary from Turtle.
    pub fn parse(ttl: &str) -> Result<Vocabulary, VocabError> {
        let mut vocab = Vocabulary::default();
        vocab.extend(ttl)?;
        Ok(vocab)
    }

    /// Merge further Turtle into this vocabulary — a module's own
    /// `rdfs:subClassOf` extension, loaded at runtime.
    ///
    /// Later declarations win over earlier ones for the single-valued facts
    /// (`log:minLevel`, `log:subjectPredicate`, `rdfs:range`), so an extension
    /// can refine a class it did not declare; superclasses accumulate.
    pub fn extend(&mut self, ttl: &str) -> Result<(), VocabError> {
        // Ranges are collected separately: a property's rdfs:range and its
        // log:keyName can arrive in either order, and in different files.
        let mut ranges: BTreeMap<String, String> = BTreeMap::new();
        let mut key_of: BTreeMap<String, String> = BTreeMap::new();

        for quad in RdfParser::from_format(RdfFormat::Turtle).for_slice(ttl.as_bytes()) {
            let quad = quad.map_err(|e| VocabError(e.to_string()))?;
            let subject = quad.subject.to_string();
            let subject = subject.trim_matches(['<', '>']).to_string();
            let predicate = quad.predicate.as_str();
            match (predicate, &quad.object) {
                (RDF_TYPE, Term::NamedNode(n)) if n.as_str() == RDFS_CLASS => {
                    self.class_mut(&subject);
                }
                (RDF_TYPE, Term::NamedNode(n)) if n.as_str() == LOG_LEVEL_CLASS => {
                    self.levels.entry(subject).or_insert(0);
                }
                (RDFS_SUBCLASS_OF, Term::NamedNode(n)) => {
                    let parent = n.as_str().to_string();
                    let class = self.class_mut(&subject);
                    if !class.super_classes.contains(&parent) {
                        class.super_classes.push(parent);
                    }
                }
                (LOG_MIN_LEVEL, Term::NamedNode(n)) => {
                    self.class_mut(&subject).min_level = Some(n.as_str().to_string());
                }
                (LOG_SUBJECT_PREDICATE, Term::NamedNode(n)) => {
                    self.class_mut(&subject).subject_predicate = Some(n.as_str().to_string());
                }
                (LOG_RANK, Term::Literal(l)) => {
                    let rank = l.value().parse::<i64>().map_err(|_| {
                        VocabError(format!("log:rank on {subject} is not an integer"))
                    })?;
                    self.levels.insert(subject, rank);
                }
                (LOG_KEY_NAME, Term::Literal(l)) => {
                    key_of.insert(subject, l.value().to_string());
                }
                (RDFS_RANGE, Term::NamedNode(n)) => {
                    ranges.insert(subject, n.as_str().to_string());
                }
                _ => {}
            }
        }

        for (property, key) in key_of {
            let range = ranges
                .get(&property)
                .cloned()
                .or_else(|| self.keys.get(&key).and_then(|k| k.range.clone()));
            self.keys.insert(
                key.clone(),
                KeyDef {
                    key,
                    property,
                    range,
                },
            );
        }
        // A range declared in a later file for a key bound in an earlier one.
        for key in self.keys.values_mut() {
            if key.range.is_none() {
                key.range = ranges.get(&key.property).cloned();
            }
        }
        Ok(())
    }

    fn class_mut(&mut self, iri: &str) -> &mut ClassDef {
        self.classes
            .entry(iri.to_string())
            .or_insert_with(|| ClassDef {
                iri: iri.to_string(),
                ..ClassDef::default()
            })
    }

    /// What the graph says about a class, if it says anything.
    pub fn class(&self, iri: &str) -> Option<&ClassDef> {
        self.classes.get(iri)
    }

    /// What the graph says about a `key=` column, if it says anything. `None`
    /// is not an error: an unclaimed key still lands losslessly, flagged
    /// `log:undeclaredKey`, so drift is measurable rather than silent.
    pub fn key(&self, name: &str) -> Option<&KeyDef> {
        self.keys.get(name)
    }

    /// A level's rank, or `None` for a level this graph does not know. Resolve
    /// a segment's level through this ONCE, at segment start, where a bad level
    /// can fail loudly — never per entry.
    pub fn rank(&self, level_iri: &str) -> Option<i64> {
        self.levels.get(level_iri).copied()
    }

    /// Every level, IRI and rank.
    pub fn levels(&self) -> impl Iterator<Item = (&str, i64)> {
        self.levels.iter().map(|(iri, rank)| (iri.as_str(), *rank))
    }

    /// Every class the graph describes.
    pub fn classes(&self) -> impl Iterator<Item = &ClassDef> {
        self.classes.values()
    }

    /// Every declared key.
    pub fn keys(&self) -> impl Iterator<Item = &KeyDef> {
        self.keys.values()
    }

    /// The level a class is written at: its own `log:minLevel`, else the
    /// nearest superclass that declares one, else [`DEFAULT_MIN_LEVEL`].
    ///
    /// Breadth-first, so the closest declaration wins, and cycle-safe, because
    /// nothing stops an extension from writing one.
    pub fn min_level(&self, class_iri: &str) -> &str {
        let mut seen: Vec<&str> = Vec::new();
        let mut queue: Vec<&str> = vec![class_iri];
        while let Some(iri) = queue.first().copied() {
            queue.remove(0);
            if seen.contains(&iri) {
                continue;
            }
            seen.push(iri);
            if let Some(class) = self.classes.get(iri) {
                if let Some(level) = &class.min_level {
                    return level;
                }
                queue.extend(class.super_classes.iter().map(String::as_str));
            }
        }
        DEFAULT_MIN_LEVEL
    }

    /// The predicate a class's subject column means, walking superclasses the
    /// same way `min_level` does.
    pub fn subject_predicate(&self, class_iri: &str) -> Option<&str> {
        let mut seen: Vec<&str> = Vec::new();
        let mut queue: Vec<&str> = vec![class_iri];
        while let Some(iri) = queue.first().copied() {
            queue.remove(0);
            if seen.contains(&iri) {
                continue;
            }
            seen.push(iri);
            if let Some(class) = self.classes.get(iri) {
                if let Some(predicate) = &class.subject_predicate {
                    return Some(predicate);
                }
                queue.extend(class.super_classes.iter().map(String::as_str));
            }
        }
        None
    }

    /// Whether a class is written into a segment running at `segment_rank`.
    ///
    /// One comparison, and `log:always` (rank -1) needs no special case: it
    /// sorts below every settable level, which is the whole always-land set
    /// implemented by arithmetic instead of by a list in code.
    pub fn emits(&self, class_iri: &str, segment_rank: i64) -> bool {
        match self.rank(self.min_level(class_iri)) {
            Some(min) => min <= segment_rank,
            // A class whose declared minimum is a level nothing defines cannot
            // be placed on the dial. Writing it is the safe failure: a spurious
            // entry is visible, a silently dropped one is exactly the hole the
            // whole design exists to prevent.
            None => true,
        }
    }

    /// Whether `class_iri` is `ancestor`, or descends from it.
    pub fn is_a(&self, class_iri: &str, ancestor: &str) -> bool {
        let mut seen: Vec<&str> = Vec::new();
        let mut queue: Vec<&str> = vec![class_iri];
        while let Some(iri) = queue.first().copied() {
            queue.remove(0);
            if iri == ancestor {
                return true;
            }
            if seen.contains(&iri) {
                continue;
            }
            seen.push(iri);
            if let Some(class) = self.classes.get(iri) {
                queue.extend(class.super_classes.iter().map(String::as_str));
            }
        }
        false
    }
}
