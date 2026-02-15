use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Archive,
    Deserialize,
    Serialize,
    SerdeSerialize,
    SerdeDeserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
#[repr(C)]
pub struct ImmortalityRule {
    pub framework: String,
    pub patterns: Vec<String>,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub action: Option<String>,
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Archive,
    Deserialize,
    Serialize,
    SerdeSerialize,
    SerdeDeserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
#[repr(C)]
pub struct MetaPattern {
    #[serde(default)]
    pub exact_matches: Vec<String>,
    #[serde(default)]
    pub suffix_matches: Vec<String>,
    #[serde(default)]
    pub prefix_matches: Vec<String>,
    #[serde(default)]
    pub syntax_markers: Vec<String>,
}

impl MetaPattern {
    pub fn merge(&mut self, other: MetaPattern) {
        self.exact_matches.extend(other.exact_matches);
        self.suffix_matches.extend(other.suffix_matches);
        self.prefix_matches.extend(other.prefix_matches);
        self.syntax_markers.extend(other.syntax_markers);
    }

    pub fn sort(&mut self) {
        self.exact_matches.sort();
        self.suffix_matches.sort();
        self.prefix_matches.sort();
        self.syntax_markers.sort();
    }
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Archive,
    Deserialize,
    Serialize,
    SerdeSerialize,
    SerdeDeserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
#[repr(C)]
pub struct WisdomSet {
    pub immortality_rules: Vec<ImmortalityRule>,
    pub meta_patterns: MetaPattern,
}

impl WisdomSet {
    pub fn sort(&mut self) {
        self.immortality_rules.sort();
        self.meta_patterns.sort();
    }
}

// Helper for JSON deserialization of files like immortality_rules.json
#[derive(Debug, SerdeDeserialize)]
pub struct ImmortalityRulesWrapper {
    pub immortality_rules: Vec<ImmortalityRule>,
}
