use bitvec::prelude::{BitVec, Lsb0};
use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// Persisted deterministic Bloom-compatible filter for hallucinated package names.
///
/// The upstream `bloom` crate sizes the filter, but its default `RandomState`
/// hashers are process-random and unsuitable for archival replay. This struct
/// stores the raw bitset plus fixed hashing parameters so `wisdom.rkyv` can be
/// memory-mapped and queried deterministically across sessions.
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
    CheckBytes,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
#[repr(C)]
pub struct SlopsquatFilter {
    pub bit_bytes: Vec<u8>,
    pub num_bits: u32,
    pub num_hashes: u32,
}

impl SlopsquatFilter {
    pub fn with_rate(rate: f32, expected_num_items: u32) -> Self {
        if expected_num_items == 0 {
            return Self::default();
        }
        let num_bits = bloom::needed_bits(rate, expected_num_items) as u32;
        let num_hashes = bloom::optimal_num_hashes(num_bits as usize, expected_num_items);
        let bits = bitvec::bitvec![u8, Lsb0; 0; num_bits as usize];
        Self {
            bit_bytes: bits.into_vec(),
            num_bits,
            num_hashes,
        }
    }

    pub fn from_seed_corpus<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let seeds: Vec<String> = items.into_iter().map(|s| s.as_ref().to_string()).collect();
        if seeds.is_empty() {
            return Self::default();
        }
        let mut filter = Self::with_rate(0.001, seeds.len() as u32);
        for seed in &seeds {
            filter.insert(seed);
        }
        filter
    }

    pub fn insert(&mut self, item: &str) {
        if self.num_bits == 0 || self.num_hashes == 0 {
            return;
        }
        let normalized = Self::normalize_name(item);
        let mut bits = BitVec::<u8, Lsb0>::from_vec(self.bit_bytes.clone());
        bits.resize(self.num_bits as usize, false);
        for idx in self.indices(&normalized) {
            bits.set(idx, true);
        }
        self.bit_bytes = bits.into_vec();
    }

    pub fn probably_contains(&self, item: &str) -> bool {
        if self.num_bits == 0 || self.num_hashes == 0 {
            return false;
        }
        let normalized = Self::normalize_name(item);
        let mut bits = BitVec::<u8, Lsb0>::from_vec(self.bit_bytes.clone());
        bits.resize(self.num_bits as usize, false);
        let hit = self.indices(&normalized).all(|idx| bits[idx]);
        hit
    }

    fn indices<'a>(&'a self, item: &'a str) -> impl Iterator<Item = usize> + 'a {
        let h1 = Self::stable_hash(0x11, item);
        let h2 = Self::stable_hash(0xA7, item).max(1);
        (0..self.num_hashes).map(move |i| {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            (combined % self.num_bits as u64) as usize
        })
    }

    fn stable_hash(domain: u8, item: &str) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[domain]);
        hasher.update(item.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest.as_bytes()[..8]);
        u64::from_le_bytes(bytes)
    }

    fn normalize_name(item: &str) -> String {
        item.trim().to_ascii_lowercase().replace('_', "-")
    }
}

#[cfg(test)]
mod tests {
    use super::SlopsquatFilter;

    #[test]
    fn inserted_seed_is_detected() {
        let filter = SlopsquatFilter::from_seed_corpus(["py-react-vsc"]);
        assert!(filter.probably_contains("py-react-vsc"));
    }

    #[test]
    fn unknown_seed_is_not_detected_in_small_corpus() {
        let filter = SlopsquatFilter::from_seed_corpus([
            "py-react-vsc",
            "django-tailwind-fast",
            "node-express-secure-template",
        ]);
        assert!(!filter.probably_contains("requests"));
    }
}
