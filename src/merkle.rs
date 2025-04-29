use sha2::digest::{generic_array::GenericArray, OutputSizeUser};
use sha2::{Digest, Sha256};

pub type HashDigest = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;

#[derive(Debug)]
pub struct Merkle {
    pub root: HashDigest,
    pub layers: Vec<Vec<HashDigest>>,
}

#[derive(Debug)]
pub struct MerkleInclusionPath {
    pub value: Vec<u8>,
    pub path: Vec<(HashDigest, bool)>,
}

impl Merkle {
    pub fn commit(data: Vec<u8>) -> Merkle {
        assert!(
            data.len().is_power_of_two(),
            "Data length must be a power of two"
        );

        let leaf_hashes: Vec<HashDigest> = data.chunks_exact(1).map(Self::hash_leaf).collect();

        let mut layers: Vec<Vec<HashDigest>> = vec![leaf_hashes];

        while layers.last().unwrap().len() > 1 {
            let current_layer = layers.last().unwrap();
            let next_layer: Vec<HashDigest> = current_layer
                .chunks(2)
                .map(|pair| Self::hash_node(&pair[0], &pair[1]))
                .collect();
            layers.push(next_layer);
        }

        Merkle {
            root: layers.last().unwrap()[0].clone(),
            layers,
        }
    }

    fn hash_leaf(data: &[u8]) -> HashDigest {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    }

    fn hash_node(left: &HashDigest, right: &HashDigest) -> HashDigest {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize()
    }
}
