use sha2::digest::{generic_array::GenericArray, OutputSizeUser};
use sha2::{Digest, Sha256};

pub type HashDigest = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;

#[derive(Debug)]
pub struct Merkle {
    pub root: HashDigest,
    pub layers: Vec<Vec<HashDigest>>,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct MerkleInclusionPath();

impl Merkle {
    pub fn commit(data: Vec<u8>) -> Merkle {
        assert!(
            data.len().is_power_of_two(),
            "Data length must be a power of two"
        );

        let first_layer: Vec<HashDigest> = data
            .chunks_exact(2)
            .map(|pair| Self::hash_node(&pair[0..1], &pair[1..2]))
            .collect();

        let mut layers: Vec<Vec<HashDigest>> = vec![first_layer];

        while layers.last().unwrap().len() > 1 {
            let current_layer = layers.last().unwrap();
            let next_layer: Vec<HashDigest> = current_layer
                .chunks(2)
                .map(|pair| Self::hash_node(pair[0], pair[1]))
                .collect();
            layers.push(next_layer);
        }

        Merkle {
            root: layers.last().unwrap()[0],
            layers,
            data,
        }
    }

    fn hash_node(left: impl AsRef<[u8]>, right: impl AsRef<[u8]>) -> HashDigest {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize()
    }
}
