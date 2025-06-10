use serde::{Deserialize, Serialize};
use sha2::digest::{generic_array::GenericArray, OutputSizeUser};
use sha2::{Digest, Sha256}; // Import Serialize and Deserialize

pub type HashDigest = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;

#[derive(Debug)]
pub struct Merkle<T> {
    pub layers: Vec<Vec<HashDigest>>,
    pub data: Vec<T>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum Direction {
    Left,
    Right,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // Add Serialize and Deserialize
pub struct MerkleInclusionPath<T> {
    pub value: T,
    pub path: Vec<(HashDigest, Direction)>,
}

impl<T> Merkle<T> {
    pub fn root(&self) -> HashDigest {
        self.layers.last().unwrap()[0]
    }

    pub fn open(&self, index: usize) -> Option<MerkleInclusionPath<T>>
    where
        T: Clone,
    {
        if index >= self.data.len() {
            return None;
        }

        let value = self.data[index].clone();
        let mut path = Vec::new();
        let mut current_index = index;

        for layer in &self.layers {
            let (sibling_index, direction) = if current_index % 2 == 0 {
                (current_index + 1, Direction::Right)
            } else {
                (current_index - 1, Direction::Left)
            };

            if sibling_index < layer.len() {
                path.push((layer[sibling_index], direction));
            }

            current_index /= 2;
        }

        Some(MerkleInclusionPath { value, path })
    }
}

impl<T> Merkle<T>
where
    T: AsRef<[u8]>,
{
    pub fn commit(data: Vec<T>) -> Self {
        assert!(
            data.len().is_power_of_two(),
            "Data length must be a power of two"
        );

        let first_layer: Vec<HashDigest> = data.iter().map(|item| hash_leaf(item)).collect();

        let mut layers: Vec<Vec<HashDigest>> = vec![first_layer];

        while layers.last().unwrap().len() > 1 {
            let current_layer = layers.last().unwrap();
            let next_layer: Vec<HashDigest> = current_layer
                .chunks(2)
                .map(|pair| hash_node(&pair[0], &pair[1]))
                .collect();
            layers.push(next_layer);
        }

        Merkle { layers, data }
    }
}

impl<T> Merkle<Vec<T>>
where
    T: AsRef<[u8]>,
{
    pub fn batch_commit(data: Vec<Vec<T>>) -> Self {
        // Ensure all batches are present and have the same length
        assert!(!data.is_empty(), "Data must not be empty");
        let batch_size = data[0].len();
        assert!(
            batch_size.is_power_of_two(),
            "Each batch length must be a power of two"
        );

        // Ensure all batches have the same length
        for batch in &data {
            assert_eq!(
                batch.len(),
                batch_size,
                "All batches must have the same length"
            );
        }

        // Hash each batch as a whole to create the first layer
        let first_layer: Vec<HashDigest> = data
            .iter()
            .map(|batch| {
                // Create a combined hash for the entire batch
                let mut hasher = Sha256::new();
                for item in batch {
                    hasher.update(item.as_ref());
                }
                hasher.finalize()
            })
            .collect();

        // Build the Merkle tree from the first layer
        let mut layers: Vec<Vec<HashDigest>> = vec![first_layer];

        while layers.last().unwrap().len() > 1 {
            let current_layer = layers.last().unwrap();
            let next_layer: Vec<HashDigest> = current_layer
                .chunks(2)
                .map(|pair| hash_node(&pair[0], &pair[1]))
                .collect();
            layers.push(next_layer);
        }

        Merkle { layers, data }
    }
}

fn hash_leaf<T: AsRef<[u8]>>(item: &T) -> HashDigest {
    let mut hasher = Sha256::new();
    hasher.update(item.as_ref());
    hasher.finalize()
}

fn hash_node(left: &HashDigest, right: &HashDigest) -> HashDigest {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

pub enum MerkleInclusionPathError {
    IncompatibleHash(HashDigest, HashDigest),
    IncompatibleIndex(usize, usize),
}

impl std::fmt::Debug for MerkleInclusionPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleInclusionPathError::IncompatibleHash(hash1, hash2) => {
                write!(
                    f,
                    "Incompatible hash. Expected {hash1:x?}, found {hash2:x?}"
                )
            }
            MerkleInclusionPathError::IncompatibleIndex(index1, index2) => {
                write!(f, "Incompatible index. Expected {index1}, found {index2}")
            }
        }
    }
}

impl<T> MerkleInclusionPath<T>
where
    T: AsRef<[u8]> + Clone,
{
    pub fn verify(&self, root: &HashDigest, index: usize) -> Result<(), MerkleInclusionPathError> {
        let mut computed_hash = {
            let mut hasher = Sha256::new();
            hasher.update(self.value.as_ref());
            hasher.finalize()
        };
        let mut computed_index = 0;
        for (i, (sibling_hash, direction)) in self.path.iter().enumerate() {
            match direction {
                Direction::Left => {
                    computed_index += 1 << i;
                    computed_hash = hash_node(sibling_hash, &computed_hash)
                }
                Direction::Right => computed_hash = hash_node(&computed_hash, sibling_hash),
            };
        }

        if &computed_hash != root {
            return Err(MerkleInclusionPathError::IncompatibleHash(
                *root,
                computed_hash,
            ));
        }
        if computed_index != index {
            return Err(MerkleInclusionPathError::IncompatibleIndex(
                index,
                computed_index,
            ));
        }
        Ok(())
    }
}

impl<T> MerkleInclusionPath<Vec<T>>
where
    T: AsRef<[u8]> + Clone,
{
    pub fn batch_verify(
        &self,
        root: &HashDigest,
        index: usize,
    ) -> Result<(), MerkleInclusionPathError> {
        // For batch verification, we need to hash the entire batch first
        let mut computed_hash = {
            let mut hasher = Sha256::new();
            for item in &self.value {
                hasher.update(item.as_ref());
            }
            hasher.finalize()
        };

        // Then follow the same verification process as the regular verify method
        let mut computed_index = 0;
        for (i, (sibling_hash, direction)) in self.path.iter().enumerate() {
            match direction {
                Direction::Left => {
                    computed_index += 1 << i;
                    computed_hash = hash_node(sibling_hash, &computed_hash)
                }
                Direction::Right => computed_hash = hash_node(&computed_hash, sibling_hash),
            };
        }

        if &computed_hash != root {
            return Err(MerkleInclusionPathError::IncompatibleHash(
                *root,
                computed_hash,
            ));
        }
        if computed_index != index {
            return Err(MerkleInclusionPathError::IncompatibleIndex(
                index,
                computed_index,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[test]
fn merkle_test() {
    let data = vec![[0], [8], [4], [1], [5], [7], [6], [1]];
    let merkle_tree = Merkle::commit(data);

    println!("Merkle Root:\n {:x?}", merkle_tree.root());
    let proof = merkle_tree.open(5).unwrap();
    println!("Inclusion Path for index 5:\n {proof:x?}");
    proof.verify(&merkle_tree.root(), 5).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_test() {
        let data = vec![[0], [8], [4], [1], [5], [7], [6], [1]];
        let merkle_tree = Merkle::commit(data);

        println!("Merkle Root:\n {:x?}", merkle_tree.root());
        let proof = merkle_tree.open(5).unwrap();
        println!("Inclusion Path for index 5:\n {proof:x?}");
        proof.verify(&merkle_tree.root(), 5).unwrap();
    }

    #[test]
    fn batched_merkle_test() {
        // Create batched data with random values in the format vec![8,2]
        let data = vec![
            vec![[0], [8], [4], [1], [5], [7], [6], [1]],
            vec![[1], [3], [2], [3], [2], [1], [2], [3]],
        ];

        // Create a batched Merkle tree
        let merkle_tree = Merkle::batch_commit(data);

        println!("Batched Merkle Root:\n {:x?}", merkle_tree.root());

        // Open and verify a proof for batch index 5
        let proof = merkle_tree.open(5).unwrap();
        println!("Batched Inclusion Path for index 5:\n {proof:x?}");

        // Verify using batch_verify
        proof.batch_verify(&merkle_tree.root(), 5).unwrap();

        // Try another index
        let proof = merkle_tree.open(2).unwrap();
        println!("Batched Inclusion Path for index 2:\n {proof:x?}");
        proof.batch_verify(&merkle_tree.root(), 2).unwrap();

        // Verify that incorrect index fails
        assert!(proof.batch_verify(&merkle_tree.root(), 1).is_err());
    }
}
