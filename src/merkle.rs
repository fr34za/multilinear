// Use sha256

#[derive(Default)]
pub struct Digest();

#[derive(Default)]
pub struct Merkle {
    data: Vec<u8>,
    root: Digest,
    digests: Vec<Vec<Digest>>,
}

pub struct MerkleInclusionPath {
    value: u8,
    path: (),
}

impl Merkle {
    pub fn commit(data: Vec<u8>) -> Merkle {
        assert!(data.len().is_power_of_two());
        todo!()
    }

    pub fn open(&self, index: usize) -> MerkleInclusionPath {
        assert!(index < self.data.len());
        todo!()
    }
}

impl MerkleInclusionPath {
    pub fn verify(&self) -> bool {
        todo!()
    }
}

// root                    hash1
//                        /     \
// hashes[0]        hash2        hash3
//                  /   \        /   \
// hashes[1]     hash4 hash5  hash6  hash7
//                / \   / \   / \   / \
// data:         0  8  1  4  5  7  6   1
