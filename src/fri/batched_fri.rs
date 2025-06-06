use crate::{
    merkle_tree::{HashDigest, Merkle, MerkleInclusionPath},
    ntt::NttField,
    transcript::{HashableField, Transcript},
};

use super::{FriProofError, FriProverData, QueryProof, ReedSolomonPair};

pub struct BatchedFriProverData<F> {
    // batched commit
    pub batch_layer: Merkle<Vec<ReedSolomonPair<F>>>,
    pub fingerprint_r: F,
    pub fri_data: FriProverData<F>,
}

pub struct BatchedQueryProof<F> {
    pub batch_layer: MerkleInclusionPath<Vec<ReedSolomonPair<F>>>,
    pub query_proof: QueryProof<F>,
}

pub struct BatchedFriProof<F> {
    pub batch_layer_commitment: HashDigest,
    pub commitments: Vec<HashDigest>,
    pub queries: Vec<BatchedQueryProof<F>>,
    pub last_elem: F,
    pub last_random: [u8; 32],
}

// USEFUL FUNCTION. USE ITERATORS `impl Iterator<Item = F>` INSTEAD OF ARRAY SLICES
fn fingerprint<F: NttField>(r: F, coeffs: &[F]) -> F {
    todo!()
}

impl<F: HashableField + NttField> BatchedFriProverData<F> {
    pub fn init(codes: &[Vec<F>], transcript: &mut Transcript) -> Self {
        // similar to normal fri, you verify that all codes are powers of 2 (check that they have the same size too!)
        // create one merkle tree per code and add them to the batch_layer.
        // create an empty fri data
        // absorb all merkle trees
        // create the fingerprint random number
        // absorb the fingerprint random number
        todo!()
    }

    pub fn batched_fold_step(&mut self, gen_pows: &[F], r: F, transcript: &mut Transcript) {
        // similar to normal fold step, but instead of last_data you will get the data of all trees from the batch layer
        // and whenever you would take last_data[i] instead you take the fingerprint of all data[j][i] for all j
        // next_data will go into the normal fri data
        todo!()
    }

    pub fn fold(gen_pows: &[F], code: &[F], transcript: &mut Transcript) -> Self {
        // similar to normal fold, except that the first step is a batched_fold_step. all other steps are normal
        todo!()
    }

    pub fn open_query_at(&self, index: usize) -> QueryProof<F> {
        todo!()
    }
}

impl<F: HashableField + NttField> BatchedFriProof<F> {
    pub fn prove(code: &[F], gen_pows: &[F], transcript: &mut Transcript) -> Self {
        todo!()
    }
}
