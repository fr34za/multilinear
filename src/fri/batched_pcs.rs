use crate::{
    constraint_system::sumcheck::{SumcheckPolynomial, SumcheckTables},
    ntt::NttField,
    polynomials::MultilinearPolynomialEvals,
    transcript::{HashableField, Transcript},
};

use super::batched_fri::{BatchedFriProof, BatchedFriProverData};

pub struct BatchedPCSProverData<F> {
    // FRI data
    pub fri_data: BatchedFriProverData<F>,
    // Sumcheck data
    pub sumcheck_tables: SumcheckTables<F>,
    pub sumcheck_polynomials: Vec<SumcheckPolynomial<F>>,
}

pub struct BatchedPCSProof<F> {
    // FRI proof
    pub fri_proof: BatchedFriProof<F>,
    // Sumcheck proof
    pub sumcheck_polynomials: Vec<SumcheckPolynomial<F>>,
    // PCS claim
    pub claims: BatchedPCSClaim<F>,
}

pub struct BatchedPCSClaim<F> {
    pub claims: Vec<(Vec<F>, F)>,
}

impl<F: HashableField + NttField> BatchedPCSProverData<F> {
    pub fn init(
        claim: &BatchedPCSClaim<F>,
        poly: &[MultilinearPolynomialEvals<F>],
        code: &[Vec<F>],
        transcript: &mut Transcript,
    ) -> Self {
        // call `BatchedFriProverData::init`
        // generate a single `MultilinearPolynomialEvals` using the polynomials in `poly` using the fingerprint function
        // and the `fingerprint_r` which is inside the prover data
        // build the sumcheck tables
        // sumcheck_polynomials start empty
        todo!()
    }

    pub fn fold(
        claim: &BatchedPCSClaim<F>,
        poly: &[MultilinearPolynomialEvals<F>],
        gen_pows: &[F],
        code: &[Vec<F>],
        transcript: &mut Transcript,
    ) -> Self {
        // multilinear_pcs's fold <-> fri's fold
        // batched_pcs's fold <-> batched_fri's fold
        todo!()
    }
}

impl<F: HashableField + NttField> BatchedPCSProof<F> {
    pub fn prove(
        claim: &BatchedPCSClaim<F>,
        poly: &[MultilinearPolynomialEvals<F>],
        transcript: &mut Transcript,
    ) -> Self {
        // Compute gen_pows for the RS code

        // For each polynomial, convert the polynomial to canonical form
        // bit reverse to change endianess
        // then compute the RS code of the canonical coefficients and collect into a vector of codes

        // Run the Batched PCS fold

        // Do the queries, similar to FRI
        todo!()
    }

    pub fn verify(&self, transcript: &mut Transcript) -> Result<(), super::FriProofError> {
        todo!()
    }
}
