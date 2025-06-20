use crate::{
    constraint_system::sumcheck::{SumcheckPolynomial, SumcheckTables},
    fri::{FriProofError, LOG_BLOWUP, NUM_QUERIES},
    ntt::{bit_reverse_permutation, NttField},
    polynomials::MultilinearPolynomialEvals,
    transcript::{HashableField, Transcript},
};

use super::{
    batched_fri::{fingerprint, BatchedFriProof, BatchedFriProverData},
    reed_solomon,
};

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
    pub claim: BatchedPCSClaim<F>,
}

pub struct BatchedPCSClaim<F> {
    pub inputs: Vec<F>,
    pub outputs: Vec<F>,
}

impl<F: HashableField + NttField> BatchedPCSProverData<F> {
    pub fn init(
        claim: &BatchedPCSClaim<F>,
        poly: &[MultilinearPolynomialEvals<F>],
        code: &[Vec<F>],
        transcript: &mut Transcript,
    ) -> Self {
        // absorb the claim
        for input in claim.inputs.iter() {
            transcript.absorb(input.as_ref());
        }
        for output in claim.outputs.iter() {
            transcript.absorb(output.as_ref());
        }
        // call `BatchedFriProverData::init`
        let fri_data = BatchedFriProverData::init(code, transcript);

        // generate a single `MultilinearPolynomialEvals` using the polynomials in `poly` using the fingerprint function
        // and the `fingerprint_r` which is inside the prover data
        let fingerprint_r = fri_data.fingerprint_r;
        let mut fingerprinted_evals = Vec::new();
        for i in 0..poly[0].evals.len() {
            let current_evals = poly.iter().map(|p| p.evals[i]);
            fingerprinted_evals.push(fingerprint(fingerprint_r, current_evals));
        }
        let fingerprinted_poly = MultilinearPolynomialEvals {
            evals: fingerprinted_evals,
        };

        // build the sumcheck tables
        let sumcheck_tables =
            SumcheckTables::build_tables_for_pcs(&claim.inputs, &fingerprinted_poly);

        // sumcheck_polynomials start empty
        let sumcheck_polynomials = Vec::new();

        Self {
            fri_data,
            sumcheck_tables,
            sumcheck_polynomials,
        }
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

        let mut prover_data = Self::init(claim, poly, code, transcript);
        let num_steps = code[0].len().trailing_zeros() as usize - LOG_BLOWUP;

        let fingerprint_r = prover_data.fri_data.fingerprint_r;
        let outputs = claim.outputs.iter().copied();
        let mut previous_sum = fingerprint(fingerprint_r, outputs);

        // Define the composition function
        let composition = &|x: &[F]| x[0];
        let total_degree = 2;

        for k in 0..num_steps {
            // Compute the sumcheck polynomial
            let (sumcheck_poly, r) = prover_data.sumcheck_tables.compute_sumcheck_polynomial(
                composition,
                total_degree,
                &mut previous_sum,
                transcript,
            );

            // Add the sumcheck polynomial to the vector
            prover_data.sumcheck_polynomials.push(sumcheck_poly);

            // Run fold_step from fri
            if k == 0 {
                prover_data
                    .fri_data
                    .batched_fold_step(gen_pows, r, transcript);
            } else {
                prover_data
                    .fri_data
                    .fri_data
                    .fold_step(gen_pows, k, r, transcript);
            }
        }
        assert!(prover_data.fri_data.fri_data.last_element.is_some());
        prover_data
    }
}

impl<F: HashableField + NttField> BatchedPCSProof<F> {
    pub fn prove(
        self,
        poly: &[MultilinearPolynomialEvals<F>],
        transcript: &mut Transcript,
    ) -> Self {
        // Compute gen_pows for the RS code
        let log_domain_size = poly[0].evals.len().trailing_zeros() as u64 + LOG_BLOWUP as u64;
        let gen_pows = F::pow_2_generator_powers(log_domain_size).unwrap();
        let gen = gen_pows[1];

        // For each polynomial, convert the polynomial to canonical form
        // bit reverse to change endianess
        // then compute the RS code of the canonical coefficients and collect into a vector of codes
        let mut codes_for_fri = Vec::new();
        for p in poly.iter() {
            let mut coeffs = p.to_coefficient();
            bit_reverse_permutation(&mut coeffs.coeffs);
            let code = reed_solomon(coeffs.coeffs, gen);
            codes_for_fri.push(code);
        }

        // Run the Batched PCS fold
        let prover_data =
            BatchedPCSProverData::fold(&self.claim, poly, &gen_pows, &codes_for_fri, transcript);

        // Do the queries, similar to FRI
        let domain_size = 1 << log_domain_size;
        let mut queries = Vec::with_capacity(NUM_QUERIES);
        for _ in 0..NUM_QUERIES {
            let random_u64 = u64::from_le_bytes(transcript.random()[..8].try_into().unwrap());
            let random_index = random_u64 as usize % (domain_size / 2);
            let query_proof = prover_data.fri_data.open_query_at(random_index);
            queries.push(query_proof);
            transcript.absorb(&random_index.to_le_bytes());
        }

        // Construct the BatchedPCSProof
        let fri_proof = BatchedFriProof {
            batch_commitment: prover_data.fri_data.batch_layer.root(),
            commitments: prover_data.fri_data.fri_data.fold_roots(),
            queries,
            last_elem: prover_data.fri_data.fri_data.last_element.unwrap(),
            last_random: transcript.random(),
        };

        BatchedPCSProof {
            fri_proof,
            sumcheck_polynomials: prover_data.sumcheck_polynomials,
            claim: self.claim,
        }
    }

    pub fn verify(&self, transcript: &mut Transcript) -> Result<(), super::FriProofError> {
        // Check if the number of queries is correct
        if self.fri_proof.queries.len() != NUM_QUERIES {
            return Err(FriProofError::WrongNumberOfQueries);
        }
        let n = self.fri_proof.commitments.len() + 1;
        assert_eq!(n, self.sumcheck_polynomials.len());
        assert_eq!(n, self.claim.inputs.len());

        // Simulate the "fold" phase of FRI to get random_elements
        let mut random_elements = Vec::new();

        // Absorb the claim
        for input in self.claim.inputs.iter() {
            transcript.absorb(input.as_ref());
        }
        for output in self.claim.outputs.iter() {
            transcript.absorb(output.as_ref());
        }
        let mut fingerprint_r = F::from(0);
        // Absorb each commitment and sumcheck polynomial coefficients
        for i in 0..self.sumcheck_polynomials.len() {
            if i == 0 {
                // Absorb the batch layer commitment
                transcript.absorb(self.fri_proof.batch_commitment.as_slice());
                // Get the fingerprint r
                fingerprint_r = transcript.next_challenge();
                // Absorb the fingerprint r
                transcript.absorb(fingerprint_r.as_ref());
            } else {
                transcript.absorb(self.fri_proof.commitments[i - 1].as_slice());
            };
            let poly = &self.sumcheck_polynomials[i];
            for coeff in poly.nonzero_coeffs.iter() {
                transcript.absorb(coeff.as_ref());
            }
            let r = transcript.next_challenge();
            random_elements.push(r);
        }
        // Absorb the last element
        transcript.absorb(self.fri_proof.last_elem.as_ref());

        // Verify the sumcheck
        let mut pol_iter = self.sumcheck_polynomials.iter();
        let mut random_iter = random_elements.iter();

        let outputs = self.claim.outputs.iter().copied();
        let sum = fingerprint(fingerprint_r, outputs);
        let mut pol = pol_iter.next().unwrap().to_polynomial(sum);

        for sumcheck_pol in pol_iter {
            let r = *random_iter.next().unwrap();
            pol = sumcheck_pol.to_polynomial(pol.evaluate(r));
        }
        let r = *random_iter.next().unwrap();
        let last_elem = self.fri_proof.last_elem;

        let delta = crate::constraint_system::evaluation::Delta {
            data: &self.claim.inputs,
        }
        .evaluate(&random_elements);
        assert_eq!(
            delta * last_elem,
            pol.evaluate(r),
            "Does not match polynomial evaluation"
        );

        // Finally, verify the FRI queries
        self.fri_proof
            .verify_queries(transcript, &random_elements, fingerprint_r)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        benchmark, field::Field128, polynomials::MultilinearPolynomial, transcript::Transcript,
    };

    #[test]
    fn batched_pcs_verify_test() {
        use generic_array::{typenum::U32, GenericArray};

        // Define parameters for the test
        let log_n = 4;
        let n = 1 << log_n;
        let num_polys = 2;

        // Generate some random polynomials
        let mut polys = Vec::new();
        for i in 0..num_polys {
            let mut evals = Vec::with_capacity(n);
            for j in 0..n {
                evals.push(Field128::from(
                    ((j as u64 * 3 + i as u64 * 5) % 100) as u128,
                ));
            }
            polys.push(MultilinearPolynomialEvals { evals });
        }

        // Create a BatchedPCSClaim (example values)
        let claim = BatchedPCSClaim {
            inputs: vec![Field128::from(1), Field128::from(2)],
            outputs: vec![Field128::from(10), Field128::from(20)],
        };

        // Create a transcript
        let mut transcript = Transcript::new();

        // Create an initial BatchedPCSProof instance with the claim
        let initial_proof = BatchedPCSProof {
            fri_proof: BatchedFriProof {
                batch_commitment: GenericArray::<u8, U32>::default(),
                commitments: vec![],
                queries: vec![],
                last_elem: Field128::from(0),
                last_random: [0; 32],
            },
            sumcheck_polynomials: vec![],
            claim,
        };

        // Prove the Batched PCS
        let proof = initial_proof.prove(&polys, &mut transcript);

        // Verify the Batched PCS proof
        let mut verifier_transcript = Transcript::new();
        proof.verify(&mut verifier_transcript).unwrap();

        println!("Batched PCS proof generated and verified successfully!");
    }
}
