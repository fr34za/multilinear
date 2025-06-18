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
        let fri_data = BatchedFriProverData::init(code, transcript);

        // generate a single `MultilinearPolynomialEvals` using the polynomials in `poly` using the fingerprint function
        // and the `fingerprint_r` which is inside the prover data
        let fingerprint_r = fri_data.fingerprint_r;
        let mut fingerprinted_evals = Vec::new();
        for i in 0..poly[0].evals.len() {
            let mut current_evals = Vec::new();
            for p in poly.iter() {
                current_evals.push(p.evals[i]);
            }
            fingerprinted_evals.push(super::batched_fri::fingerprint(
                fingerprint_r,
                &current_evals,
            ));
        }
        let fingerprinted_poly = MultilinearPolynomialEvals {
            evals: fingerprinted_evals,
        };

        // build the sumcheck tables
        let sumcheck_tables =
            SumcheckTables::build_tables_for_pcs(&claim.claims[0].0, &fingerprinted_poly);

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
        let num_steps = code[0].len().trailing_zeros() as usize - super::frimod::LOG_BLOWUP;

        let mut previous_sum = claim.claims[0].1;

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
                prover_data.fri_data.fold_step(gen_pows, k, r, transcript);
            }
        }
        assert!(prover_data.fri_data.last_element.is_some());
        prover_data
    }
}

impl<F: HashableField + NttField> BatchedPCSProof<F> {
    pub fn prove(
        claim: &BatchedPCSClaim<F>,
        poly: &[MultilinearPolynomialEvals<F>],
        transcript: &mut Transcript,
    ) -> Self {
        // Compute gen_pows for the RS code
        let log_domain_size =
            poly[0].evals.len().trailing_zeros() as u64 + super::frimod::LOG_BLOWUP as u64;
        let gen_pows = F::pow_2_generator_powers(log_domain_size).unwrap();
        let gen = gen_pows[1];

        // For each polynomial, convert the polynomial to canonical form
        // bit reverse to change endianess
        // then compute the RS code of the canonical coefficients and collect into a vector of codes
        let mut codes_for_fri = Vec::new();
        for p in poly.iter() {
            let mut coeffs = p.to_coefficient();
            super::ntt::bit_reverse_permutation(&mut coeffs.coeffs);
            let code = super::frimod::reed_solomon(coeffs.coeffs, gen);
            codes_for_fri.push(code);
        }

        // Run the Batched PCS fold
        let prover_data =
            BatchedPCSProverData::fold(claim, poly, &gen_pows, &codes_for_fri, transcript);

        // Do the queries, similar to FRI
        let domain_size = 1 << log_domain_size;
        let mut queries = Vec::with_capacity(super::frimod::NUM_QUERIES);
        for _ in 0..super::frimod::NUM_QUERIES {
            let random_u64 = u64::from_le_bytes(transcript.random()[..8].try_into().unwrap());
            let random_index = random_u64 as usize % (domain_size / 2);
            let query_proof = prover_data.open_query_at(random_index);
            queries.push(query_proof);
            transcript.absorb(&random_index.to_le_bytes());
        }

        // Construct the BatchedPCSProof
        let fri_proof = super::batched_fri::BatchedFriProof {
            batch_commitment: prover_data.fri_data.batch_layer.root(),
            commitments: prover_data.fri_data.fri_data.fold_roots(),
            queries,
            last_elem: prover_data.fri_data.fri_data.last_element.unwrap(),
            last_random: transcript.random(),
        };

        BatchedPCSProof {
            fri_proof,
            sumcheck_polynomials: prover_data.sumcheck_polynomials,
            claims: claim.clone(),
        }
    }

    pub fn verify(&self, transcript: &mut Transcript) -> Result<(), super::FriProofError> {
        // Check if the number of queries is correct
        if self.fri_proof.queries.len() != super::frimod::NUM_QUERIES {
            return Err(super::FriProofError::WrongNumberOfQueries);
        }

        // Simulate the "fold" phase of FRI to get random_elements
        let mut random_elements = Vec::new();

        // Absorb the batch layer commitment
        transcript.absorb(self.fri_proof.batch_commitment.as_slice());

        // Get the fingerprint r
        let fingerprint_r: F = transcript.next_challenge();

        // Absorb the fingerprint r
        transcript.absorb(fingerprint_r.as_ref());

        // Absorb each commitment and sumcheck polynomial coefficients
        for i in 0..self.fri_proof.commitments.len() {
            let root = &self.fri_proof.commitments[i];
            let poly = &self.sumcheck_polynomials[i];

            transcript.absorb(root.as_slice());
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

        let mut pol = pol_iter
            .next()
            .unwrap()
            .to_polynomial(self.claims.claims[0].1);

        for sumcheck_pol in pol_iter {
            let r = *random_iter.next().unwrap();
            pol = sumcheck_pol.to_polynomial(pol.evaluate(r));
        }
        let r = *random_iter.next().unwrap();
        let last_elem = self.fri_proof.last_elem;

        let delta = crate::constraint_system::evaluation::Delta {
            data: &self.claims.claims[0].0,
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
