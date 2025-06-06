use crate::{
    constraint_system::{
        evaluation::Delta,
        sumcheck::{SumcheckPolynomial, SumcheckTables},
    },
    fri::LOG_BLOWUP,
    ntt::{bit_reverse_permutation, NttField},
    polynomials::MultilinearPolynomialEvals,
    transcript::{HashableField, Transcript},
};

use super::{reed_solomon, FriProof, FriProofError, FriProverData, NUM_QUERIES};

pub struct PCSProverData<F> {
    // FRI data
    pub fri_data: FriProverData<F>,
    // Sumcheck data
    pub sumcheck_tables: SumcheckTables<F>,
    pub sumcheck_polynomials: Vec<SumcheckPolynomial<F>>,
}

impl<F: HashableField + NttField> PCSProverData<F> {
    pub fn init(
        inputs: &[F],
        poly: &MultilinearPolynomialEvals<F>,
        code: &[F],
        transcript: &mut Transcript,
    ) -> Self {
        // call `FriProverData::init`
        let fri_data = FriProverData::init(code, transcript);
        let sumcheck_tables = SumcheckTables::build_tables_for_pcs(inputs, poly);

        // sumcheck_polynomials start empty
        let sumcheck_polynomials = Vec::new();

        Self {
            fri_data,
            sumcheck_tables,
            sumcheck_polynomials,
        }
    }

    pub fn fold(
        inputs: &[F],
        output: F,
        poly: &MultilinearPolynomialEvals<F>,
        gen_pows: &[F],
        code: &[F],
        transcript: &mut Transcript,
    ) -> Self {
        let mut prover_data = Self::init(inputs, poly, code, transcript);
        let num_steps = code.len().trailing_zeros() as usize - LOG_BLOWUP;

        let mut previous_sum = output;
        // Define the composition function
        let composition = &|x: &[F]| x[0];
        // TODO Why 2 and not 1???
        let total_degree = 2;
        for k in 0..num_steps {
            // Compute the sumcheck polynomial
            // This returns a tuple (SumcheckPolynomial, F)
            let (sumcheck_poly, r) = prover_data.sumcheck_tables.compute_sumcheck_polynomial(
                composition,
                total_degree,
                &mut previous_sum,
                transcript,
            );

            // Add the sumcheck polynomial to the vector
            prover_data.sumcheck_polynomials.push(sumcheck_poly);

            // Run fold_step from fri
            prover_data.fri_data.fold_step(gen_pows, k, r, transcript);
        }
        assert!(prover_data.fri_data.last_element.is_some());
        prover_data
    }
}

pub struct PCSProof<F> {
    // FRI proof
    pub fri_proof: FriProof<F>,
    // Sumcheck proof
    pub sumcheck_polynomials: Vec<SumcheckPolynomial<F>>,
    // PCS claim
    pub inputs: Vec<F>,
    pub output: F,
}

impl<F: HashableField + NttField> PCSProof<F> {
    pub fn prove(
        inputs: Vec<F>,
        output: F,
        poly: MultilinearPolynomialEvals<F>,
        transcript: &mut Transcript,
    ) -> Self {
        // First, convert the polynomial to canonical form
        let mut coeffs = poly.to_coefficient();
        // bit reverse to change endianess
        bit_reverse_permutation(&mut coeffs.coeffs);

        // Compute gen_pows for the RS code
        let log_domain_size = coeffs.coeffs.len().trailing_zeros() as u64 + LOG_BLOWUP as u64;
        let gen_pows = F::pow_2_generator_powers(log_domain_size).unwrap();
        let gen = gen_pows[1];

        // Then compute the RS code of the canonical coefficients
        let code = reed_solomon(coeffs.coeffs, gen);

        // Run the PCS fold, using the polynomial, code, gen_pows
        let prover_data = PCSProverData::fold(&inputs, output, &poly, &gen_pows, &code, transcript);

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

        // Construct the PCSProof
        let fri_proof = FriProof {
            commitments: prover_data.fri_data.fold_roots(),
            queries,
            last_elem: prover_data.fri_data.last_element.unwrap(),
            last_random: transcript.random(),
        };
        PCSProof {
            fri_proof,
            sumcheck_polynomials: prover_data.sumcheck_polynomials,
            inputs,
            output,
        }
    }

    pub fn verify(&self, transcript: &mut Transcript) -> Result<(), super::FriProofError> {
        // Check if the number of queries is correct
        if self.fri_proof.queries.len() != NUM_QUERIES {
            return Err(FriProofError::WrongNumberOfQueries);
        }
        let n = self.fri_proof.commitments.len();
        assert_eq!(n, self.sumcheck_polynomials.len());
        assert_eq!(n, self.inputs.len());

        // This simulates the "fold" phase of FRI
        let mut random_elements = Vec::new();
        for (root, poly) in self
            .fri_proof
            .commitments
            .iter()
            .zip(self.sumcheck_polynomials.iter())
        {
            // Absorb the root into the transcript
            // This is similar to init/fold
            transcript.absorb(root.as_slice());
            // Absorb the polynomial coefficients into the transcript
            // This is similar to what happens in compute_sumcheck_polynomial
            for coeff in poly.nonzero_coeffs.iter() {
                transcript.absorb(coeff.as_ref());
            }
            let r = transcript.next_challenge();
            random_elements.push(r);
        }
        // Absorb the last element into the transcript
        transcript.absorb(self.fri_proof.last_elem.as_ref());

        let mut pol_iter = self.sumcheck_polynomials.iter();
        let mut random_iter = random_elements.iter();
        let mut pol = pol_iter.next().unwrap().to_polynomial(self.output);
        for sumcheck_pol in pol_iter {
            let r = *random_iter.next().unwrap();
            pol = sumcheck_pol.to_polynomial(pol.evaluate(r));
        }
        let r = *random_iter.next().unwrap();
        let last_elem = self.fri_proof.last_elem;

        let delta = Delta { data: &self.inputs }.evaluate(&random_elements);
        assert_eq!(
            delta * last_elem,
            pol.evaluate(r),
            "Does not match polynomial evaluation"
        );

        // Finally, verify the FRI queries
        self.fri_proof
            .verify_queries(transcript, &random_elements)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{benchmark, field::Field128};

    #[test]
    fn multilinear_pcs_bench_test() {
        let n_vars = 20;
        let evals: Vec<Field128> = (0..1 << n_vars)
            .map(|i| Field128::from(i as i64 * 7 + 3))
            .collect();
        let multilinear = MultilinearPolynomialEvals { evals };
        let inputs = (0..n_vars)
            .map(|i| Field128::from(i as i64))
            .collect::<Vec<_>>();
        let output = multilinear.evaluate(&inputs);
        let transcript = &mut Transcript::new();
        let proof = benchmark!(
            "PCS proof: ",
            PCSProof::prove(inputs, output, multilinear, transcript)
        );
        let transcript = &mut Transcript::new();
        benchmark!("PCS verification ", proof.verify(transcript).unwrap());
    }
}
