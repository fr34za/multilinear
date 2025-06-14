#![allow(clippy::needless_range_loop)]

use super::{evaluation::Mask, system::System};
use crate::{
    field::Field,
    polynomials::{MultilinearPolynomialEvals, Polynomial, PolynomialEvals},
    transcript::{HashableField, Transcript},
};

pub struct SumcheckTables<F> {
    matrix: Box<[F]>,
    width: usize,
    height: usize,
    delta: Box<[F]>,
}

pub struct SumcheckPolynomial<F> {
    pub nonzero_coeffs: Box<[F]>,
}

impl<F: HashableField> System<F> {
    pub fn build_tables(&self) -> SumcheckTables<F> {
        let trace = self.trace().unwrap();
        let n_vars = trace.height().trailing_zeros() as usize;
        let row = self.challenges().row();
        let delta = (0..trace.height())
            .map(|index| {
                let mask = Mask { index, n_vars };
                mask.evaluate(row)
            })
            .collect::<Vec<_>>();
        SumcheckTables {
            matrix: trace.matrix().into(),
            width: trace.width(),
            height: trace.height(),
            delta: delta.into(),
        }
    }

    pub fn compute_sumcheck_polynomials(
        &self,
        transcript: &mut Transcript,
        tables: &mut SumcheckTables<F>,
        sum: F,
    ) -> (Box<[SumcheckPolynomial<F>]>, Box<[F]>) {
        let composition_degree = self.constraints().degree();
        tables.compute_sumcheck_polynomials(
            &|args| self.evaluate_composition(args),
            composition_degree,
            transcript,
            sum,
        )
    }

    pub fn verify_sumcheck_debug(
        &self,
        transcript: &mut Transcript,
        pols: &[SumcheckPolynomial<F>],
        sum: F,
    ) {
        let mut rs = Vec::with_capacity(pols.len());
        let mut iter = pols.iter();
        let sumcheck_pol = iter.next().expect("At least one polynomial is expected");
        sumcheck_pol
            .nonzero_coeffs
            .iter()
            .for_each(|coeff| transcript.absorb(coeff.as_ref()));
        let mut pol = sumcheck_pol.to_polynomial(sum);
        for sumcheck_pol in iter {
            let r = transcript.next_challenge();
            sumcheck_pol
                .nonzero_coeffs
                .iter()
                .for_each(|coeff| transcript.absorb(coeff.as_ref()));
            pol = sumcheck_pol.to_polynomial(pol.evaluate(r));
            rs.push(r);
        }
        let r = transcript.next_challenge();
        rs.push(r);
        let trace = self.trace().unwrap();
        let output = trace.evaluate(&rs);
        let delta = self.evaluate_delta(&rs);
        let composition = self.evaluate_composition(&output);
        assert_eq!(
            delta * composition,
            pol.evaluate(r),
            "Does not match polynomial evaluation"
        );
    }

    pub fn verify_with_evaluations(
        &self,
        transcript: &mut Transcript,
        pols: &[SumcheckPolynomial<F>],
        sum: F,
        output: &[F],
    ) {
        let mut rs = Vec::with_capacity(pols.len());
        let mut iter = pols.iter();
        let sumcheck_pol = iter.next().expect("At least one polynomial is expected");
        sumcheck_pol
            .nonzero_coeffs
            .iter()
            .for_each(|coeff| transcript.absorb(coeff.as_ref()));
        let mut pol = sumcheck_pol.to_polynomial(sum);
        for sumcheck_pol in iter {
            let r = transcript.next_challenge();
            sumcheck_pol
                .nonzero_coeffs
                .iter()
                .for_each(|coeff| transcript.absorb(coeff.as_ref()));
            pol = sumcheck_pol.to_polynomial(pol.evaluate(r));
            rs.push(r);
        }
        let r = transcript.next_challenge();
        rs.push(r);
        let delta = self.evaluate_delta(&rs);
        let composition = self.evaluate_composition(output);
        assert_eq!(
            delta * composition,
            pol.evaluate(r),
            "Does not match polynomial evaluation"
        );
    }
}

impl<F: HashableField> SumcheckTables<F> {
    pub fn build_tables_for_pcs(inputs: &[F], poly: &MultilinearPolynomialEvals<F>) -> Self {
        let n_vars = inputs.len();
        let height = poly.evals.len();
        assert_eq!(1 << n_vars, height);
        let trace = poly.evals.clone();
        let delta = (0..trace.len())
            .map(|index| {
                let mask = Mask { index, n_vars };
                mask.evaluate(inputs)
            })
            .collect::<Vec<_>>();
        Self {
            matrix: trace.into(),
            width: 1,
            height,
            delta: delta.into(),
        }
    }

    pub fn compute_sumcheck_polynomials(
        &mut self,
        composition: &impl Fn(&[F]) -> F,
        composition_degree: usize,
        transcript: &mut Transcript,
        sum: F,
    ) -> (Box<[SumcheckPolynomial<F>]>, Box<[F]>) {
        let mut pols = vec![];
        let mut randoms = vec![];
        let mut previous_sum = sum;
        // degree of the composition polynomial plus 1 to account for
        // the delta multilinear
        let total_degree = composition_degree + 1;
        let n_rounds = self.height.trailing_zeros();
        for _ in 0..n_rounds {
            let (pol, r) = self.compute_sumcheck_polynomial(
                composition,
                total_degree,
                &mut previous_sum,
                transcript,
            );
            pols.push(pol);
            randoms.push(r);
        }
        (pols.into(), randoms.into())
    }

    pub fn compute_sumcheck_polynomial(
        &mut self,
        composition: &impl Fn(&[F]) -> F,
        total_degree: usize,
        previous_sum: &mut F,
        transcript: &mut Transcript,
    ) -> (SumcheckPolynomial<F>, F) {
        let mut evals = vec![F::from(0); total_degree + 1];
        // you need `total_degree + 1` points to compute the
        // partial sum polynomial. But the first point can be
        // derived from the second
        for i in 1..total_degree + 1 {
            evals[i] = self.partial_sum(composition, F::from(i as i64));
        }
        evals[0] = *previous_sum - evals[1];
        let pol = PolynomialEvals {
            evals: evals.into(),
        }
        .interpolate();
        let sumcheck_pol = SumcheckPolynomial::new(&pol);
        sumcheck_pol
            .nonzero_coeffs
            .iter()
            .for_each(|coeff| transcript.absorb(coeff.as_ref()));
        let r = transcript.next_challenge();
        *previous_sum = pol.evaluate(r);
        self.fold(r);
        (sumcheck_pol, r)
    }

    pub fn partial_sum(&self, composition: &impl Fn(&[F]) -> F, r: F) -> F {
        let offset = self.height >> 1;
        let one = F::from(1);
        // small optimization
        if r == one {
            (0..offset)
                .map(|i| {
                    let d = r * self.delta[i + offset];
                    let m: Box<_> = (0..self.width)
                        .map(|j| r * self.matrix_get(i + offset, j))
                        .collect();
                    let a = composition(&m);
                    a * d
                })
                .sum()
        } else {
            let s = one - r;
            (0..offset)
                .map(|i| {
                    let d = s * self.delta[i] + r * self.delta[i + offset];
                    let m: Box<_> = (0..self.width)
                        .map(|j| s * self.matrix_get(i, j) + r * self.matrix_get(i + offset, j))
                        .collect();
                    let a = composition(&m);
                    a * d
                })
                .sum()
        }
    }

    pub fn fold(&mut self, r: F) {
        self.height >>= 1;
        let offset = self.height;
        let s = F::from(1) - r;
        for i in 0..offset {
            self.delta[i] = s * self.delta[i] + r * self.delta[i + offset];
            for j in 0..self.width {
                let a = self.matrix_get(i, j);
                let b = self.matrix_get(i + offset, j);
                let entry = self.matrix_get_mut(i, j);
                *entry = s * a + r * b;
            }
        }
    }

    pub fn matrix_get(&self, i: usize, j: usize) -> F {
        self.matrix[i * self.width + j]
    }

    pub fn matrix_get_mut(&mut self, i: usize, j: usize) -> &mut F {
        &mut self.matrix[i * self.width + j]
    }
}

impl<F: Field> SumcheckPolynomial<F> {
    pub fn degree(&self) -> usize {
        self.nonzero_coeffs.len()
    }

    pub fn new(pol: &Polynomial<F>) -> SumcheckPolynomial<F> {
        Self {
            nonzero_coeffs: pol.coeffs[1..].into(),
        }
    }

    pub fn to_polynomial(&self, sum: F) -> Polynomial<F> {
        let sum_coeff = self.nonzero_coeffs.iter().copied().sum();
        let a0 = (sum - sum_coeff) / F::from(2);
        let coeffs = std::iter::once(a0)
            .chain(self.nonzero_coeffs.iter().copied())
            .collect();
        Polynomial { coeffs }
    }
}

impl<F: std::fmt::Debug> std::fmt::Debug for SumcheckPolynomial<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, coeff) in self.nonzero_coeffs.iter().enumerate() {
            if i == 0 {
                write!(f, "#### + {coeff:?}*X")?;
            } else {
                write!(f, " + {coeff:?}*X^{}", i + 1)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Field128 as F;
    use crate::{
        benchmark,
        constraint_system::{
            constraints::{ConstraintSet, Expr},
            system::WitnessLayout,
            trace::Trace,
        },
    };

    fn pythagorean_trace<F: Field>() -> Trace<F> {
        let f = F::from;
        // The first three columns are pythagorean triples
        // The fourth is the sum of the first two
        let matrix = Box::new(
            [
                3, 4, 5, 7, //
                5, 12, 13, 17, //
                8, 15, 17, 23, //
                7, 24, 25, 31, //
                20, 21, 29, 41, //
                12, 35, 37, 47, //
                9, 40, 41, 49, //
                28, 45, 53, 73, //
                11, 60, 61, 71, //
                16, 63, 65, 79, //
                33, 56, 65, 89, //
                48, 55, 73, 103, //
                13, 84, 85, 97, //
                36, 77, 85, 113, //
                39, 80, 89, 119, //
                65, 72, 97, 137, //
            ]
            .map(f),
        );
        Trace::new(matrix, 4)
    }

    fn pythagorean_set<F: Field>() -> ConstraintSet<F> {
        let expr1 = Expr(|var, _| var[0] * var[0] + var[1] * var[1] - var[2] * var[2]);
        let expr2 = Expr(|var, _| var[0] + var[1] - var[3]);
        let constraints = [expr1, expr2].into();
        let degree = 2;
        ConstraintSet::new(constraints, degree)
    }

    fn pythagorean_layout() -> WitnessLayout {
        WitnessLayout {
            columns: 4,
            randoms: 0,
            sum_columns: [].into(),
            pre_random_columns: 0,
        }
    }

    #[test]
    fn sumcheck_test() {
        let set = pythagorean_set();
        let trace = pythagorean_trace();
        let layout = pythagorean_layout();
        let transcript = &mut Transcript::new();
        let prover = System::<F>::prover(transcript, set, layout, trace);
        let verifier_transcript = &mut transcript.clone();
        let tables = &mut prover.build_tables();
        let sum = F::from(0);
        let pols = prover
            .compute_sumcheck_polynomials(transcript, tables, sum)
            .0;
        println!("{pols:#?}");
        prover.verify_sumcheck_debug(verifier_transcript, &pols, sum);
    }

    #[test]
    fn sumcheck_high_bench() {
        let trace = pythagorean_trace::<F>();
        let mut matrix = trace.matrix().to_vec();
        const TOTAL_LOG_HEIGHT: u32 = 20;
        let log_height = trace.height().trailing_zeros();
        for _ in 0..TOTAL_LOG_HEIGHT - log_height {
            matrix.extend(matrix.clone());
        }
        let height = 1 << TOTAL_LOG_HEIGHT;
        let width = trace.width();
        assert_eq!(matrix.len(), height * width);
        let trace = Trace::new(matrix.into(), width);
        println!("### PROVING SUMCHECK FOR HEIGHT {height} AND WIDTH {width}",);
        let set = pythagorean_set();
        let layout = pythagorean_layout();
        let transcript = &mut Transcript::new();
        let prover = System::<F>::prover(transcript, set, layout, trace);
        let verifier_transcript = &mut transcript.clone();
        let sum = F::from(0);
        let tables = &mut benchmark!("  - Table generation: ", prover.build_tables());
        let pols = benchmark!(
            "  - Proof: ",
            prover
                .compute_sumcheck_polynomials(transcript, tables, sum)
                .0
        );
        benchmark!(
            "  - Verification: ",
            prover.verify_sumcheck_debug(verifier_transcript, &pols, sum)
        );
    }
}
