use crate::{
    evaluation::Mask,
    field::Field,
    polynomials::{Polynomial, PolynomialEvals},
    system::{System, Transcript},
};

pub struct Tables<F> {
    matrix: Box<[F]>,
    width: usize,
    height: usize,
    delta: Box<[F]>,
}

pub struct SumcheckPolynomial<F> {
    nonzero_coeffs: Box<[F]>,
}

impl<F: Field> System<F> {
    pub fn build_tables(&self) -> Tables<F> {
        let trace = self.trace().unwrap();
        let n_vars = trace.height().trailing_zeros() as usize;
        let row = self.challenges().row();
        let delta = (0..trace.height())
            .map(|index| {
                let mask = Mask { index, n_vars };
                mask.evaluate(row)
            })
            .collect::<Vec<_>>();
        Tables {
            matrix: trace.matrix().into(),
            width: trace.width(),
            height: trace.height(),
            delta: delta.into(),
        }
    }

    #[allow(clippy::needless_range_loop)]
    pub fn compute_sumcheck_polynomials(
        &self,
        transcript: &mut Transcript,
        tables: &mut Tables<F>,
        sum: F,
    ) -> Box<[SumcheckPolynomial<F>]> {
        let mut pols = vec![];
        let mut previous_sum = sum;
        // degree of the composition polynomial plus 1 to account for
        // the delta multilinear
        let total_degree = self.constraints().degree() + 1;
        let n_rounds = tables.height.trailing_zeros();
        for _ in 0..n_rounds {
            let mut evals = vec![F::from(0); total_degree + 1];
            // you need `total_degree + 1` points to compute the
            // partial sum polynomial. But the first point can be
            // derived from the second
            for i in 1..total_degree + 1 {
                evals[i] = self.partial_sum(tables, F::from(i as u64));
            }
            evals[0] = previous_sum - evals[1];
            let pol = PolynomialEvals {
                evals: evals.into(),
            }
            .interpolate();
            let r = transcript.next_challenge();
            previous_sum = pol.evaluate(r);
            pols.push(SumcheckPolynomial::new(&pol));
            tables.fold(r);
        }
        pols.into()
    }

    pub fn partial_sum(&self, tables: &mut Tables<F>, r: F) -> F {
        let offset = tables.height >> 1;
        let one = F::from(1);
        // small optimization
        if r == one {
            (0..offset)
                .map(|i| {
                    let d = r * tables.delta[i + offset];
                    let m: Box<_> = (0..tables.width)
                        .map(|j| r * tables.matrix_get(i + offset, j))
                        .collect();
                    // without compilation, this step might be slow
                    let a = self.evaluate_composition(&m);
                    a * d
                })
                .sum()
        } else {
            let s = one - r;
            (0..offset)
                .map(|i| {
                    let d = s * tables.delta[i] + r * tables.delta[i + offset];
                    let m: Box<_> = (0..tables.width)
                        .map(|j| s * tables.matrix_get(i, j) + r * tables.matrix_get(i + offset, j))
                        .collect();
                    // without compilation, this step might be slow
                    let a = self.evaluate_composition(&m);
                    a * d
                })
                .sum()
        }
    }
}

impl<F: Field + std::fmt::Debug> System<F> {
    pub fn verify_sumcheck_debug(
        &self,
        transcript: &mut Transcript,
        pols: &[SumcheckPolynomial<F>],
        sum: F,
    ) {
        let mut rs = Vec::with_capacity(pols.len());
        let mut iter = pols.iter();
        let mut pol = iter
            .next()
            .expect("At least one polynomial is expected")
            .to_polynomial(sum);
        for sumcheck_pol in iter {
            let r = transcript.next_challenge();
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
}

impl<F: Field> Tables<F> {
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
                write!(f, "#### + {:?}*X", coeff)?;
            } else {
                write!(f, " + {:?}*X^{}", coeff, i + 1)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constraints::ConstraintSet, expr::Expr, field::Field128 as F, trace::Trace};
    use std::time::Instant;

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
        let var = Expr::<F>::var;
        let expr1 = var(0) * var(0) + var(1) * var(1) - var(2) * var(2);
        let expr2 = var(0) + var(1) - var(3);
        let constraints = [expr1, expr2].into();
        ConstraintSet::new(constraints, 4, [].into(), 0)
    }

    #[test]
    fn sumcheck_test() {
        let set = pythagorean_set();
        let trace = pythagorean_trace();
        let transcript = &mut Transcript::new();
        let prover = System::<F>::prover(transcript, set, trace);
        let verifier_transcript = &mut transcript.clone();
        let tables = &mut prover.build_tables();
        let sum = F::from(0);
        let pols = prover.compute_sumcheck_polynomials(transcript, tables, sum);
        println!("{:#?}", pols);
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
        let transcript = &mut Transcript::new();
        let prover = System::<F>::prover(transcript, set, trace);
        let verifier_transcript = &mut transcript.clone();
        let sum = F::from(0);

        let now = Instant::now();
        let tables = &mut prover.build_tables();
        println!("  - Table generation took {:?}", now.elapsed());

        let now = Instant::now();
        let pols = prover.compute_sumcheck_polynomials(transcript, tables, sum);
        println!("  - Proof took {:?}", now.elapsed());

        let now = Instant::now();
        prover.verify_sumcheck_debug(verifier_transcript, &pols, sum);
        println!("  - Verification took {:?}", now.elapsed());
    }
}
