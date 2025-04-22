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
    ) -> Vec<SumcheckPolynomial<F>> {
        let mut pols = vec![];
        let mut previous_sum = sum;
        let degree = self.constraints().degree();
        let height = tables.height;
        for _ in 0..height {
            let mut evals = vec![F::from(0); degree + 1];
            for i in 1..degree + 1 {
                evals[i] = self.partial_sum(tables, F::from(i as u64));
            }
            evals[0] = previous_sum - evals[1];
            let pol = PolynomialEvals {
                evals: evals.into(),
            }
            .interpolate();
            let r = transcript.next_challenge();
            previous_sum = pol.evaluate(r);
            pols.push(SumcheckPolynomial::new(pol));
            tables.fold(r);
        }
        pols
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

    pub fn new(pol: Polynomial<F>) -> SumcheckPolynomial<F> {
        Self {
            nonzero_coeffs: pol.coeffs[1..].into(),
        }
    }
}
