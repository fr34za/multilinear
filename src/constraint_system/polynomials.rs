use crate::field::Field;

#[derive(PartialEq, Eq)]
pub struct Polynomial<F> {
    pub coeffs: Box<[F]>,
}

impl<F: Field> Polynomial<F> {
    pub fn evaluate(&self, x: F) -> F {
        self.coeffs
            .iter()
            .rev()
            .fold(F::from(0), |acc, &coeff| acc * x + coeff)
    }

    pub fn evaluate_over_domain(&self, n: usize) -> PolynomialEvals<F> {
        let evals = (0..n)
            .map(|i| {
                let x = F::from(i as i64);
                self.evaluate(x)
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        PolynomialEvals { evals }
    }
}

impl<F: std::fmt::Debug> std::fmt::Debug for Polynomial<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, coeff) in self.coeffs.iter().enumerate() {
            if i == 0 {
                write!(f, "{:?}", coeff)?;
            } else if i == 1 {
                write!(f, " + {:?}*X", coeff)?;
            } else {
                write!(f, " + {:?}*X^{i}", coeff)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PolynomialEvals<F> {
    pub evals: Box<[F]>,
}

impl<F: Field> PolynomialEvals<F> {
    pub fn interpolate(&self) -> Polynomial<F> {
        let n = self.evals.len();
        let mut coeffs = vec![F::from(0); n];

        for (j, &yj) in self.evals.iter().enumerate() {
            // Compute the j-th Lagrange basis polynomial L_j(x)
            let mut lj = [F::from(1)].to_vec(); // start with the constant 1

            let xj = F::from(j as i64);
            let mut denom = F::from(1);

            for (m, _) in self.evals.iter().enumerate() {
                if m == j {
                    continue;
                }

                let xm = F::from(m as i64);

                // lj(x) *= (x - xm)
                lj = poly_mul(&lj, &[-xm, F::from(1)]);

                // denom *= (xj - xm)
                denom *= xj - xm;
            }

            // Scale basis poly by yj / denom
            let scale = yj / denom;
            for (c, l) in coeffs.iter_mut().zip(lj) {
                *c += scale * l;
            }
        }

        Polynomial {
            coeffs: coeffs.into_boxed_slice(),
        }
    }
}

// Helper: multiply two polynomials
fn poly_mul<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    let mut result = vec![F::from(0); a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            result[i + j] += ai * bj;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::field::Field128 as F;

    use super::*;

    #[test]
    fn interpolation_test() {
        let f = F::from;
        let evals = PolynomialEvals {
            evals: [f(0), f(1), f(4), f(8), f(9), f(3)].into(),
        };
        let pol = evals.interpolate();
        assert_eq!(evals, pol.evaluate_over_domain(6));
    }
}
