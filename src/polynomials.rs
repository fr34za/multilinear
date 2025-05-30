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

    pub fn evaluate_over_domain(&self) -> PolynomialEvals<F> {
        let n = self.coeffs.len();
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
                write!(f, "{coeff:?}")?;
            } else if i == 1 {
                write!(f, " + {coeff:?}*X")?;
            } else {
                write!(f, " + {coeff:?}*X^{i}")?;
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

#[derive(PartialEq, Eq, Debug)]
pub struct MultilinearPolynomial<F> {
    pub coeffs: Vec<F>,
}

#[derive(PartialEq, Eq, Debug)]
pub struct MultilinearPolynomialEvals<F> {
    pub evals: Vec<F>,
}

impl<F: Field> MultilinearPolynomial<F> {
    pub fn to_evaluation(&self) -> MultilinearPolynomialEvals<F> {
        let n = self.coeffs.len().trailing_zeros() as usize;
        let mut evals = self.coeffs.to_vec();
        for i in 0..n {
            let mask = 1 << i;
            for j in 0..(1 << n) {
                if (j & mask) != 0 {
                    let masked = evals[j ^ mask];
                    evals[j] += masked;
                }
            }
        }
        MultilinearPolynomialEvals { evals }
    }

    pub fn evaluate(&self, args: &[F]) -> F {
        assert_eq!(
            1 << args.len(),
            self.coeffs.len().next_power_of_two(),
            "Wrong number of arguments"
        );

        self.coeffs
            .iter()
            .enumerate()
            .map(|(pos, &coeff)| {
                let mut term = coeff;
                for (bit_pos, &arg) in args.iter().enumerate() {
                    if (pos >> bit_pos) & 1 == 1 {
                        term *= arg;
                    }
                }
                term
            })
            .sum()
    }
}

impl<F: Field> MultilinearPolynomialEvals<F> {
    pub fn to_coefficient(&self) -> MultilinearPolynomial<F> {
        let n = self.evals.len().trailing_zeros() as usize;
        let mut coeffs = self.evals.to_vec();
        for i in 0..n {
            let mask = 1 << i;
            for j in 0..(1 << n) {
                if (j & mask) != 0 {
                    let masked = coeffs[j ^ mask];
                    coeffs[j] -= masked;
                }
            }
        }
        MultilinearPolynomial { coeffs }
    }

    pub fn evaluate(&self, args: &[F]) -> F {
        assert_eq!(
            1 << args.len(),
            self.evals.len().next_power_of_two(),
            "Wrong number of arguments"
        );

        self.evals
            .iter()
            .enumerate()
            .map(|(pos, &eval)| {
                let mut term = eval;
                for (bit_pos, &arg) in args.iter().enumerate() {
                    if (pos >> bit_pos) & 1 == 1 {
                        term *= arg;
                    } else {
                        term *= F::from(1) - arg;
                    }
                }
                term
            })
            .sum()
    }
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
        assert_eq!(evals, pol.evaluate_over_domain());
    }

    #[test]
    fn multilinear_conversion_test() {
        let f = F::from;
        let evals = MultilinearPolynomialEvals {
            evals: [f(0), f(1), f(4), f(8), f(9), f(3)].into(),
        };
        let pol = evals.to_coefficient();
        assert_eq!(evals, pol.to_evaluation());
    }
}
