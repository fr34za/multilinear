use crate::field::Field;

#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial<F> {
    pub coeffs: Vec<F>,
}

impl<F: Field> Polynomial<F> {
    pub fn evaluate(&self, x: F) -> F {
        self.coeffs
            .iter()
            .rev()
            .fold(F::from(0), |acc, &coeff| acc * x + coeff)
    }

    pub fn ntt(&self, gen: F) -> LagrangePolynomial<F> {
        let n = self.coeffs.len();
        assert!(n.is_power_of_two(), "The number of coeffs must be a power of 2");

        let evals = Self::recursive_ntt(&self.coeffs, gen, n);
        LagrangePolynomial { gen, evals }
    }

    fn recursive_ntt(coeffs: &[F], omega: F, n: usize) -> Vec<F> {
        if n == 1 {
            return vec![coeffs[0]];
        }

        let half_n = n / 2;
        let omega_squared = omega * omega;

        let (even_coeffs, odd_coeffs): (Vec<F>, Vec<F>) = coeffs
            .iter()
            .enumerate()
            .fold(
                (Vec::with_capacity(half_n), Vec::with_capacity(half_n)),
                |(mut evens, mut odds), (i, &val)| {
                    if i % 2 == 0 {
                        evens.push(val);
                    } else {
                        odds.push(val);
                    }
                    (evens, odds)
                },
            );

        let (even_evals, odd_evals) = (
            Self::recursive_ntt(&even_coeffs, omega_squared, half_n),
            Self::recursive_ntt(&odd_coeffs, omega_squared, half_n),
        );

        let omega_powers: Vec<F> =
            std::iter::successors(Some(F::from(1)), |&prev| Some(prev * omega))
                .take(half_n)
                .collect();

        (0..half_n)
            .flat_map(|i| {
                let even = even_evals[i];
                let odd_term = omega_powers[i] * odd_evals[i];
                vec![even + odd_term, even - odd_term]
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LagrangePolynomial<F> {
    pub gen: F,
    pub evals: Vec<F>,
}

impl<F: Field> LagrangePolynomial<F> {
    pub fn intt(&self) -> Polynomial<F> {
        let n = self.evals.len();
        assert!(n.is_power_of_two());

        let gen_inv = F::from(1) / self.gen;
        let n_inv = F::from(1) / F::from(n as i64);

        let coeffs = self.recursive_intt(&self.evals, gen_inv, n);

        let scaled_coeffs = coeffs.into_iter().map(|coeff| coeff * n_inv).collect();

        Polynomial {
            coeffs: scaled_coeffs,
        }
    }

    fn recursive_intt(&self, values: &[F], omega: F, n: usize) -> Vec<F> {
        if n == 1 {
            return vec![values[0]];
        }

        let half_n = n / 2;
        let omega_squared = omega * omega;

        let (even_indices, odd_indices): (Vec<F>, Vec<F>) = values.iter().enumerate().fold(
            (Vec::with_capacity(half_n), Vec::with_capacity(half_n)),
            |(mut evens, mut odds), (i, &val)| {
                if i % 2 == 0 {
                    evens.push(val);
                } else {
                    odds.push(val);
                }
                (evens, odds)
            },
        );

        let (even_coeffs, odd_coeffs) = (
            self.recursive_intt(&even_indices, omega_squared, half_n),
            self.recursive_intt(&odd_indices, omega_squared, half_n),
        );

        let omega_powers: Vec<F> =
            std::iter::successors(Some(F::from(1)), |&prev| Some(prev * omega))
                .take(half_n)
                .collect();

        (0..half_n)
            .flat_map(|i| {
                let even = even_coeffs[i];
                let odd_term = omega_powers[i] * odd_coeffs[i];
                vec![even + odd_term, even - odd_term]
            })
            .collect()
    }
}

#[test]
fn ntt_test() {
    use ark_ff::Field;
    use crate::field::Field128 as F;
    const MODULUS: u128 = 340282366920938463463374557953744961537;
    let f = F::from;
    let coeffs = [1, 3, 4, 2, 8, 7, 6, 1].into_iter().map(f).collect();
    let pol = Polynomial::<F> { coeffs };
    let exp = (MODULUS - 1) / ((pol.coeffs.len()) as u128);
    let exp_low = exp as u64;
    let exp_high = (exp >> 64) as u64;
    let gen = F::from(3).pow([exp_low, exp_high]);
    assert_eq!(pol.ntt(gen), pol.ntt(gen));
}