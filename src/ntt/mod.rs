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

    pub fn ntt_naive(&self, gen: F) -> LagrangePolynomial<F> {
        assert!(self.coeffs.len().is_power_of_two());
        let n = self.coeffs.len();
        let mut evals = Vec::with_capacity(n);
        let mut root = F::from(1); // Start with the first root of unity (gen^0)

        for _ in 0..n {
            evals.push(self.evaluate(root));
            root *= gen; // Move to the next root of unity
        }

        LagrangePolynomial { gen, evals }
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

        // Perform recursive INTT
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

        // Split into even and odd indices - functional approach
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

        // Pre-compute omega powers for efficiency
        let omega_powers: Vec<F> =
            std::iter::successors(Some(F::from(1)), |&prev| Some(prev * omega))
                .take(half_n)
                .collect();

        // Combine results using functional programming
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
    let coeffs = [1, 3, 4, 2, 8, 7, 6, 1].into();
    let pol = Polynomial::<i64> { coeffs };
    let gen = 3;
    let lagrange = pol.ntt_naive(gen);
    assert_eq!(pol, lagrange.intt());
}
