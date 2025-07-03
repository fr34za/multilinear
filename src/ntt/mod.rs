use winterfell::math::FieldElement;

use crate::field::{Field, Field128};

#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial<F> {
    pub coeffs: Vec<F>,
}

pub struct BatchedPolynomial<F> {
    pub coeffs: Vec<F>,
    pub width: usize,
}

pub trait NttField: Field {
    fn modulus() -> u128;

    fn generator() -> Self;

    fn pow_2_generator(log_size: u64) -> Option<Self>;

    // 1, gen, gen^2, gen^3, ..., gen^(2^log_size - 1)
    fn pow_2_generator_powers(log_size: u64) -> Option<Vec<Self>> {
        let gen = Self::pow_2_generator(log_size)?;
        let size = 1 << log_size;
        let mut powers = Vec::with_capacity(size);
        let mut current = Self::from(1);
        for _ in 0..size {
            powers.push(current);
            current *= gen;
        }
        Some(powers)
    }

    fn pow(&self, exp: u128) -> Self;
}

impl NttField for Field128 {
    fn modulus() -> u128 {
        340282366920938463463374557953744961537
    }

    fn generator() -> Self {
        Field128::from(3)
    }

    fn pow_2_generator(log_size: u64) -> Option<Self> {
        let modulus_minus_1 = Self::modulus() - 1;
        let max_log_size = modulus_minus_1.trailing_zeros();

        if log_size > max_log_size as u64 {
            return None;
        }

        let size = 1u128 << log_size;
        let exp = modulus_minus_1 / size;

        Some(Self::generator().pow(exp))
    }

    fn pow(&self, exp: u128) -> Self {
        Field128(self.0.exp(exp))
    }
}

// Direct butterfly implementations (Plonky3 style, but as simple functions)

/// Apply DIT butterfly operation to two slices
/// Computes: output_1 = x1 + x2 * twiddle, output_2 = x1 - x2 * twiddle
#[inline]
fn apply_dit_butterfly<F: Field>(hi_row: &mut [F], lo_row: &mut [F], twiddle: F) {
    for (hi, lo) in hi_row.iter_mut().zip(lo_row.iter_mut()) {
        let lo_twiddle = *lo * twiddle;
        let temp_hi = *hi;
        *hi = temp_hi + lo_twiddle;
        *lo = temp_hi - lo_twiddle;
    }
}

/// Apply twiddle-free butterfly operation to two slices
/// Computes: output_1 = x1 + x2, output_2 = x1 - x2
#[inline]
fn apply_twiddle_free_butterfly<F: Field>(hi_row: &mut [F], lo_row: &mut [F]) {
    for (hi, lo) in hi_row.iter_mut().zip(lo_row.iter_mut()) {
        let temp_hi = *hi;
        *hi = temp_hi + *lo;
        *lo = temp_hi - *lo;
    }
}

impl<F: NttField> Polynomial<F> {
    pub fn evaluate(&self, x: F) -> F {
        self.coeffs
            .iter()
            .rev()
            .fold(F::from(0), |acc, &coeff| acc * x + coeff)
    }

    pub fn ntt(&self, gen: F) -> LagrangePolynomial<F> {
        let n = self.coeffs.len();
        assert!(
            n.is_power_of_two(),
            "The number of coeffs must be a power of 2"
        );

        let mut values = self.coeffs.clone();

        bit_reverse_permutation(&mut values);

        // unroll the first step
        for i in (0..n).step_by(2) {
            let u = values[i];
            let v = values[i + 1];
            values[i] = u + v;
            values[i + 1] = u - v;
        }
        let mut len = 4;
        while len <= n {
            let current_gen = gen.pow((n / len) as u128);
            let mut acc = F::from(1);
            let gen_pows: Vec<_> = (0..len / 2)
                .map(|_| {
                    let res = acc;
                    acc *= current_gen;
                    res
                })
                .collect();
            for i in (0..n).step_by(len) {
                for j in 0..len / 2 {
                    let v = values[i + j + len / 2] * gen_pows[j];
                    let u = values[i + j];
                    values[i + j] = u + v;
                    values[i + j + len / 2] = u - v;
                }
            }
            len *= 2;
        }

        LagrangePolynomial { gen, evals: values }
    }
}

pub fn bit_reverse_permutation<F>(values: &mut [F]) {
    let n = values.len();
    let bits = n.trailing_zeros() as usize;

    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS as usize - bits);
        if i < j {
            values.swap(i, j);
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LagrangePolynomial<F> {
    pub gen: F,
    pub evals: Vec<F>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BatchedLagrangePolynomial<F> {
    pub gen: F,
    pub evals: Vec<F>,
    pub width: usize,
}

impl<F: NttField> BatchedPolynomial<F> {
    pub fn ntt(&self, gen: F) -> BatchedLagrangePolynomial<F> {
        let total_len = self.coeffs.len();
        let poly_len = total_len / self.width;

        assert!(
            poly_len.is_power_of_two(),
            "Each polynomial length must be a power of 2"
        );
        assert_eq!(
            total_len % self.width,
            0,
            "Total coefficients must be divisible by width"
        );

        let mut batched_values = self.coeffs.clone();

        // Process each polynomial in the batch
        for poly_values in batched_values.chunks_mut(poly_len) {
            // Apply NTT to this polynomial
            bit_reverse_permutation(poly_values);

            // unroll the first step
            for i in (0..poly_len).step_by(2) {
                let u = poly_values[i];
                let v = poly_values[i + 1];
                poly_values[i] = u + v;
                poly_values[i + 1] = u - v;
            }

            let mut len = 4;
            while len <= poly_len {
                let current_gen = gen.pow((poly_len / len) as u128);
                let mut acc = F::from(1);
                let gen_pows: Vec<_> = (0..len / 2)
                    .map(|_| {
                        let res = acc;
                        acc *= current_gen;
                        res
                    })
                    .collect();
                for i in (0..poly_len).step_by(len) {
                    for j in 0..len / 2 {
                        let v = poly_values[i + j + len / 2] * gen_pows[j];
                        let u = poly_values[i + j];
                        poly_values[i + j] = u + v;
                        poly_values[i + j + len / 2] = u - v;
                    }
                }
                len *= 2;
            }
        }

        BatchedLagrangePolynomial {
            gen,
            evals: batched_values,
            width: self.width,
        }
    }

    // Optimized batched NTT using Plonky3-style layer processing
    pub fn ntt_optimized(&self, gen: F) -> BatchedLagrangePolynomial<F> {
        let width = self.width;
        let total_len = self.coeffs.len();
        let h = total_len / width;
        let log_h = h.trailing_zeros() as usize;

        assert!(
            h.is_power_of_two(),
            "Each polynomial length must be a power of 2"
        );
        assert_eq!(
            total_len % width,
            0,
            "Total coefficients must be divisible by width"
        );

        // Pre-calculate twiddle factors for efficiency
        let twiddles =
            F::pow_2_generator_powers(log_h as u64).expect("Failed to generate twiddle factors");

        let mut evals = self.coeffs.clone();

        // Apply bit reversal to the matrix
        reverse_matrix_index_bits(&mut evals, width, h, log_h);

        // Apply DIT layers
        for layer in 0..log_h {
            dit_layer_optimized(&mut evals, width, h, log_h, layer, &twiddles);
        }

        BatchedLagrangePolynomial { evals, width, gen }
    }
}

// Optimized DIT layer processing using direct butterfly functions
fn dit_layer_optimized<F: Field>(
    mat: &mut [F],
    width: usize,
    h: usize,
    log_h: usize,
    layer: usize,
    twiddles: &[F],
) {
    let layer_rev = log_h - 1 - layer;
    // Each butterfly operates on 2 rows; this is the number of rows in half a block
    let half_block_size = width << layer;
    // Each block contains 2^layer * 2 rows; full size of the butterfly block
    let block_size = half_block_size * 2;

    // Process the matrix in blocks of rows of size `block_size`
    for block_start in (0..mat.len()).step_by(block_size) {
        let block_end = (block_start + block_size).min(mat.len());
        if block_start + half_block_size >= block_end {
            continue;
        }

        // Split each block vertically into top (hi) and bottom (lo) halves
        let (hi_block, lo_block) = mat[block_start..block_end].split_at_mut(half_block_size);

        // For each pair of rows (hi, lo), apply a butterfly
        for (ind, (hi_chunk, lo_chunk)) in hi_block
            .chunks_exact_mut(width)
            .zip(lo_block.chunks_exact_mut(width))
            .enumerate()
        {
            if ind == 0 {
                // The first pair doesn't require a twiddle factor
                apply_twiddle_free_butterfly(hi_chunk, lo_chunk);
            } else {
                // Apply DIT butterfly using the twiddle factor at index `ind << layer_rev`
                let twiddle_idx = ind << layer_rev;
                if twiddle_idx < twiddles.len() {
                    apply_dit_butterfly(hi_chunk, lo_chunk, twiddles[twiddle_idx]);
                }
            }
        }
    }
}

pub fn reverse_matrix_index_bits<F>(mat: &mut [F], w: usize, h: usize, log_h: usize) {
    let values = mat.as_mut_ptr() as usize;

    // SAFETY: Due to the i < j check, we are guaranteed that `swap_rows_raw
    // will never try and access a particular slice of data more than once
    // across all parallel threads. Hence the following code is safe and does
    // not trigger undefined behaviour.
    (0..h).into_iter().for_each(|i| {
        let values = values as *mut F;
        let j = reverse_bits_len(i, log_h);
        if i < j {
            unsafe { swap_rows_raw(values, w, i, j) };
        }
    });
}

unsafe fn swap_rows_raw<F>(mat: *mut F, w: usize, i: usize, j: usize) {
    unsafe {
        let row_i = core::slice::from_raw_parts_mut(mat.add(i * w), w);
        let row_j = core::slice::from_raw_parts_mut(mat.add(j * w), w);
        row_i.swap_with_slice(row_j);
    }
}

pub const fn reverse_bits_len(x: usize, bit_len: usize) -> usize {
    // NB: The only reason we need overflowing_shr() here as opposed
    // to plain '>>' is to accommodate the case n == num_bits == 0,
    // which would become `0 >> 64`. Rust thinks that any shift of 64
    // bits causes overflow, even when the argument is zero.
    x.reverse_bits()
        .overflowing_shr(usize::BITS - bit_len as u32)
        .0
}

impl<F: NttField> LagrangePolynomial<F> {
    pub fn intt(&self) -> Polynomial<F> {
        let n = self.evals.len();
        assert!(n.is_power_of_two());

        let mut values = self.evals.clone();

        bit_reverse_permutation(&mut values);

        let gen_inv = F::from(1) / self.gen;
        // unroll the first step
        for i in (0..n).step_by(2) {
            let u = values[i];
            let v = values[i + 1];
            values[i] = u + v;
            values[i + 1] = u - v;
        }
        let mut len = 4;
        while len <= n {
            let current_gen = gen_inv.pow((n / len) as u128);
            let mut acc = F::from(1);
            let gen_pows: Vec<_> = (0..len / 2)
                .map(|_| {
                    let res = acc;
                    acc *= current_gen;
                    res
                })
                .collect();
            for i in (0..n).step_by(len) {
                for j in 0..len / 2 {
                    let u = values[i + j];
                    let v = values[i + j + len / 2] * gen_pows[j];
                    values[i + j] = u + v;
                    values[i + j + len / 2] = u - v;
                }
            }
            len *= 2;
        }

        let n_inv = F::from(1) / F::from(n as i64);
        values.iter_mut().for_each(|val| *val *= n_inv);
        Polynomial { coeffs: values }
    }
}

impl<F: NttField> BatchedLagrangePolynomial<F> {
    pub fn intt(&self) -> BatchedPolynomial<F> {
        let total_len = self.evals.len();
        let poly_len = total_len / self.width;

        assert!(
            poly_len.is_power_of_two(),
            "Each polynomial length must be a power of 2"
        );
        assert_eq!(
            total_len % self.width,
            0,
            "Total evaluations must be divisible by width"
        );

        let mut batched_values = self.evals.clone();
        let gen_inv = F::from(1) / self.gen;

        // Process each polynomial in the batch
        for poly_values in batched_values.chunks_mut(poly_len) {
            // Apply INTT to this polynomial
            bit_reverse_permutation(poly_values);

            // unroll the first step
            for i in (0..poly_len).step_by(2) {
                let u = poly_values[i];
                let v = poly_values[i + 1];
                poly_values[i] = u + v;
                poly_values[i + 1] = u - v;
            }

            let mut len = 4;
            while len <= poly_len {
                let current_gen = gen_inv.pow((poly_len / len) as u128);
                let mut acc = F::from(1);
                let gen_pows: Vec<_> = (0..len / 2)
                    .map(|_| {
                        let res = acc;
                        acc *= current_gen;
                        res
                    })
                    .collect();
                for i in (0..poly_len).step_by(len) {
                    for j in 0..len / 2 {
                        let u = poly_values[i + j];
                        let v = poly_values[i + j + len / 2] * gen_pows[j];
                        poly_values[i + j] = u + v;
                        poly_values[i + j + len / 2] = u - v;
                    }
                }
                len *= 2;
            }

            // Apply normalization
            let n_inv = F::from(1) / F::from(poly_len as i64);
            poly_values.iter_mut().for_each(|val| *val *= n_inv);
        }

        BatchedPolynomial {
            coeffs: batched_values,
            width: self.width,
        }
    }

    // Optimized INTT using Plonky3-style layer processing
    pub fn intt_optimized(&self) -> BatchedPolynomial<F> {
        let width = self.width;
        let total_len = self.evals.len();
        let h = total_len / width;
        let log_h = h.trailing_zeros() as usize;

        assert!(
            h.is_power_of_two(),
            "Each polynomial length must be a power of 2"
        );
        assert_eq!(
            total_len % width,
            0,
            "Total evaluations must be divisible by width"
        );

        // Pre-calculate inverse twiddle factors for efficiency
        let gen_inv = F::from(1) / self.gen;
        let twiddles =
            F::pow_2_generator_powers(log_h as u64).expect("Failed to generate twiddle factors");

        // Convert to inverse twiddles
        let inv_twiddles: Vec<F> = twiddles
            .iter()
            .map(|&t| {
                if t == F::from(1) {
                    F::from(1)
                } else {
                    F::from(1) / t
                }
            })
            .collect();

        let mut coeffs = self.evals.clone();

        // Apply bit reversal to the matrix
        reverse_matrix_index_bits(&mut coeffs, width, h, log_h);

        // Apply DIT layers with inverse twiddles
        for layer in 0..log_h {
            dit_layer_optimized(&mut coeffs, width, h, log_h, layer, &inv_twiddles);
        }

        // Apply normalization to each polynomial
        let n_inv = F::from(1) / F::from(h as i64);
        coeffs.iter_mut().for_each(|val| *val *= n_inv);

        BatchedPolynomial { coeffs, width }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{benchmark, field::Field128 as F};

    #[test]
    fn ntt_benchmark_test() {
        let log_n = 24;
        let n = 1 << log_n;
        let coeffs = (0..n).map(F::from).collect();
        let pol = Polynomial::<F> { coeffs };
        let gen = F::pow_2_generator(log_n).unwrap();
        benchmark!("NTT ", pol.ntt(gen));
    }

    #[test]
    fn intt_test() {
        let log_n = 18;
        let n = 1 << log_n;
        let coeffs = (0..n).map(|i| F::from(i as i64)).collect();
        let pol = Polynomial::<F> { coeffs };
        let gen = F::pow_2_generator(log_n as u64).unwrap();
        let ntt = benchmark!("NTT ", pol.ntt(gen));
        let intt = benchmark!("INTT ", ntt.intt());
        assert_eq!(pol, intt);
    }

    #[test]
    fn batched_ntt_test() {
        let log_n = 4; // 16 coefficients per polynomial
        let poly_len = 1 << log_n;
        let width = 3; // 3 polynomials in batch
        let total_len = poly_len * width;

        // Create batched polynomial with 3 polynomials of length 16 each
        let coeffs: Vec<F> = (0..total_len).map(|i| F::from(i as i64)).collect();
        let batched_poly = BatchedPolynomial::<F> { coeffs, width };

        let gen = F::pow_2_generator(log_n as u64).unwrap();
        let batched_ntt = batched_poly.ntt(gen);
        let batched_intt = batched_ntt.intt();

        assert_eq!(batched_poly.coeffs, batched_intt.coeffs);
        assert_eq!(batched_poly.width, batched_intt.width);
    }

    #[test]
    fn batched_ntt_optimized_test() {
        let log_n = 4; // 16 coefficients per polynomial
        let poly_len = 1 << log_n;
        let width = 3; // 3 polynomials in batch
        let total_len = poly_len * width;

        // Create batched polynomial with 3 polynomials of length 16 each
        let coeffs: Vec<F> = (0..total_len).map(|i| F::from(i as i64)).collect();
        let batched_poly = BatchedPolynomial::<F> { coeffs, width };

        let gen = F::pow_2_generator(log_n as u64).unwrap();

        // Test that optimized version gives same results as regular version
        let batched_ntt_regular = batched_poly.ntt(gen);
        let batched_ntt_optimized = batched_poly.ntt_optimized(gen);

        assert_eq!(batched_ntt_regular.evals, batched_ntt_optimized.evals);

        // Test roundtrip with optimized versions
        let batched_intt_optimized = batched_ntt_optimized.intt_optimized();
        assert_eq!(batched_poly.coeffs, batched_intt_optimized.coeffs);
        assert_eq!(batched_poly.width, batched_intt_optimized.width);
    }

    #[test]
    fn batched_ntt_consistency_test() {
        let log_n = 3; // 8 coefficients per polynomial
        let poly_len = 1 << log_n;
        let width = 2; // 2 polynomials in batch

        // Create individual polynomials
        let poly1_coeffs: Vec<F> = (0..poly_len).map(|i| F::from(i as i64)).collect();
        let poly2_coeffs: Vec<F> = (poly_len..2 * poly_len)
            .map(|i| F::from(i as i64))
            .collect();

        let poly1 = Polynomial::<F> {
            coeffs: poly1_coeffs.clone(),
        };
        let poly2 = Polynomial::<F> {
            coeffs: poly2_coeffs.clone(),
        };

        // Create batched polynomial
        let mut batched_coeffs = poly1_coeffs;
        batched_coeffs.extend(poly2_coeffs);
        let batched_poly = BatchedPolynomial::<F> {
            coeffs: batched_coeffs,
            width,
        };

        let gen = F::pow_2_generator(log_n as u64).unwrap();

        // Compute individual NTTs
        let ntt1 = poly1.ntt(gen);
        let ntt2 = poly2.ntt(gen);

        // Compute batched NTT (both regular and optimized)
        let batched_ntt = batched_poly.ntt(gen);
        let batched_ntt_opt = batched_poly.ntt_optimized(gen);

        // Check that batched NTT gives same results as individual NTTs
        assert_eq!(ntt1.evals, batched_ntt.evals[0..poly_len]);
        assert_eq!(ntt2.evals, batched_ntt.evals[poly_len..2 * poly_len]);

        // Check that optimized version gives same results
        assert_eq!(batched_ntt.evals, batched_ntt_opt.evals);
    }

    #[test]
    fn batched_ntt_benchmark_test() {
        let log_n = 20;
        let poly_len = 1 << log_n;
        let width = 20;
        let total_len = poly_len * width;

        let coeffs: Vec<F> = (0..total_len).map(|i| F::from(i as i64)).collect();
        let batched_poly = BatchedPolynomial::<F> { coeffs, width };
        let gen = F::pow_2_generator(log_n as u64).unwrap();

        // Benchmark regular version
        let batched_ntt = benchmark!(
            "Batched NTT (regular) of length {poly_len} and width {width}",
            batched_poly.ntt(gen)
        );
        let batched_intt = benchmark!(
            "Batched INTT (regular) of length {poly_len} and width {width}",
            batched_ntt.intt()
        );

        // Benchmark optimized version
        let batched_ntt_opt = benchmark!(
            "Batched NTT (optimized) of length {poly_len} and width {width}",
            batched_poly.ntt_optimized(gen)
        );
        let batched_intt_opt = benchmark!(
            "Batched INTT (optimized) of length {poly_len} and width {width}",
            batched_ntt_opt.intt_optimized()
        );

        // Verify results are the same
        assert_eq!(batched_intt.coeffs, batched_intt_opt.coeffs);
    }

    #[test]
    fn butterfly_functions_test() {
        // Test the direct butterfly functions
        let mut hi = vec![F::from(1), F::from(2), F::from(3)];
        let mut lo = vec![F::from(4), F::from(5), F::from(6)];

        // Test twiddle-free butterfly
        let hi_orig = hi.clone();
        let lo_orig = lo.clone();
        apply_twiddle_free_butterfly(&mut hi, &mut lo);

        // Verify: hi = hi_orig + lo_orig, lo = hi_orig - lo_orig
        for i in 0..hi.len() {
            assert_eq!(hi[i], hi_orig[i] + lo_orig[i]);
            assert_eq!(lo[i], hi_orig[i] - lo_orig[i]);
        }

        // Test DIT butterfly with twiddle factor 2
        let mut hi2 = vec![F::from(1), F::from(2), F::from(3)];
        let mut lo2 = vec![F::from(4), F::from(5), F::from(6)];
        let twiddle = F::from(2);

        let hi2_orig = hi2.clone();
        let lo2_orig = lo2.clone();
        apply_dit_butterfly(&mut hi2, &mut lo2, twiddle);

        // Verify: hi = hi_orig + lo_orig * twiddle, lo = hi_orig - lo_orig * twiddle
        for i in 0..hi2.len() {
            assert_eq!(hi2[i], hi2_orig[i] + lo2_orig[i] * twiddle);
            assert_eq!(lo2[i], hi2_orig[i] - lo2_orig[i] * twiddle);
        }
    }
}
