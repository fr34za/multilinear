use std::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use ark_ff::{Field as ArkField, Fp128, MontBackend, MontConfig};

pub trait Field = Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Neg<Output = Self>
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Self>
    + DivAssign
    + Sized
    + Copy
    + Sum
    + Product
    + From<i64>
    + Eq;

#[derive(MontConfig)]
#[modulus = "340282366920938463463374557953744961537"]
#[generator = "3"]
pub struct FrConfig128;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Field128(pub Fp128<MontBackend<FrConfig128, 2>>);

impl AsRef<[u8]> for Field128 {
    fn as_ref(&self) -> &[u8] {
        let data = &self.0 .0 .0;
        unsafe {
            std::slice::from_raw_parts(
                data.as_ptr() as *const u8,
                data.len() * std::mem::size_of::<u64>(),
            )
        }
    }
}

impl Field128 {
    pub fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        Field128(self.0.pow(exp))
    }
}
// Implement Add
impl Add for Field128 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Field128(self.0 + rhs.0)
    }
}

impl AddAssign for Field128 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for Field128 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Field128(self.0 - rhs.0)
    }
}

impl SubAssign for Field128 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Neg for Field128 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Field128(-self.0)
    }
}

impl Mul for Field128 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Field128(self.0 * rhs.0)
    }
}

impl MulAssign for Field128 {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl Div for Field128 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        Field128(self.0 / rhs.0)
    }
}

impl DivAssign for Field128 {
    fn div_assign(&mut self, rhs: Self) {
        self.0 /= rhs.0;
    }
}

impl Sum for Field128 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Field128(Fp128::from(0)), |a, b| a + b)
    }
}

impl Product for Field128 {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Field128(Fp128::from(1)), |a, b| a * b)
    }
}

impl From<i64> for Field128 {
    fn from(val: i64) -> Self {
        Field128(Fp128::from(val))
    }
}

impl std::fmt::Display for Field128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
