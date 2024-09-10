use std::ops::Add;

use ark_ff::{PrimeField, Zero};

pub struct Univariate<F: PrimeField, const SIZE: usize> {
    pub(crate) coefficients: [F; SIZE],
}

impl<F: PrimeField, const SIZE: usize> Default for Univariate<F, SIZE> {
    fn default() -> Self {
        Self {
            coefficients: [F::zero(); SIZE],
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Add for Univariate<F, SIZE> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result = self;
        for i in 0..SIZE {
            result.coefficients[i] += rhs.coefficients[i];
        }
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Zero for Univariate<F, SIZE> {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        for val in self.coefficients.iter() {
            if !val.is_zero() {
                return false;
            }
        }
        true
    }
}
