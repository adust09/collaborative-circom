use ark_ff::{PrimeField, Zero};
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

#[derive(Clone, Debug)]
pub struct Univariate<F: PrimeField, const SIZE: usize> {
    pub(crate) evaluations: [F; SIZE],
}

impl<F: PrimeField, const SIZE: usize> Univariate<F, SIZE> {
    pub fn sqr(self) -> Self {
        let mut result = self;
        for i in 0..SIZE {
            result.evaluations[i].square_in_place();
        }
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Default for Univariate<F, SIZE> {
    fn default() -> Self {
        Self {
            evaluations: [F::zero(); SIZE],
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Add for Univariate<F, SIZE> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result = self;
        result += rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Add<&Self> for Univariate<F, SIZE> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let mut result = self;
        result += rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Add<&F> for Univariate<F, SIZE> {
    type Output = Self;

    fn add(self, rhs: &F) -> Self::Output {
        let mut result = self;
        result += rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> AddAssign for Univariate<F, SIZE> {
    fn add_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.evaluations[i] += rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> AddAssign<&Self> for Univariate<F, SIZE> {
    fn add_assign(&mut self, rhs: &Self) {
        for i in 0..SIZE {
            self.evaluations[i] += rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> AddAssign<&F> for Univariate<F, SIZE> {
    fn add_assign(&mut self, rhs: &F) {
        for i in 0..SIZE {
            self.evaluations[i] += rhs;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Sub<u64> for Univariate<F, SIZE> {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        let mut result = self;
        let rhs = F::from(rhs);

        result -= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Sub for Univariate<F, SIZE> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut result = self;
        result -= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Sub<&Self> for Univariate<F, SIZE> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let mut result = self;
        result -= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> SubAssign<F> for Univariate<F, SIZE> {
    fn sub_assign(&mut self, rhs: F) {
        for i in 0..SIZE {
            self.evaluations[i] -= rhs;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> SubAssign for Univariate<F, SIZE> {
    fn sub_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.evaluations[i] -= rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> SubAssign<&Self> for Univariate<F, SIZE> {
    fn sub_assign(&mut self, rhs: &Self) {
        for i in 0..SIZE {
            self.evaluations[i] -= rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Mul for Univariate<F, SIZE> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut result = self;
        result *= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Mul<&Self> for Univariate<F, SIZE> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        let mut result = self;
        result *= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Mul<F> for Univariate<F, SIZE> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        let mut result = self;
        result *= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Mul<&F> for Univariate<F, SIZE> {
    type Output = Self;

    fn mul(self, rhs: &F) -> Self::Output {
        let mut result = self;
        result *= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> MulAssign for Univariate<F, SIZE> {
    fn mul_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.evaluations[i] *= rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> MulAssign<&Self> for Univariate<F, SIZE> {
    fn mul_assign(&mut self, rhs: &Self) {
        for i in 0..SIZE {
            self.evaluations[i] *= rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> MulAssign<F> for Univariate<F, SIZE> {
    fn mul_assign(&mut self, rhs: F) {
        for i in 0..SIZE {
            self.evaluations[i] *= rhs;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> MulAssign<&F> for Univariate<F, SIZE> {
    fn mul_assign(&mut self, rhs: &F) {
        for i in 0..SIZE {
            self.evaluations[i] *= rhs;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Zero for Univariate<F, SIZE> {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        for val in self.evaluations.iter() {
            if !val.is_zero() {
                return false;
            }
        }
        true
    }
}
