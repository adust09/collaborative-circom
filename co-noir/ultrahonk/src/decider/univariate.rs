use ark_ff::{PrimeField, Zero};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

#[derive(Clone, Debug)]
pub struct Univariate<F: PrimeField, const SIZE: usize> {
    pub(crate) evaluations: [F; SIZE],
}

impl<F: PrimeField, const SIZE: usize> Univariate<F, SIZE> {
    pub const SIZE: usize = SIZE;

    pub fn new(evaluations: [F; SIZE]) -> Self {
        Self { evaluations }
    }

    pub fn double(self) -> Self {
        let mut result = self;
        result.double_in_place();
        result
    }

    pub fn double_in_place(&mut self) {
        for i in 0..SIZE {
            self.evaluations[i].double_in_place();
        }
    }

    pub fn sqr(self) -> Self {
        let mut result = self;
        result.square_in_place();
        result
    }

    pub fn square_in_place(&mut self) {
        for i in 0..SIZE {
            self.evaluations[i].square_in_place();
        }
    }

    /**
     * @brief Given a univariate f represented by {f(domain_start), ..., f(domain_end - 1)}, compute the
     * evaluations {f(domain_end),..., f(extended_domain_end -1)} and return the Univariate represented by
     * {f(domain_start),..., f(extended_domain_end -1)}
     *
     * @details Write v_i = f(x_i) on a the domain {x_{domain_start}, ..., x_{domain_end-1}}. To efficiently
     * compute the needed values of f, we use the barycentric formula
     *      - f(x) = B(x) Σ_{i=domain_start}^{domain_end-1} v_i / (d_i*(x-x_i))
     * where
     *      - B(x) = Π_{i=domain_start}^{domain_end-1} (x-x_i)
     *      - d_i  = Π_{j ∈ {domain_start, ..., domain_end-1}, j≠i} (x_i-x_j) for i ∈ {domain_start, ...,
     * domain_end-1}
     *
     * When the domain size is two, extending f = v0(1-X) + v1X to a new value involves just one addition
     * and a subtraction: setting Δ = v1-v0, the values of f(X) are f(0)=v0, f(1)= v0 + Δ, v2 = f(1) + Δ, v3
     * = f(2) + Δ...
     *
     */
    pub(crate) fn extend_from(&mut self, poly: &[F]) {
        self.evaluations[0] = poly[0];
        self.evaluations[1] = poly[1];

        // We only need to implement LENGTH = 2
        // TODO this is not the case anymore...
        assert_eq!(poly.len(), 2);
        let delta = self.evaluations[1] - self.evaluations[0];
        for i in 2..SIZE {
            self.evaluations[i] = self.evaluations[i - 1] + delta;
        }
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE2: usize>(
        &self,
        result: &mut Univariate<F, SIZE2>,
        extended_random_poly: &Univariate<F, SIZE2>,
        partial_evaluation_result: &F,
        linear_independant: bool,
    ) {
        // let extended =
        todo!()
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

impl<F: PrimeField, const SIZE: usize> Neg for Univariate<F, SIZE> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut result = self;
        for i in 0..SIZE {
            result.evaluations[i] = -result.evaluations[i];
        }
        result
    }
}
