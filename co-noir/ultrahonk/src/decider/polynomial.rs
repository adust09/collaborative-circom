use std::ops::{AddAssign, Index, IndexMut};

use ark_ff::PrimeField;

#[derive(Clone, Debug, Default)]
pub struct Polynomial<F: PrimeField> {
    pub(crate) coefficients: Vec<F>,
}

impl<F: PrimeField> Polynomial<F> {
    pub fn new(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }

    pub fn new_zero(size: usize) -> Self {
        Self {
            coefficients: vec![F::zero(); size],
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &F> {
        self.coefficients.iter()
    }

    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    pub fn degree(&self) -> usize {
        let mut len = self.coefficients.len() - 1;
        for c in self.coefficients.iter().rev() {
            if c.is_zero() {
                len -= 1;
            } else {
                break;
            }
        }
        len
    }

    pub(crate) fn add_scaled_slice(&mut self, src: &[F], scalar: &F) {
        // Barrettenberg uses multithreading here
        for (des, &src) in self.coefficients.iter_mut().zip(src.iter()) {
            *des += *scalar * src;
        }
    }

    pub(crate) fn add_scaled(&mut self, src: &Polynomial<F>, scalar: &F) {
        self.add_scaled_slice(&src.coefficients, scalar);
    }

    // Can only shift by 1
    pub(crate) fn shifted(&self) -> &[F] {
        assert!(!self.coefficients.is_empty());
        assert!(self.coefficients[0].is_zero());
        assert!(self.coefficients.last().unwrap().is_zero());
        &self.coefficients[1..]
    }
}

impl<F: PrimeField> Index<usize> for Polynomial<F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        &self.coefficients[index]
    }
}

impl<F: PrimeField> IndexMut<usize> for Polynomial<F> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coefficients[index]
    }
}

impl<F: PrimeField> AddAssign<&[F]> for Polynomial<F> {
    fn add_assign(&mut self, rhs: &[F]) {
        if rhs.len() > self.coefficients.len() {
            panic!("Polynomial too large, this should not have happened");
            self.coefficients.resize(rhs.len(), F::zero());
        }
        for (l, r) in self.coefficients.iter_mut().zip(rhs.iter()) {
            *l += *r;
        }
    }
}
