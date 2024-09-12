pub mod prover;
pub mod types;

use super::polynomial::Polynomial;
use ark_ff::PrimeField;

pub struct ZeroMorphOpeningClaim<F: PrimeField> {
    polynomial: Polynomial<F>,
    opening_pair: OpeningPair<F>,
}

pub struct OpeningPair<F: PrimeField> {
    pub(crate) challenge: F,
    pub(crate) evaluation: F,
}
pub mod verifier;
