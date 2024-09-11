//  copied from barustenberg:

pub(crate) mod file_reference_string;
pub(crate) mod mem_reference_string;
pub(crate) mod pippenger_reference_string;

use std::fmt::Debug;
use std::sync::{Arc, RwLock};

use ark_ec::pairing::Pairing;
use eyre::{anyhow, Result};
#[derive(Clone, Debug, Default)]
pub(crate) struct Pippenger<P: Pairing> {
    monomials: Vec<P::G1Affine>,
    num_points: usize,
}
pub(crate) trait VerifierReferenceString<P: Pairing>: Debug + Send + Sync {
    fn get_g2x(&self) -> P::G2Affine;
}

pub(crate) trait ProverReferenceString<P: Pairing>: Debug + Send + Sync {
    // cpp definition for this is non-const but all implementations are const,
    // unclear to me that we need a mut ref to self
    fn get_monomial_points(&self) -> Arc<Vec<P::G1Affine>>;
    fn get_monomial_size(&self) -> usize;
}
pub(crate) trait ReferenceStringFactory<P: Pairing>: Default {
    type Pro: ProverReferenceString<P> + 'static;
    type Ver: VerifierReferenceString<P> + 'static;
    fn get_prover_crs(&self, _size: usize) -> Result<Option<Arc<RwLock<Self::Pro>>>>;

    fn get_verifier_crs(&self) -> Result<Option<Arc<RwLock<Self::Ver>>>>;
}
