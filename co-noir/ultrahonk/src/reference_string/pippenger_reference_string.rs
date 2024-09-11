//  copied from barustenberg:

use std::sync::{Arc, RwLock};

use crate::reference_string::{ProverReferenceString, ReferenceStringFactory};
use ark_ec::pairing::Pairing;
use eyre::{anyhow, Result};

use super::{mem_reference_string::VerifierMemReferenceString, Pippenger};

#[derive(Debug)]
pub(crate) struct PippengerReferenceString<P: Pairing> {
    pippenger: Arc<Pippenger<P>>,
}

impl<P: Pairing> PippengerReferenceString<P> {
    pub(crate) fn new(pippenger: Arc<Pippenger<P>>) -> Self {
        PippengerReferenceString { pippenger }
    }
}

impl<P: Pairing> ProverReferenceString<P> for PippengerReferenceString<P> {
    // TODO
    fn get_monomial_size(&self) -> usize {
        todo!()
    }

    fn get_monomial_points(&self) -> Arc<Vec<P::G1Affine>> {
        // will we mutate self here?
        todo!()
    }
}

#[derive(Debug, Default)]
pub(crate) struct PippengerReferenceStringFactory<'a, P: Pairing> {
    pippenger: Arc<Pippenger<P>>,
    g2x: &'a [u8],
}

impl<'a, P: Pairing> PippengerReferenceStringFactory<'a, P> {
    pub(crate) fn new(pippenger: Arc<Pippenger<P>>, g2x: &'a [u8]) -> Self {
        PippengerReferenceStringFactory { pippenger, g2x }
    }
}

impl<'a, P: Pairing> ReferenceStringFactory<P> for PippengerReferenceStringFactory<'a, P> {
    type Pro = PippengerReferenceString<P>;
    type Ver = VerifierMemReferenceString<P>;

    fn get_prover_crs(&self, degree: usize) -> Result<Option<Arc<RwLock<Self::Pro>>>> {
        assert!(degree <= self.pippenger.get_num_points());
        Ok(Some(Arc::new(RwLock::new(PippengerReferenceString::new(
            self.pippenger.clone(),
        )))))
    }
    fn get_verifier_crs(&self) -> Result<Option<Arc<RwLock<Self::Ver>>>> {
        Ok(Some(Arc::new(RwLock::new(
            VerifierMemReferenceString::new(self.g2x),
        ))))
    }
}
