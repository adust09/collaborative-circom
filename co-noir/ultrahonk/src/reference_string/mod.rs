//  copied from barustenberg:

pub(crate) mod file_reference_string;
pub(crate) mod mem_reference_string;
// pub(crate) mod pippenger_reference_string;

use std::fmt::Debug;
use std::sync::{Arc, RwLock};

use ark_ec::pairing::Pairing;
use eyre::{anyhow, Result};

use crate::crs::read_transcript_g1;
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

// impl<P: Pairing> Pippenger<P> {
//     pub(crate) fn get_num_points(&self) -> usize {
//         todo!()
//     }

//     pub(crate) fn from_points(_points: &[P::G1Affine], _num_points: usize) -> Self {
//         todo!()
//     }

//     pub(crate) fn from_path(path: &str, num_points: usize) -> Result<Self> {
//         let mut monomials = vec![P::G1Affine::default(); num_points];
//         read_transcript_g1(&mut monomials, num_points, path)?;
//         let point_table = monomials.clone();
//         generate_pippenger_point_table(&point_table, &mut monomials, num_points);
//         Ok(Self {
//             monomials,
//             num_points,
//         })
//     }
// }
