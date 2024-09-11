//  copied from barustenberg:

use std::sync::{Arc, RwLock};

use super::{Pippenger, ProverReferenceString, ReferenceStringFactory, VerifierReferenceString};
use crate::crs::read_transcript_g2;
// use crate::ecc::curves::bn254_scalar_multiplication::Pippenger;

use ark_ec::pairing::Pairing;
use eyre::{anyhow, Result};

#[derive(Debug, Default)]
pub(crate) struct VerifierFileReferenceString<P: Pairing> {
    g2_x: P::G2Affine,
}

impl<P: Pairing> VerifierFileReferenceString<P>
where
    P: Pairing,
{
    pub(crate) fn new(path: &str) -> Result<Self> {
        let mut g2_x = P::G2Affine::default();
        read_transcript_g2::<P>(&mut g2_x, path)?;

        Ok(Self { g2_x })
    }
}

impl<P: Pairing> VerifierReferenceString<P> for VerifierFileReferenceString<P> {
    fn get_g2x(&self) -> P::G2Affine {
        self.g2_x
    }
}

#[derive(Debug, Default)]
pub(crate) struct FileReferenceString<P: Pairing> {
    num_points: usize,
    pippenger: Pippenger<P>,
}

impl<P: Pairing> FileReferenceString<P> {
    pub(crate) fn new(num_points: usize, path: &str) -> Result<Self> {
        // Implementation depends on your project.
        // let pippenger = Pippenger::<P>::from_path(path, num_points)?;
        // Ok(Self {
        //     num_points,
        //     pippenger,
        // })
        todo!()
    }

    pub(crate) fn read_from_path(_path: &str) -> Result<Self, std::io::Error> {
        // Implementation depends on your project.
        todo!("FileReferenceString::read_from_path")
    }
}

impl<P: Pairing> ProverReferenceString<P> for FileReferenceString<P> {
    fn get_monomial_points(&self) -> Arc<Vec<P::G1Affine>> {
        // Implementation depends on your project.
        todo!()
    }

    fn get_monomial_size(&self) -> usize {
        self.num_points
    }
}

#[derive(Debug, Default)]
pub(crate) struct FileReferenceStringFactory {
    path: String,
}

impl FileReferenceStringFactory {
    pub(crate) fn new(path: String) -> Self {
        Self { path }
    }
}
impl<P: Pairing> ReferenceStringFactory<P> for FileReferenceStringFactory {
    type Pro = FileReferenceString<P>;
    type Ver = VerifierFileReferenceString<P>;
    fn get_prover_crs(&self, degree: usize) -> Result<Option<Arc<RwLock<Self::Pro>>>> {
        Ok(Some(Arc::new(RwLock::new(FileReferenceString::new(
            degree, &self.path,
        )?))))
    }

    fn get_verifier_crs(&self) -> Result<Option<Arc<RwLock<Self::Ver>>>> {
        Ok(Some(Arc::new(RwLock::new(
            VerifierFileReferenceString::new(&self.path)?,
        ))))
    }
}

#[derive(Debug, Default)]
pub(crate) struct DynamicFileReferenceStringFactory<P: Pairing> {
    path: String,
    degree: RwLock<usize>,
    prover_crs: Arc<RwLock<FileReferenceString<P>>>,
    verifier_crs: Arc<RwLock<VerifierFileReferenceString<P>>>,
}

impl<P: Pairing> DynamicFileReferenceStringFactory<P> {
    pub(crate) fn new(path: String, initial_degree: usize) -> Result<Self> {
        let verifier_crs = Arc::new(RwLock::new(VerifierFileReferenceString::new(&path)?));
        let prover_crs = Arc::new(RwLock::new(FileReferenceString::new(
            initial_degree,
            &path,
        )?));
        Ok(Self {
            path,
            degree: RwLock::new(initial_degree),
            prover_crs,
            verifier_crs,
        })
    }
}

impl<P: Pairing + std::default::Default> ReferenceStringFactory<P>
    for DynamicFileReferenceStringFactory<P>
{
    type Pro = FileReferenceString<P>;
    type Ver = VerifierFileReferenceString<P>;
    fn get_prover_crs(&self, degree: usize) -> Result<Option<Arc<RwLock<Self::Pro>>>> {
        if degree != *self.degree.read().unwrap() {
            *self.prover_crs.write().unwrap() = FileReferenceString::new(degree, &self.path)?;
            *self.degree.write().unwrap() = degree;
        }
        Ok(Some(self.prover_crs.clone()))
    }

    fn get_verifier_crs(&self) -> Result<Option<Arc<RwLock<Self::Ver>>>> {
        Ok(Some(self.verifier_crs.clone()))
    }
}
