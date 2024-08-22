use ark_ec::pairing::Pairing;
use std::{io, marker::PhantomData};

use crate::{oink::prover::Oink, types::ProvingKey};

pub type HonkProofResult<T> = std::result::Result<T, HonkProofError>;

/// The errors that may arise during the computation of a co-PLONK proof.
#[derive(Debug, thiserror::Error)]
pub enum HonkProofError {
    /// Indicates that the witness is too small for the provided circuit.
    #[error("Cannot index into witness {0}")]
    CorruptedWitness(usize),
    /// Indicates that the crs is too small
    #[error("CRS too small")]
    CrsTooSmall,
    #[error(transparent)]
    IOError(#[from] io::Error),
}

pub struct UltraHonk<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Default for UltraHonk<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Pairing> UltraHonk<P> {
    pub fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }

    pub fn prove(
        mut self,
        proving_key: ProvingKey<P>,
        public_inputs: Vec<P::ScalarField>,
    ) -> HonkProofResult<()> {
        tracing::trace!("UltraHonk prove");

        let oink = Oink::<P>::default();
        let oink_memory = oink.prove(proving_key, public_inputs)?;

        todo!();
        Ok(())
    }
}
