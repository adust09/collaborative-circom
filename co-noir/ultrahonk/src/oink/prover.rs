use crate::{
    transcript::Keccak256Transcript,
    types::{ProverCrs, ProvingKey},
};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use std::{io, marker::PhantomData};

type HonkProofResult<T> = std::result::Result<T, HonkProofError>;

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

pub struct Plonk<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Plonk<P> {
    pub fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }

    // Add circuit size public input size and public inputs to transcript
    fn execute_preamble_round(
        transcript: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
        public_inputs: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("executing preamble round");

        transcript.add(proving_key.circuit_size.to_le_bytes());
        transcript.add(proving_key.num_public_inputs.to_le_bytes());
        transcript.add(proving_key.pub_inputs_offset.to_le_bytes());

        if proving_key.num_public_inputs as usize != public_inputs.len() {
            return Err(HonkProofError::CorruptedWitness(public_inputs.len()));
        }

        for public_input in public_inputs {
            transcript.add_scalar(*public_input);
        }
        Ok(())
    }

    fn commit(poly: &[P::ScalarField], crs: &ProverCrs<P>) -> HonkProofResult<P::G1> {
        if poly.len() > crs.monomials.len() {
            return Err(HonkProofError::CrsTooSmall);
        }
        Ok(P::G1::msm_unchecked(&crs.monomials, poly))
    }

    // Compute first three wire commitments
    fn execute_wire_commitments_round(
        transcript: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing wire commitments round");

        // Commit to the first three wire polynomials of the instance
        // We only commit to the fourth wire polynomial after adding memory records
        let w_l_comm = Self::commit(&proving_key.polynomials.w_l, &proving_key.crs)?;
        let w_r_comm = Self::commit(&proving_key.polynomials.w_r, &proving_key.crs)?;
        let w_o_comm = Self::commit(&proving_key.polynomials.w_o, &proving_key.crs)?;

        transcript.add_point(w_l_comm.into());
        transcript.add_point(w_r_comm.into());
        transcript.add_point(w_o_comm.into());

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    pub fn prove(
        self,
        proving_key: ProvingKey<P>,
        public_inputs: Vec<P::ScalarField>,
    ) -> HonkProofResult<()> {
        let mut transcript = Keccak256Transcript::default();

        Self::execute_preamble_round(&mut transcript, &proving_key, &public_inputs)?;
        Self::execute_wire_commitments_round(&mut transcript, &proving_key)?;

        Ok(())
    }
}
