use crate::{
    transcript::Keccak256Transcript,
    types::{ProverCrs, ProverMemory, ProvingKey},
};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{One, Zero};
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
    memory: ProverMemory<P>,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Plonk<P> {
    pub fn new() -> Self {
        Self {
            memory: ProverMemory::default(),
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
        &mut self,
        transcript: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing wire commitments round");

        // Commit to the first three wire polynomials of the instance
        // We only commit to the fourth wire polynomial after adding memory records

        self.memory.witness_commitments.w_l_comm =
            Self::commit(&proving_key.polynomials.w_l, &proving_key.crs)?;
        self.memory.witness_commitments.w_r_comm =
            Self::commit(&proving_key.polynomials.w_r, &proving_key.crs)?;
        self.memory.witness_commitments.w_o_comm =
            Self::commit(&proving_key.polynomials.w_o, &proving_key.crs)?;

        transcript.add_point(self.memory.witness_commitments.w_l_comm.into());
        transcript.add_point(self.memory.witness_commitments.w_r_comm.into());
        transcript.add_point(self.memory.witness_commitments.w_o_comm.into());

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    // Compute sorted list accumulator and commitment
    fn execute_sorted_list_accumulator_round(
        &mut self,
        transcript_inout: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) {
        let mut transcript = Keccak256Transcript::<P>::default();
        std::mem::swap(&mut transcript, transcript_inout);

        self.memory.challenges.eta_1 = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(self.memory.challenges.eta_1);
        self.memory.challenges.eta_2 = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(self.memory.challenges.eta_2);
        self.memory.challenges.eta_3 = transcript.get_challenge();

        transcript_inout.add_scalar(self.memory.challenges.eta_3);

        // The memory record values are computed at the indicated indices as
        // w4 = w3 * eta^3 + w2 * eta^2 + w1 * eta + read_write_flag;

        // Compute read record values
        for gate_idx in proving_key.memory_read_records.iter() {
            let gate_idx = *gate_idx as usize;
            let target = &mut self.memory.w_4[gate_idx];
            *target += proving_key.polynomials.w_l[gate_idx] * self.memory.challenges.eta_1
                + proving_key.polynomials.w_r[gate_idx] * self.memory.challenges.eta_2
                + proving_key.polynomials.w_o[gate_idx] * self.memory.challenges.eta_3;
        }

        // Compute write record values
        for gate_idx in proving_key.memory_write_records.iter() {
            let gate_idx = *gate_idx as usize;
            let target = &mut self.memory.w_4[gate_idx];
            *target += proving_key.polynomials.w_l[gate_idx] * self.memory.challenges.eta_1
                + proving_key.polynomials.w_r[gate_idx] * self.memory.challenges.eta_2
                + proving_key.polynomials.w_o[gate_idx] * self.memory.challenges.eta_3
                + P::ScalarField::one();
        }

        // Commit to lookup argument polynomials and the finalized (i.e. with memory records) fourth wire polynomial

        todo!()
    }

    pub fn prove(
        mut self,
        proving_key: ProvingKey<P>,
        public_inputs: Vec<P::ScalarField>,
    ) -> HonkProofResult<()> {
        let mut transcript = Keccak256Transcript::default();

        // Add circuit size public input size and public inputs to transcript
        Self::execute_preamble_round(&mut transcript, &proving_key, &public_inputs)?;
        // Compute first three wire commitments
        self.execute_wire_commitments_round(&mut transcript, &proving_key)?;
        // Compute sorted list accumulator and commitment
        self.execute_sorted_list_accumulator_round(&mut transcript, &proving_key);

        debug_assert_eq!(
            proving_key.polynomials.w_l.len(),
            proving_key.polynomials.w_r.len()
        );
        debug_assert_eq!(
            proving_key.polynomials.w_l.len(),
            proving_key.polynomials.w_o.len()
        );
        self.memory
            .w_4
            .resize(proving_key.polynomials.w_l.len(), P::ScalarField::zero());

        Ok(())
    }
}
