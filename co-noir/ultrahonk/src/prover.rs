use crate::{
    decider::{prover::Decider, types::ProverMemory},
    get_msb,
    oink::prover::Oink,
    transcript::Keccak256Transcript,
    types::ProvingKey,
    NUM_ALPHAS,
};
use ark_ec::pairing::Pairing;
use std::{io, marker::PhantomData};

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

    fn generate_gate_challenges(&self, memory: &mut ProverMemory<P>, proving_key: &ProvingKey<P>) {
        tracing::trace!("generate gate challenges");

        let challenge_size = get_msb(proving_key.circuit_size) as usize;
        let mut gate_challenges = Vec::with_capacity(challenge_size);

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(memory.relation_parameters.alphas[NUM_ALPHAS - 1]);

        gate_challenges.push(transcript.get_challenge());
        for idx in 1..challenge_size {
            let mut transcript = Keccak256Transcript::<P>::default();
            transcript.add_scalar(gate_challenges[idx - 1]);
            gate_challenges.push(transcript.get_challenge());
        }
        memory.relation_parameters.gate_challenges = gate_challenges;
    }

    pub fn prove(
        self,
        proving_key: &ProvingKey<P>,
        public_inputs: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("UltraHonk prove");

        let oink = Oink::<P>::default();
        let mut memory = ProverMemory::from(oink.prove(proving_key, public_inputs)?);
        self.generate_gate_challenges(&mut memory, proving_key);

        let decider = Decider::new(memory);
        decider.prove(proving_key)?;
        todo!("What is the proof")
    }
}
