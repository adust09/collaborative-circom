use crate::{
    decider::{prover::Decider, types::ProverMemory},
    field_convert::HonkCurve,
    get_msb,
    oink::prover::Oink,
    transcript::{TranscriptFieldType, TranscriptType},
    types::ProvingKey,
};
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
    /// The proof has too little elements
    #[error("Proof too small")]
    ProofTooSmall,
    #[error(transparent)]
    IOError(#[from] io::Error),
}

pub struct UltraHonk<P: HonkCurve<TranscriptFieldType>> {
    phantom_data: PhantomData<P>,
}

impl<P: HonkCurve<TranscriptFieldType>> Default for UltraHonk<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: HonkCurve<TranscriptFieldType>> UltraHonk<P> {
    pub fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }

    fn generate_gate_challenges(
        &self,
        memory: &mut ProverMemory<P>,
        proving_key: &ProvingKey<P>,
        transcript: &mut TranscriptType,
    ) {
        tracing::trace!("generate gate challenges");

        let challenge_size = get_msb(proving_key.circuit_size) as usize;
        let mut gate_challenges = Vec::with_capacity(challenge_size);

        for idx in 0..challenge_size {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{}", idx));
            gate_challenges.push(chall);
        }
        memory.relation_parameters.gate_challenges = gate_challenges;
    }

    pub fn prove(
        self,
        proving_key: &ProvingKey<P>,
        public_inputs: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("UltraHonk prove");

        let mut transcript = TranscriptType::default();

        let oink = Oink::<P>::default();
        let mut memory =
            ProverMemory::from(oink.prove(proving_key, public_inputs, &mut transcript)?);
        self.generate_gate_challenges(&mut memory, proving_key, &mut transcript);

        let decider = Decider::new(memory);
        decider.prove(proving_key, transcript)?;
        todo!("What is the proof")
    }
}
