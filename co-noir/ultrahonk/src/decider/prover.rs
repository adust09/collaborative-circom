use super::types::ProverMemory;
use crate::{prover::HonkProofResult, transcript, types::ProvingKey};
use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

pub struct Decider<P: Pairing> {
    pub(super) memory: ProverMemory<P>,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Decider<P> {
    pub fn new(memory: ProverMemory<P>) -> Self {
        Self {
            memory,
            phantom_data: PhantomData,
        }
    }

    // Run sumcheck subprotocol.
    fn execute_relation_check_rounds(
        &self,
        transcript: &mut transcript::Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) {
        // This is just Sumcheck.prove

        self.sumcheck_prove(transcript, proving_key);

        todo!();
    }

    // Fiat-Shamir: rho, y, x, z
    // Execute Zeromorph multilinear PCS
    fn execute_pcs_rounds(&self) {
        todo!();
    }

    pub fn prove(
        self,
        proving_key: ProvingKey<P>,
        public_inputs: Vec<P::ScalarField>,
    ) -> HonkProofResult<()> {
        tracing::trace!("Decider prove");

        let mut transcript = transcript::Keccak256Transcript::<P>::default();
        transcript.add_scalar(
            self.memory
                .challenges
                .gate_challenges
                .last()
                .expect("Element is present")
                .to_owned(),
        );

        // Run sumcheck subprotocol.
        self.execute_relation_check_rounds(&mut transcript, &proving_key);
        // Fiat-Shamir: rho, y, x, z
        // Execute Zeromorph multilinear PCS
        self.execute_pcs_rounds();

        todo!("output the proof");
        Ok(())
    }
}
