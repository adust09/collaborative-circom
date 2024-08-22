use super::types::ProverMemory;
use crate::{prover::HonkProofResult, types::ProvingKey};
use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

pub struct Decider<P: Pairing> {
    memory: ProverMemory<P>,
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
    fn execute_relation_check_rounds(&self) {
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

        // Run sumcheck subprotocol.
        self.execute_relation_check_rounds();
        // Fiat-Shamir: rho, y, x, z
        // Execute Zeromorph multilinear PCS
        self.execute_pcs_rounds();

        todo!("output the proof");
        Ok(())
    }
}
