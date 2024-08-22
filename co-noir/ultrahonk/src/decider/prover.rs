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

    pub fn prove(
        self,
        proving_key: ProvingKey<P>,
        public_inputs: Vec<P::ScalarField>,
    ) -> HonkProofResult<()> {
        tracing::trace!("Decider prove");

        todo!("Implement Decider::prove");
        Ok(())
    }
}
