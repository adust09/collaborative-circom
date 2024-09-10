use crate::decider::types::PowPolynomial;
use crate::CONST_PROOF_SIZE_LOG_N;
use crate::{
    get_msb,
    oink::{self, types::WitnessCommitments, verifier::RelationParameters},
    transcript::{self, Keccak256Transcript},
    types::VerifyingKey,
    NUM_ALPHAS,
};
use ark_ec::pairing::{self, Pairing};
use ark_ec::VariableBaseMSM;
use ark_ff::Field;
use std::{io, marker::PhantomData};

pub struct DeciderVerifier<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Default for DeciderVerifier<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Pairing> DeciderVerifier<P> {
    pub fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
    pub fn verify(
        self,
        honk_proof: PhantomData<P>,
        vk: VerifyingKey<P>,
        public_inputs: Vec<P::ScalarField>,
        relation_parameters: RelationParameters<P>, //weg damit
        witness_comms: WitnessCommitments<P>,       //weg damit
    ) {
    }
}
