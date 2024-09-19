use crate::decider::sumcheck::verifier::sumcheck_verify;
use crate::decider::types::{ClaimedEvaluations, RelationParameters};
use crate::transcript::{self, Poseidon2Transcript, TranscriptFieldType, TranscriptType};
use crate::types::{VerifyingKey, WitnessCommitments, WitnessEntities};
use crate::{get_msb, honk_curve, oink, CONST_PROOF_SIZE_LOG_N};
use ark_ec::pairing::{self, Pairing};
use ark_ec::Group;
use ark_ec::VariableBaseMSM;
use ark_ff::Field;
use std::{io, marker::PhantomData};
#[derive(Default)]
pub struct UltraHonkVerifier<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<
        P: Pairing
            + std::default::Default
            + honk_curve::HonkCurve<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>,
    > UltraHonkVerifier<P>
{
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
        transcript: TranscriptType,
        relation_parameters: RelationParameters<P::ScalarField>, //weg damit
        witness_comms: WitnessCommitments<P>,
        claimed_evaluations: ClaimedEvaluations<P::ScalarField>, //weg damit
    ) -> bool {
        tracing::trace!("UltraHonk verification");
        let log_circuit_size = get_msb(vk.circuit_size);
        let oink_output = oink::verifier::OinkVerifier::<P>::new(
            transcript,
            vk,
            relation_parameters,
            witness_comms,
        )
        .verify(public_inputs);

        let mut gate_challenges = Vec::<P::ScalarField>::with_capacity(log_circuit_size as usize);
        for idx in 0..log_circuit_size as usize {
            gate_challenges
                .push(transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{}", idx)));
        }
        let (multivariate_challenge, claimed_evaluations, libra_option, sumcheck_verified) =
            sumcheck_verify(
                relation_parameters,
                &mut transcript,
                &mut oink_output.alphas,
                claimed_evaluations,
                &vk,
            );

        todo!()
    }
}
