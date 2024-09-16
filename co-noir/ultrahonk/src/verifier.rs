use crate::decider::sumcheck::verifier::sumcheck_verify;
use crate::types::WitnessEntities;
use crate::CONST_PROOF_SIZE_LOG_N;
use crate::{
    get_msb,
    oink::{self, verifier::RelationParameters},
    transcript::Poseidon2Transcript,
    types::VerifyingKey,
};
use ark_ec::pairing::{self, Pairing};
use ark_ec::Group;
use ark_ec::VariableBaseMSM;
use ark_ff::Field;
use std::{io, marker::PhantomData};

pub struct UltraHonkVerifier<P: Pairing> {
    phantom_data: PhantomData<P>,
}
pub struct OpeningClaim<P: Pairing> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) evaluation: P::ScalarField,
    pub(crate) commitment: P::G1,
}

// impl<P: Pairing> Default for UltraHonkVerifier<P> {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// impl<P: Pairing + std::default::Default> UltraHonkVerifier<P> {
//     pub fn new() -> Self {
//         Self {
//             phantom_data: PhantomData,
//         }
//     }

//     pub fn verify(
//         self,
//         honk_proof: PhantomData<P>,
//         vk: VerifyingKey<P>,
//         public_inputs: Vec<P::ScalarField>,
//         relation_parameters: RelationParameters<P>, //weg damit
//         witness_comms: WitnessEntities<P>,          //weg damit
//     ) -> bool {
//         tracing::trace!("UltraHonk verification");
//         let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
//         let log_circuit_size = get_msb(vk.circuit_size.clone());
//         let oink_output = oink::verifier::OinkVerifier::<P>::new(
//             transcript,
//             vk,
//             relation_parameters,
//             witness_comms,
//         )
//         .verify(public_inputs);

//         let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
//         let mut gate_challenges = Vec::with_capacity(log_circuit_size as usize);
//         gate_challenges[0] = transcript.get_challenge();
//         for idx in 1..log_circuit_size as usize {
//             let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
//             // transcript.add_scalar(gate_challenges[idx - 1]);
//             // gate_challenges[idx] = transcript.get_challenge();
//         }
//         let (multivariate_challenge, claimed_evaluations, sumcheck_verified) =
//             sumcheck_verify(relation_parameters, &mut transcript, oink_output.alphas, vk);
//         // to do: build sumcheck verifier, returns (multivariate_challenge, claimed_evaluations, sumcheck_verified)
//         // get_unshifted(), get_to_be_shifted(), get_shifted()

//         //         let opening_claim = zeromorph_verify(
//         //             vk.circuit_size,
//         //             witness_comms,
//         //             witness_comms,
//         //             claimed_evaluations,
//         //             claimed_evaluations,
//         //             multivariate_challenge,
//         //             &mut transcript,
//         //             // concatenated_evaluations
//         //             // actually it is
//         //             // commitments.get_unshifted(),
//         //             // commitments.get_to_be_shifted(),
//         //             // claimed_evaluations.get_unshifted(),
//         //             // claimed_evaluations.get_shifted()
//         //             // but i dont understand the shift yet
//         //         );
//         //         let pairing_points = reduce_verify(&mut transcript, opening_claim);
//         //         let pcs_verified = pairing_check(pairing_points[0], pairing_points[1]);
//         //         sumcheck_verified && pcs_verified
//         //     }
//         // }
//         todo!()
//     }
// }
