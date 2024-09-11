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

// pub struct DeciderVerifier<P: Pairing> {
//     phantom_data: PhantomData<P>,
// }

// impl<P: Pairing> Default for DeciderVerifier<P> {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// impl<P: Pairing> DeciderVerifier<P> {
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
//         witness_comms: WitnessCommitments<P>,       //weg damit
//     ) -> bool {
//         // tracing::trace!("Decider verification");
//         let mut transcript = Keccak256Transcript::<P>::default();
//         let log_circuit_size = get_msb(vk.circuit_size.clone());
//         let oink_output = oink::verifier::OinkVerifier::<P>::new(
//             transcript,
//             vk,
//             relation_parameters,
//             witness_comms,
//         )
//         .verify(public_inputs);

        let mut transcript = Keccak256Transcript::<P>::default();
        let mut gate_challenges = Vec::with_capacity(log_circuit_size as usize);
        gate_challenges[0] = transcript.get_challenge();
        for idx in 1..log_circuit_size as usize {
            let mut transcript = Keccak256Transcript::<P>::default();
            transcript.add_scalar(gate_challenges[idx - 1]);
            gate_challenges[idx] = transcript.get_challenge();
        }
        let (multivariate_challenge, claimed_evaluations, sumcheck_verified) =
            crate::decider::sumcheck::verifier::sumcheck_verify(
                relation_parameters,
                &mut transcript,
                oink_output.alphas,
                vk,
            );
        // to do: build sumcheck verifier, returns (multivariate_challenge, claimed_evaluations, sumcheck_verified)
        // get_unshifted(), get_to_be_shifted(), get_shifted()

        let opening_claim = crate::decider::zeromorph::verifier::zeromorph_verify(
            vk.circuit_size,
            witness_comms,
            witness_comms,
            claimed_evaluations,
            claimed_evaluations,
            multivariate_challenge,
            &mut transcript,
            // TODO Check these types/shifts
            // concatenated_evaluations
            // actually it is
            // commitments.get_unshifted(),
            // commitments.get_to_be_shifted(),
            // claimed_evaluations.get_unshifted(),
            // claimed_evaluations.get_shifted()
            // but i dont understand the shift yet
        );
        let pairing_points = reduce_verify(&mut transcript, opening_claim);
        let pcs_verified = pairing_check(pairing_points[0], pairing_points[1]);
        sumcheck_verified && pcs_verified
    }
}

// I don't know about this one...
// this is the kzg one:
pub fn reduce_verify<P: Pairing>(
    transcript: &mut crate::transcript::Keccak256Transcript<P>,
    opening_pair: crate::verifier::OpeningClaim<P>,
) -> [P::G1Affine; 2] {
    // TODO: quotient_commitment = verifier_transcript->template receive_from_prover<Commitment>("KZG:W");
    let quotient_commitment: P::G1;

    // Note: The pairing check can be expressed naturally as
    // e(C - v * [1]_1, [1]_2) = e([W]_1, [X - r]_2) where C =[p(X)]_1. This can be rearranged (e.g. see the plonk
    // paper) as e(C + r*[W]_1 - v*[1]_1, [1]_2) * e(-[W]_1, [X]_2) = 1, or e(P_0, [1]_2) * e(P_1, [X]_2) = 1
    // let mut p0 = opening_pair.commitment + quotient_commitment * opening_pair.challenge
    //     - std::ops::Mul::mul(P::G1::generator(), opening_pair.evaluation);
    todo!()
}

//need (?) the verifier SRS for the following ("https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/flat/g1.dat" and "https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/flat/g2.dat")
//Check: g1_identity first element in the SRS!
pub fn pairing_check<P: Pairing>(p0: P::G1Affine, p1: P::G1Affine) -> bool {
    let g1_prepared = [P::G1Prepared::from(p0), P::G1Prepared::from(p1)];
    let precomputedlines: [P::G2Prepared; 2]; //todo: where to get this from
    let m_loop = P::multi_miller_loop(g1_prepared, precomputedlines);
    let result = P::final_exponentiation(m_loop);
    match result {
        Some(pairing_output) => pairing_output.0 == P::TargetField::ONE,
        None => false, // todo: what does that mean?
    }
}
