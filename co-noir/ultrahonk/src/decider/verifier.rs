use crate::decider::types::RelationParameters;
use crate::honk_curve::HonkCurve;
use crate::transcript::{TranscriptFieldType, TranscriptType};
use crate::types::WitnessCommitments;
use crate::{
    get_msb,
    oink::{self},
    types::VerifyingKey,
};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use std::marker::PhantomData;

use super::types::ClaimedEvaluations;

pub struct DeciderVerifier<P: HonkCurve<TranscriptFieldType>> {
    phantom_data: PhantomData<P>,
}

pub struct OpeningClaim<P: Pairing> {
    pub(crate) challenge: P::ScalarField,
    pub(crate) evaluation: P::ScalarField,
    pub(crate) commitment: P::G1,
}

impl<P: HonkCurve<TranscriptFieldType>> Default for DeciderVerifier<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: HonkCurve<TranscriptFieldType>> DeciderVerifier<P> {
    pub fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
    pub fn verify(
        self,
        vk: VerifyingKey<P>,
        public_inputs: Vec<P::ScalarField>,
        transcript: &mut TranscriptType,
        relation_parameters: RelationParameters<P::ScalarField>, //weg damit
        witness_comms: WitnessCommitments<P>,                    //weg damit
        claimed_evaluations: ClaimedEvaluations<P::ScalarField>,
    ) -> bool {
        tracing::trace!("Decider verification");
        let log_circuit_size = get_msb(vk.circuit_size);
        let mut oink_output = oink::verifier::OinkVerifier::<P>::new().verify(public_inputs);

        let mut gate_challenges = Vec::with_capacity(log_circuit_size as usize);
        gate_challenges[0] = transcript.get_challenge::<P>(format!("public_input_{}", 0));
        gate_challenges
            .iter_mut()
            .enumerate()
            .take(log_circuit_size as usize)
            .skip(1)
            .for_each(|(idx, gate_challenge)| {
                *gate_challenge = transcript.get_challenge::<P>(format!("public_input_{}", idx));
            });
        let (multivariate_challenge, claimed_evaluations, libra, sumcheck_verified) =
            crate::decider::sumcheck::verifier::sumcheck_verify(
                relation_parameters,
                transcript,
                &mut oink_output.alphas,
                claimed_evaluations,
                &vk,
            );

        // get_unshifted(), get_to_be_shifted(), get_shifted()

        let opening_claim: OpeningClaim<P> = crate::decider::zeromorph::verifier::zeromorph_verify(
            &vk.circuit_size,
            witness_comms.to_vec(),
            witness_comms.to_vec(),
            &claimed_evaluations,
            &claimed_evaluations,
            multivariate_challenge,
            transcript,
            // TODO Check these types/shifts
            // concatenated_evaluations
            // actually it is
            // commitments.get_unshifted(),
            // commitments.get_to_be_shifted(),
            // claimed_evaluations.get_unshifted(),
            // claimed_evaluations.get_shifted()
            // but i dont understand the shift yet
        );
        let pairing_points = reduce_verify(opening_claim, transcript);
        let pcs_verified =
            pairing_check::<P>(pairing_points[0], pairing_points[1], vk.g2_x, vk.g2_gen);
        sumcheck_verified && pcs_verified
    }
}

// this is the KZG one:
pub fn reduce_verify<P: HonkCurve<TranscriptFieldType>>(
    opening_pair: crate::decider::verifier::OpeningClaim<P>,
    transcript: &mut TranscriptType,
) -> [P::G1Affine; 2] {
    // Note: The pairing check can be expressed naturally as
    // e(C - v * [1]_1, [1]_2) = e([W]_1, [X - r]_2) where C =[p(X)]_1. This can be rearranged (e.g. see the plonk
    // paper) as e(C + r*[W]_1 - v*[1]_1, [1]_2) * e(-[W]_1, [X]_2) = 1, or e(P_0, [1]_2) * e(P_1, [X]_2) = 1
    let g1_affine = <P as Pairing>::G1Affine::generator();
    let g1_projective: <P as Pairing>::G1 = g1_affine.into_group();
    let quotient_commitment = transcript
        .receive_point_from_prover::<P>("KZG:W".to_string())
        .expect("Failed to receive quotient_commitment \"KZG:W\"");
    let p_1 = std::ops::Neg::neg(quotient_commitment.into_group());
    let p_0 = opening_pair.commitment.into_affine();
    let first = quotient_commitment.into_group() * opening_pair.challenge;
    // i dont understand why i have to do the multiplication like this???
    let second = std::ops::Mul::mul(g1_projective, opening_pair.evaluation);
    let p_0 = p_0 + first;
    let p_0 = p_0 - second;
    [p_0.into(), p_1.into()]
}

//need (?) the verifier SRS for the following ("https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/flat/g1.dat" and "https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/flat/g2.dat")
//Check: g1_identity first element in the SRS!
pub fn pairing_check<P: Pairing>(
    p0: P::G1Affine,
    p1: P::G1Affine,
    g2_x: P::G2Affine,
    g2_gen: P::G2Affine,
) -> bool {
    let p: Vec<P::G2Affine> = vec![g2_gen, g2_x];
    let g1_prepared = [P::G1Prepared::from(p0), P::G1Prepared::from(p1)];
    P::multi_pairing(g1_prepared, p).0 == P::TargetField::ONE
}
