use crate::honk_curve::HonkCurve;
use crate::transcript::{TranscriptFieldType, TranscriptType};
use crate::types::WitnessCommitments;
use crate::{
    get_msb,
    oink::{self, verifier::RelationParameters},
    types::VerifyingKey,
};
use ark_bn254::G1Affine;
use ark_ec::pairing::{self, Pairing};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use std::marker::PhantomData;

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
        honk_proof: PhantomData<P>,
        vk: VerifyingKey<P>,
        public_inputs: Vec<P::ScalarField>,
        transcript: &mut TranscriptType,
        relation_parameters: RelationParameters<P>, //weg damit
        witness_comms: WitnessCommitments<P>,       //weg damit
    ) -> bool {
        tracing::trace!("Decider verification");
        let log_circuit_size = get_msb(vk.circuit_size.clone());
        let oink_output = oink::verifier::OinkVerifier::<P>::new().verify(public_inputs);

        let mut gate_challenges = Vec::with_capacity(log_circuit_size as usize);
        gate_challenges[0] = transcript.get_challenge::<P>(format!("public_input_{}", 0));
        for idx in 1..log_circuit_size as usize {
            gate_challenges[idx] = transcript.get_challenge::<P>(format!("public_input_{}", idx));
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

        let opening_claim: OpeningClaim<P> = crate::decider::zeromorph::verifier::zeromorph_verify(
            vk.circuit_size,
            witness_comms.to_vec(),
            witness_comms.to_vec(),
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
        let pairing_points = reduce_verify(opening_claim, &mut transcript);
        let pcs_verified = pairing_check(pairing_points[0], pairing_points[1]);
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
    let p_1 = quotient_commitment;
    // let mut p0 = opening_pair.commitment + quotient_commitment * opening_pair.challenge
    //     - std::ops::Mul::mul(P::G1::generator(), opening_pair.evaluation);
    let mut p_0 = opening_pair.commitment.into_affine();
    let first = quotient_commitment.into_group() * opening_pair.challenge;
    // i dont understand why i have to do this multiplication like this???
    let second = std::ops::Mul::mul(g1_projective, opening_pair.evaluation);
    p_0 = (first - second).into();
    [p_0, p_1]
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

/*    pub(crate) challenge: P::ScalarField,
pub(crate) evaluation: P::ScalarField,
pub(crate) commitment: P::G1, */
