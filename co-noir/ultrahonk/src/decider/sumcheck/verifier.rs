use crate::decider::types::ClaimedEvaluations;
use crate::decider::types::GateSeparatorPolynomial;
use crate::decider::types::RelationParameters;
use crate::decider::types::MAX_PARTIAL_RELATION_LENGTH;
use crate::decider::univariate::Univariate;
use crate::honk_curve::HonkCurve;
use crate::transcript::{TranscriptFieldType, TranscriptType};
use crate::{get_msb, types::VerifyingKey, NUM_ALPHAS};
use crate::{CONST_PROOF_SIZE_LOG_N, NUM_ALL_ENTITIES};
use ark_ec::pairing::Pairing;
use ark_ff::Field;

pub const HAS_ZK: bool = false;

pub fn sumcheck_verify<P: HonkCurve<TranscriptFieldType>>(
    relation_parameters: RelationParameters<P::ScalarField>,
    transcript: &mut TranscriptType,
    alphas: [P::ScalarField; NUM_ALPHAS],
    // claimed_evaluations: ClaimedEvaluations<P::ScalarField>, dont know if i need them
    relation_evaluations: (
        &mut Vec<P::ScalarField>,
        &mut Vec<P::ScalarField>,
        &mut Vec<P::ScalarField>,
    ),
    vk: &VerifyingKey<P>,
) -> (
    Vec<P::ScalarField>,
    Vec<P::ScalarField>,
    Option<Vec<P::ScalarField>>,
    bool,
) {
    let mut pow_univariate = GateSeparatorPolynomial::new(vk.gate_challenges.to_vec());
    let multivariate_n = vk.circuit_size;
    let multivariate_d = get_msb(multivariate_n);
    if multivariate_d == 0 {
        todo!("Number of variables in multivariate is 0.");
    }
    let mut libra_challenge = P::ScalarField::ZERO;
    let libra_total_sum: P::ScalarField;
    let mut target_total_sum = P::ScalarField::ZERO; //??????

    // if Flavor has ZK, the target total sum is corrected by Libra total sum multiplied by the Libra challenge
    if HAS_ZK {
        // get the claimed sum of libra masking multivariate over the hypercube
        libra_total_sum = transcript
            .receive_fr_from_prover::<P>("Libra:Sum".to_string())
            .expect(&format!("Failed to receive Libra:Sum"));
        // get the challenge for the ZK Sumcheck claim
        libra_challenge = transcript
            .receive_fr_from_prover::<P>("Libra:Challenge".to_string())
            .expect(&format!("Failed to receive Libra:Challenge"));
        target_total_sum += libra_total_sum * libra_challenge;
    };
    let mut multivariate_challenge: Vec<P::ScalarField> =
        Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);
    let mut verified: bool = true;

    for round_idx in 0..CONST_PROOF_SIZE_LOG_N {
        // TODO make this correct: (receive_from_prover<bb::Univariate<FF, BATCHED_RELATION_PARTIAL_LENGTH>>(round_univariate_label);)
        let round_univariate_label = format!("Sumcheck:univariate_{}", round_idx);

        let evaluations = transcript
            .receive_fr_array_from_verifier::<P, { MAX_PARTIAL_RELATION_LENGTH + 1 }>(
                round_univariate_label,
            )
            .expect(&format!(
                "Failed to receive round_univariate with idx {}",
                round_idx
            ));
        let round_univariate =
            Univariate::<P::ScalarField, { MAX_PARTIAL_RELATION_LENGTH + 1 }>::new(evaluations);

        let round_challenge = transcript.get_challenge::<P>(format!("Sumcheck:u_{}", round_idx));

        // no recursive flavor I guess, otherwise we need to make some modifications to the following
        if round_idx < multivariate_d as usize {
            let checked = check_sum::<P>(&round_univariate.evaluations, &target_total_sum); //round-check_sum?
            verified = verified && checked;
            multivariate_challenge.push(round_challenge);

            compute_next_target_sum::<P>(round_univariate, round_challenge); //round.compute_next_target_sum
            pow_univariate.partially_evaluate(round_challenge);
        } else {
            multivariate_challenge.push(round_challenge);
        }
    }
    let mut libra_evaluations = Vec::<P::ScalarField>::with_capacity(multivariate_d as usize);
    let mut full_libra_purported_value = P::ScalarField::ZERO;
    if HAS_ZK {
        for idx in 0..multivariate_d as usize {
            libra_evaluations[idx] = transcript
                .receive_fr_from_prover::<P>(format!("libra_evaluation{}", idx))
                .expect(&format!(
                    "Failed to receive libra_evaluations with idx {}",
                    idx
                ));
            full_libra_purported_value += libra_evaluations[idx];
        }
        full_libra_purported_value *= libra_challenge;
    }
    // todo!("I think these come from the below, check again with barretenberg");
    // let purported_evaluations = transcript
    //     .receive_fr_vec_from_verifier::<P>("Sumcheck:evaluations".to_string(), NUM_ALL_ENTITIES)
    //     .expect(&format!("Failed to receive Sumcheck:evaluations"));

    let transcript_evaluations = transcript
        .receive_fr_vec_from_verifier::<P>("Sumcheck:evaluations".to_string(), NUM_ALL_ENTITIES)
        .expect(&format!("Failed to receive Sumcheck:evaluations"));
    let full_honk_relation_purported_value = compute_full_relation_purported_value::<P>(
        &transcript_evaluations,
        relation_parameters,
        pow_univariate,
        relation_evaluations,
        alphas,
        if HAS_ZK {
            Some(full_libra_purported_value)
        } else {
            None
        },
    );
    let checked: bool = full_honk_relation_purported_value == target_total_sum;
    verified = verified && checked;
    if HAS_ZK {
        return (
            multivariate_challenge,
            transcript_evaluations,
            Some(libra_evaluations),
            verified,
        );
    }
    return (
        multivariate_challenge,
        transcript_evaluations,
        None,
        verified,
    );
}

fn compute_next_target_sum<P: Pairing>(
    mut univariate: Univariate<P::ScalarField, { MAX_PARTIAL_RELATION_LENGTH + 1 }>,
    round_challenge: P::ScalarField,
) -> P::ScalarField {
    univariate.evaluate(round_challenge)
}

fn check_sum<P: Pairing>(univariate: &[P::ScalarField], target_total_sum: &P::ScalarField) -> bool {
    let total_sum = univariate[0] + univariate[1];
    let mut sumcheck_round_failed = false;
    sumcheck_round_failed = target_total_sum != &total_sum;
    todo!("where does round_failed come from? is false per default, where should we save this? in a struct? I guess we maybe need something like a round struct");
    let mut round_failed = false;
    round_failed = round_failed || sumcheck_round_failed;
    !sumcheck_round_failed
}

fn compute_full_relation_purported_value<P: Pairing>(
    purported_evaluations: &Vec<P::ScalarField>,
    relation_parameters: RelationParameters<P::ScalarField>,
    gate_sparators: GateSeparatorPolynomial<P::ScalarField>,
    relation_evaluations: (
        &mut Vec<P::ScalarField>,
        &mut Vec<P::ScalarField>,
        &mut Vec<P::ScalarField>,
    ),
    alphas: [P::ScalarField; NUM_ALPHAS],
    full_libra_purported_value: Option<P::ScalarField>,
) -> P::ScalarField {
    accumulate_relation_evaluations_without_skipping::<P>(
        purported_evaluations,
        relation_parameters,
        &relation_evaluations,
        gate_sparators.partial_evaluation_result,
    );
    let running_challenge = P::ScalarField::ONE;
    let mut output = P::ScalarField::ZERO;
    scale_by_challenge_and_batch::<P>(
        relation_evaluations,
        &alphas,
        running_challenge,
        &mut output,
    );
    // Only add `full_libra_purported_value` if ZK is enabled
    if HAS_ZK {
        if let Some(value) = full_libra_purported_value {
            output += value;
        }
    }
    output
}
fn accumulate_relation_evaluations_without_skipping<P: Pairing>(
    purported_evaluations: &Vec<P::ScalarField>,
    relation_parameters: RelationParameters<P::ScalarField>,
    relation_evaluations: &(
        &mut Vec<P::ScalarField>,
        &mut Vec<P::ScalarField>,
        &mut Vec<P::ScalarField>,
    ),
    partial_evaluation_result: P::ScalarField,
) -> P::ScalarField {
    todo!()
}

fn scale_by_challenge_and_batch<P: Pairing>(
    tuple: (
        &mut Vec<P::ScalarField>,
        &mut Vec<P::ScalarField>,
        &mut Vec<P::ScalarField>,
    ),
    challenge: &[P::ScalarField; NUM_ALPHAS],
    mut current_scalar: P::ScalarField,
    result: &mut P::ScalarField,
) -> P::ScalarField {
    let (vec1, vec2, vec3) = tuple;
    for vec in [&mut *vec1, &mut *vec2, &mut *vec3].iter_mut() {
        for entry in vec.iter() {
            *result += *entry * current_scalar;
            for &alpha in challenge.iter() {
                current_scalar *= alpha;
            }
        }
    }

    *result
}
