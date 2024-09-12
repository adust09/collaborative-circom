use crate::decider::types::GateSeparatorPolynomial;
use crate::CONST_PROOF_SIZE_LOG_N;
use crate::{
    get_msb,
    oink::{self, types::WitnessCommitments, verifier::RelationParameters},
    transcript::{self, Keccak256Transcript},
    types::VerifyingKey,
    NUM_ALPHAS,
};
use ark_ec::pairing::{self, Pairing};
use ark_ec::Group;
use ark_ec::VariableBaseMSM;
use ark_ff::Field;
use std::{io, marker::PhantomData};

pub const HAS_ZK: bool = false;

pub fn sumcheck_verify<P: Pairing>(
    relation_parameters: RelationParameters<P>,
    transcript: &mut transcript::Keccak256Transcript<P>,
    alphas: [P::ScalarField; NUM_ALPHAS],
    // gate_challenges: Vec<P::ScalarField>,
    vk: VerifyingKey<P>,
) -> (Vec<P::ScalarField>, Vec<P::ScalarField>, bool) {
    let mut pow_univariate = GateSeparatorPolynomial::new(vk.gate_challenges);
    let multivariate_n = vk.circuit_size;
    let multivariate_d = get_msb(multivariate_n);
    if multivariate_d == 0 {
        todo!("Number of variables in multivariate is 0.");
    }
    if HAS_ZK {
        todo!();
    };
    let mut multivariate_challenge: Vec<P::ScalarField> =
        Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);
    let target_total_sum = P::ScalarField::ZERO; //??????
    let mut verified: bool = true;
    for round_idx in 0..CONST_PROOF_SIZE_LOG_N {
        // TODO make this correct: (receive_from_prover<bb::Univariate<FF, BATCHED_RELATION_PARTIAL_LENGTH>>(round_univariate_label);)
        let round_univariate = Vec::<P::ScalarField>::with_capacity(multivariate_n as usize);

        let mut transcript = Keccak256Transcript::<P>::default();
        // transcript.add_scalar(round_univariate);

        let round_challenge = transcript.get_challenge();

        // no recursive flavor I guess, otherwise we need to make some modifications to the following
        if round_idx < multivariate_d as usize {
            let checked = check_sum::<P>(&round_univariate, &target_total_sum); //round-check_sum?
            verified = verified && checked;
            multivariate_challenge.push(round_challenge);

            compute_next_target_sum::<P>(round_univariate, round_challenge); //round.compute_next_target_sum
            pow_univariate.partially_evaluate(round_challenge);
        } else {
            multivariate_challenge.push(round_challenge);
        }
    }
    todo!("new Libra stuff (ZK?)");
    let purported_evaluations: Vec<P::ScalarField>;
    todo!("get transcript_evaluations from prover");
    let full_honk_relation_purported_value = compute_full_relation_purported_value(
        purported_evaluations,
        relation_parameters,
        pow_univariate,
        alphas,
    );
    let checked: bool = full_honk_relation_purported_value == target_total_sum;
    verified = verified && checked;
    if HAS_ZK {
        todo!(); // For ZK Flavors: the evaluations of Libra univariates are included in the Sumcheck Output
    };
    todo!("return multivariate_challenge, purported_evaluations, verified");
}

fn compute_next_target_sum<P: Pairing>(
    univariate: Vec<P::ScalarField>,
    round_challenge: P::ScalarField,
) -> P::ScalarField {
    todo!("return evalution of univariate on round_challenge");
}

fn check_sum<P: Pairing>(
    univariate: &Vec<P::ScalarField>,
    target_total_sum: &P::ScalarField,
) -> bool {
    let total_sum: P::ScalarField; //= univariate.value_at(0) + univariate.value_at(1);
    let mut sumcheck_round_failed = false;
    sumcheck_round_failed = target_total_sum != &total_sum;
    round_failed = round_failed || sumcheck_round_failed;
    //where does round_failed come from? is false per default, where should we save this? in a struct? I guess we maybe need something like a round struct
    !sumcheck_round_failed
}

fn compute_full_relation_purported_value<P: Pairing>(
    purported_evaluations: Vec<P::ScalarField>,
    relation_parameters: RelationParameters<P>,
    pow_polynomial: GateSeparatorPolynomial<P::ScalarField>,
    alphas: [P::ScalarField; NUM_ALPHAS],
) -> P::ScalarField {
    let mut running_challenge = P::ScalarField::ONE;
    let mut output = P::ScalarField::ZERO;
    scale_by_challenge_and_batch(
        relation_evaluations,
        &alphas,
        running_challenge,
        &mut output,
    );
    if HAS_ZK {
        todo!();
        // output += full_libra_purported_value.value();
    };
    output
}
fn accumulate_relation_evaluations_without_skipping<P: Pairing>(
    purported_evaluations: Vec<P::ScalarField>,
    relation_parameters: RelationParameters<P>,
    pow_polynomial: GateSeparatorPolynomial<P::ScalarField>,
    relation_evaluations: Vec<P::ScalarField>,
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
