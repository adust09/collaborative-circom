use crate::decider::types::PowPolynomial;
use crate::CONST_PROOF_SIZE_LOG_N;
use crate::{
    get_msb,
    oink::{self, types::WitnessCommitments, verifier::RelationParameters},
    transcript::{self, Poseidon2Transcript},
    types::VerifyingKey,
    NUM_ALPHAS,
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
    challenge: P::ScalarField,
    evaluation: P::ScalarField,
    commitment: P::G1,
}

impl<P: Pairing> Default for UltraHonkVerifier<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Pairing> UltraHonkVerifier<P> {
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
    ) -> bool {
        tracing::trace!("UltraHonk verification");
        let mut transcript = Poseidon2Transcript::<P>::default();
        let log_circuit_size = get_msb(vk.circuit_size.clone());
        let oink_output = oink::verifier::OinkVerifier::<P>::new(
            transcript,
            vk,
            relation_parameters,
            witness_comms,
        )
        .verify(public_inputs);

        let mut transcript = Poseidon2Transcript::<P>::default();
        let mut gate_challenges = Vec::with_capacity(log_circuit_size as usize);
        gate_challenges[0] = transcript.get_challenge();
        for idx in 1..log_circuit_size as usize {
            let mut transcript = Poseidon2Transcript::<P>::default();
            transcript.add_scalar(gate_challenges[idx - 1]);
            gate_challenges[idx] = transcript.get_challenge();
        }
        let (multivariate_challenge, claimed_evaluations, sumcheck_verified) =
            sumcheck_verify(relation_parameters, &mut transcript, oink_output.alphas, vk);
        // to do: build sumcheck verifier, returns (multivariate_challenge, claimed_evaluations, sumcheck_verified)
        // get_unshifted(), get_to_be_shifted(), get_shifted()

        let opening_claim = zeromorph_verify(
            vk.circuit_size,
            witness_comms,
            witness_comms,
            claimed_evaluations,
            claimed_evaluations,
            multivariate_challenge,
            &mut transcript,
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

// (compare cpp/src/barretenberg/commitment_schemes/zeromorph/zeromorph.hpp or https://hackmd.io/dlf9xEwhTQyE3hiGbq4FsA?view)

pub fn zeromorph_verify<P: Pairing>(
    circuit_size: u32,
    unshifted_commitments: Vec<P::G1>,
    to_be_shifted_commitments: Vec<P::G1>,
    unshifted_evaluations: Vec<P::ScalarField>,
    shifted_evaluations: Vec<P::ScalarField>,
    multivariate_challenge: Vec<P::ScalarField>,
    transcript_inout: &mut Poseidon2Transcript<P>,
    concatenated_evaluations: Vec<P::ScalarField>, // RefSpan<FF> concatenated_evaluations = {}
) -> OpeningClaim<P> {
    let log_n = get_msb(circuit_size.clone()); //TODO: check this
    let mut transcript = Poseidon2Transcript::<P>::default();
    std::mem::swap(&mut transcript, transcript_inout);

    let rho = transcript.get_challenge();

    let mut transcript = Poseidon2Transcript::<P>::default();
    transcript.add_scalar(rho);

    let mut batched_evaluation = P::ScalarField::ZERO;
    let mut batching_scalar = P::ScalarField::ONE;

    for &value in unshifted_evaluations
        .iter()
        .chain(shifted_evaluations.iter())
    // .chain(concatenated_evaluations.iter())
    {
        batched_evaluation += value * batching_scalar;
        batching_scalar *= rho;
    }

    let mut c_q_k: Vec<P::G1> = Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);
    // todo: where do we get the commitments [q_k] from? rsp. which commitments are these? fill above vector with these
    todo!("get commitments");
    let mut transcript = Poseidon2Transcript::<P>::default();
    transcript.add_scalar(rho);

    let y_challenge = transcript.get_challenge();

    // Receive commitment C_{q}
    //  auto c_q = transcript->template receive_from_prover<Commitment>("ZM:C_q");
    let c_q: P::G1;

    let mut transcript = Poseidon2Transcript::<P>::default();
    transcript.add_scalar(y_challenge);

    let x_challenge = transcript.get_challenge();
    let mut transcript = Poseidon2Transcript::<P>::default();
    transcript.add_scalar(x_challenge);
    let z_challenge = transcript.get_challenge();

    let c_zeta_x = compute_c_zeta_x::<P>(
        c_q,
        &c_q_k,
        y_challenge,
        x_challenge,
        log_n as u32,
        circuit_size,
    );

    let c_z_x = compute_c_z_x::<P>(
        unshifted_commitments,
        to_be_shifted_commitments,
        &c_q_k,
        rho,
        batched_evaluation,
        x_challenge,
        multivariate_challenge,
        log_n as u32,
        circuit_size,
    );
    let c_zeta_z = c_zeta_x + c_z_x * z_challenge;

    return OpeningClaim {
        challenge: x_challenge,
        evaluation: P::ScalarField::ZERO,
        commitment: c_zeta_z,
    };
}
fn compute_c_zeta_x<P: Pairing>(
    c_q: P::G1,
    c_q_k: &Vec<P::G1>,
    y_challenge: P::ScalarField,
    x_challenge: P::ScalarField,
    log_circuit_size: u32,
    circuit_size: u32,
) -> P::G1 {
    let mut scalars: Vec<P::ScalarField> = Vec::new();
    scalars.push(P::ScalarField::ONE);
    let mut commitments: Vec<P::G1Affine> = Vec::new();
    commitments.push(P::G1Affine::from(c_q));

    // Contribution from C_q_k, k = 0,...,log_N-1
    for k in 0..CONST_PROOF_SIZE_LOG_N {
        // Utilize dummy rounds in order to make verifier circuit independent of proof size
        let is_dummy_round = k >= log_circuit_size as usize;
        let deg_k = (1 << k) - 1;
        // Compute scalar y^k * x^{N - deg_k - 1}
        let mut scalar = y_challenge.pow([k as u64]);
        let x_exponent = if is_dummy_round {
            0
        } else {
            circuit_size - deg_k - 1
        };
        scalar *= x_challenge.pow([x_exponent as u64]);
        scalar *= P::ScalarField::ZERO - P::ScalarField::ONE;

        if is_dummy_round {
            scalar = P::ScalarField::ZERO;
        }

        scalars.push(scalar);
        commitments.push(P::G1Affine::from(c_q_k[k]));
    }

    P::G1::msm_unchecked(&commitments, &scalars)
}

fn compute_c_z_x<P: Pairing>(
    f_commitments: Vec<P::G1>,
    g_commitments: Vec<P::G1>,
    c_q_k: &Vec<P::G1>,
    rho: P::ScalarField,
    batched_evaluation: P::ScalarField,
    x_challenge: P::ScalarField,
    u_challenge: Vec<P::ScalarField>,
    log_circuit_size: u32,
    circuit_size: u32,
) -> P::G1 {
    let mut scalars: Vec<P::ScalarField> = Vec::new();
    let mut commitments: Vec<P::G1> = Vec::new();
    let phi_numerator = x_challenge.pow(&[circuit_size as u64]) - P::ScalarField::ONE;
    let minus_one = P::ScalarField::ZERO - P::ScalarField::ONE;
    //todo
    let phi_n_x = phi_numerator / (x_challenge - P::ScalarField::ONE);
    scalars.push(batched_evaluation * x_challenge * phi_n_x * minus_one);
    //TODO: push g1_identity = first element in the SRS!
    // commitments.push(P::G1::identity)

    let mut rho_pow = P::ScalarField::ONE;
    for &value in f_commitments.iter() {
        scalars.push(x_challenge * rho_pow);
        commitments.push(value);
        rho_pow *= rho;
    }
    for &value in g_commitments.iter() {
        scalars.push(rho_pow);
        commitments.push(value);
        rho_pow *= rho;
    }

    // TODO: do we want the following:
    /*     // If applicable, add contribution from concatenated polynomial commitments
    // Note: this is an implementation detail related to Translator and is not part of the standard protocol.
    if (!concatenation_groups_commitments.empty()) {
        size_t CONCATENATION_GROUP_SIZE = concatenation_groups_commitments[0].size();
        size_t MINICIRCUIT_N = N / CONCATENATION_GROUP_SIZE;
        std::vector<FF> x_shifts;
        auto current_x_shift = x_challenge;
        auto x_to_minicircuit_n = x_challenge.pow(MINICIRCUIT_N);
        for (size_t i = 0; i < CONCATENATION_GROUP_SIZE; ++i) {
            x_shifts.emplace_back(current_x_shift);
            current_x_shift *= x_to_minicircuit_n;
        }
        for (auto& concatenation_group_commitment : concatenation_groups_commitments) {
            for (size_t i = 0; i < CONCATENATION_GROUP_SIZE; ++i) {
                scalars.emplace_back(rho_pow * x_shifts[i]);
                commitments.emplace_back(concatenation_group_commitment[i]);
            }
            rho_pow *= rho;
        }
    } */

    let mut x_pow_2k = x_challenge; // x^{2^k}
    let mut x_pow_2kp1 = x_challenge * x_challenge;

    for k in 0..CONST_PROOF_SIZE_LOG_N {
        let is_dummy_round = k >= log_circuit_size as usize;
        if is_dummy_round {
            scalars.push(P::ScalarField::ZERO);
            commitments.push(c_q_k[k]);
        } else {
            let phi_term_1 = phi_numerator / (x_pow_2kp1 - P::ScalarField::ONE); // \Phi_{n-k-1}(x^{2^{k + 1}})
            let phi_term_2 = phi_numerator / (x_pow_2k - P::ScalarField::ONE); // \Phi_{n-k}(x^{2^k})

            let scalar =
                ((x_pow_2k * phi_term_1) - (u_challenge[k] * phi_term_2)) * x_challenge * minus_one;

            scalars.push(scalar);
            commitments.push(c_q_k[k]);

            // Update powers of challenge x
            x_pow_2k = x_pow_2kp1;
            x_pow_2kp1 *= x_pow_2kp1;
        }
    }
    P::G1::msm_unchecked(
        &commitments
            .iter()
            .map(|g| P::G1Affine::from(*g))
            .collect::<Vec<P::G1Affine>>(),
        &scalars,
    )
}

pub fn sumcheck_verify<P: Pairing>(
    relation_parameters: RelationParameters<P>,
    transcript: &mut transcript::Poseidon2Transcript<P>,
    alphas: [P::ScalarField; NUM_ALPHAS],
    // gate_challenges: Vec<P::ScalarField>,
    vk: VerifyingKey<P>,
) -> (Vec<P::ScalarField>, Vec<P::ScalarField>, bool) {
    let mut pow_univariate = PowPolynomial::new(vk.gate_challenges);
    let multivariate_n = vk.circuit_size;
    let multivariate_d = get_msb(multivariate_n);
    if multivariate_d == 0 {
        todo!("Number of variables in multivariate is 0.");
    }
    if crate::decider::sumcheck::HAS_ZK {
        todo!();
    };
    let mut multivariate_challenge: Vec<P::ScalarField> =
        Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);
    let target_total_sum = P::ScalarField::ZERO; //??????
    let mut verified: bool = true;
    for round_idx in 0..CONST_PROOF_SIZE_LOG_N {
        // TODO make this correct: (receive_from_prover<bb::Univariate<FF, BATCHED_RELATION_PARTIAL_LENGTH>>(round_univariate_label);)
        let round_univariate = Vec::<P::ScalarField>::with_capacity(multivariate_n as usize);

        let mut transcript = Poseidon2Transcript::<P>::default();
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
    if crate::decider::sumcheck::HAS_ZK {
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
    purported_evaluations: Vec<P::ScalarField>,
    relation_parameters: RelationParameters<P>,
    pow_polynomial: PowPolynomial<P::ScalarField>,
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
    if crate::decider::sumcheck::HAS_ZK {
        todo!();
        // output += full_libra_purported_value.value();
    };
    output
}
fn accumulate_relation_evaluations_without_skipping<P: Pairing>(
    purported_evaluations: Vec<P::ScalarField>,
    relation_parameters: RelationParameters<P>,
    pow_polynomial: PowPolynomial<P::ScalarField>,
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

// I don't know about this one...
// this is the kzg one:
fn reduce_verify<P: Pairing>(
    transcript: &mut transcript::Poseidon2Transcript<P>,
    opening_pair: OpeningClaim<P>,
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
