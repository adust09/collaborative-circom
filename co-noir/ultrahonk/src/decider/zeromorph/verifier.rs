use crate::get_msb;
use crate::honk_curve::HonkCurve;
use crate::transcript::{TranscriptFieldType, TranscriptType};
use crate::CONST_PROOF_SIZE_LOG_N;
use ark_ec::pairing::Pairing;
use ark_ec::VariableBaseMSM;
use ark_ff::Field;

pub fn zeromorph_verify<P: HonkCurve<TranscriptFieldType>>(
    circuit_size: &u32,
    unshifted_commitments: Vec<P::G1>,
    to_be_shifted_commitments: Vec<P::G1>,
    unshifted_evaluations: &Vec<P::ScalarField>,
    shifted_evaluations: &Vec<P::ScalarField>,
    multivariate_challenge: Vec<P::ScalarField>,
    transcript_inout: &mut TranscriptType,
    // concatenated_evaluations: Vec<P::ScalarField>, // RefSpan<FF> concatenated_evaluations = {}
) -> crate::decider::verifier::OpeningClaim<P> {
    let log_n = get_msb(*circuit_size); //TODO: check this

    let rho = transcript_inout.get_challenge::<P>("rho".to_string());

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
    for i in 0..CONST_PROOF_SIZE_LOG_N {
        c_q_k.push(
            transcript_inout
                .receive_point_from_prover::<P>(format!("ZM:C_q_{}", i))
                .unwrap_or_else(|_| panic!("Failed to receive ZM:C_q_{}", i))
                .into(),
        );
    }

    let y_challenge = transcript_inout.get_challenge::<P>("y_challenge".to_string());

    // Receive commitment C_{q}
    //  auto c_q = transcript->template receive_from_prover<Commitment>("ZM:C_q");
    let c_q = transcript_inout
        .receive_point_from_prover::<P>("ZM:C_q".to_string())
        .unwrap_or_else(|_| panic!("Failed to receive ZM:C_q"))
        .into();

    let x_challenge = transcript_inout.get_challenge::<P>("x_challenge".to_string());

    let z_challenge = transcript_inout.get_challenge::<P>("z_challenge".to_string());

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

    crate::decider::verifier::OpeningClaim {
        challenge: x_challenge,
        evaluation: P::ScalarField::ZERO,
        commitment: c_zeta_z,
    }
}

// (compare cpp/src/barretenberg/commitment_schemes/zeromorph/zeromorph.hpp or https://hackmd.io/dlf9xEwhTQyE3hiGbq4FsA?view)

fn compute_c_zeta_x<P: Pairing>(
    c_q: P::G1,
    c_q_k: &Vec<P::G1>,
    y_challenge: P::ScalarField,
    x_challenge: P::ScalarField,
    log_circuit_size: u32,
    circuit_size: &u32,
) -> P::G1 {
    let mut scalars: Vec<P::ScalarField> = Vec::new();
    scalars.push(P::ScalarField::ONE);
    let mut commitments: Vec<P::G1Affine> = Vec::new();
    commitments.push(P::G1Affine::from(c_q));

    // Contribution from C_q_k, k = 0,...,log_N-1
    c_q_k
        .iter()
        .enumerate()
        .take(CONST_PROOF_SIZE_LOG_N)
        .for_each(|(k, &c_q_k_item)| {
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
            commitments.push(P::G1Affine::from(c_q_k_item));
        });

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
    circuit_size: &u32,
) -> P::G1 {
    let mut scalars: Vec<P::ScalarField> = Vec::new();
    let mut commitments: Vec<P::G1> = Vec::new();
    let phi_numerator = x_challenge.pow([*circuit_size as u64]) - P::ScalarField::ONE;
    let minus_one = P::ScalarField::ZERO - P::ScalarField::ONE;
    //todo
    let phi_n_x = phi_numerator / (x_challenge - P::ScalarField::ONE);
    scalars.push(batched_evaluation * x_challenge * phi_n_x * minus_one);
    //TODO: push g1_identity = first element in the SRS!
    // commitments.push(P::G1::)

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
