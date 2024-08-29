use crate::decider::types::PowPolynomial;
use crate::CONST_PROOF_SIZE_LOG_N;
use crate::{
    decider::{prover::Decider, types::ProverMemory},
    get_msb,
    oink::{
        self,
        prover::Oink,
        types::WitnessCommitments,
        verifier::{self, OinkVerifier, RelationParameters},
    },
    transcript::{self, Keccak256Transcript},
    types::{ProvingKey, VerifyingKey},
    NUM_ALPHAS,
};
use ark_ec::pairing::{self, Pairing};
use ark_ec::VariableBaseMSM;
use ark_ff::Field;
use std::vec;
use std::{io, marker::PhantomData};

pub struct UltraHonkVerifier<P: Pairing> {
    phantom_data: PhantomData<P>,
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
        relation_parameters: RelationParameters<P>,
        witness_comms: WitnessCommitments<P>,
    ) {
        tracing::trace!("UltraHonk verification");
        let mut transcript = Keccak256Transcript::<P>::default();
        let log_circuit_size = get_msb(vk.circuit_size.clone()); //todo: is this what we want?
        let oink_output = oink::verifier::OinkVerifier::<P>::new(
            transcript,
            vk,
            relation_parameters,
            witness_comms,
        )
        .verify(public_inputs);

        let mut transcript = Keccak256Transcript::<P>::default();
        let mut gate_challenges = Vec::with_capacity(log_circuit_size as usize);
        gate_challenges[0] = transcript.get_challenge();
        for idx in 1..log_circuit_size as usize {
            let mut transcript = Keccak256Transcript::<P>::default();
            transcript.add_scalar(gate_challenges[idx - 1]);
            gate_challenges[idx] = transcript.get_challenge();
        }
        // to do: build sumcheck verifier, returns (multivariate_challenge, claimed_evaluations, sumcheck_verified)
        // get_unshifted(), get_to_be_shifted()

        // let opening_claim = zeromorph_verify(
        //     vk.circuit_size,
        //     unshifted_commitments,
        //     to_be_shifted_commitments,
        //     unshifted_evaluations,
        //     shifted_evaluations,
        //     multivariate_challenge,
        //     transcript_inout,
        // );
    }
}

//need (?) the verifier SRS for the following ("https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/flat/g1.dat" and "https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/flat/g2.dat")
//Check: g1_identity first element in the SRS!
fn pairing_check<P: Pairing>(
    p0: P::G1Affine,
    p1: P::G1Affine,
    precomputedlines: [P::G2Prepared; 2], //todo: where to get this from
) -> bool {
    let g1_prepared = [P::G1Prepared::from(p0), P::G1Prepared::from(p1)];
    let m_loop = P::multi_miller_loop(g1_prepared, precomputedlines);
    let result = P::final_exponentiation(m_loop);
    match result {
        Some(pairing_output) => pairing_output.0 == P::TargetField::ONE,
        None => false, // todo: what does that mean?
    }
}

// (compare cpp/src/barretenberg/commitment_schemes/zeromorph/zeromorph.hpp or https://hackmd.io/dlf9xEwhTQyE3hiGbq4FsA?view)

fn zeromorph_verify<P: Pairing>(
    circuit_size: u32,
    unshifted_commitments: Vec<P::G1>,
    to_be_shifted_commitments: Vec<P::G1>,
    unshifted_evaluations: Vec<P::ScalarField>,
    shifted_evaluations: Vec<P::ScalarField>,
    multivariate_challenge: Vec<P::ScalarField>,
    transcript_inout: &mut Keccak256Transcript<P>,
) {
    let log_n = get_msb(circuit_size.clone()); //TODO: check this
    let mut transcript = Keccak256Transcript::<P>::default();
    std::mem::swap(&mut transcript, transcript_inout);

    let rho = transcript.get_challenge();

    let mut transcript = Keccak256Transcript::<P>::default();
    transcript.add_scalar(rho);

    let mut batched_evaluation = P::ScalarField::ZERO;
    let mut batching_scalar = P::ScalarField::ONE;

    for &value in unshifted_evaluations
        .iter()
        .chain(shifted_evaluations.iter())
    {
        batched_evaluation += value * batching_scalar;
        batching_scalar *= rho;
    }

    let mut c_q_k: Vec<P::G1> = Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);
    // todo: where do we get the commitments [q_k] from? rsp. which commitments are these? fill above vector with these
    todo!("get commitments");
    let mut transcript = Keccak256Transcript::<P>::default();
    transcript.add_scalar(rho);

    let y_challenge = transcript.get_challenge();

    // Receive commitment C_{q}
    //  auto c_q = transcript->template receive_from_prover<Commitment>("ZM:C_q");
    let c_q: P::G1;

    let mut transcript = Keccak256Transcript::<P>::default();
    transcript.add_scalar(y_challenge);

    let x_challenge = transcript.get_challenge();
    let mut transcript = Keccak256Transcript::<P>::default();
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
    // return { .opening_pair = { .challenge = x_challenge, .evaluation = FF(0) }, .commitment = C_zeta_Z };
    // ????
    todo!();
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
    //TODO: push g1_identity first element in the SRS!
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

// fn reduce_verify

fn sumcheck_verify<P: Pairing>(
    relation_parameters: RelationParameters<P>,
    transcript: &mut transcript::Keccak256Transcript<P>,
    alphas: [P::ScalarField; NUM_ALPHAS],
    gate_challenges: Vec<P::ScalarField>,
) {
    let pow_univariate = PowPolynomial::new(gate_challenges);
    // if (multivariate_d == 0) {
    //     throw_or_abort("Number of variables in multivariate is 0.");
    // }
}

fn compute_next_target_sum() {}
fn compute_full_honk_relation_purported_value() {}
