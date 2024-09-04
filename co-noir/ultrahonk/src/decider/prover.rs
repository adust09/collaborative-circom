use super::types::ProverMemory;
use crate::{prover::HonkProofResult, transcript, types::ProvingKey, CONST_PROOF_SIZE_LOG_N};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use std::marker::PhantomData;

pub struct Decider<P: Pairing> {
    pub(super) memory: ProverMemory<P>,
    phantom_data: PhantomData<P>,
}

//TODO: polynomial struct?

impl<P: Pairing> Decider<P> {
    pub fn new(memory: ProverMemory<P>) -> Self {
        Self {
            memory,
            phantom_data: PhantomData,
        }
    }

    // Run sumcheck subprotocol.
    fn execute_relation_check_rounds(
        &self,
        transcript: &mut transcript::Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) {
        // This is just Sumcheck.prove

        self.sumcheck_prove(transcript, proving_key);

        todo!();
    }

    // Fiat-Shamir: rho, y, x, z
    // Execute Zeromorph multilinear PCS
    fn execute_pcs_rounds(&self) {
        todo!();
    }

    fn compute_multilinear_quotients(
        polynomial: Vec<P::ScalarField>,
        u_challenge: Vec<P::ScalarField>,
    )
    //->  std::vector<Polynomial> quotients
    {
        todo!()
    }

    fn compute_batched_lifted_degree_quotient() {
        todo!()
    }
    fn compute_partially_evaluated_degree_check_polynomial() {
        todo!()
    }
    fn compute_partially_evaluated_zeromorph_identity_polynomial() {
        todo!()
    }
    fn compute_batched_evaluation_and_degree_check_polynomial() {
        todo!()
    }

    fn zeromorph_prove(
        circuit_size: u32,
        f_polynomials: Vec<Vec<P::ScalarField>>,
        g_polynomials: Vec<Vec<P::ScalarField>>,
        f_evaluations: Vec<P::ScalarField>,
        g_shift_evaluations: Vec<P::ScalarField>,
        multilinear_challenge: Vec<P::ScalarField>,
        transcript_inout: &mut transcript::Keccak256Transcript<P>,
        concatenation_groups: Vec<Vec<Vec<P::ScalarField>>>,
        concatenated_polynomials: Vec<Vec<P::ScalarField>>,
        concatenated_evaluations: Vec<P::ScalarField>,
        // todo: think about types
        // commitment_key
        // RefSpan<Polynomial> concatenated_polynomials = {},
        //                       RefSpan<FF> concatenated_evaluations = {},
        //                       const std::vector<RefVector<Polynomial>>& concatenation_groups = {}
    ) {
        let mut transcript = transcript::Keccak256Transcript::<P>::default();
        std::mem::swap(&mut transcript, transcript_inout);
        // Generate batching challenge \rho and powers 1,...,\rho^{m-1}
        let rho = transcript.get_challenge();
        let mut transcript = transcript::Keccak256Transcript::<P>::default();
        transcript.add_scalar(rho);

        // Extract multilinear challenge u and claimed multilinear evaluations from Sumcheck output
        // std::span<const FF> u_challenge = multilinear_challenge;
        let u_challenge = multilinear_challenge;
        let log_n = crate::get_msb(circuit_size);
        let n = 1 << log_n;

        // Compute batching of unshifted polynomials f_i and to-be-shifted polynomials g_i:
        // f_batched = sum_{i=0}^{m-1}\rho^i*f_i and g_batched = sum_{i=0}^{l-1}\rho^{m+i}*g_i,
        // and also batched evaluation
        // v = sum_{i=0}^{m-1}\rho^i*f_i(u) + sum_{i=0}^{l-1}\rho^{m+i}*h_i(u).
        // Note: g_batched is formed from the to-be-shifted polynomials, but the batched evaluation incorporates the
        // evaluations produced by sumcheck of h_i = g_i_shifted.
        let mut batched_evaluation = P::ScalarField::ZERO;
        let mut batching_scalar = P::ScalarField::ONE;
        let mut f_batched = Vec::<P::ScalarField>::with_capacity(n); // batched unshifted polynomials
        let mut g_batched = Vec::<P::ScalarField>::with_capacity(n); // batched to-be-shifted polynomials

        //todo: check if this is really correct
        for (value1, value2) in f_polynomials.iter().zip(f_evaluations.iter()) {
            for (i, &other_value) in value1.iter().enumerate() {
                //this is add.scaled, see cpp/src/barretenberg/polynomials/polynomial.cpp
                f_batched[i] += batching_scalar * other_value;
            }
            batched_evaluation += batching_scalar * value2;
            batching_scalar *= rho;
        }
        for (value1, value2) in g_polynomials.iter().zip(g_shift_evaluations.iter()) {
            for (i, &other_value) in value1.iter().enumerate() {
                g_batched[i] += batching_scalar * other_value;
            }
            batched_evaluation += batching_scalar * value2;
            batching_scalar *= rho;
        }

        let num_groups = concatenation_groups.len();
        let num_chunks_per_group = if concatenation_groups.is_empty() {
            0
        } else {
            concatenation_groups[0].len()
        };

        let mut concatenated_batched = Vec::<P::ScalarField>::with_capacity(n); // Concatenated polynomials

        // construct concatention_groups_batched
        let mut concatenation_groups_batched: Vec<Vec<P::ScalarField>> =
            Vec::with_capacity(num_chunks_per_group);

        for _ in 0..num_chunks_per_group {
            concatenation_groups_batched.push(Vec::with_capacity(n));
        }

        // For each group
        for i in 0..num_groups {
            for (k, &other_value) in concatenated_polynomials[i].iter().enumerate() {
                concatenated_batched[k] += batching_scalar * other_value;
            }

            // For each element in a group
            for j in 0..num_chunks_per_group {
                for (k, &other_value) in concatenation_groups[i][j].iter().enumerate() {
                    concatenation_groups_batched[j][k] += batching_scalar * other_value;
                }
            }

            batched_evaluation += batching_scalar * concatenated_evaluations[i];
            batching_scalar *= rho;
        }

        let f_polynomial = f_batched;
        // TODO f_polynomial += g_batched.shifted();
        // f_polynomial += concatenated_batched;

        // Compute the multilinear quotients q_k = q_k(X_0, ..., X_{k-1})
        let quotients = Self::compute_multilinear_quotients(f_polynomial, u_challenge);
        // Compute and send commitments C_{q_k} = [q_k], k = 0,...,d-1
        for idx in 0..log_n {
            // TODO let q_k_commitment = commitment_key.commit(&quotients[idx]);
            let label = format!("ZM:C_q_{}", idx);
            transcript.add(q_k_commitment);
        }

        // Add buffer elements to remove log_N dependence in proof
        for idx in log_n..CONST_PROOF_SIZE_LOG_N as u8 {
            // let buffer_element = Commitment::one();
            let label = format!("ZM:C_q_{}", idx);
            transcript.add(buffer_element);
        }
        let y_challenge = transcript.get_challenge();

        let batched_quotient =
            Self::compute_batched_lifted_degree_quotient(quotients, y_challenge, n);

        // auto q_commitment = commitment_key->commit(batched_quotient);
        let mut transcript = transcript::Keccak256Transcript::<P>::default();
        transcript.add_scalar(y_challenge);
        transcript.add_scalar(q_commitment);
        let x_challenge = transcript.get_challenge();
        let mut transcript = transcript::Keccak256Transcript::<P>::default();
        transcript.add_scalar(x_challenge);
        let z_challenge = transcript.get_challenge();

        // Compute degree check polynomial \zeta partially evaluated at x
        let zeta_x = compute_partially_evaluated_degree_check_polynomial(
            batched_quotient,
            quotients,
            y_challenge,
            x_challenge,
        );
        // Compute ZeroMorph identity polynomial Z partially evaluated at x
        let z_x = compute_partially_evaluated_zeromorph_identity_polynomial(
            f_batched,
            g_batched,
            quotients,
            batched_evaluation,
            u_challenge,
            x_challenge,
            concatenation_groups_batched,
        );
        // Compute batched degree-check and ZM-identity quotient polynomial pi
        let pi_polynomial =
            compute_batched_evaluation_and_degree_check_polynomial(zeta_x, z_x, z_challenge);

        todo!("return pi_polynomial,  .challenge = x_challenge, .evaluation = FF(0) ")
    }

    pub fn prove(
        self,
        proving_key: ProvingKey<P>,
        public_inputs: Vec<P::ScalarField>,
    ) -> HonkProofResult<()> {
        tracing::trace!("Decider prove");

        let mut transcript = transcript::Keccak256Transcript::<P>::default();
        transcript.add_scalar(
            self.memory
                .challenges
                .gate_challenges
                .last()
                .expect("Element is present")
                .to_owned(),
        );

        // Run sumcheck subprotocol.
        self.execute_relation_check_rounds(&mut transcript, &proving_key);
        // Fiat-Shamir: rho, y, x, z
        // Execute Zeromorph multilinear PCS
        self.execute_pcs_rounds();

        todo!("output the proof");
        Ok(())
    }
}
