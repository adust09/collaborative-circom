use super::types::ProverMemory;
use crate::{
    get_msb, prover::HonkProofResult, transcript, types::ProvingKey, CONST_PROOF_SIZE_LOG_N, N_MAX,
};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use std::marker::PhantomData;

pub struct Decider<P: Pairing> {
    pub(super) memory: ProverMemory<P>,
    phantom_data: PhantomData<P>,
}

fn add_scaled<F: PrimeField>(polynomial: &mut Vec<F>, scalars: &Vec<F>, batching_scalar: F) {
    for (i, &other_value) in scalars.iter().enumerate() {
        polynomial[i] += batching_scalar * other_value;
    }
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
    ) -> Vec<Vec<P::ScalarField>> //->  std::vector<Polynomial> quotients
    {
        let log_n = get_msb(polynomial.len() as u32);
        // Define the vector of quotients q_k, k = 0, ..., log_N-1
        let mut quotients: Vec<Vec<P::ScalarField>> = Vec::with_capacity(1 << log_n);
        for k in 0..log_n {
            let size = 1 << k;
            quotients.push(Vec::with_capacity(size)); // degree 2^k - 1
        }

        let mut size_q = 1 << (log_n - 1);
        let mut q: Vec<P::ScalarField> = Vec::with_capacity(size_q);
        for l in 0..size_q {
            q[l] = polynomial[size_q + l] - polynomial[l];
        }

        quotients[log_n as usize - 1] = q.clone();

        let mut f_k = Vec::<P::ScalarField>::with_capacity(size_q);

        // TODO: std::vector<FF> g(polynomial.data().get(), polynomial.data().get() + size_q);
        let mut g = Vec::<P::ScalarField>::with_capacity(size_q);

        // Compute q_k in reverse order from k = n - 2, i.e., q_{n-2}, ..., q_0
        for k in (1..log_n).rev() {
            // Compute f_k
            for l in 0..size_q {
                f_k[l] = g[l] + u_challenge[log_n as usize - k as usize] * q[l];
            }

            size_q /= 2;
            let mut q: Vec<P::ScalarField> = Vec::with_capacity(size_q);

            for l in 0..size_q {
                q[l] = f_k[size_q + l] - f_k[l];
            }

            quotients[log_n as usize - k as usize - 1] = q.clone(); // Assuming `clone` is implemented for Polynomial
            g = f_k.clone(); // Assuming `clone` is implemented for Vec<i32>
        }

        quotients
    }

    fn compute_batched_lifted_degree_quotient(
        quotients: Vec<Vec<P::ScalarField>>,
        y_challenge: P::ScalarField,
        n: usize,
    ) -> Vec<<P as Pairing>::ScalarField> {
        let mut result = Vec::<P::ScalarField>::with_capacity(n);
        let mut k = 0;
        let mut scalar = P::ScalarField::ONE;

        // Compute \hat{q} = \sum_k y^k * X^{N - d_k - 1} * q_k
        for quotient in quotients {
            // Rather than explicitly computing the shifts of q_k by N - d_k - 1 (i.e. multiplying q_k by X^{N - d_k -
            // 1}) then accumulating them, we simply accumulate y^k*q_k into \hat{q} at the index offset N - d_k - 1
            let deg_k = (1 << k) - 1;
            let offset = n - deg_k - 1;
            for idx in 0..=deg_k {
                result[offset + idx] += scalar * quotient[idx];
            }
            scalar *= y_challenge; // update batching scalar y^k
            k += 1;
        }

        result
    }
    fn compute_partially_evaluated_degree_check_polynomial(
        batched_quotient: Vec<P::ScalarField>,
        quotients: Vec<Vec<P::ScalarField>>,
        y_challenge: P::ScalarField,
        x_challenge: P::ScalarField,
    ) -> Vec<P::ScalarField> {
        let n = batched_quotient.len();
        let log_n = quotients.len();

        // Initialize partially evaluated degree check polynomial \zeta_x to \hat{q}
        let mut result = batched_quotient.clone();

        let mut y_power = P::ScalarField::ONE; // y^k
        for k in 0..log_n {
            // Accumulate y^k * x^{N - d_k - 1} * q_k into \hat{q}
            let deg_k = (1 << k) - 1;
            let exponent = (n - deg_k - 1) as u64;
            let x_power = x_challenge.pow([exponent]); // x^{N - d_k - 1}

            // // result.add_scaled(&quotients[k], -y_power * x_power);
            // for (i, &other_value) in quotients[k].iter().enumerate() {
            //     //this is add_scaled, see cpp/src/barretenberg/polynomials/polynomial.cpp
            //     result[i] += -y_power * x_power * other_value;
            // }
            add_scaled(&mut result, &quotients[k], -y_power * x_power);

            y_power *= y_challenge; // update batching scalar y^k
        }

        result
    }
    fn compute_partially_evaluated_zeromorph_identity_polynomial(
        f_batched: Vec<P::ScalarField>,
        g_batched: Vec<P::ScalarField>,
        quotients: Vec<Vec<P::ScalarField>>,
        v_evaluation: P::ScalarField,
        u_challenge: Vec<P::ScalarField>,
        x_challenge: P::ScalarField,
        concatenation_groups_batched: Vec<Vec<P::ScalarField>>, //todo: empty if not provided,
    ) -> Vec<<P as Pairing>::ScalarField> {
        let n = f_batched.len();
        let log_n = quotients.len();

        // Initialize Z_x with x * \sum_{i=0}^{m-1} f_i + \sum_{i=0}^{l-1} g_i
        let mut result = g_batched.clone();
        add_scaled(&mut result, &f_batched, x_challenge);

        // Compute Z_x -= v * x * \Phi_n(x)
        let phi_numerator = x_challenge.pow([n as u64]) - P::ScalarField::ONE; // x^N - 1
        let phi_n_x = phi_numerator / (x_challenge - P::ScalarField::ONE);
        result[0] -= v_evaluation * x_challenge * phi_n_x;

        // Add contribution from q_k polynomials
        let mut x_power = x_challenge; // x^{2^k}
        for k in 0..log_n {
            let exp_1 = 1 << k;
            x_power = x_challenge.pow([exp_1 as u64]); // x^{2^k}

            // \Phi_{n-k-1}(x^{2^{k + 1}})
            let exp_2 = 1 << (k + 1);
            let phi_term_1 =
                phi_numerator / (x_challenge.pow([exp_2 as u64]) - P::ScalarField::ONE);

            // \Phi_{n-k}(x^{2^k})
            let phi_term_2 =
                phi_numerator / (x_challenge.pow([exp_1 as u64]) - P::ScalarField::ONE);

            // x^{2^k} * \Phi_{n-k-1}(x^{2^{k+1}}) - u_k *  \Phi_{n-k}(x^{2^k})
            let mut scalar = x_power * phi_term_1 - u_challenge[k] * phi_term_2;

            scalar *= x_challenge;
            scalar *= -P::ScalarField::ONE;

            add_scaled(&mut result, &quotients[k], scalar);
        }

        // If necessary, add to Z_x the contribution related to concatenated polynomials:
        if !concatenation_groups_batched.is_empty() {
            let minicircuit_n = n / concatenation_groups_batched.len();
            let x_to_minicircuit_n = x_challenge.pow([minicircuit_n as u64]); // power of x used to shift polynomials to the right
            let mut running_shift = x_challenge;
            for group in &concatenation_groups_batched {
                add_scaled(&mut result, group, running_shift);
                running_shift *= x_to_minicircuit_n;
            }
        }

        result
    }

    fn compute_batched_evaluation_and_degree_check_polynomial(
        zeta_x: Vec<P::ScalarField>,
        z_x: Vec<P::ScalarField>,
        z_challenge: P::ScalarField,
    ) -> Vec<<P as Pairing>::ScalarField> {
        let n = zeta_x.len();
        assert!(n <= N_MAX);
        let mut batched_polynomial = zeta_x.clone();
        add_scaled(&mut batched_polynomial, &z_x, z_challenge);

        /*
        // TODO(#742): To complete the degree check, we need to do an opening proof for x_challenge with a univariate
        // PCS for the degree-lifted polynomial (\zeta_c + z*Z_x)*X^{N_max - N - 1}. If this PCS is KZG, verification
        // then requires a pairing check similar to the standard KZG check but with [1]_2 replaced by [X^{N_max - N
        // -1}]_2. Two issues: A) we do not have an SRS with these G2 elements (so need to generate a fake setup until
        // we can do the real thing), and B) its not clear to me how to update our pairing algorithms to do this type of
        // pairing. For now, simply construct pi without the shift and do a standard KZG pairing check if the PCS is
        // KZG. When we're ready, all we have to do to make this fully legit is commit to the shift here and update the
        // pairing check accordingly. Note: When this is implemented properly, it doesnt make sense to store the
        // (massive) shifted polynomial of size N_max. Ideally would only store the unshifted version and just compute
        // the shifted commitment directly via a new method.
         */
        batched_polynomial
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
            // for (i, &other_value) in value1.iter().enumerate() {
            //     //this is add_scaled, see cpp/src/barretenberg/polynomials/polynomial.cpp
            //     f_batched[i] += batching_scalar * other_value;
            // }
            add_scaled(&mut f_batched, value1, batching_scalar);
            batched_evaluation += batching_scalar * value2;
            batching_scalar *= rho;
        }
        for (value1, value2) in g_polynomials.iter().zip(g_shift_evaluations.iter()) {
            // for (i, &other_value) in value1.iter().enumerate() {
            //     g_batched[i] += batching_scalar * other_value;
            // }
            add_scaled(&mut g_batched, value1, batching_scalar);
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
            Self::compute_batched_lifted_degree_quotient(quotients, y_challenge, n as usize);

        // auto q_commitment = commitment_key->commit(batched_quotient);
        let mut transcript = transcript::Keccak256Transcript::<P>::default();
        transcript.add_scalar(y_challenge);
        transcript.add_scalar(q_commitment);
        let x_challenge = transcript.get_challenge();
        let mut transcript = transcript::Keccak256Transcript::<P>::default();
        transcript.add_scalar(x_challenge);
        let z_challenge = transcript.get_challenge();

        // Compute degree check polynomial \zeta partially evaluated at x
        let zeta_x = Self::compute_partially_evaluated_degree_check_polynomial(
            batched_quotient,
            quotients,
            y_challenge,
            x_challenge,
        );
        // Compute ZeroMorph identity polynomial Z partially evaluated at x
        let z_x = Self::compute_partially_evaluated_zeromorph_identity_polynomial(
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
            Self::compute_batched_evaluation_and_degree_check_polynomial(zeta_x, z_x, z_challenge);

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
