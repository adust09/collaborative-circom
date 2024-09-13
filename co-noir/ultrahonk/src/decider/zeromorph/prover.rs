use super::{
    super::{prover::Decider, sumcheck::prover::SumcheckOutput},
    types::{PolyF, PolyG, PolyGShift},
};
use crate::{
    decider::{polynomial::Polynomial, types::ClaimedEvaluations},
    get_msb,
    prover::HonkProofResult,
    transcript::Keccak256Transcript,
    types::ProvingKey,
    CONST_PROOF_SIZE_LOG_N, N_MAX,
};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{Field, One, PrimeField, Zero};
use itertools::izip;

impl<P: Pairing> Decider<P> {
    fn compute_multilinear_quotients(
        polynomial: &Polynomial<P::ScalarField>,
        u_challenge: &[P::ScalarField],
    ) -> Vec<Polynomial<P::ScalarField>> {
        let log_n = get_msb(polynomial.len() as u32);
        // Define the vector of quotients q_k, k = 0, ..., log_N-1
        // let mut quotients = Vec::with_capacity(log_n as usize);
        let mut quotients = vec![Polynomial::default(); log_n as usize];

        // Compute the coefficients of q_{n-1}
        let mut size_q = 1 << (log_n - 1);
        let mut q = Vec::with_capacity(size_q);
        let (half_a, half_b) = polynomial.coefficients.split_at(size_q);
        for (a, b) in half_a.iter().zip(half_b.iter()) {
            q.push(*b - a);
        }

        quotients[log_n as usize - 1].coefficients = q;

        let mut g = half_a.to_owned();

        // Compute q_k in reverse order from k= n-2, i.e. q_{n-2}, ..., q_0
        for k in 1..log_n {
            // Compute f_k
            let mut f_k = Vec::with_capacity(size_q);
            let index = log_n as usize - k as usize;
            for (g, q) in izip!(g, quotients[index].iter()) {
                f_k.push(g + u_challenge[index] * q);
            }
            size_q >>= 1;
            let mut q = Vec::with_capacity(size_q);
            let (half_a, half_b) = f_k.split_at(size_q);
            for (a, b) in half_a.iter().zip(half_b.iter()) {
                q.push(*b - a);
            }

            quotients[index - 1].coefficients = q;
            g = f_k;
        }

        quotients
    }

    /**
     * @brief Construct batched, lifted-degree univariate quotient \hat{q} = \sum_k y^k * X^{N - d_k - 1} * q_k
     * @details The purpose of the batched lifted-degree quotient is to reduce the individual degree checks
     * deg(q_k) <= 2^k - 1 to a single degree check on \hat{q}. This is done by first shifting each of the q_k to the
     * right (i.e. multiplying by an appropriate power of X) so that each is degree N-1, then batching them all together
     * using powers of the provided challenge. Note: In practice, we do not actually compute the shifted q_k, we simply
     * accumulate them into \hat{q} at the appropriate offset.
     *
     * @param quotients Polynomials q_k, interpreted as univariates; deg(q_k) = 2^k - 1
     * @param N circuit size
     * @return Polynomial
     */
    fn compute_batched_lifted_degree_quotient(
        quotients: &[Polynomial<P::ScalarField>],
        y_challenge: &P::ScalarField,
        n: usize,
    ) -> Polynomial<P::ScalarField> {
        // Batched lifted degree quotient polynomial
        let mut result = vec![P::ScalarField::zero(); n];

        // Compute \hat{q} = \sum_k y^k * X^{N - d_k - 1} * q_k
        let mut scalar = P::ScalarField::one();
        for (k, quotient) in quotients.iter().enumerate() {
            // Rather than explicitly computing the shifts of q_k by N - d_k - 1 (i.e. multiplying q_k by X^{N - d_k -
            // 1}) then accumulating them, we simply accumulate y^k*q_k into \hat{q} at the index offset N - d_k - 1
            let deg_k = (1 << k) - 1;
            let offset = n - deg_k - 1;

            for (r, q) in result
                .iter_mut()
                .skip(offset)
                .take(deg_k + 1)
                .zip(quotient.iter())
            {
                *r += scalar * q;
            }

            scalar *= y_challenge; // update batching scalar y^k
        }

        Polynomial::new(result)
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
            //     //this is Self::add_scaled, see cpp/src/barretenberg/polynomials/polynomial.cpp
            //     result[i] += -y_power * x_power * other_value;
            // }
            // Self::add_scaled(&mut result, &quotients[k], -y_power * x_power);

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
        // Self::add_scaled(&mut result, &f_batched, x_challenge);

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

            // Self::add_scaled(&mut result, &quotients[k], scalar);
        }

        // If necessary, add to Z_x the contribution related to concatenated polynomials:
        if !concatenation_groups_batched.is_empty() {
            let minicircuit_n = n / concatenation_groups_batched.len();
            let x_to_minicircuit_n = x_challenge.pow([minicircuit_n as u64]); // power of x used to shift polynomials to the right
            let mut running_shift = x_challenge;
            for group in &concatenation_groups_batched {
                // Self::add_scaled(&mut result, group, running_shift);
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
        // Self::add_scaled(&mut batched_polynomial, &z_x, z_challenge);

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

    fn get_f_polyomials<'a>(
        &'a self,
        proving_key: &'a ProvingKey<P>,
    ) -> PolyF<'a, Vec<P::ScalarField>> {
        let memory = [
            self.memory.memory.w_4(),
            self.memory.memory.z_perm(),
            self.memory.memory.lookup_inverses(),
        ];

        PolyF {
            precomputed: &proving_key.polynomials.precomputed,
            witness: &proving_key.polynomials.witness,
            memory,
        }
    }

    fn get_g_shift_evaluations(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyGShift<P::ScalarField> {
        PolyGShift {
            tables: &evaluations.polys.shifted_tables,
            wires: &evaluations.polys.shifted_witness,
            z_perm: evaluations.memory.z_perm_shift(),
        }
    }

    fn get_g_polyomials<'a>(
        &'a self,
        proving_key: &'a ProvingKey<P>,
    ) -> PolyG<'a, Vec<P::ScalarField>> {
        let tables = [
            proving_key.polynomials.precomputed.table_1(),
            proving_key.polynomials.precomputed.table_2(),
            proving_key.polynomials.precomputed.table_3(),
            proving_key.polynomials.precomputed.table_4(),
        ];

        let wires = [
            proving_key.polynomials.witness.w_l(),
            proving_key.polynomials.witness.w_r(),
            proving_key.polynomials.witness.w_o(),
            self.memory.memory.w_4(),
        ];

        PolyG {
            tables,
            wires,
            z_perm: self.memory.memory.z_perm(),
        }
    }

    fn get_f_evaluations(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyF<P::ScalarField> {
        let memory = [
            evaluations.memory.w_4(),
            evaluations.memory.z_perm(),
            evaluations.memory.lookup_inverses(),
        ];

        PolyF {
            precomputed: &evaluations.polys.precomputed,
            witness: &evaluations.polys.witness,
            memory,
        }
    }

    /**
     * @brief  * @brief Returns a univariate opening claim equivalent to a set of multilinear evaluation claims for
     * unshifted polynomials f_i and to-be-shifted polynomials g_i to be subsequently proved with a univariate PCS
     *
     * @param f_polynomials Unshifted polynomials
     * @param g_polynomials To-be-shifted polynomials (of which the shifts h_i were evaluated by sumcheck)
     * @param evaluations Set of evaluations v_i = f_i(u), w_i = h_i(u) = g_i_shifted(u)
     * @param multilinear_challenge Multilinear challenge point u
     * @param commitment_key
     * @param transcript
     *
     * @todo https://github.com/AztecProtocol/barretenberg/issues/1030: document concatenation trick
     */
    pub(crate) fn zeromorph_prove(
        &mut self,
        mut transcript: Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
    ) -> HonkProofResult<()> {
        let circuit_size = proving_key.circuit_size;
        let f_polynomials = self.get_f_polyomials(proving_key);
        let g_polynomials = self.get_g_polyomials(proving_key);
        let f_evaluations = Self::get_f_evaluations(&sumcheck_output.claimed_evaluations);
        let g_shift_evaluations =
            Self::get_g_shift_evaluations(&sumcheck_output.claimed_evaluations);
        let multilinear_challenge = &sumcheck_output.challenges;
        let commitment_key = &proving_key.crs;

        // Generate batching challenge \rho and powers 1,...,\rho^{m-1}
        let rho = transcript.get_challenge();
        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(rho);

        // Extract multilinear challenge u and claimed multilinear evaluations from Sumcheck output
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
        let mut f_batched = Polynomial::new_zero(n); // batched unshifted polynomials

        for (f_poly, f_eval) in f_polynomials.iter().zip(f_evaluations.iter()) {
            f_batched.add_scaled_slice(f_poly, &batching_scalar);
            batched_evaluation += batching_scalar * f_eval;
            batching_scalar *= rho;
        }

        let mut g_batched = Polynomial::new_zero(n); // batched to-be-shifted polynomials

        for (g_poly, g_shift_eval) in g_polynomials.iter().zip(g_shift_evaluations.iter()) {
            g_batched.add_scaled_slice(g_poly, &batching_scalar);
            batched_evaluation += batching_scalar * g_shift_eval;
            batching_scalar *= rho;
        }

        // We don't have groups, so we skip a lot now

        // Compute the full batched polynomial f = f_batched + g_batched.shifted() = f_batched + h_batched. This is the
        // polynomial for which we compute the quotients q_k and prove f(u) = v_batched.
        let mut f_polynomial = f_batched;
        f_polynomial += g_batched.shifted();
        // f_polynomial += concatenated_batched; // No groups

        // Compute the multilinear quotients q_k = q_k(X_0, ..., X_{k-1})
        let quotients = Self::compute_multilinear_quotients(&f_polynomial, u_challenge);
        debug_assert_eq!(quotients.len(), log_n as usize);
        // Compute and send commitments C_{q_k} = [q_k], k = 0,...,d-1
        for (res, val) in self
            .memory
            .witness_commitments
            .q_k
            .iter_mut()
            .zip(quotients.iter())
        {
            *res = crate::commit(&val.coefficients, commitment_key)?;
            transcript.add_point((*res).into());
        }
        // Add buffer elements to remove log_N dependence in proof
        for res in self
            .memory
            .witness_commitments
            .q_k
            .iter_mut()
            .skip(log_n as usize)
        {
            *res = P::G1::generator(); // TODO Is this one?
            transcript.add_point((*res).into());
        }

        // Get challenge y
        let y_challenge = transcript.get_challenge();
        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(y_challenge);

        // Compute the batched, lifted-degree quotient \hat{q}
        let batched_quotient =
            Self::compute_batched_lifted_degree_quotient(&quotients, &y_challenge, n as usize);

        // Compute and send the commitment C_q = [\hat{q}]
        self.memory.witness_commitments.q_commitment =
            crate::commit(&batched_quotient.coefficients, commitment_key)?;
        transcript.add_point(self.memory.witness_commitments.q_commitment.into());

        // Get challenges x and z
        let x_challenge = transcript.get_challenge();
        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(x_challenge);
        let z_challenge = transcript.get_challenge();

        todo!();

        // // Compute degree check polynomial \zeta partially evaluated at x
        // let zeta_x = Self::compute_partially_evaluated_degree_check_polynomial(
        //     batched_quotient,
        //     quotients,
        //     y_challenge,
        //     x_challenge,
        // );
        // // Compute ZeroMorph identity polynomial Z partially evaluated at x
        // let z_x = Self::compute_partially_evaluated_zeromorph_identity_polynomial(
        //     f_batched,
        //     g_batched,
        //     quotients,
        //     batched_evaluation,
        //     u_challenge,
        //     x_challenge,
        //     concatenation_groups_batched,
        // );
        // // Compute batched degree-check and ZM-identity quotient polynomial pi
        // let pi_polynomial =
        //     Self::compute_batched_evaluation_and_degree_check_polynomial(zeta_x, z_x, z_challenge);

        // todo!("return pi_polynomial,  .challenge = x_challenge, .evaluation = FF(0) ")
    }
}
