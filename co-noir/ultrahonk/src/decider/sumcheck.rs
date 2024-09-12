use super::prover::Decider;
use super::types::MemoryElements;
use crate::decider::sumcheck_round::SumcheckRound;
use crate::decider::types::PartiallyEvaluatePolys;
use crate::transcript::Keccak256Transcript;
use crate::types::{Polynomials, ProvingKey};
use crate::{decider::types::GateSeparatorPolynomial, get_msb};
use ark_ec::pairing::Pairing;

macro_rules! partially_evaluate_macro {
    ($src:expr, $des:expr, $round_size:expr, $round_challenge:expr, $inplace:expr, ($($el:ident),*)) => {{
        $(
            if $inplace {
                Self::partially_evaluate_poly_inplace(&mut $des.$el, $round_size, $round_challenge);
            } else {
                Self::partially_evaluate_poly(&$src.$el, &mut $des.$el, $round_size, $round_challenge);
            }
        )*
    }};
}

// Keep in mind, the UltraHonk protocol (UltraFlavor) does not per default have ZK
impl<P: Pairing> Decider<P> {
    pub(crate) fn partially_evaluate_poly(
        poly_src: &[P::ScalarField],
        poly_des: &mut [P::ScalarField],
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) {
        for i in (0..round_size).step_by(2) {
            poly_des[i >> 1] = poly_src[i] + (poly_src[i + 1] - poly_src[i]) * round_challenge;
        }
    }

    pub(crate) fn partially_evaluate_poly_inplace(
        poly: &mut [P::ScalarField],
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) {
        for i in (0..round_size).step_by(2) {
            poly[i >> 1] = poly[i] + (poly[i + 1] - poly[i]) * round_challenge;
        }
    }

    // after the first round, operate in place on partially_evaluated_polynomials. To avoid giving partially_evaluated_poly as &mut and as &, we use a boolean flag to indicate whether we should operate in place.
    pub(crate) fn partially_evaluate<const INPLACE: bool>(
        partially_evaluated_poly: &mut PartiallyEvaluatePolys<P::ScalarField>,
        polys: &Polynomials<P::ScalarField>,
        memory: &MemoryElements<Vec<P::ScalarField>>,
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) {
        tracing::trace!("Partially_evaluate");

        // Barretenberg uses multithreading here

        // Memory
        partially_evaluate_macro!(
            memory,
            &mut partially_evaluated_poly.memory,
            round_size,
            round_challenge,
            INPLACE,
            (w_4, z_perm, z_perm_shift, lookup_inverses)
        );

        // WitnessEntities
        partially_evaluate_macro!(
            &polys.witness,
            &mut partially_evaluated_poly.polys.witness,
            round_size,
            round_challenge,
            INPLACE,
            (w_l, w_r, w_o, lookup_read_counts, lookup_read_tags)
        );

        // ShiftedWitnessEntities
        partially_evaluate_macro!(
            &polys.shifted,
            &mut partially_evaluated_poly.polys.shifted,
            round_size,
            round_challenge,
            INPLACE,
            (w_l, w_r, w_o, w_4)
        );

        // PrecomputedEntities
        partially_evaluate_macro!(
            &polys.precomputed,
            &mut partially_evaluated_poly.polys.precomputed,
            round_size,
            round_challenge,
            INPLACE,
            (
                q_m,
                q_c,
                q_l,
                q_r,
                q_o,
                q_4,
                q_arith,
                q_delta_range,
                q_elliptic,
                q_aux,
                q_lookup,
                q_poseidon2_external,
                q_poseidon2_internal,
                sigma_1,
                sigma_2,
                sigma_3,
                sigma_4,
                id_1,
                id_2,
                id_3,
                id_4,
                table_1,
                table_2,
                table_3,
                table_4,
                lagrange_first,
                lagrange_last
            )
        );
    }

    pub(crate) fn sumcheck_prove(
        &self,
        transcript_inout: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) {
        tracing::trace!("Sumcheck prove");

        // Get the challenges and refresh the transcript
        let mut transcript = Keccak256Transcript::<P>::default();
        std::mem::swap(&mut transcript, transcript_inout);

        let multivariate_n = proving_key.circuit_size;
        let multivariate_d = get_msb(multivariate_n);

        let mut sum_check_round = SumcheckRound::new(multivariate_n as usize);

        let mut gate_separators = GateSeparatorPolynomial::new(
            self.memory.relation_parameters.gate_challenges.to_owned(),
        );

        let mut multivariate_challenge = Vec::with_capacity(multivariate_d as usize);
        let round_idx = 0;

        tracing::trace!("Sumcheck prove round {}", round_idx);

        // In the first round, we compute the first univariate polynomial and populate the book-keeping table of
        // #partially_evaluated_polynomials, which has \f$ n/2 \f$ rows and \f$ N \f$ columns. When the Flavor has ZK,
        // compute_univariate also takes into account the zk_sumcheck_data.
        let round_univariate = sum_check_round.compute_univariate(
            round_idx,
            &self.memory.relation_parameters,
            &gate_separators,
            &self.memory.memory,
            &proving_key.polynomials,
        );

        for val in round_univariate.evaluations.iter() {
            transcript.add_scalar(*val);
        }
        let mut round_challenge = transcript.get_challenge();
        multivariate_challenge.push(round_challenge);

        let mut partially_evaluated_polys = PartiallyEvaluatePolys::default();

        Self::partially_evaluate::<false>(
            &mut partially_evaluated_polys,
            &proving_key.polynomials,
            &self.memory.memory,
            multivariate_n as usize,
            &round_challenge,
        );

        gate_separators.partially_evaluate(round_challenge);
        sum_check_round.round_size >>= 1; // TODO(#224)(Cody): Maybe partially_evaluate should do this and
                                          // release memory?        // All but final round
                                          // We operate on partially_evaluated_polynomials in place.

        for round_idx in 1..multivariate_d as usize {
            tracing::trace!("Sumcheck prove round {}", round_idx);
            // Write the round univariate to the transcript
            let mut transcript: crate::transcript::Transcript<
                sha3::digest::core_api::CoreWrapper<sha3::Keccak256Core>,
                P,
            > = Keccak256Transcript::<P>::default();
            transcript.add_scalar(round_challenge);

            let round_univariate = sum_check_round.compute_univariate(
                round_idx,
                &self.memory.relation_parameters,
                &gate_separators,
                &partially_evaluated_polys.memory,
                &partially_evaluated_polys.polys,
            );

            for val in round_univariate.evaluations.iter() {
                transcript.add_scalar(*val);
            }
            round_challenge = transcript.get_challenge();
            multivariate_challenge.push(round_challenge); // Prepare sumcheck book-keeping table for the next round
            Self::partially_evaluate::<true>(
                &mut partially_evaluated_polys,
                &proving_key.polynomials,
                &self.memory.memory,
                sum_check_round.round_size,
                &round_challenge,
            );
            gate_separators.partially_evaluate(round_challenge);
            sum_check_round.round_size >>= 1;
        }
        todo!("continue")
    }
}
