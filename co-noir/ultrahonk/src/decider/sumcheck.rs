use super::prover::Decider;
use crate::decider::sumcheck_round::SumcheckRound;
use crate::decider::types::PartiallyEvaluatePolys;
use crate::transcript::Keccak256Transcript;
use crate::types::{Polynomials, ProvingKey};
use crate::{decider::types::GateSeparatorPolynomial, get_msb};
use ark_ec::pairing::Pairing;

macro_rules! partially_evaluate_macro {
    ($src:expr, $des:expr, $round_size:expr, $round_challenge:expr, ($($el:ident),*)) => {{
        $(
            Self::partially_evaluate_poly(&$src.$el, &mut $des.$el, $round_size, $round_challenge);
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

    pub(crate) fn partially_evaluate(
        &self,
        polys: &Polynomials<P::ScalarField>,
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) -> PartiallyEvaluatePolys<P::ScalarField> {
        tracing::trace!("Partially_evaluate");

        let mut res = PartiallyEvaluatePolys::default();
        // Barretenberg uses multithreading here

        // Memory
        partially_evaluate_macro!(
            &self.memory,
            res,
            round_size,
            round_challenge,
            (w_4, z_perm, z_perm_shift, lookup_inverses)
        );

        // WitnessEntities
        partially_evaluate_macro!(
            &polys.witness,
            &mut res.polys.witness,
            round_size,
            round_challenge,
            (w_l, w_r, w_o, lookup_read_counts, lookup_read_tags)
        );

        // ShiftedWitnessEntities
        partially_evaluate_macro!(
            &polys.shifted,
            &mut res.polys.shifted,
            round_size,
            round_challenge,
            (w_l, w_r, w_o, w_4)
        );

        // PrecomputedEntities
        partially_evaluate_macro!(
            &polys.precomputed,
            &mut res.polys.precomputed,
            round_size,
            round_challenge,
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
        res
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
        let mut round_idx = 0;
        // In the first round, we compute the first univariate polynomial and populate the book-keeping table of
        // #partially_evaluated_polynomials, which has \f$ n/2 \f$ rows and \f$ N \f$ columns. When the Flavor has ZK,
        // compute_univariate also takes into account the zk_sumcheck_data.
        let round_univariate = sum_check_round.compute_univariate(
            round_idx,
            &self.memory.relation_parameters,
            &gate_separators,
            &self.memory,
            proving_key,
        );

        for val in multivariate_challenge.iter() {
            transcript.add_scalar(*val);
        }
        let round_challenge = transcript.get_challenge();
        multivariate_challenge.push(round_challenge);

        let mut transcript: crate::transcript::Transcript<
            sha3::digest::core_api::CoreWrapper<sha3::Keccak256Core>,
            P,
        > = Keccak256Transcript::<P>::default();

        let partially_evaluated_polys = self.partially_evaluate(
            &proving_key.polynomials,
            multivariate_n as usize,
            &round_challenge,
        );

        gate_separators.partially_evaluate(round_challenge);
        sum_check_round.round_size >>= 1; // TODO(#224)(Cody): Maybe partially_evaluate should do this and
                                          // release memory?        // All but final round
                                          // We operate on partially_evaluated_polynomials in place.

        todo!("return multivariate_challenge and multivariate_evaluations")
    }
}
