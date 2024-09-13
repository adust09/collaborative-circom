use crate::decider::prover::Decider;
use crate::decider::sumcheck::sumcheck_round::{SumcheckRound, SumcheckRoundOutput};
use crate::decider::sumcheck::SumcheckOutput;
use crate::decider::types::{ClaimedEvaluations, MemoryElements, PartiallyEvaluatePolys};
use crate::transcript::Keccak256Transcript;
use crate::types::{Polynomials, ProvingKey};
use crate::CONST_PROOF_SIZE_LOG_N;
use crate::{decider::types::GateSeparatorPolynomial, get_msb};
use ark_ec::pairing::Pairing;
use ark_ff::Zero;

// Keep in mind, the UltraHonk protocol (UltraFlavor) does not per default have ZK
impl<P: Pairing> Decider<P> {
    fn partially_evaluate_poly(
        poly_src: &[P::ScalarField],
        poly_des: &mut [P::ScalarField],
        round_size: usize,
        round_challenge: &P::ScalarField,
    ) {
        for i in (0..round_size).step_by(2) {
            poly_des[i >> 1] = poly_src[i] + (poly_src[i + 1] - poly_src[i]) * round_challenge;
        }
    }

    fn partially_evaluate_poly_inplace(
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
        for (src, des) in memory
            .iter()
            .chain(polys.iter())
            .zip(partially_evaluated_poly.iter_mut())
        {
            if INPLACE {
                Self::partially_evaluate_poly_inplace(des, round_size, round_challenge);
            } else {
                Self::partially_evaluate_poly(src, des, round_size, round_challenge);
            }
        }
    }

    // TODO order is probably wrong
    fn add_evals_to_transcript(
        transcript: &mut Keccak256Transcript<P>,
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) {
        tracing::trace!("Add Evals to Transcript");

        for src in evaluations.iter() {
            transcript.add_scalar(*src);
        }
    }

    fn extract_claimed_evaluations(
        partially_evaluated_polynomials: PartiallyEvaluatePolys<P::ScalarField>,
    ) -> ClaimedEvaluations<P::ScalarField> {
        let mut multivariate_evaluations = ClaimedEvaluations::default();

        for (src, des) in partially_evaluated_polynomials
            .iter()
            .zip(multivariate_evaluations.iter_mut())
        {
            *des = src[0];
        }

        multivariate_evaluations
    }

    pub(crate) fn sumcheck_prove(
        &self,
        transcript_inout: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) -> SumcheckOutput<P::ScalarField> {
        tracing::trace!("Sumcheck prove");

        // Refresh the transcript
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
            multivariate_challenge.push(round_challenge);
            // Prepare sumcheck book-keeping table for the next round
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

        // Zero univariates are used to pad the proof to the fixed size CONST_PROOF_SIZE_LOG_N.
        for _ in multivariate_d as usize..CONST_PROOF_SIZE_LOG_N {
            let mut transcript: crate::transcript::Transcript<
                sha3::digest::core_api::CoreWrapper<sha3::Keccak256Core>,
                P,
            > = Keccak256Transcript::<P>::default();
            transcript.add_scalar(round_challenge);

            for _ in 0..SumcheckRoundOutput::<P::ScalarField>::SIZE {
                transcript.add_scalar(P::ScalarField::zero());
            }
            round_challenge = transcript.get_challenge();
            multivariate_challenge.push(round_challenge);
        }

        // Claimed evaluations of Prover polynomials are extracted and added to the transcript. When Flavor has ZK, the
        // evaluations of all witnesses are masked.
        let multivariate_evaluations = Self::extract_claimed_evaluations(partially_evaluated_polys);

        transcript_inout.add_scalar(round_challenge);
        Self::add_evals_to_transcript(transcript_inout, &multivariate_evaluations);

        SumcheckOutput {
            claimed_evaluations: multivariate_evaluations,
            challenges: multivariate_challenge,
        }
    }
}
