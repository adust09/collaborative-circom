use super::prover::Decider;
use crate::oink::verifier::RelationParameters;
use crate::{decider::types::GateSeparatorPolynomial, get_msb};
use crate::{transcript, types::ProvingKey};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use rand::{thread_rng, Rng};
use crate::decider::sumcheck_round::SumcheckRound;

// Keep in mind, the UltraHonk protocol (UltraFlavor) does not per default have ZK
// The UltraFlavorWithZK has ZK
pub(crate) const HAS_ZK: bool = false;

impl<P: Pairing> Decider<P> {
    fn setup_zk_sumcheck_data<R: Rng>(&self, rng: &mut R) {
        const NUM_ALL_WITNESS_ENTITIES: usize = 13;

        let eval_masking_scalars = (0..NUM_ALL_WITNESS_ENTITIES)
            .map(|_| P::ScalarField::rand(rng))
            .collect::<Vec<_>>();

        todo!("Not yet implemented");
    }

    pub(crate) fn sumcheck_prove(
        &self,
        transcript: &mut transcript::Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) {
        tracing::trace!("Sumcheck prove");

        // TODO another RNG?
        let mut rng = thread_rng();

        let multivariate_n = proving_key.circuit_size;
        let multivariate_d = get_msb(multivariate_n);
        // TODO check this
        let sum_check_round = SumcheckRound::new(multivariate_n as usize);
        // In case the Flavor has ZK, we populate sumcheck data structure with randomness, compute correcting term for
        // the total sum, etc.
        if HAS_ZK {
            self.setup_zk_sumcheck_data(&mut rng);
        };

        let pow_univariate = GateSeparatorPolynomial::new(self.memory.challenges.gate_challenges.to_owned());

        let mut multivariate_challenge = Vec::with_capacity(multivariate_d as usize);
        let mut round_idx = 0;
        // In the first round, we compute the first univariate polynomial and populate the book-keeping table of
        // #partially_evaluated_polynomials, which has \f$ n/2 \f$ rows and \f$ N \f$ columns. When the Flavor has ZK,
        // compute_univariate also takes into account the zk_sumcheck_data.

        todo!("first round");

        multivariate_challenge.push(transcript.get_challenge());
        let mut transcript = transcript::Keccak256Transcript::<P>::default();
        transcript.add_scalar(multivariate_challenge[0]);
        for round_idx in 1..multivariate_d {
            let round_univariate= sum_check_round.compute_univariate(round_idx,partially_evaluated_polynomials, relation_parameters, pow_univariate, alpha)
            transcript.add_scalar(round_univariate);
            let round_challenge= transcript.get_challenge();
            multivariate_challenge.push(round_challenge);
            let mut transcript = transcript::Keccak256Transcript::<P>::default();
            transcript.add_scalar(round_challenge);
            // need SumcheckRound struct here:
            sum_check_round.partially_evaluate_poly(partially_evaluated_polynomials, round_challenge);
            pow_univariate.partially_evaluate(round_challenge);
            sum_check_round.round_size = sum_check_round.round_size >> 1;
        }

        // auto zero_univariate = bb::Univariate<FF, Flavor::BATCHED_RELATION_PARTIAL_LENGTH>::zero();
        let placeholder=347;

        let zero_univariate= Vec::<P::ScalarField>::with_capacity(placeholder);
        for idx in multivariate_d as usize .. crate::CONST_PROOF_SIZE_LOG_N  {
            zero_univariate.iter().for_each(|inst| {
                transcript.add_scalar(*inst);
            }); // TODO is this really what we want?
            let round_challenge=transcript.get_challenge();
            multivariate_challenge.push(round_challenge);
            let mut transcript = transcript::Keccak256Transcript::<P>::default();
            transcript.add_scalar(round_challenge);
        }

// Final round: Extract multivariate evaluations from #partially_evaluated_polynomials and add to transcript



        todo!("return multivariate_challenge and multivariate_evaluations")
    }
}
