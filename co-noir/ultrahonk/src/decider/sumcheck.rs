use super::prover::Decider;
use crate::{decider::types::PowPolynomial, get_msb};
use crate::{transcript, types::ProvingKey};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use rand::{thread_rng, Rng};

// Keep in mind, the UltraHonk protocol (UltraFlavor) does not per default have ZK
// The UltraFlavorWithZK has ZK
pub(crate) const HAS_ZK: bool = false;

impl<P: Pairing> Decider<P> {
    fn setup_zk_sumcheck_data<R: Rng>(&self, rng: &mut R) {
        const NUM_ALL_WITNESS_ENTITIES: usize = 13;

        let eval_masking_scalars = (0..NUM_ALL_WITNESS_ENTITIES)
            .map(|_| P::ScalarField::rand(rng))
            .collect::<Vec<_>>();

        todo!();
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

        // In case the Flavor has ZK, we populate sumcheck data structure with randomness, compute correcting term for
        // the total sum, etc.
        if HAS_ZK {
            self.setup_zk_sumcheck_data(&mut rng);
        };

        let pow_univariate = PowPolynomial::new(self.memory.challenges.gate_challenges.to_owned());

        let mut multivariate_challenge = Vec::with_capacity(multivariate_d as usize);
        let mut round_idx = 0;
        // In the first round, we compute the first univariate polynomial and populate the book-keeping table of
        // #partially_evaluated_polynomials, which has \f$ n/2 \f$ rows and \f$ N \f$ columns. When the Flavor has ZK,
        // compute_univariate also takes into account the zk_sumcheck_data.

        todo!("first round");

        multivariate_challenge.push(transcript.get_challenge());

        todo!()
    }
}
