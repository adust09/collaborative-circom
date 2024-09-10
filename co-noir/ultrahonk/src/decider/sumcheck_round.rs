use ark_ec::pairing::Pairing;
use crate::{decider::types::ProverUnivariates, oink::verifier::RelationParameters};
use super::types::GateSeparatorPolynomial;

pub(crate) struct SumcheckRound {
    pub(crate) round_size: usize,
}

impl SumcheckRound {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        SumcheckRound {
            round_size: initial_round_size,
        }
    }

    pub(crate) fn compute_univariate<P: Pairing>(
        &self,
        round_index: usize,
        relation_parameters: RelationParameters<P>,
        gate_sparators: GateSeparatorPolynomial<P::ScalarField>,
        alphas: [P::ScalarField; crate::NUM_ALPHAS],
        // polynomials: Vec<P::ScalarField>, // Proving key instead?
    ) {
        tracing::trace!("Sumcheck round {}", round_index);

        // Barretenberg uses multithreading here
        let extended_edge = ProverUnivariates::<P::ScalarField>::default();

        todo!()
    }

    pub(crate) fn partially_evaluate_poly<P: Pairing>(
        &self,
        polynomials: Vec<P::ScalarField>,
        round_challenge: P::ScalarField,
    ) {
        // Barretenberg uses multithreading here
        todo!()
    }
}
