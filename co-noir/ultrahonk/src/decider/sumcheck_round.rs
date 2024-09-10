use super::types::{GateSeparatorPolynomial, MAX_PARTIAL_RELATION_LENGTH};
use crate::{
    decider::types::ProverUnivariates,
    oink::verifier::RelationParameters,
    types::{Polynomials, ProvingKey},
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub(crate) struct SumcheckRound {
    pub(crate) round_size: usize,
}

impl SumcheckRound {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        SumcheckRound {
            round_size: initial_round_size,
        }
    }

    fn extend_to<F: PrimeField>(
        poly: &[F],
        res: &mut [F; MAX_PARTIAL_RELATION_LENGTH],
        idx: usize,
    ) {
        res[0] = poly[idx];
        res[1] = poly[idx + 1];

        // We only need to implement LENGTH = 2
        let delta = res[1] - res[0];
        for i in 2..MAX_PARTIAL_RELATION_LENGTH {
            res[i] = res[i - 1] + delta;
        }
    }

    fn extend_edges<F: PrimeField>(
        &self,
        extended_edges: &mut ProverUnivariates<F>,
        multivariates: &Polynomials<F>,
        edge_index: usize,
    ) {
        todo!()
    }

    pub(crate) fn compute_univariate<P: Pairing>(
        &self,
        round_index: usize,
        relation_parameters: RelationParameters<P>,
        gate_sparators: GateSeparatorPolynomial<P::ScalarField>,
        alphas: [P::ScalarField; crate::NUM_ALPHAS],
        proving_key: &ProvingKey<P>,
    ) {
        tracing::trace!("Sumcheck round {}", round_index);

        // Barretenberg uses multithreading here

        // Construct extended edge containers
        let mut extended_edge = ProverUnivariates::<P::ScalarField>::default();

        // Accumulate the contribution from each sub-relation accross each edge of the hyper-cube
        for edge_idx in (0..self.round_size).step_by(2) {
            self.extend_edges(&mut extended_edge, &proving_key.polynomials, edge_idx);
            // Compute the \f$ \ell \f$-th edge's univariate contribution,
            // scale it by the corresponding \f$ pow_{\beta} \f$ contribution and add it to the accumulators for \f$
            // \tilde{S}^i(X_i) \f$. If \f$ \ell \f$'s binary representation is given by \f$ (\ell_{i+1},\ldots,
            // \ell_{d-1})\f$, the \f$ pow_{\beta}\f$-contribution is \f$\beta_{i+1}^{\ell_{i+1}} \cdot \ldots \cdot
            // \beta_{d-1}^{\ell_{d-1}}\f$.
            todo!()
        }

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
