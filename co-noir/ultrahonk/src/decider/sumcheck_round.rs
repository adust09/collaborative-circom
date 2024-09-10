use super::types::{GateSeparatorPolynomial, ProverMemory, MAX_PARTIAL_RELATION_LENGTH};
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

    fn extend_edges<P: Pairing>(
        extended_edges: &mut ProverUnivariates<P::ScalarField>,
        multivariates: &Polynomials<P::ScalarField>,
        prover_memory: &ProverMemory<P>,
        edge_index: usize,
    ) {
        let idx = edge_index;

        let src = &prover_memory;
        let des = extended_edges;
        // Memory
        Self::extend_to(&src.w_4, &mut des.w_4, idx);
        Self::extend_to(&src.z_perm, &mut des.z_perm, idx);
        Self::extend_to(&src.lookup_inverses, &mut des.lookup_inverses, idx);

        let extended_edges = des;
        let src = &multivariates.witness;
        let des = &mut extended_edges.polys.witness;
        // WitnessEntities
        Self::extend_to(&src.w_l, &mut des.w_l, idx);
        Self::extend_to(&src.w_r, &mut des.w_r, idx);
        Self::extend_to(&src.w_o, &mut des.w_o, idx);
        Self::extend_to(&src.lookup_read_counts, &mut des.lookup_read_counts, idx);
        Self::extend_to(&src.lookup_read_tags, &mut des.lookup_read_tags, idx);

        let src = &multivariates.shifted;
        let des = &mut extended_edges.polys.shifted;
        // ShiftedWitnessEntities
        Self::extend_to(&src.w_l, &mut des.w_l, idx);
        Self::extend_to(&src.w_r, &mut des.w_r, idx);
        Self::extend_to(&src.w_o, &mut des.w_o, idx);

        let src = &multivariates.precomputed;
        let des = &mut extended_edges.polys.precomputed;
        // PrecomputedEntities
        Self::extend_to(&src.q_m, &mut des.q_m, idx);
        Self::extend_to(&src.q_c, &mut des.q_c, idx);
        Self::extend_to(&src.q_r, &mut des.q_r, idx);
        Self::extend_to(&src.q_o, &mut des.q_o, idx);
        Self::extend_to(&src.q_lookup, &mut des.q_lookup, idx);
        Self::extend_to(&src.sigma_1, &mut des.sigma_1, idx);
        Self::extend_to(&src.sigma_2, &mut des.sigma_2, idx);
        Self::extend_to(&src.sigma_3, &mut des.sigma_3, idx);
        Self::extend_to(&src.id_1, &mut des.id_1, idx);
        Self::extend_to(&src.id_2, &mut des.id_2, idx);
        Self::extend_to(&src.id_3, &mut des.id_3, idx);
        Self::extend_to(&src.id_4, &mut des.id_4, idx);
        Self::extend_to(&src.table_1, &mut des.table_1, idx);
        Self::extend_to(&src.table_2, &mut des.table_2, idx);
        Self::extend_to(&src.table_3, &mut des.table_3, idx);
        Self::extend_to(&src.table_4, &mut des.table_4, idx);
    }

    pub(crate) fn compute_univariate<P: Pairing>(
        &self,
        round_index: usize,
        relation_parameters: RelationParameters<P>,
        gate_sparators: GateSeparatorPolynomial<P::ScalarField>,
        alphas: [P::ScalarField; crate::NUM_ALPHAS],
        prover_memory: &ProverMemory<P>,
        proving_key: &ProvingKey<P>,
    ) {
        tracing::trace!("Sumcheck round {}", round_index);

        // Barretenberg uses multithreading here

        // Construct extended edge containers
        let mut extended_edge = ProverUnivariates::<P::ScalarField>::default();

        // Accumulate the contribution from each sub-relation accross each edge of the hyper-cube
        for edge_idx in (0..self.round_size).step_by(2) {
            Self::extend_edges(
                &mut extended_edge,
                &proving_key.polynomials,
                prover_memory,
                edge_idx,
            );
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
