use super::{
    relations::{
        auxiliary_relation::AuxiliaryRelationAcc,
        delta_range_constraint_relation::DeltaRangeConstraintRelationAcc,
        elliptic_relation::EllipticRelationAcc,
        logderiv_lookup_relation::LogDerivLookupRelationAcc,
        permutation_relation::UltraPermutationRelationAcc,
        poseidon2_external_relation::Poseidon2ExternalRelationAcc,
        poseidon2_internal_relation::Poseidon2InternalRelationAcc,
        ultra_arithmetic_relation::{UltraArithmeticRelation, UltraArithmeticRelationAcc},
        Relation,
    },
    types::{
        GateSeparatorPolynomial, ProverMemory, RelationParameters, MAX_PARTIAL_RELATION_LENGTH,
    },
    univariate::Univariate,
};
use crate::{
    decider::{
        relations::{
            auxiliary_relation::AuxiliaryRelation,
            delta_range_constraint_relation::DeltaRangeConstraintRelation,
            elliptic_relation::EllipticRelation, logderiv_lookup_relation::LogDerivLookupRelation,
            permutation_relation::UltraPermutationRelation,
            poseidon2_external_relation::Poseidon2ExternalRelation,
            poseidon2_internal_relation::Poseidon2InternalRelation,
        },
        types::ProverUnivariates,
    },
    types::{Polynomials, ProvingKey},
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub(crate) struct SumcheckRound {
    pub(crate) round_size: usize,
}

struct AllRelationAcc<F: PrimeField> {
    r_arith: UltraArithmeticRelationAcc<F>,
    r_perm: UltraPermutationRelationAcc<F>,
    r_delta: DeltaRangeConstraintRelationAcc<F>,
    r_elliptic: EllipticRelationAcc<F>,
    r_aux: AuxiliaryRelationAcc<F>,
    r_lookup: LogDerivLookupRelationAcc<F>,
    r_pos_ext: Poseidon2ExternalRelationAcc<F>,
    r_pos_int: Poseidon2InternalRelationAcc<F>,
}

macro_rules! extend_macro {
    ($src:expr, $des:expr, $idx:expr, ($($el:ident),*)) => {{
        $(
            Self::extend_to(&$src.$el, &mut $des.$el, $idx);
        )*
    }};
}

impl SumcheckRound {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        SumcheckRound {
            round_size: initial_round_size,
        }
    }

    fn extend_to<F: PrimeField>(
        poly: &[F],
        res: &mut Univariate<F, MAX_PARTIAL_RELATION_LENGTH>,
        idx: usize,
    ) {
        res.evaluations[0] = poly[idx];
        res.evaluations[1] = poly[idx + 1];

        // We only need to implement LENGTH = 2
        let delta = res.evaluations[1] - res.evaluations[0];
        for i in 2..MAX_PARTIAL_RELATION_LENGTH {
            res.evaluations[i] = res.evaluations[i - 1] + delta;
        }
    }

    fn extend_edges<P: Pairing>(
        extended_edges: &mut ProverUnivariates<P::ScalarField>,
        multivariates: &Polynomials<P::ScalarField>,
        prover_memory: &ProverMemory<P>,
        edge_index: usize,
    ) {
        tracing::trace!("Extend edges");
        // Memory
        extend_macro!(
            &prover_memory,
            extended_edges,
            edge_index,
            (w_4, z_perm, z_perm_shift, lookup_inverses)
        );

        // WitnessEntities
        extend_macro!(
            &multivariates.witness,
            &mut extended_edges.polys.witness,
            edge_index,
            (w_l, w_r, w_o, lookup_read_counts, lookup_read_tags)
        );

        // ShiftedWitnessEntities
        extend_macro!(
            &multivariates.shifted,
            &mut extended_edges.polys.shifted,
            edge_index,
            (w_l, w_r, w_o, w_4)
        );

        // PrecomputedEntities
        extend_macro!(
            &multivariates.precomputed,
            &mut extended_edges.polys.precomputed,
            edge_index,
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

    fn batch_over_relations_univariates<P: Pairing>(// extended_edges: &ProverUnivariates<P::ScalarField>,
        // relation_parameters: &RelationParameters<P::ScalarField>,
        // scaling_factor: &P::ScalarField,
    ) -> Univariate<P::ScalarField, { MAX_PARTIAL_RELATION_LENGTH + 1 }> {
        // Self::accumulate_relation_univariates::<P>(
        //     extended_edges,
        //     relation_parameters,
        //     scaling_factor,
        // );
        todo!()
    }

    fn accumulate_one_relation_univariates<F: PrimeField, R: Relation<F>>(
        extended_edges: &ProverUnivariates<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) -> R::Acc {
        if R::SKIPPABLE && R::skip(extended_edges) {
            return R::Acc::default();
        }

        R::accumulate(extended_edges, relation_parameters, scaling_factor)
    }

    fn accumulate_relation_univariates<F: PrimeField>(
        extended_edges: &ProverUnivariates<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) -> AllRelationAcc<F> {
        tracing::trace!("Accumulate relation");

        let r_arith = Self::accumulate_one_relation_univariates::<F, UltraArithmeticRelation>(
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        let r_perm = Self::accumulate_one_relation_univariates::<F, UltraPermutationRelation>(
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        let r_delta = Self::accumulate_one_relation_univariates::<F, DeltaRangeConstraintRelation>(
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        // TODO we skip the EllipticRelation relation so far due to implementation issues (see the implementation file)
        assert!(
            <EllipticRelation as Relation<F>>::SKIPPABLE
                && <EllipticRelation as Relation<F>>::skip(extended_edges)
        );
        let r_elliptic = <EllipticRelation as Relation<F>>::Acc::default();
        let r_aux = Self::accumulate_one_relation_univariates::<F, AuxiliaryRelation>(
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        let r_lookup = Self::accumulate_one_relation_univariates::<F, LogDerivLookupRelation>(
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        let r_pos_ext = Self::accumulate_one_relation_univariates::<F, Poseidon2ExternalRelation>(
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        let r_pos_int = Self::accumulate_one_relation_univariates::<F, Poseidon2InternalRelation>(
            extended_edges,
            relation_parameters,
            scaling_factor,
        );

        AllRelationAcc {
            r_arith,
            r_perm,
            r_delta,
            r_elliptic,
            r_aux,
            r_lookup,
            r_pos_ext,
            r_pos_int,
        }
    }

    pub(crate) fn compute_univariate<P: Pairing>(
        &self,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
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
            let accs = Self::accumulate_relation_univariates(
                &extended_edge,
                relation_parameters,
                &gate_sparators.beta_products[(edge_idx >> 1) * gate_sparators.periodicity],
            );
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
