use super::{
    super::{
        types::{
            GateSeparatorPolynomial, MemoryElements, RelationParameters,
            MAX_PARTIAL_RELATION_LENGTH,
        },
        univariate::Univariate,
    },
    verifier::HAS_ZK,
};
use crate::{
    decider::{
        self,
        relations::{
            auxiliary_relation::AuxiliaryRelation,
            delta_range_constraint_relation::DeltaRangeConstraintRelation,
            elliptic_relation::{EllipticRelation, EllipticRelationAcc, EllipticRelationEvals},
            logderiv_lookup_relation::LogDerivLookupRelation,
            permutation_relation::UltraPermutationRelation,
            poseidon2_external_relation::Poseidon2ExternalRelation,
            poseidon2_internal_relation::Poseidon2InternalRelation,
            ultra_arithmetic_relation::UltraArithmeticRelation,
            AllRelationAcc, AllRelationEvaluations, Relation,
        },
        types::{ClaimedEvaluations, ProverUnivariates},
    },
    honk_curve::HonkCurve,
    transcript::TranscriptFieldType,
    types::Polynomials,
    NUM_ALPHAS,
};
use ark_ff::Field;
use ark_ff::PrimeField;

pub(crate) type SumcheckRoundOutput<F> = Univariate<F, { MAX_PARTIAL_RELATION_LENGTH + 1 }>;
#[derive(Clone, Copy)]
pub(crate) struct SumcheckRound {
    pub(crate) round_size: usize,
}
#[derive(Clone, Copy)]
pub(crate) struct SumcheckVerifierRound<F: PrimeField> {
    pub(crate) sumcheck_round: SumcheckRound,
    pub(crate) target_total_sum: F,
    pub(crate) round_failed: bool,
}

impl<F: PrimeField> SumcheckVerifierRound<F> {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        Self {
            sumcheck_round: SumcheckRound {
                round_size: initial_round_size,
            },
            target_total_sum: F::ZERO,
            round_failed: false,
        }
    }
    pub fn compute_next_target_sum(
        mut self, // Move self instead of borrowing
        univariate: &Univariate<F, { MAX_PARTIAL_RELATION_LENGTH + 1 }>,
        round_challenge: F,
    ) {
        self.target_total_sum = univariate.evaluate(round_challenge);
    }
    pub fn check_sum(
        mut self,
        univariate: &Univariate<F, { MAX_PARTIAL_RELATION_LENGTH + 1 }>,
    ) -> bool {
        let total_sum = univariate.evaluate(F::ZERO) + univariate.evaluate(F::ONE);
        let sumcheck_round_failed = self.target_total_sum != total_sum;

        self.round_failed = self.round_failed || sumcheck_round_failed;
        !sumcheck_round_failed
    }
    pub fn compute_full_relation_purported_value<P: HonkCurve<TranscriptFieldType>>(
        //mut self, Todo:
        purported_evaluations: &ClaimedEvaluations<P::ScalarField>,
        relation_parameters: RelationParameters<P::ScalarField>,
        gate_sparators: GateSeparatorPolynomial<P::ScalarField>,
        relation_evaluations: &mut AllRelationEvaluations<P::ScalarField>,
        alphas: &mut [P::ScalarField; NUM_ALPHAS],
        full_libra_purported_value: Option<P::ScalarField>,
    ) -> P::ScalarField {
        decider::sumcheck::sumcheck_round::SumcheckRound::accumulate_relation_evaluations::<P>(
            relation_evaluations,
            purported_evaluations,
            &relation_parameters,
            &gate_sparators.partial_evaluation_result,
        );
        let mut running_challenge = P::ScalarField::ONE;
        let mut output = P::ScalarField::ZERO;
        //todo!("FIX scale_and_batch_elements_all to take an array of alphas");
        AllRelationEvaluations::<P::ScalarField>::scale_and_batch_elements_all(
            relation_evaluations,
            &mut alphas[0],
            &mut running_challenge,
            &mut output,
        );
        // Only add `full_libra_purported_value` if ZK is enabled
        if HAS_ZK {
            if let Some(value) = full_libra_purported_value {
                output += value;
            }
        }
        output
    }
}
impl SumcheckRound {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        SumcheckRound {
            round_size: initial_round_size,
        }
    }

    fn extend_edges<F: PrimeField>(
        extended_edges: &mut ProverUnivariates<F>,
        multivariates: &Polynomials<F>,
        memory: &MemoryElements<Vec<F>>,
        edge_index: usize,
    ) {
        tracing::trace!("Extend edges");

        for (src, des) in memory
            .iter()
            .chain(multivariates.iter())
            .zip(extended_edges.iter_mut())
        {
            des.extend_from(&src[edge_index..edge_index + 2]);
        }
    }

    /**
     * @brief Extend Univariates then sum them multiplying by the current \f$ pow_{\beta} \f$-contributions.
     * @details Since the sub-relations comprising full Honk relation are of different degrees, the computation of the
     * evaluations of round univariate \f$ \tilde{S}_{i}(X_{i}) \f$ at points \f$ X_{i} = 0,\ldots, D \f$ requires to
     * extend evaluations of individual relations to the domain \f$ 0,\ldots, D\f$. Moreover, linearly independent
     * sub-relations, i.e. whose validity is being checked at every point of the hypercube, are multiplied by the
     * constant \f$ c_i = pow_\beta(u_0,\ldots, u_{i-1}) \f$ and the current \f$pow_{\beta}\f$-factor \f$ ( (1−X_i) +
     * X_i\cdot \beta_i ) \vert_{X_i = k} \f$ for \f$ k = 0,\ldots, D\f$.
     * @tparam extended_size Size after extension
     * @param tuple A tuple of tuples of Univariates
     * @param result Round univariate \f$ \tilde{S}^i\f$ represented by its evaluations over \f$ \{0,\ldots, D\} \f$.
     * @param gate_sparators Round \f$pow_{\beta}\f$-factor  \f$ ( (1−X_i) + X_i\cdot \beta_i )\f$.
     */
    fn extend_and_batch_univariates<F: PrimeField>(
        result: &mut SumcheckRoundOutput<F>,
        univariate_accumulators: AllRelationAcc<F>,
        gate_sparators: &GateSeparatorPolynomial<F>,
    ) {
        // Pow-Factor  \f$ (1-X) + X\beta_i \f$
        let random_polynomial = [F::one(), gate_sparators.current_element()];
        let mut extended_random_polynomial = SumcheckRoundOutput::default();
        extended_random_polynomial.extend_from(&random_polynomial);

        univariate_accumulators.extend_and_batch_univariates(
            result,
            &extended_random_polynomial,
            &gate_sparators.partial_evaluation_result,
        )
    }

    /**
     * @brief Given a tuple of tuples of extended per-relation contributions,  \f$ (t_0, t_1, \ldots,
     * t_{\text{NUM_SUBRELATIONS}-1}) \f$ and a challenge \f$ \alpha \f$, scale them by the relation separator
     * \f$\alpha\f$, extend to the correct degree, and take the sum multiplying by \f$pow_{\beta}\f$-contributions.
     *
     * @details This method receives as input the univariate accumulators computed by \ref
     * accumulate_relation_univariates "accumulate relation univariates" after passing through the entire hypercube and
     * applying \ref bb::RelationUtils::add_nested_tuples "add_nested_tuples" method to join the threads. The
     * accumulators are scaled using the method \ref bb::RelationUtils< Flavor >::scale_univariates "scale univariates",
     * extended to the degree \f$ D \f$ and summed with appropriate  \f$pow_{\beta}\f$-factors using \ref
     * extend_and_batch_univariates "extend and batch univariates method" to return a vector \f$(\tilde{S}^i(0), \ldots,
     * \tilde{S}^i(D))\f$.
     *
     * @param challenge Challenge \f$\alpha\f$.
     * @param gate_sparators Round \f$pow_{\beta}\f$-factor given by  \f$ ( (1−u_i) + u_i\cdot \beta_i )\f$.
     */
    fn batch_over_relations_univariates<F: PrimeField>(
        mut univariate_accumulators: AllRelationAcc<F>,
        alphas: &[F; crate::NUM_ALPHAS],
        gate_sparators: &GateSeparatorPolynomial<F>,
    ) -> SumcheckRoundOutput<F> {
        tracing::trace!("batch over relations");

        let running_challenge = F::one();
        univariate_accumulators.scale(running_challenge, alphas);

        let mut res = SumcheckRoundOutput::default();
        Self::extend_and_batch_univariates(&mut res, univariate_accumulators, gate_sparators);
        res
    }

    fn accumulate_one_relation_univariates<F: PrimeField, R: Relation<F>>(
        univariate_accumulator: &mut R::Acc,
        extended_edges: &ProverUnivariates<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        if R::SKIPPABLE && R::skip(extended_edges) {
            return;
        }

        R::accumulate(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }
    fn accumulate_one_relation_evaluations<F: PrimeField, R: Relation<F>>(
        univariate_accumulator: &mut R::AccVerify,
        extended_edges: &ClaimedEvaluations<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        // if R::SKIPPABLE && R::skip(extended_edges) {
        //     return;
        // }

        R::verify_accumulate(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn accumulate_elliptic_curve_relation_univariates<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulator: &mut EllipticRelationAcc<P::ScalarField>,
        extended_edges: &ProverUnivariates<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        if EllipticRelation::SKIPPABLE && EllipticRelation::skip(extended_edges) {
            return;
        }

        EllipticRelation::accumulate::<P>(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }
    fn accumulate_elliptic_curve_relation_evaluations<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulator: &mut EllipticRelationEvals<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        // if EllipticRelation::SKIPPABLE && EllipticRelation::skip(extended_edges) {
        //     return;
        // }

        EllipticRelation::verify_accumulate::<P>(
            univariate_accumulator,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn accumulate_relation_univariates<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut AllRelationAcc<P::ScalarField>,
        extended_edges: &ProverUnivariates<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        tracing::trace!("Accumulate relations");

        Self::accumulate_one_relation_univariates::<P::ScalarField, UltraArithmeticRelation>(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<P::ScalarField, UltraPermutationRelation>(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<P::ScalarField, DeltaRangeConstraintRelation>(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_elliptic_curve_relation_univariates::<P>(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<P::ScalarField, AuxiliaryRelation>(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<P::ScalarField, LogDerivLookupRelation>(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<P::ScalarField, Poseidon2ExternalRelation>(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_univariates::<P::ScalarField, Poseidon2InternalRelation>(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    fn accumulate_relation_evaluations<P: HonkCurve<TranscriptFieldType>>(
        univariate_accumulators: &mut AllRelationEvaluations<P::ScalarField>,
        extended_edges: &ClaimedEvaluations<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) {
        tracing::trace!("Accumulate relation evaluations");

        Self::accumulate_one_relation_evaluations::<P::ScalarField, UltraArithmeticRelation>(
            &mut univariate_accumulators.r_arith,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<P::ScalarField, UltraPermutationRelation>(
            &mut univariate_accumulators.r_perm,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<P::ScalarField, DeltaRangeConstraintRelation>(
            &mut univariate_accumulators.r_delta,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_elliptic_curve_relation_evaluations::<P>(
            &mut univariate_accumulators.r_elliptic,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<P::ScalarField, AuxiliaryRelation>(
            &mut univariate_accumulators.r_aux,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<P::ScalarField, LogDerivLookupRelation>(
            &mut univariate_accumulators.r_lookup,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<P::ScalarField, Poseidon2ExternalRelation>(
            &mut univariate_accumulators.r_pos_ext,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
        Self::accumulate_one_relation_evaluations::<P::ScalarField, Poseidon2InternalRelation>(
            &mut univariate_accumulators.r_pos_int,
            extended_edges,
            relation_parameters,
            scaling_factor,
        );
    }

    pub(crate) fn compute_univariate<P: HonkCurve<TranscriptFieldType>>(
        &self,
        round_index: usize,
        relation_parameters: &RelationParameters<P::ScalarField>,
        gate_sparators: &GateSeparatorPolynomial<P::ScalarField>,
        memory: &MemoryElements<Vec<P::ScalarField>>,
        polynomials: &Polynomials<P::ScalarField>,
    ) -> SumcheckRoundOutput<P::ScalarField> {
        tracing::trace!("Sumcheck round {}", round_index);

        // Barretenberg uses multithreading here

        // Construct extended edge containers
        let mut extended_edge = ProverUnivariates::<P::ScalarField>::default();

        let mut univariate_accumulators = AllRelationAcc::<P::ScalarField>::default();

        // Accumulate the contribution from each sub-relation accross each edge of the hyper-cube
        for edge_idx in (0..self.round_size).step_by(2) {
            Self::extend_edges(&mut extended_edge, polynomials, memory, edge_idx);
            // Compute the \f$ \ell \f$-th edge's univariate contribution,
            // scale it by the corresponding \f$ pow_{\beta} \f$ contribution and add it to the accumulators for \f$
            // \tilde{S}^i(X_i) \f$. If \f$ \ell \f$'s binary representation is given by \f$ (\ell_{i+1},\ldots,
            // \ell_{d-1})\f$, the \f$ pow_{\beta}\f$-contribution is \f$\beta_{i+1}^{\ell_{i+1}} \cdot \ldots \cdot
            // \beta_{d-1}^{\ell_{d-1}}\f$.
            Self::accumulate_relation_univariates::<P>(
                &mut univariate_accumulators,
                &extended_edge,
                relation_parameters,
                &gate_sparators.beta_products[(edge_idx >> 1) * gate_sparators.periodicity],
            );
        }
        Self::batch_over_relations_univariates(
            univariate_accumulators,
            &relation_parameters.alphas,
            gate_sparators,
        )
    }
}
