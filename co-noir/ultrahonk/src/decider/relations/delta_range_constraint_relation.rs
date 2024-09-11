use super::Relation;
use crate::decider::{
    types::{ProverUnivariates, RelationParameters},
    univariate::Univariate,
};
use ark_ec::pairing::Pairing;
use ark_ff::{One, PrimeField, Zero};

#[derive(Clone, Debug, Default)]
pub(crate) struct DeltaRangeConstraintRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 6>,
    pub(crate) r2: Univariate<F, 6>,
    pub(crate) r3: Univariate<F, 6>,
}

pub(crate) struct DeltaRangeConstraintRelation {}

impl<P: Pairing> Relation<P> for DeltaRangeConstraintRelation {
    type Acc = DeltaRangeConstraintRelationAcc<P::ScalarField>;
    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<P::ScalarField>) -> bool {
        input.polys.precomputed.q_delta_range.is_zero()
    }

    /**
     * @brief Expression for the generalized permutation sort gate.
     * @details The relation is defined as C(in(X)...) =
     *    q_delta_range * \sum{ i = [0, 3]} \alpha^i D_i(D_i - 1)(D_i - 2)(D_i - 3)
     *      where
     *      D_0 = w_2 - w_1
     *      D_1 = w_3 - w_2
     *      D_2 = w_4 - w_3
     *      D_3 = w_1_shift - w_4
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate(
        input: &ProverUnivariates<P::ScalarField>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) -> Self::Acc {
        tracing::trace!("Accumulate DeltaRangeConstraintRelation");

        let w_1 = &input.polys.witness.w_l;
        let w_2 = &input.polys.witness.w_r;
        let w_3 = &input.polys.witness.w_o;
        let w_4 = &input.w_4;
        let w_1_shift = &input.polys.shifted.w_l;
        let q_delta_range = &input.polys.precomputed.q_delta_range;
        let minus_one = -P::ScalarField::one();
        let minus_two = -P::ScalarField::from(2u64);

        // Compute wire differences
        let delta_1 = w_2.to_owned() - w_1;
        let delta_2 = w_3.to_owned() - w_2;
        let delta_3 = w_4.to_owned() - w_3;
        let delta_4 = w_1_shift.to_owned() - w_4;

        // Contribution (1)
        let mut tmp_1 = (delta_1.to_owned() + &minus_one).sqr() + &minus_one;
        tmp_1 *= (delta_1.to_owned() + &minus_two).sqr() + &minus_one;
        tmp_1 *= q_delta_range;
        tmp_1 *= scaling_factor;

        let mut r0 = Univariate::default();
        for i in 0..r0.evaluations.len() {
            r0.evaluations[i] = tmp_1.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////
        // Contribution (2)
        let mut tmp_2 = (delta_2.to_owned() + &minus_one).sqr() + &minus_one;
        tmp_2 *= (delta_2.to_owned() + &minus_two).sqr() + &minus_one;
        tmp_2 *= q_delta_range;
        tmp_2 *= scaling_factor;

        let mut r1 = Univariate::default();
        for i in 0..r1.evaluations.len() {
            r1.evaluations[i] = tmp_2.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////
        // Contribution (3)
        let mut tmp_3 = (delta_3.to_owned() + &minus_one).sqr() + &minus_one;
        tmp_3 *= (delta_3.to_owned() + &minus_two).sqr() + &minus_one;
        tmp_3 *= q_delta_range;
        tmp_3 *= scaling_factor;

        let mut r2 = Univariate::default();
        for i in 0..r2.evaluations.len() {
            r2.evaluations[i] = tmp_3.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////
        // Contribution (4)
        let mut tmp_4 = (delta_4.to_owned() + &minus_one).sqr() + &minus_one;
        tmp_4 *= (delta_4.to_owned() + &minus_two).sqr() + &minus_one;
        tmp_4 *= q_delta_range;
        tmp_4 *= scaling_factor;

        let mut r3 = Univariate::default();
        for i in 0..r3.evaluations.len() {
            r3.evaluations[i] = tmp_4.evaluations[i];
        }

        Self::Acc { r0, r1, r2, r3 }
    }
}
