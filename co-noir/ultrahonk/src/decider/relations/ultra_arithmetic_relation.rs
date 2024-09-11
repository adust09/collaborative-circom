use super::Relation;
use crate::decider::{
    types::{ProverUnivariates, RelationParameters},
    univariate::Univariate,
};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, Zero};

#[derive(Clone, Debug, Default)]
pub(crate) struct UltraArithmeticRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 5>,
}

pub(crate) struct UltraArithmeticRelation {}

impl<P: Pairing> Relation<P> for UltraArithmeticRelation {
    type Acc = UltraArithmeticRelationAcc<P::ScalarField>;
    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<P::ScalarField>) -> bool {
        input.polys.precomputed.q_arith.is_zero()
    }

    /**
     * @brief Expression for the Ultra Arithmetic gate.
     * @details This relation encapsulates several idenitities, toggled by the value of q_arith in [0, 1, 2, 3, ...].
     * The following description is reproduced from the Plonk analog 'plookup_arithmetic_widget':
     * The whole formula is:
     *
     * q_arith * ( ( (-1/2) * (q_arith - 3) * q_m * w_1 * w_2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c ) +
     * (q_arith - 1)*( α * (q_arith - 2) * (w_1 + w_4 - w_1_omega + q_m) + w_4_omega) ) = 0
     *
     * This formula results in several cases depending on q_arith:
     * 1. q_arith == 0: Arithmetic gate is completely disabled
     *
     * 2. q_arith == 1: Everything in the minigate on the right is disabled. The equation is just a standard plonk
     * equation with extra wires: q_m * w_1 * w_2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c = 0
     *
     * 3. q_arith == 2: The (w_1 + w_4 - ...) term is disabled. THe equation is:
     * (1/2) * q_m * w_1 * w_2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c + w_4_omega = 0
     * It allows defining w_4 at next index (w_4_omega) in terms of current wire values
     *
     * 4. q_arith == 3: The product of w_1 and w_2 is disabled, but a mini addition gate is enabled. α² allows us to
     * split the equation into two:
     *
     * q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c + 2 * w_4_omega = 0
     *
     * w_1 + w_4 - w_1_omega + q_m = 0  (we are reusing q_m here)
     *
     * 5. q_arith > 3: The product of w_1 and w_2 is scaled by (q_arith - 3), while the w_4_omega term is scaled by
     * (q_arith
     * - 1). The equation can be split into two:
     *
     * (q_arith - 3)* q_m * w_1 * w_ 2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c + (q_arith - 1) * w_4_omega
     * = 0
     *
     * w_1 + w_4 - w_1_omega + q_m = 0
     *
     * The problem that q_m is used both in both equations can be dealt with by appropriately changing selector values
     * at the next gate. Then we can treat (q_arith - 1) as a simulated q_6 selector and scale q_m to handle (q_arith -
     * 3) at product.
     *
     * The relation is
     * defined as C(in(X)...) = q_arith * [ -1/2(q_arith - 3)(q_m * w_r * w_l) + (q_l * w_l) + (q_r * w_r) +
     * (q_o * w_o) + (q_4 * w_4) + q_c + (q_arith - 1)w_4_shift ]
     *
     *    q_arith *
     *      (q_arith - 2) * (q_arith - 1) * (w_l + w_4 - w_l_shift + q_m)
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
        tracing::trace!("Accumulate UltraArithmeticRelation");

        let w_l = &input.polys.witness.w_l;
        let w_r = &input.polys.witness.w_r;
        let w_o = &input.polys.witness.w_o;
        let w_4 = &input.w_4;
        let w_4_shift = &input.polys.shifted.w_4;
        let q_m = &input.polys.precomputed.q_m;
        let q_l = &input.polys.precomputed.q_l;
        let q_r = &input.polys.precomputed.q_r;
        let q_o = &input.polys.precomputed.q_o;
        let q_4 = &input.polys.precomputed.q_4;
        let q_c = &input.polys.precomputed.q_c;
        let q_arith = &input.polys.precomputed.q_arith;
        let w_l_shift = &input.polys.shifted.w_l;

        let neg_half = -P::ScalarField::from(2u64).inverse().unwrap();

        let mut tmp = (q_arith.to_owned() - 3) * (q_m.to_owned() * w_r * w_l) * neg_half;
        tmp += (q_l.to_owned() * w_l)
            + (q_r.to_owned() * w_r)
            + (q_o.to_owned() * w_o)
            + (q_4.to_owned() * w_4)
            + q_c;
        tmp += (q_arith.to_owned() - 1) * w_4_shift;
        tmp *= q_arith;
        tmp *= scaling_factor;

        let mut r0 = Univariate::default();
        for i in 0..r0.evaluations.len() {
            r0.evaluations[i] = tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let mut tmp = w_l.to_owned() + w_4 - w_l_shift + q_m;
        tmp *= q_arith.to_owned() - 2;
        tmp *= q_arith.to_owned() - 1;
        tmp *= q_arith;
        tmp *= scaling_factor;

        let mut r1 = Univariate::default();
        for i in 0..r1.evaluations.len() {
            r1.evaluations[i] = tmp.evaluations[i];
        }

        Self::Acc { r0, r1 }
    }
}
