use std::str::FromStr;

use super::Relation;
use crate::decider::{
    sumcheck_round::SumcheckRoundOutput,
    types::{ProverUnivariates, RelationParameters},
    univariate::Univariate,
};
use ark_ff::{PrimeField, Zero};
use lazy_static::lazy_static;
use num_bigint::BigUint;

// TODO is this the most beatiful way to do this?
lazy_static! {
    static ref INTERNAL_MATRIX_DIAG_0: BigUint = BigUint::from_str(
        "7626475329478847982857743246276194948757851985510858890691733676098590062311"
    )
    .unwrap();
    static ref INTERNAL_MATRIX_DIAG_1: BigUint = BigUint::from_str(
        "5498568565063849786384470689962419967523752476452646391422913716315471115275"
    )
    .unwrap();
    static ref INTERNAL_MATRIX_DIAG_2: BigUint = BigUint::from_str(
        "148936322117705719734052984176402258788283488576388928671173547788498414613"
    )
    .unwrap();
    static ref INTERNAL_MATRIX_DIAG_3: BigUint = BigUint::from_str(
        "15456385653678559339152734484033356164266089951521103188900320352052358038155"
    )
    .unwrap();
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Poseidon2InternalRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 7>,
    pub(crate) r1: Univariate<F, 7>,
    pub(crate) r2: Univariate<F, 7>,
    pub(crate) r3: Univariate<F, 7>,
}

impl<F: PrimeField> Poseidon2InternalRelationAcc<F> {
    pub fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == Poseidon2InternalRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
        self.r2 *= elements[2];
        self.r3 *= elements[3];
    }

    pub fn extend_and_batch_univariates(
        &self,
        result: &mut SumcheckRoundOutput<F>,
        extended_random_poly: &SumcheckRoundOutput<F>,
        partial_evaluation_result: &F,
    ) {
        self.r0.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );

        self.r1.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );

        self.r2.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );

        self.r3.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }
}

pub(crate) struct Poseidon2InternalRelation {}

impl Poseidon2InternalRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
}

impl<F: PrimeField> Relation<F> for Poseidon2InternalRelation {
    type Acc = Poseidon2InternalRelationAcc<F>;
    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<F>) -> bool {
        <Self as Relation<F>>::check_skippable();
        input.polys.precomputed.q_poseidon2_internal().is_zero()
    }

    /**
     * @brief Expression for the poseidon2 internal round relation, based on I_i in Section 6 of
     * https://eprint.iacr.org/2023/323.pdf.
     * @details This relation is defined as C(in(X)...) :=
     * q_poseidon2_internal * ( (v1 - w_1_shift) + \alpha * (v2 - w_2_shift) +
     * \alpha^2 * (v3 - w_3_shift) + \alpha^3 * (v4 - w_4_shift) ) = 0 where:
     *      u1 := (w_1 + q_1)^5
     *      sum := u1 + w_2 + w_3 + w_4
     *      v1 := u1 * D1 + sum
     *      v2 := w_2 * D2 + sum
     *      v3 := w_3 * D3 + sum
     *      v4 := w_4 * D4 + sum
     *      Di is the ith internal diagonal value - 1 of the internal matrix M_I
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate Poseidon2InternalRelation");

        let w_l = input.polys.witness.w_l();
        let w_r = input.polys.witness.w_r();
        let w_o = input.polys.witness.w_o();
        let w_4 = &input.memory.w_4;
        let w_l_shift = input.polys.shifted.w_l();
        let w_r_shift = input.polys.shifted.w_r();
        let w_o_shift = input.polys.shifted.w_o();
        let w_4_shift = input.polys.shifted.w_4();
        let q_l = input.polys.precomputed.q_l();
        let q_poseidon2_internal = input.polys.precomputed.q_poseidon2_internal();

        // add round constants
        let s1 = w_l.to_owned() + q_l;

        // apply s-box round
        let mut u1 = s1.to_owned().sqr();
        u1 = u1.sqr();
        u1 *= s1;
        let u2 = w_r.to_owned();
        let u3 = w_o.to_owned();
        let u4 = w_4.to_owned();

        // matrix mul with v = M_I * u 4 muls and 7 additions
        let sum = u1.to_owned() + &u2 + &u3 + &u4;

        let q_pos_by_scaling = q_poseidon2_internal.to_owned() * scaling_factor;

        let mut v1 = u1 * F::from(INTERNAL_MATRIX_DIAG_0.to_owned());
        v1 += &sum;
        let tmp = (v1 - w_l_shift) * &q_pos_by_scaling;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let mut v2 = u2 * F::from(INTERNAL_MATRIX_DIAG_1.to_owned());
        v2 += &sum;
        let tmp = (v2 - w_r_shift) * &q_pos_by_scaling;
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let mut v3 = u3 * F::from(INTERNAL_MATRIX_DIAG_2.to_owned());
        v3 += &sum;
        let tmp = (v3 - w_o_shift) * &q_pos_by_scaling;
        for i in 0..univariate_accumulator.r2.evaluations.len() {
            univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let mut v4 = u4 * F::from(INTERNAL_MATRIX_DIAG_3.to_owned());
        v4 += sum;
        let tmp = (v4 - w_4_shift) * q_pos_by_scaling;
        for i in 0..univariate_accumulator.r3.evaluations.len() {
            univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
        }
    }
}
