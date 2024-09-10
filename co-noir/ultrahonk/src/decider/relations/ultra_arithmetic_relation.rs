use super::Relation;
use crate::decider::types::ProverUnivariates;
use ark_ff::{PrimeField, Zero};

pub(crate) struct UltraArithmeticRelation {}

impl<F: PrimeField> Relation<F> for UltraArithmeticRelation {
    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<F>) -> bool {
        input.polys.precomputed.q_arith.is_zero()
    }

    fn accumulate(input: &ProverUnivariates<F>) {
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

        todo!()
    }
}
