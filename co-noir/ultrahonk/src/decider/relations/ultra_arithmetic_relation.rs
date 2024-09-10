use super::Relation;
use crate::decider::{types::ProverUnivariates, univariate::Univariate};
use ark_ff::{PrimeField, Zero};

#[derive(Clone, Debug, Default)]
pub(crate) struct UltraArithmeticRelationAcc<F: PrimeField> {
    pub(crate) r1: Univariate<F, 6>,
    pub(crate) r2: Univariate<F, 5>,
}

pub(crate) struct UltraArithmeticRelation {}

impl<F: PrimeField> Relation<F> for UltraArithmeticRelation {
    type Acc = UltraArithmeticRelationAcc<F>;
    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<F>) -> bool {
        input.polys.precomputed.q_arith.is_zero()
    }

    fn accumulate(input: &ProverUnivariates<F>, scaling_factor: &F) -> Self::Acc {
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

        let neg_half = -F::from(2u64).inverse().unwrap();

        let mut tmp = (q_arith.to_owned() - 3) * (q_m.to_owned() * w_r * w_l) * neg_half;
        tmp += (q_l.to_owned() * w_l)
            + (q_r.to_owned() * w_r)
            + (q_o.to_owned() * w_o)
            + (q_4.to_owned() * w_4)
            + q_c;
        tmp += (q_arith.to_owned() - 1) * w_4_shift;
        tmp *= q_arith;
        tmp *= scaling_factor;

        let mut r1 = Univariate::default();
        for i in 0..r1.evaluations.len() {
            r1.evaluations[i] = tmp.evaluations[i];
        }

        let mut tmp = w_l.to_owned() + w_4 - w_l_shift + q_m;
        tmp *= q_arith.to_owned() - 2;
        tmp *= q_arith.to_owned() - 1;
        tmp *= q_arith;
        tmp *= scaling_factor;

        let mut r2 = Univariate::default();
        for i in 0..r2.evaluations.len() {
            r2.evaluations[i] = tmp.evaluations[i];
        }

        UltraArithmeticRelationAcc { r1, r2 }
    }
}
