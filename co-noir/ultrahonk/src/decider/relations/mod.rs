pub(crate) mod auxiliary_relation;
pub(crate) mod delta_range_constraint_relation;
pub(crate) mod elliptic_relation;
pub(crate) mod logderiv_lookup_relation;
pub(crate) mod permutation_relation;
pub(crate) mod poseidon2_external_relation;
pub(crate) mod poseidon2_internal_relation;
pub(crate) mod ultra_arithmetic_relation;

use crate::{honk_curve::HonkCurve, transcript::TranscriptFieldType};

use super::{
    sumcheck::sumcheck_round::SumcheckRoundOutput,
    types::{ClaimedEvaluations, ProverUnivariates, RelationParameters},
};
use ark_ff::PrimeField;
use auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationAcc, AuxiliaryRelationEvals};
use delta_range_constraint_relation::{
    DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
    DeltaRangeConstraintRelationEvals,
};
use elliptic_relation::{EllipticRelation, EllipticRelationAcc, EllipticRelationEvals};
use logderiv_lookup_relation::{
    LogDerivLookupRelation, LogDerivLookupRelationAcc, LogDerivLookupRelationEvals,
};
use permutation_relation::{
    UltraPermutationRelation, UltraPermutationRelationAcc, UltraPermutationRelationEvals,
};
use poseidon2_external_relation::{
    Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc, Poseidon2ExternalRelationEvals,
};
use poseidon2_internal_relation::{
    Poseidon2InternalRelation, Poseidon2InternalRelationAcc, Poseidon2InternalRelationEvals,
};
use ultra_arithmetic_relation::{
    UltraArithmeticRelation, UltraArithmeticRelationAcc, UltraArithmeticRelationEvals,
};

pub(crate) trait Relation<F: PrimeField> {
    type Acc: Default;
    type AccVerify: Default;
    const SKIPPABLE: bool;

    fn check_skippable() {
        if !Self::SKIPPABLE {
            panic!("Cannot skip this relation");
        }
    }

    fn skip(input: &ProverUnivariates<F>) -> bool;
    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );
    fn verify_accumulate(
        univariate_accumulator: &mut Self::AccVerify,
        input: &ClaimedEvaluations<F>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );
    fn scale_and_batch_elements(
        univariate_accumulator: &mut Self::AccVerify,
        current_scalar: &mut F,
        running_challenge: &mut F,
        result: &mut F,
    );
}

pub(crate) const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
    + UltraPermutationRelation::NUM_RELATIONS
    + DeltaRangeConstraintRelation::NUM_RELATIONS
    + EllipticRelation::NUM_RELATIONS
    + AuxiliaryRelation::NUM_RELATIONS
    + LogDerivLookupRelation::NUM_RELATIONS
    + Poseidon2ExternalRelation::NUM_RELATIONS
    + Poseidon2InternalRelation::NUM_RELATIONS;

#[derive(Default)]
pub(crate) struct AllRelationAcc<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<F>,
    pub(crate) r_perm: UltraPermutationRelationAcc<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<F>,
    pub(crate) r_elliptic: EllipticRelationAcc<F>,
    pub(crate) r_aux: AuxiliaryRelationAcc<F>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<F>,
}

// #[derive(Default)]
pub(crate) struct AllRelationEvaluations<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationEvals<F>,
    pub(crate) r_perm: UltraPermutationRelationEvals<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationEvals<F>,
    pub(crate) r_elliptic: EllipticRelationEvals<F>,
    pub(crate) r_aux: AuxiliaryRelationEvals<F>,
    pub(crate) r_lookup: LogDerivLookupRelationEvals<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationEvals<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationEvals<F>,
}

impl<F: PrimeField> AllRelationAcc<F> {
    pub fn scale(&mut self, first_scalar: F, elements: &[F]) {
        assert!(elements.len() == NUM_SUBRELATIONS - 1);
        self.r_arith.scale(&[first_scalar, elements[0]]);
        self.r_perm.scale(&elements[1..3]);
        self.r_delta.scale(&elements[3..7]);
        self.r_elliptic.scale(&elements[7..11]);
        self.r_aux.scale(&elements[11..17]);
        self.r_lookup.scale(&elements[17..19]);
        self.r_pos_ext.scale(&elements[19..23]);
        self.r_pos_int.scale(&elements[23..]);
    }

    pub fn extend_and_batch_univariates(
        &self,
        result: &mut SumcheckRoundOutput<F>,
        extended_random_poly: &SumcheckRoundOutput<F>,
        partial_evaluation_result: &F,
    ) {
        self.r_arith.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_perm.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_delta.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_elliptic.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_aux.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_lookup.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_pos_ext.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        self.r_pos_int.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
    }
}
impl<F: PrimeField> AllRelationEvaluations<F> {
    pub(crate) fn zero() -> Self {
        AllRelationEvaluations {
            r_arith: UltraArithmeticRelationEvals::zero(),
            r_perm: UltraPermutationRelationEvals::zero(),
            r_delta: DeltaRangeConstraintRelationEvals::zero(),
            r_elliptic: EllipticRelationEvals::zero(),
            r_aux: AuxiliaryRelationEvals::zero(),
            r_lookup: LogDerivLookupRelationEvals::zero(),
            r_pos_ext: Poseidon2ExternalRelationEvals::zero(),
            r_pos_int: Poseidon2InternalRelationEvals::zero(),
        }
    }

    pub(crate) fn scale_and_batch_elements_all(
        &mut self,
        current_scalar: &mut F,
        running_challenge: &mut F,
        result: &mut F,
    ) {
        AuxiliaryRelation::scale_and_batch_elements(
            &mut self.r_aux,
            current_scalar,
            running_challenge,
            result,
        );
        UltraArithmeticRelation::scale_and_batch_elements(
            &mut self.r_arith,
            current_scalar,
            running_challenge,
            result,
        );
        DeltaRangeConstraintRelation::scale_and_batch_elements(
            &mut self.r_delta,
            current_scalar,
            running_challenge,
            result,
        );
        EllipticRelation::scale_and_batch_elements(
            &mut self.r_elliptic,
            current_scalar,
            running_challenge,
            result,
        );
        LogDerivLookupRelation::scale_and_batch_elements(
            &mut self.r_lookup,
            current_scalar,
            running_challenge,
            result,
        );
        Poseidon2ExternalRelation::scale_and_batch_elements(
            &mut self.r_pos_ext,
            current_scalar,
            running_challenge,
            result,
        );
        Poseidon2InternalRelation::scale_and_batch_elements(
            &mut self.r_pos_int,
            current_scalar,
            running_challenge,
            result,
        );
        UltraPermutationRelation::scale_and_batch_elements(
            &mut self.r_perm,
            current_scalar,
            running_challenge,
            result,
        );
    }
}
