pub(crate) mod auxiliary_relation;
pub(crate) mod delta_range_constraint_relation;
pub(crate) mod elliptic_relation;
pub(crate) mod logderiv_lookup_relation;
pub(crate) mod permutation_relation;
pub(crate) mod poseidon2_external_relation;
pub(crate) mod poseidon2_internal_relation;
pub(crate) mod ultra_arithmetic_relation;

use super::types::{ProverUnivariates, RelationParameters};
use ark_ec::pairing::Pairing;

pub(crate) trait Relation<P: Pairing> {
    type Acc: Default;
    const SKIPPABLE: bool;

    fn check_skippable() {
        if !Self::SKIPPABLE {
            panic!("Cannot skip this relation");
        }
    }

    fn skip(input: &ProverUnivariates<P::ScalarField>) -> bool;
    fn accumulate(
        input: &ProverUnivariates<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) -> Self::Acc;
}
