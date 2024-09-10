pub(crate) mod ultra_arithmetic_relation;

use super::types::ProverUnivariates;
use ark_ff::PrimeField;

pub(crate) trait Relation<F: PrimeField> {
    const SKIPPABLE: bool;

    fn check_skippable() {
        if !Self::SKIPPABLE {
            panic!("Cannot skip this relation");
        }
    }

    fn skip(input: &ProverUnivariates<F>) -> bool;
    fn accumulate(input: &ProverUnivariates<F>);
}
