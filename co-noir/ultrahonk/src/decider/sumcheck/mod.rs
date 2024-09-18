pub mod prover;
pub mod sumcheck_round;

use super::types::ClaimedEvaluations;
use ark_ff::PrimeField;

pub struct SumcheckOutput<F: PrimeField> {
    pub(crate) claimed_evaluations: ClaimedEvaluations<F>,
    pub(crate) challenges: Vec<F>,
}

pub struct RelationEvaluations<F: PrimeField> {
    ultra_arithmetic_relation: Vec<F>,
    ultra_permutation_relation: Vec<F>,
    delta_range_constraint_relation: Vec<F>,
    elliptic_relation: Vec<F>,
    auxiliary_relation: Vec<F>,
    log_deriv_lookup_relation: Vec<F>,
    poseidon2_external_relation: Vec<F>,
    poseidon2_internal_relation: Vec<F>,
}
pub mod verifier;
