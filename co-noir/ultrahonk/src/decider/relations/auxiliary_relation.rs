use super::Relation;
use crate::decider::{
    types::{Challenges, ProverMemory, ProverUnivariates},
    univariate::Univariate,
};
use ark_ec::pairing::Pairing;
use ark_ff::{One, PrimeField, Zero};
use num_bigint::BigUint;

#[derive(Clone, Debug, Default)]

/**
 * TODO(https://github.com/AztecProtocol/barretenberg/issues/757): Investigate optimizations.
 * It seems that we could have:
 *     static constexpr std::array<size_t, 6> SUBRELATION_PARTIAL_LENGTHS{
 *     5 // auxiliary sub-relation;
 *     6 // ROM consistency sub-relation 1
 *     6 // ROM consistency sub-relation 2
 *     6 // RAM consistency sub-relation 1
 *     5 // RAM consistency sub-relation 2
 *     5 // RAM consistency sub-relation 3
 * };
 */
pub(crate) struct AuxiliaryRelationAcc<F: PrimeField> {
    pub(crate) r1: Univariate<F, 6>,
    pub(crate) r2: Univariate<F, 6>,
    pub(crate) r3: Univariate<F, 6>,
    pub(crate) r4: Univariate<F, 6>,
    pub(crate) r5: Univariate<F, 6>,
    pub(crate) r6: Univariate<F, 6>,
}

pub(crate) struct AuxiliaryRelation {}

impl<P: Pairing> Relation<P> for AuxiliaryRelation {
    type Acc = AuxiliaryRelationAcc<P::ScalarField>;
    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<P::ScalarField>) -> bool {
        input.polys.precomputed.q_aux.is_zero()
    }

    /**
     * @brief Expression for the generalized permutation sort gate.
     * @details The following explanation is reproduced from the Plonk analog 'plookup_auxiliary_widget':
     * Adds contributions for identities associated with several custom gates:
     *  * RAM/ROM read-write consistency check
     *  * RAM timestamp difference consistency check
     *  * RAM/ROM index difference consistency check
     *  * Bigfield product evaluation (3 in total)
     *  * Bigfield limb accumulation (2 in total)
     *
     * Multiple selectors are used to 'switch' aux gates on/off according to the following pattern:
     *
     * | gate type                    | q_aux | q_1 | q_2 | q_3 | q_4 | q_m | q_c | q_arith |
     * | ---------------------------- | ----- | --- | --- | --- | --- | --- | --- | ------  |
     * | Bigfield Limb Accumulation 1 | 1     | 0   | 0   | 1   | 1   | 0   | --- | 0       |
     * | Bigfield Limb Accumulation 2 | 1     | 0   | 0   | 1   | 0   | 1   | --- | 0       |
     * | Bigfield Product 1           | 1     | 0   | 1   | 1   | 0   | 0   | --- | 0       |
     * | Bigfield Product 2           | 1     | 0   | 1   | 0   | 1   | 0   | --- | 0       |
     * | Bigfield Product 3           | 1     | 0   | 1   | 0   | 0   | 1   | --- | 0       |
     * | RAM/ROM access gate          | 1     | 1   | 0   | 0   | 0   | 1   | --- | 0       |
     * | RAM timestamp check          | 1     | 1   | 0   | 0   | 1   | 0   | --- | 0       |
     * | ROM consistency check        | 1     | 1   | 1   | 0   | 0   | 0   | --- | 0       |
     * | RAM consistency check        | 1     | 0   | 0   | 0   | 0   | 0   | 0   | 1       |
     *
     * N.B. The RAM consistency check identity is degree 3. To keep the overall quotient degree at <=5, only 2 selectors
     * can be used to select it.
     *
     * N.B.2 The q_c selector is used to store circuit-specific values in the RAM/ROM access gate
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the Totaly extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate(
        input: &ProverUnivariates<P::ScalarField>,
        memory: &ProverMemory<P>,
        challenges: &Challenges<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) -> Self::Acc {
        let eta = &challenges.eta_1;
        let eta_two = &challenges.eta_2;
        let eta_three = &challenges.eta_3;

        let w_1 = &input.polys.witness.w_l;
        let w_2 = &input.polys.witness.w_r;
        let w_3 = &input.polys.witness.w_o;
        let w_4 = &input.w_4;
        let w_1_shift = &input.polys.shifted.w_l;
        let w_2_shift = &input.polys.shifted.w_r;
        let w_3_shift = &input.polys.shifted.w_o;
        let w_4_shift = &input.polys.shifted.w_4;

        let q_1 = &input.polys.precomputed.q_l;
        let q_2 = &input.polys.precomputed.q_r;
        let q_3 = &input.polys.precomputed.q_o;
        let q_4 = &input.polys.precomputed.q_4;
        let q_m = &input.polys.precomputed.q_m;
        let q_c = &input.polys.precomputed.q_c;
        let q_arith = &input.polys.precomputed.q_arith;
        let q_aux = &input.polys.precomputed.q_aux;

        let limb_size = P::ScalarField::from(BigUint::one() << 68);
        let sublimb_shift = P::ScalarField::from(1u64 << 14);

        /*
         * Non native field arithmetic gate 2
         * deg 4
         *
         *             _                                                                               _
         *            /   _                   _                               _       14                \
         * q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
         *            \_                                                                               _/
         *
         **/
        let mut limb_subproduct = w_1.to_owned() * w_2_shift + w_1_shift.to_owned() * w_2;
        let mut non_native_field_gate_2 = w_1.to_owned() * w_4 + w_2.to_owned() * w_3 - w_3_shift;
        non_native_field_gate_2 *= limb_size;
        non_native_field_gate_2 -= w_4_shift;
        non_native_field_gate_2 += &limb_subproduct;
        non_native_field_gate_2 *= q_4;

        limb_subproduct *= limb_size;
        limb_subproduct += w_1_shift.to_owned() * w_2_shift;
        let mut non_native_field_gate_1 = limb_subproduct.to_owned();
        non_native_field_gate_1 -= w_3.to_owned() + w_4;
        non_native_field_gate_1 *= q_3;

        let mut non_native_field_gate_3 = limb_subproduct;
        non_native_field_gate_3 += w_4;
        non_native_field_gate_3 -= w_3_shift.to_owned() + w_4_shift;
        non_native_field_gate_3 *= q_m;

        let mut non_native_field_identity =
            non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3;
        non_native_field_identity *= q_2;

        // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * qm
        // deg 2
        let mut limb_accumulator_1 = w_2_shift.to_owned() * sublimb_shift;
        limb_accumulator_1 += w_1_shift;
        limb_accumulator_1 *= sublimb_shift;
        limb_accumulator_1 += w_3;
        limb_accumulator_1 *= sublimb_shift;
        limb_accumulator_1 += w_2;
        limb_accumulator_1 *= sublimb_shift;
        limb_accumulator_1 += w_1;
        limb_accumulator_1 -= w_4;
        limb_accumulator_1 *= q_4;

        // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * qm
        // deg 2
        let mut limb_accumulator_2 = w_3_shift.to_owned() * sublimb_shift;
        limb_accumulator_2 += w_2_shift;
        limb_accumulator_2 *= sublimb_shift;
        limb_accumulator_2 += w_1_shift;
        limb_accumulator_2 *= sublimb_shift;
        limb_accumulator_2 += w_4;
        limb_accumulator_2 *= sublimb_shift;
        limb_accumulator_2 += w_3;
        limb_accumulator_2 -= w_4_shift;
        limb_accumulator_2 *= q_m;

        let mut limb_accumulator_identity = limb_accumulator_1 + limb_accumulator_2;
        limb_accumulator_identity *= q_3; //  deg 3

        /*
         * MEMORY
         *
         * A RAM memory record contains a tuple of the following fields:
         *  * i: `index` of memory cell being accessed
         *  * t: `timestamp` of memory cell being accessed (used for RAM, set to 0 for ROM)
         *  * v: `value` of memory cell being accessed
         *  * a: `access` type of record. read: 0 = read, 1 = write
         *  * r: `record` of memory cell. record = access + index * eta + timestamp * η₂ + value * η₃
         *
         * A ROM memory record contains a tuple of the following fields:
         *  * i: `index` of memory cell being accessed
         *  * v: `value1` of memory cell being accessed (ROM tables can store up to 2 values per index)
         *  * v2:`value2` of memory cell being accessed (ROM tables can store up to 2 values per index)
         *  * r: `record` of memory cell. record = index * eta + value2 * η₂ + value1 * η₃
         *
         *  When performing a read/write access, the values of i, t, v, v2, a, r are stored in the following wires +
         * selectors, depending on whether the gate is a RAM read/write or a ROM read
         *
         *  | gate type | i  | v2/t  |  v | a  | r  |
         *  | --------- | -- | ----- | -- | -- | -- |
         *  | ROM       | w1 | w2    | w3 | -- | w4 |
         *  | RAM       | w1 | w2    | w3 | qc | w4 |
         *
         * (for accesses where `index` is a circuit constant, it is assumed the circuit will apply a copy constraint on
         * `w2` to fix its value)
         *
         **/

        /*
         * Memory Record Check
         * Partial degree: 1
         * Total degree: 2
         *
         * A ROM/ROM access gate can be evaluated with the identity:
         *
         * qc + w1 \eta + w2 η₂ + w3 η₃ - w4 = 0
         *
         * For ROM gates, qc = 0
         */
        let mut memory_record_check = w_3.to_owned() * eta_three;
        memory_record_check += w_2.to_owned() * eta_two;
        memory_record_check += w_1.to_owned() * eta;
        memory_record_check += q_c;
        let partial_record_check = memory_record_check.to_owned(); // used in RAM consistency check; deg 1 or 2
        memory_record_check -= w_4;

        /*
         * ROM Consistency Check
         * Partial degree: 1
         * Total degree: 4
         *
         * For every ROM read, a set equivalence check is applied between the record witnesses, and a second set of
         * records that are sorted.
         *
         * We apply the following checks for the sorted records:
         *
         * 1. w1, w2, w3 correctly map to 'index', 'v1, 'v2' for a given record value at w4
         * 2. index values for adjacent records are monotonically increasing
         * 3. if, at gate i, index_i == index_{i + 1}, then value1_i == value1_{i + 1} and value2_i == value2_{i + 1}
         *
         */
        let index_delta = w_1_shift.to_owned() - w_1;
        let record_delta = w_4_shift.to_owned() - w_4;

        let index_is_monotonically_increasing = index_delta.to_owned().sqr() - &index_delta; // deg 2

        let adjacent_values_match_if_adjacent_indices_match =
            (-index_delta + &P::ScalarField::one()) * record_delta; // deg 2

        let q_aux_by_scaling = q_aux.to_owned() * scaling_factor;
        let q_one_by_two = q_1.to_owned() * q_2;
        let q_one_by_two_by_aux_by_scaling = q_one_by_two * q_aux_by_scaling;

        // let mut r1 = Univariate::default();
        // for i in 0..r1.evaluations.len() {
        //     r1.evaluations[i] = tmp.evaluations[i];
        // }

        ///////////////////////////////////////////////////////////////////////

        // let mut r2 = Univariate::default();
        // for i in 0..r2.evaluations.len() {
        //     r2.evaluations[i] = tmp.evaluations[i];
        // }

        // Self::Acc { r1, r2 }
        todo!()
    }
}
