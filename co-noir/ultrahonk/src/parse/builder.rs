use super::{
    acir_format::AcirFormat,
    types::{
        AggregationObjectIndices, AggregationObjectPubInputIndices, UltraTraceBlock,
        UltraTraceBlocks,
    },
};
use crate::{parse::types::GateCounter, poseidon2::field_from_hex_string};
use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use num_bigint::BigUint;
use std::collections::HashMap;

type GateBlocks<F> = UltraTraceBlocks<UltraTraceBlock<F>>;

pub struct UltraCircuitBuilder<P: Pairing> {
    variables: Vec<P::ScalarField>,
    variable_names: HashMap<u32, String>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    real_variable_index: Vec<u32>,
    real_variable_tags: Vec<u32>,
    public_inputs: Vec<u32>,
    is_recursive_circuit: bool,
    tau: HashMap<u32, u32>,
    constant_variable_indices: HashMap<P::ScalarField, u32>,
    zero_idx: u32,
    blocks: GateBlocks<P::ScalarField>, // Storage for wires and selectors for all gate types
    num_gates: usize,
    circuit_finalized: bool,
    contains_recursive_proof: bool,
    recursive_proof_public_input_indices: AggregationObjectPubInputIndices,
}

impl<P: Pairing> UltraCircuitBuilder<P> {
    const DUMMY_TAG: u32 = 0;
    const REAL_VARIABLE: u32 = u32::MAX - 1;
    const FIRST_VARIABLE_IN_CLASS: u32 = u32::MAX - 2;

    pub fn create_circuit(
        constraint_system: AcirFormat<P::ScalarField>,
        size_hint: usize,
        witness: Vec<P::ScalarField>,
        honk_recursion: bool,           // true for ultrahonk
        collect_gates_per_opcode: bool, // false for ultrahonk
    ) -> Self {
        let has_valid_witness_assignments = !witness.is_empty();

        let mut builder = Self::init(
            size_hint,
            witness,
            constraint_system.public_inputs.to_owned(),
            constraint_system.varnum as usize,
            constraint_system.recursive,
        );

        builder.build_constraints(
            constraint_system,
            has_valid_witness_assignments,
            honk_recursion,
            collect_gates_per_opcode,
        );

        builder
    }

    fn new(size_hint: usize) -> Self {
        let variables = Vec::with_capacity(size_hint * 3);
        let variable_names = HashMap::with_capacity(size_hint * 3);
        let next_var_index = Vec::with_capacity(size_hint * 3);
        let prev_var_index = Vec::with_capacity(size_hint * 3);
        let real_variable_index = Vec::with_capacity(size_hint * 3);
        let real_variable_tags = Vec::with_capacity(size_hint * 3);

        Self {
            variables,
            variable_names,
            next_var_index,
            prev_var_index,
            real_variable_index,
            real_variable_tags,
            public_inputs: Vec::new(),
            is_recursive_circuit: false,
            tau: HashMap::new(),
            constant_variable_indices: HashMap::new(),
            zero_idx: 0,
            blocks: GateBlocks::default(),
            num_gates: 0,
            circuit_finalized: false,
            contains_recursive_proof: false,
            recursive_proof_public_input_indices: Default::default(),
        }
    }

    /**
     * @brief Constructor from data generated from ACIR
     *
     * @param size_hint
     * @param witness_values witnesses values known to acir
     * @param public_inputs indices of public inputs in witness array
     * @param varnum number of known witness
     *
     * @note The size of witness_values may be less than varnum. The former is the set of actual witness values known at
     * the time of acir generation. The latter may be larger and essentially acounts for placeholders for witnesses that
     * we know will exist but whose values are not known during acir generation. Both are in general less than the total
     * number of variables/witnesses that might be present for a circuit generated from acir, since many gates will
     * depend on the details of the bberg implementation (or more generally on the backend used to process acir).
     */
    fn init(
        size_hint: usize,
        witness_values: Vec<P::ScalarField>,
        public_inputs: Vec<u32>,
        varnum: usize,
        recursive: bool,
    ) -> Self {
        let mut builder = Self::new(size_hint);

        // TODO(https://github.com/AztecProtocol/barretenberg/issues/870): reserve space in blocks here somehow?

        for idx in 0..varnum {
            // Zeros are added for variables whose existence is known but whose values are not yet known. The values may
            // be "set" later on via the assert_equal mechanism.
            let value = if idx < witness_values.len() {
                witness_values[idx]
            } else {
                P::ScalarField::zero()
            };
            builder.add_variable(value);
        }

        // Add the public_inputs from acir
        builder.public_inputs = public_inputs;

        // Add the const zero variable after the acir witness has been
        // incorporated into variables.
        builder.zero_idx = builder.put_constant_variable(P::ScalarField::zero());
        builder.tau.insert(Self::DUMMY_TAG, Self::DUMMY_TAG); // TODO(luke): explain this

        builder.is_recursive_circuit = recursive;
        builder
    }

    fn add_variable(&mut self, value: P::ScalarField) -> u32 {
        let idx = self.variables.len() as u32;
        self.variables.push(value);
        self.real_variable_index.push(idx);
        self.next_var_index.push(Self::REAL_VARIABLE);
        self.prev_var_index.push(Self::FIRST_VARIABLE_IN_CLASS);
        self.real_variable_tags.push(Self::DUMMY_TAG);
        idx
    }

    fn put_constant_variable(&mut self, variable: P::ScalarField) -> u32 {
        if let Some(val) = self.constant_variable_indices.get(&variable) {
            *val
        } else {
            let variable_index = self.add_variable(variable);
            self.fix_witness(variable_index, variable);
            self.constant_variable_indices
                .insert(variable, variable_index);
            variable_index
        }
    }

    fn fix_witness(&mut self, witness_index: u32, witness_value: P::ScalarField) {
        self.assert_valid_variables(&[witness_index]);

        self.blocks.arithmetic.populate_wires(
            witness_index,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
        self.blocks.arithmetic.q_m().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_1().push(P::ScalarField::one());
        self.blocks.arithmetic.q_2().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_3().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_c().push(-witness_value);
        self.blocks.arithmetic.q_arith().push(P::ScalarField::one());
        self.blocks.arithmetic.q_4().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.arithmetic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());
        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    fn assert_valid_variables(&self, variable_indices: &[u32]) {
        for variable_index in variable_indices.iter().cloned() {
            assert!(self.is_valid_variable(variable_index as usize));
        }
    }

    fn is_valid_variable(&self, variable_index: usize) -> bool {
        variable_index < self.variables.len()
    }

    fn check_selector_length_consistency(&self) {
        for block in self.blocks.get() {
            let nominal_size = block.selectors[0].len();
            for selector in block.selectors.iter().skip(1) {
                debug_assert_eq!(selector.len(), nominal_size);
            }
        }
    }

    fn build_constraints(
        &mut self,
        mut constraint_system: AcirFormat<P::ScalarField>,
        has_valid_witness_assignments: bool,
        honk_recursion: bool,
        collect_gates_per_opcode: bool,
    ) {
        if collect_gates_per_opcode {
            constraint_system
                .gates_per_opcode
                .resize(constraint_system.num_acir_opcodes as usize, 0);
        }

        let mut gate_counter = GateCounter::new(collect_gates_per_opcode);

        //
        // Add arithmetic gates
        for (i, constraint) in constraint_system.poly_triple_constraints.iter().enumerate() {
            todo!("Arithmetic gates triple");
        }
        for (i, constraint) in constraint_system.quad_constraints.iter().enumerate() {
            todo!("Arithmetic gates quad");
        }

        // Add logic constraint
        // for (i, constraint) in constraint_system.logic_constraints.iter().enumerate() {
        //     todo!("Logic gates");
        // }

        // Add range constraint
        // for (i, constraint) in constraint_system.range_constraints.iter().enumerate() {
        //     todo!("rage gates");
        // }

        // Add aes128 constraints
        // for (i, constraint) in constraint_system.aes128_constraints.iter().enumerate() {
        //     todo!("aes128 gates");
        // }

        // Add sha256 constraints
        // for (i, constraint) in constraint_system.sha256_constraints.iter().enumerate() {
        //     todo!("sha256 gates");
        // }

        // for (i, constraint) in constraint_system.sha256_compression.iter().enumerate() {
        //     todo!("sha256 compression gates");
        // }

        // Add schnorr constraints
        // for (i, constraint) in constraint_system.schnorr_constraints.iter().enumerate() {
        //     todo!("schnorr gates");
        // }

        // Add ECDSA k1 constraints
        // for (i, constraint) in constraint_system.ecdsa_k1_constraints.iter().enumerate() {
        //     todo!("ecdsa k1 gates");
        // }

        // Add ECDSA r1 constraints
        // for (i, constraint) in constraint_system.ecdsa_r1_constraints.iter().enumerate() {
        //     todo!("ecdsa r1 gates");
        // }

        // Add blake2s constraints
        // for (i, constraint) in constraint_system.blake2s_constraints.iter().enumerate() {
        //     todo!("blake2s gates");
        // }

        // Add blake3 constraints
        // for (i, constraint) in constraint_system.blake3_constraints.iter().enumerate() {
        //     todo!("blake3 gates");
        // }

        // Add keccak constraints
        // for (i, constraint) in constraint_system.keccak_constraints.iter().enumerate() {
        //     todo!("keccak gates");
        // }

        // for (i, constraint) in constraint_system.keccak_permutations.iter().enumerate() {
        //     todo!("keccak permutation gates");
        // }

        // Add pedersen constraints
        // for (i, constraint) in constraint_system.pedersen_constraints.iter().enumerate() {
        //     todo!("pederson gates");
        // }

        // for (i, constraint) in constraint_system.pedersen_hash_constraints.iter().enumerate() {
        //     todo!("pedersen hash gates");
        // }

        // Add poseidon2 constraints
        // for (i, constraint) in constraint_system.poseidon2_constraints.iter().enumerate() {
        //     todo!("poseidon2 gates");
        // }

        // Add multi scalar mul constraints
        // for (i, constraint) in constraint_system.multi_scalar_mul_constraints.iter().enumerate() {
        //     todo!("multi scalar mul gates");
        // }

        // Add ec add constraints
        // for (i, constraint) in constraint_system.ec_add_constraints.iter().enumerate() {
        //     todo!("ec add gates");
        // }

        // Add block constraints
        for (i, constraint) in constraint_system.block_constraints.iter().enumerate() {
            todo!("block constraints gates");
        }

        // Add big_int constraints
        // for (i, constraint) in constraint_system.bigint_from_le_bytes_constraints.iter().enumerate() {
        //     todo!("bigint from le bytes gates");
        // }

        // for (i, constraint) in constraint_system.bigint_operations.iter().enumerate() {
        //     todo!("bigint operations gates");
        // }

        // for (i, constraint) in constraint_system.bigint_to_le_bytes_constraints.iter().enumerate() {
        //     todo!("bigint to le bytes gates");
        // }

        // assert equals
        for (i, constraint) in constraint_system.assert_equalities.iter().enumerate() {
            todo!("assert equalities gates");
        }

        // RecursionConstraints
        self.process_plonk_recursion_constraints(
            &constraint_system,
            has_valid_witness_assignments,
            &mut gate_counter,
        );
        self.process_honk_recursion_constraints(
            &constraint_system,
            has_valid_witness_assignments,
            &mut gate_counter,
        );

        // If the circuit does not itself contain honk recursion constraints but is going to be
        // proven with honk then recursively verified, add a default aggregation object
        if constraint_system.honk_recursion_constraints.is_empty()
            && honk_recursion
            && self.is_recursive_circuit
        {
            // Set a default aggregation object if we don't have one.
            let current_aggregation_object = self.init_default_agg_obj_indices();
            // Make sure the verification key records the public input indices of the
            // final recursion output.
            self.add_recursive_proof(current_aggregation_object);
        }
    }

    fn process_plonk_recursion_constraints(
        &mut self,
        constraint_system: &AcirFormat<P::ScalarField>,
        has_valid_witness_assignments: bool,
        gate_counter: &mut GateCounter,
    ) {
        todo!("Plonk recursion");
    }

    fn process_honk_recursion_constraints(
        &mut self,
        constraint_system: &AcirFormat<P::ScalarField>,
        has_valid_witness_assignments: bool,
        gate_counter: &mut GateCounter,
    ) {
        {
            todo!("Honk recursion");
        }
    }

    pub(crate) fn get_num_gates(&self) -> usize {
        // if circuit finalized already added extra gates
        if self.circuit_finalized {
            return self.num_gates;
        }
        let mut count = 0;
        let mut rangecount = 0;
        let mut romcount = 0;
        let mut ramcount = 0;
        let mut nnfcount = 0;
        self.get_num_gates_split_into_components(
            &mut count,
            &mut rangecount,
            &mut romcount,
            &mut ramcount,
            &mut nnfcount,
        );
        count + romcount + ramcount + rangecount + nnfcount
    }

    fn get_num_gates_split_into_components(
        &self,
        count: &mut usize,
        rangecount: &mut usize,
        romcount: &mut usize,
        ramcount: &mut usize,
        nnfcount: &mut usize,
    ) {
        *count = self.num_gates;

        todo!("Get num gates split into components");
    }

    fn add_recursive_proof(&mut self, proof_output_witness_indices: AggregationObjectIndices) {
        if self.contains_recursive_proof {
            panic!("added recursive proof when one already exists");
        }
        self.contains_recursive_proof = true;

        for (i, idx) in proof_output_witness_indices.into_iter().enumerate() {
            self.set_public_input(idx);
            self.recursive_proof_public_input_indices[i] = self.public_inputs.len() as u32 - 1;
        }
    }

    fn set_public_input(&mut self, witness_index: u32) {
        for public_input in self.public_inputs.iter().cloned() {
            if public_input == witness_index {
                panic!("Attempted to set a public input that is already public!");
            }
        }
        self.public_inputs.push(witness_index);
    }

    fn init_default_agg_obj_indices(&mut self) -> AggregationObjectIndices {
        const NUM_LIMBS: usize = 4;
        const NUM_LIMB_BITS: u32 = 68;
        const TOTAL_BITS: u32 = 254;

        let mask = (BigUint::one() << NUM_LIMB_BITS) - BigUint::one();

        // TODO(https://github.com/AztecProtocol/barretenberg/issues/911): These are pairing points extracted from a valid
        // proof. This is a workaround because we can't represent the point at infinity in biggroup yet.
        let mut agg_obj_indices = AggregationObjectIndices::default();
        let x0 = field_from_hex_string::<P::BaseField>(
            "0x031e97a575e9d05a107acb64952ecab75c020998797da7842ab5d6d1986846cf",
        )
        .expect("x0 works");
        let y0 = field_from_hex_string::<P::BaseField>(
            "0x178cbf4206471d722669117f9758a4c410db10a01750aebb5666547acf8bd5a4",
        )
        .expect("y0 works");
        let x1 = field_from_hex_string::<P::BaseField>(
            "0x0f94656a2ca489889939f81e9c74027fd51009034b3357f0e91b8a11e7842c38",
        )
        .expect("x1 works");
        let y1 = field_from_hex_string::<P::BaseField>(
            "0x1b52c2020d7464a0c80c0da527a08193fe27776f50224bd6fb128b46c1ddb67f",
        )
        .expect("y1 works");

        let mut agg_obj_indices_idx = 0;
        let aggregation_object_fq_values = [x0, y0, x1, y1];

        for val in aggregation_object_fq_values {
            let mut x: BigUint = val.into();
            let x0 = &x & &mask;
            x >>= NUM_LIMB_BITS;
            let x1 = &x & &mask;
            x >>= NUM_LIMB_BITS;
            let x2 = &x & &mask;
            x >>= NUM_LIMB_BITS;
            let x3 = x;

            let val_limbs: [P::ScalarField; NUM_LIMBS] = [
                P::ScalarField::from(x0),
                P::ScalarField::from(x1),
                P::ScalarField::from(x2),
                P::ScalarField::from(x3),
            ];

            for val in val_limbs {
                let idx = self.add_variable(val);
                agg_obj_indices[agg_obj_indices_idx] = idx;
                agg_obj_indices_idx += 1;
            }
        }
        agg_obj_indices
    }
}
