use super::types::{UltraTraceBlock, UltraTraceBlocks};
use ark_ff::PrimeField;
use std::collections::HashMap;

type GateBlocks<F> = UltraTraceBlocks<UltraTraceBlock<F>>;

pub struct UltraCircuitBuilder<F: PrimeField> {
    variables: Vec<F>,
    variable_names: HashMap<u32, String>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    real_variable_index: Vec<u32>,
    real_variable_tags: Vec<u32>,
    public_inputs: Vec<u32>,
    is_recursive_circuit: bool,
    tau: HashMap<u32, u32>,
    constant_variable_indices: HashMap<F, u32>,
    zero_idx: u32,
    blocks: GateBlocks<F>, // Storage for wires and selectors for all gate types
    num_gates: usize,
}

impl<F: PrimeField> UltraCircuitBuilder<F> {
    const DUMMY_TAG: u32 = 0;
    const REAL_VARIABLE: u32 = u32::MAX - 1;
    const FIRST_VARIABLE_IN_CLASS: u32 = u32::MAX - 2;

    pub(crate) fn new(size_hint: usize) -> Self {
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
    pub fn init(
        size_hint: usize,
        witness_values: Vec<F>,
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
                F::zero()
            };
            builder.add_variable(value);
        }

        // Add the public_inputs from acir
        builder.public_inputs = public_inputs;

        // Add the const zero variable after the acir witness has been
        // incorporated into variables.
        builder.zero_idx = builder.put_constant_variable(F::zero());
        builder.tau.insert(Self::DUMMY_TAG, Self::DUMMY_TAG); // TODO(luke): explain this

        builder.is_recursive_circuit = recursive;
        builder
    }

    fn add_variable(&mut self, value: F) -> u32 {
        let idx = self.variables.len() as u32;
        self.variables.push(value);
        self.real_variable_index.push(idx);
        self.next_var_index.push(Self::REAL_VARIABLE);
        self.prev_var_index.push(Self::FIRST_VARIABLE_IN_CLASS);
        self.real_variable_tags.push(Self::DUMMY_TAG);
        idx
    }

    fn put_constant_variable(&mut self, variable: F) -> u32 {
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

    fn fix_witness(&mut self, witness_index: u32, witness_value: F) {
        self.assert_valid_variables(&[witness_index]);

        self.blocks.arithmetic.populate_wires(
            witness_index,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
        self.blocks.arithmetic.q_m().push(F::zero());
        self.blocks.arithmetic.q_1().push(F::one());
        self.blocks.arithmetic.q_2().push(F::zero());
        self.blocks.arithmetic.q_3().push(F::zero());
        self.blocks.arithmetic.q_c().push(-witness_value);
        self.blocks.arithmetic.q_arith().push(F::one());
        self.blocks.arithmetic.q_4().push(F::zero());
        self.blocks.arithmetic.q_delta_range().push(F::zero());
        self.blocks.arithmetic.q_lookup_type().push(F::zero());
        self.blocks.arithmetic.q_elliptic().push(F::zero());
        self.blocks.arithmetic.q_aux().push(F::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(F::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(F::zero());
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
}
