use std::collections::HashMap;

use acir::{acir_field::GenericFieldElement, native_types::WitnessStack};
use ark_ff::PrimeField;

pub struct UltraCircuitBuilder<F: PrimeField> {
    variables: Vec<F>,
    variable_names: HashMap<u32, String>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    real_variable_index: Vec<u32>,
    real_variable_tags: Vec<u32>,
    public_inputs: Vec<u32>,
    is_recursive_circuit: bool,
}

impl<F: PrimeField> UltraCircuitBuilder<F> {
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
        todo!("Add the const zero variable after the acir witness has been incorporated into variables.");
        // builder.zero_idx = put_constant_variable(FF::zero());
        // builder.tau.insert({ DUMMY_TAG, DUMMY_TAG }); // TODO(luke): explain this

        builder.is_recursive_circuit = recursive;
        builder
    }
}
