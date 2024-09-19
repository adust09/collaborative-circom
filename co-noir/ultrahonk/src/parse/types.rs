use std::array;

use ark_ff::PrimeField;

#[derive(Default, PartialEq, Eq)]
pub struct PolyTriple<F: PrimeField> {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub q_m: F,
    pub q_l: F,
    pub q_r: F,
    pub q_o: F,
    pub q_c: F,
}

#[derive(Default, PartialEq, Eq)]
pub struct MulQuad<F: PrimeField> {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub mul_scaling: F,
    pub a_scaling: F,
    pub b_scaling: F,
    pub c_scaling: F,
    pub d_scaling: F,
    pub const_scaling: F,
}

pub struct MemOp<F: PrimeField> {
    pub access_type: u8,
    pub index: PolyTriple<F>,
    pub value: PolyTriple<F>,
}

#[derive(PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum BlockType {
    ROM = 0,
    RAM = 1,
    CallData = 2,
    ReturnData = 3,
}

impl Default for BlockType {
    fn default() -> Self {
        Self::ROM
    }
}

#[derive(Default)]
pub struct BlockConstraint<F: PrimeField> {
    pub init: Vec<PolyTriple<F>>,
    pub trace: Vec<MemOp<F>>,
    pub type_: BlockType,
    pub calldata: u32,
}

#[derive(Default)]
pub struct AcirFormatOriginalOpcodeIndices {
    // pub logic_constraints: Vec<usize>,
    // pub range_constraints: Vec<usize>,
    // pub aes128_constraints: Vec<usize>,
    // pub sha256_constraints: Vec<usize>,
    // pub sha256_compression: Vec<usize>,
    // pub schnorr_constraints: Vec<usize>,
    // pub ecdsa_k1_constraints: Vec<usize>,
    // pub ecdsa_r1_constraints: Vec<usize>,
    // pub blake2s_constraints: Vec<usize>,
    // pub blake3_constraints: Vec<usize>,
    // pub keccak_constraints: Vec<usize>,
    // pub keccak_permutations: Vec<usize>,
    // pub pedersen_constraints: Vec<usize>,
    // pub pedersen_hash_constraints: Vec<usize>,
    // pub poseidon2_constraints: Vec<usize>,
    // pub multi_scalar_mul_constraints: Vec<usize>,
    // pub ec_add_constraints: Vec<usize>,
    // pub recursion_constraints: Vec<usize>,
    // pub honk_recursion_constraints: Vec<usize>,
    // pub ivc_recursion_constraints: Vec<usize>,
    // pub bigint_from_le_bytes_constraints: Vec<usize>,
    // pub bigint_to_le_bytes_constraints: Vec<usize>,
    // pub bigint_operations: Vec<usize>,
    pub assert_equalities: Vec<usize>,
    pub poly_triple_constraints: Vec<usize>,
    pub quad_constraints: Vec<usize>,
    // Multiple opcode indices per block:
    pub block_constraints: Vec<Vec<usize>>,
}

#[derive(Default)]
pub struct UltraTraceBlocks<T: Default> {
    pub(crate) pub_inputs: T,
    pub(crate) arithmetic: T,
    pub(crate) delta_range: T,
    pub(crate) elliptic: T,
    pub(crate) aux: T,
    pub(crate) lookup: T,
    pub(crate) poseidon_external: T,
    pub(crate) poseidon_internal: T,
}

impl<T: Default> UltraTraceBlocks<T> {
    pub(crate) fn get(&self) -> [&T; 8] {
        [
            &self.pub_inputs,
            &self.arithmetic,
            &self.delta_range,
            &self.elliptic,
            &self.aux,
            &self.lookup,
            &self.poseidon_external,
            &self.poseidon_internal,
        ]
    }
}

pub type UltraTraceBlock<F> = ExecutionTraceBlock<F, 4, 13>;
pub struct ExecutionTraceBlock<F: PrimeField, const NUM_WIRES: usize, const NUM_SELECTORS: usize> {
    pub(crate) wires: [Vec<u32>; NUM_WIRES], // vectors of indices into a witness variables array
    pub(crate) selectors: [Vec<F>; NUM_SELECTORS],
    pub(crate) has_ram_rom: bool, // does the block contain RAM/ROM gates
    pub(crate) is_pub_inputs: bool, // is this the public inputs block
    pub(crate) fixed_size: u32,   // Fixed size for use in structured trace
}

impl<F: PrimeField, const NUM_WIRES: usize, const NUM_SELECTORS: usize> Default
    for ExecutionTraceBlock<F, NUM_WIRES, NUM_SELECTORS>
{
    fn default() -> Self {
        Self {
            wires: array::from_fn(|_| Vec::new()),
            selectors: array::from_fn(|_| Vec::new()),
            has_ram_rom: false,
            is_pub_inputs: false,
            fixed_size: 0,
        }
    }
}

impl<F: PrimeField> UltraTraceBlock<F> {
    const W_L: usize = 0; // column 0
    const W_R: usize = 1; // column 1
    const W_O: usize = 2; // column 2
    const W_4: usize = 3; // column 3

    const Q_M: usize = 0; // column 0
    const Q_C: usize = 1; // column 1
    const Q_1: usize = 2; // column 2
    const Q_2: usize = 3; // column 3
    const Q_3: usize = 4; // column 4
    const Q_4: usize = 5; // column 5
    const Q_ARITH: usize = 6; // column 6
    const Q_DELTA_RANGE: usize = 7; // column 7
    const Q_ELLIPTIC: usize = 8; // column 8
    const Q_AUX: usize = 9; // column 9
    const Q_LOOKUP_TYPE: usize = 10; // column 10
    const Q_POSEIDON2_EXTERNAL: usize = 11; // column 11
    const Q_POSEIDON2_INTERNAL: usize = 12; // column 12

    pub fn w_l(&mut self) -> &mut Vec<u32> {
        &mut self.wires[Self::W_L]
    }

    pub fn w_r(&mut self) -> &mut Vec<u32> {
        &mut self.wires[Self::W_R]
    }

    pub fn w_o(&mut self) -> &mut Vec<u32> {
        &mut self.wires[Self::W_O]
    }

    pub fn w_4(&mut self) -> &mut Vec<u32> {
        &mut self.wires[Self::W_4]
    }

    pub fn q_m(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_M]
    }

    pub fn q_c(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_C]
    }

    pub fn q_1(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_1]
    }

    pub fn q_2(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_2]
    }

    pub fn q_3(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_3]
    }

    pub fn q_4(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_4]
    }

    pub fn q_arith(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_ARITH]
    }

    pub fn q_delta_range(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_DELTA_RANGE]
    }

    pub fn q_elliptic(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_ELLIPTIC]
    }

    pub fn q_aux(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_AUX]
    }

    pub fn q_lookup_type(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_LOOKUP_TYPE]
    }

    pub fn q_poseidon2_external(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_POSEIDON2_EXTERNAL]
    }

    pub fn q_poseidon2_internal(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_POSEIDON2_INTERNAL]
    }

    pub fn populate_wires(&mut self, idx1: u32, idx2: u32, idx3: u32, idx4: u32) {
        self.w_l().push(idx1);
        self.w_r().push(idx2);
        self.w_o().push(idx3);
        self.w_4().push(idx4);
    }
}

pub struct GateCounter {
    collect_gates_per_opcode: bool,
    prev_gate_count: usize,
}

impl GateCounter {
    pub fn new(collect_gates_per_opcode: bool) -> Self {
        Self {
            collect_gates_per_opcode,
            prev_gate_count: 0,
        }
    }
}
