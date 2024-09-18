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
