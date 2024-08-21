use crate::NUM_ALPHAS;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub struct ProvingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
}

pub struct ProverCrs<P: Pairing> {
    pub monomials: Vec<P::G1Affine>,
}

pub struct Polynomials<F: PrimeField> {
    pub witness: WitnessEntities<F>,
    pub precomputed: PrecomputedEntities<F>,
    pub shifted: ShiftedWitnessEntities<F>,
}

pub struct WitnessEntities<F: PrimeField> {
    pub w_l: Vec<F>, // column 0
    pub w_r: Vec<F>, // column 1
    pub w_o: Vec<F>, // column 2
    // pub w_4: Vec<F>, // column 3 -> computed by prover
    // pub z_perm : Vec<F>, // column 4 -> computed by prover
    // pub lookup_inverses: Vec<F>,    // column 5 -> computed by prover
    pub lookup_read_counts: Vec<F>, // column 6
    pub lookup_read_tags: Vec<F>,   // column 7
}

pub struct ShiftedWitnessEntities<F: PrimeField> {
    pub w_l: Vec<F>, // column 0
    pub w_r: Vec<F>, // column 1
    pub w_o: Vec<F>, // column 2
}

pub struct PrecomputedEntities<F: PrimeField> {
    pub q_m: Vec<F>, // column 0
    pub q_c: Vec<F>, // column 1
    // pub q_l: Vec<F>,      // column 2
    pub q_r: Vec<F>,      // column 3
    pub q_o: Vec<F>,      // column 4
    pub q_lookup: Vec<F>, // column 10
    pub sigma_1: Vec<F>,  // column 11
    pub sigma_2: Vec<F>,  // column 12
    pub sigma_3: Vec<F>,  // column 13
    pub sigma_4: Vec<F>,  // column 14
    pub id_1: Vec<F>,     // column 15
    pub id_2: Vec<F>,     // column 16
    pub id_3: Vec<F>,     // column 17
    pub id_4: Vec<F>,     // column 18
    pub table_1: Vec<F>,  // column 19
    pub table_2: Vec<F>,  // column 20
    pub table_3: Vec<F>,  // column 21
    pub table_4: Vec<F>,  // column 22
}

pub struct VerifyingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P>,
}

pub struct VerifyingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P>,
}
