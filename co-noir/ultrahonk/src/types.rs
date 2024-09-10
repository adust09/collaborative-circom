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

#[derive(Default)]
pub struct Polynomials<T: Default> {
    pub witness: WitnessEntities<T>,
    pub precomputed: PrecomputedEntities<T>,
    pub shifted: ShiftedWitnessEntities<T>,
}

#[derive(Default)]
pub struct WitnessEntities<T: Default> {
    pub w_l: Vec<T>, // column 0
    pub w_r: Vec<T>, // column 1
    pub w_o: Vec<T>, // column 2
    // pub w_4: Vec<T>, // column 3 -> computed by prover
    // pub z_perm : Vec<T>, // column 4 -> computed by prover
    // pub lookup_inverses: Vec<T>,    // column 5 -> computed by prover
    pub lookup_read_counts: Vec<T>, // column 6
    pub lookup_read_tags: Vec<T>,   // column 7
}

#[derive(Default)]
pub struct ShiftedWitnessEntities<T: Default> {
    pub w_l: Vec<T>, // column 0
    pub w_r: Vec<T>, // column 1
    pub w_o: Vec<T>, // column 2
}

#[derive(Default)]
pub struct PrecomputedEntities<T: Default> {
    pub q_m: Vec<T>, // column 0
    pub q_c: Vec<T>, // column 1
    // pub q_l: Vec<T>,      // column 2
    pub q_r: Vec<T>,      // column 3
    pub q_o: Vec<T>,      // column 4
    pub q_lookup: Vec<T>, // column 10
    pub sigma_1: Vec<T>,  // column 11
    pub sigma_2: Vec<T>,  // column 12
    pub sigma_3: Vec<T>,  // column 13
    pub sigma_4: Vec<T>,  // column 14
    pub id_1: Vec<T>,     // column 15
    pub id_2: Vec<T>,     // column 16
    pub id_3: Vec<T>,     // column 17
    pub id_4: Vec<T>,     // column 18
    pub table_1: Vec<T>,  // column 19
    pub table_2: Vec<T>,  // column 20
    pub table_3: Vec<T>,  // column 21
    pub table_4: Vec<T>,  // column 22
}

pub struct VerifyingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P::ScalarField>,
}
