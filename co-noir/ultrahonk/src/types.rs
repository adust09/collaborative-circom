use ark_ec::pairing::Pairing;

pub type Polynomials<F> = AllEntities<Vec<F>>;

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
pub struct AllEntities<T: Default> {
    pub witness: WitnessEntities<T>,
    pub precomputed: PrecomputedEntities<T>,
    pub shifted: ShiftedWitnessEntities<T>,
}

#[derive(Default)]
pub struct WitnessEntities<T: Default> {
    pub w_l: T, // column 0
    pub w_r: T, // column 1
    pub w_o: T, // column 2
    // pub w_4: T, // column 3 -> computed by prover
    // pub z_perm : T, // column 4 -> computed by prover
    // pub lookup_inverses: T,    // column 5 -> computed by prover
    pub lookup_read_counts: T, // column 6
    pub lookup_read_tags: T,   // column 7
}

#[derive(Default)]
pub struct ShiftedWitnessEntities<T: Default> {
    pub w_l: T, // column 0
    pub w_r: T, // column 1
    pub w_o: T, // column 2
    pub w_4: T, // column 3
}

#[derive(Default)]
pub struct PrecomputedEntities<T: Default> {
    pub q_m: T,            // column 0
    pub q_c: T,            // column 1
    pub q_l: T,            // column 2
    pub q_r: T,            // column 3
    pub q_o: T,            // column 4
    pub q_4: T,            // column 5
    pub q_arith: T,        // column 6
    pub q_lookup: T,       // column 10
    pub sigma_1: T,        // column 13
    pub sigma_2: T,        // column 14
    pub sigma_3: T,        // column 15
    pub sigma_4: T,        // column 16
    pub id_1: T,           // column 17
    pub id_2: T,           // column 18
    pub id_3: T,           // column 19
    pub id_4: T,           // column 20
    pub table_1: T,        // column 21
    pub table_2: T,        // column 22
    pub table_3: T,        // column 23
    pub table_4: T,        // column 24
    pub lagrange_first: T, // column 25
    pub lagrange_last: T,  // column 26
}

pub struct VerifyingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P::ScalarField>,
}
