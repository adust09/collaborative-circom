use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub struct ProverCrs<P: Pairing> {
    pub monomials: Vec<P::G1Affine>,
}

pub struct ProvingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
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
    // pub z_perm : Vec<F>, // column 4 (???)
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
    pub table_1: Vec<F>,  // column 19
    pub table_2: Vec<F>,  // column 20
    pub table_3: Vec<F>,  // column 21
    pub table_4: Vec<F>,  // column 22
}

pub struct Challenges<F: PrimeField> {
    pub eta_1: F,
    pub eta_2: F,
    pub eta_3: F,
    pub beta: F,
    pub gamma: F,
}

pub struct WitnessCommitments<P: Pairing> {
    pub w_l: P::G1,
    pub w_r: P::G1,
    pub w_o: P::G1,
    pub w_4: P::G1,
    pub lookup_inverses: P::G1,
    pub lookup_read_counts: P::G1,
    pub lookup_read_tags: P::G1,
}
pub struct ProverMemory<P: Pairing> {
    pub w_4: Vec<P::ScalarField>,             // column 3
    pub lookup_inverses: Vec<P::ScalarField>, // column 5
    pub witness_commitments: WitnessCommitments<P>,
    pub challenges: Challenges<P::ScalarField>,
}

impl<P: Pairing> Default for WitnessCommitments<P> {
    fn default() -> Self {
        Self {
            w_l: Default::default(),
            w_r: Default::default(),
            w_o: Default::default(),
            w_4: Default::default(),
            lookup_inverses: Default::default(),
            lookup_read_counts: Default::default(),
            lookup_read_tags: Default::default(),
        }
    }
}

impl<F: PrimeField> Default for Challenges<F> {
    fn default() -> Self {
        Self {
            eta_1: Default::default(),
            eta_2: Default::default(),
            eta_3: Default::default(),
            beta: Default::default(),
            gamma: Default::default(),
        }
    }
}

impl<P: Pairing> Default for ProverMemory<P> {
    fn default() -> Self {
        Self {
            w_4: Default::default(),
            lookup_inverses: Default::default(),
            witness_commitments: Default::default(),
            challenges: Default::default(),
        }
    }
}
