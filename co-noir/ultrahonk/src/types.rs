use ark_ec::pairing::Pairing;

pub struct ProverCrs<P: Pairing> {
    pub monomials: Vec<P::G1Affine>,
}

pub struct ProvingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
}

pub struct Polynomials<P: Pairing> {
    pub w_l: Vec<P::ScalarField>,
    pub w_r: Vec<P::ScalarField>,
    pub w_o: Vec<P::ScalarField>,
}

pub struct Challenges<P: Pairing> {
    pub eta_1: P::ScalarField,
    pub eta_2: P::ScalarField,
    pub eta_3: P::ScalarField,
}

// pub struct WitnessEntities<P: Pairing> {}

pub struct WitnessCommitments<P: Pairing> {
    pub w_l_comm: P::G1,
    pub w_r_comm: P::G1,
    pub w_o_comm: P::G1,
}
pub struct ProverMemory<P: Pairing> {
    pub w_4: Vec<P::ScalarField>,
    pub witness_commitments: WitnessCommitments<P>,
    pub challenges: Challenges<P>,
}

impl<P: Pairing> Default for WitnessCommitments<P> {
    fn default() -> Self {
        Self {
            w_l_comm: Default::default(),
            w_r_comm: Default::default(),
            w_o_comm: Default::default(),
        }
    }
}

impl<P: Pairing> Default for Challenges<P> {
    fn default() -> Self {
        Self {
            eta_1: Default::default(),
            eta_2: Default::default(),
            eta_3: Default::default(),
        }
    }
}

impl<P: Pairing> Default for ProverMemory<P> {
    fn default() -> Self {
        Self {
            w_4: Default::default(),
            witness_commitments: Default::default(),
            challenges: Default::default(),
        }
    }
}
