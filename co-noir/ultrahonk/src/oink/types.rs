use crate::NUM_ALPHAS;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub struct ProverMemory<P: Pairing> {
    pub w_4: Vec<P::ScalarField>,             // column 3
    pub z_perm: Vec<P::ScalarField>,          // column 4
    pub lookup_inverses: Vec<P::ScalarField>, // column 5
    pub public_input_delta: P::ScalarField,
    pub witness_commitments: WitnessCommitments<P>,
    pub challenges: Challenges<P::ScalarField>,
}

pub struct Challenges<F: PrimeField> {
    pub eta_1: F,
    pub eta_2: F,
    pub eta_3: F,
    pub beta: F,
    pub gamma: F,
    pub alphas: [F; NUM_ALPHAS],
}

pub struct WitnessCommitments<P: Pairing> {
    pub w_l: P::G1,
    pub w_r: P::G1,
    pub w_o: P::G1,
    pub w_4: P::G1,
    pub z_perm: P::G1,
    pub lookup_inverses: P::G1,
    pub lookup_read_counts: P::G1,
    pub lookup_read_tags: P::G1,
}

impl<P: Pairing> Default for WitnessCommitments<P> {
    fn default() -> Self {
        Self {
            w_l: Default::default(),
            w_r: Default::default(),
            w_o: Default::default(),
            w_4: Default::default(),
            z_perm: Default::default(),
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
            alphas: [Default::default(); NUM_ALPHAS],
        }
    }
}

impl<P: Pairing> Default for ProverMemory<P> {
    fn default() -> Self {
        Self {
            w_4: Default::default(),
            z_perm: Default::default(),
            lookup_inverses: Default::default(),
            public_input_delta: Default::default(),
            witness_commitments: Default::default(),
            challenges: Default::default(),
        }
    }
}
