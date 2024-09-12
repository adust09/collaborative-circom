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
    pub shifted_witness: ShiftedWitnessEntities<T>,
    pub shifted_tables: ShiftedTableEntities<T>,
}

impl<T: Default> AllEntities<T> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.witness
            .iter()
            .chain(self.precomputed.iter())
            .chain(self.shifted_witness.iter())
            .chain(self.shifted_tables.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.witness
            .iter_mut()
            .chain(self.precomputed.iter_mut())
            .chain(self.shifted_witness.iter_mut())
            .chain(self.shifted_tables.iter_mut())
    }
}

pub struct VerifyingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P::ScalarField>,
    pub gate_challenges: Vec<P::ScalarField>,
}
