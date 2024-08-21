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
}

pub struct Polynomials<P: Pairing> {
    pub w_l: Vec<P::ScalarField>,
    pub w_r: Vec<P::ScalarField>,
    pub w_o: Vec<P::ScalarField>,
}

pub struct VerifyingKey<P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P>,
}
