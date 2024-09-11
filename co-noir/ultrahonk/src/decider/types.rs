use super::univariate::Univariate;
use crate::{types::AllEntities, NUM_ALPHAS};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub struct ProverMemory<P: Pairing> {
    pub w_4: Vec<P::ScalarField>,             // column 3
    pub z_perm: Vec<P::ScalarField>,          // column 4
    pub lookup_inverses: Vec<P::ScalarField>, // column 5
    pub z_perm_shift: Vec<P::ScalarField>, // TODO this is never calculated? also the permutation relation might always be skipped right now?
    pub witness_commitments: WitnessCommitments<P>,
    pub relation_parameters: RelationParameters<P::ScalarField>,
}

pub const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
#[derive(Default)]
pub struct ProverUnivariates<F: PrimeField> {
    pub w_4: Univariate<F, MAX_PARTIAL_RELATION_LENGTH>, // column 3
    pub z_perm: Univariate<F, MAX_PARTIAL_RELATION_LENGTH>, // column 4
    pub lookup_inverses: Univariate<F, MAX_PARTIAL_RELATION_LENGTH>, // column 5
    pub z_perm_shift: Univariate<F, MAX_PARTIAL_RELATION_LENGTH>, // TODO this is never calculated? also the permutation relation might always be skipped right now?
    pub polys: AllEntities<Univariate<F, MAX_PARTIAL_RELATION_LENGTH>>,
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

pub struct RelationParameters<F: PrimeField> {
    pub eta_1: F,
    pub eta_2: F,
    pub eta_3: F,
    pub beta: F,
    pub gamma: F,
    pub public_input_delta: F,
    pub alphas: [F; NUM_ALPHAS],
    pub gate_challenges: Vec<F>,
}

pub struct GateSeparatorPolynomial<F: PrimeField> {
    betas: Vec<F>,
    pub(crate) beta_products: Vec<F>,
    //dont know if only verifier needs the following, then maybe separate struct for this
    pub(crate) partial_evaluation_result: F,
    current_element_idx: usize,
    pub(crate) periodicity: usize,
}

impl<F: PrimeField> GateSeparatorPolynomial<F> {
    pub fn new(betas: Vec<F>) -> Self {
        let pow_size = 1 << betas.len();
        let current_element_idx = 0;
        let periodicity = 2;
        let partial_evaluation_result = F::ONE;

        let mut beta_products = Vec::with_capacity(pow_size);

        // Barretenberg uses multithreading here
        for i in 0..pow_size {
            let mut res = F::one();
            let mut j = i;
            let mut beta_idx = 0;
            while j > 0 {
                if j & 1 == 1 {
                    res *= betas[beta_idx];
                }
                j >>= 1;
                beta_idx += 1;
            }
            beta_products.push(res);
        }

        Self {
            betas,
            beta_products,
            partial_evaluation_result,
            current_element_idx,
            periodicity,
        }
    }

    pub fn partially_evaluate(&mut self, round_challenge: F) {
        let current_univariate_eval =
            F::ONE + (round_challenge * (self.betas[self.current_element_idx] - F::ONE));
        self.partial_evaluation_result *= current_univariate_eval;
        self.current_element_idx + 1;
        self.periodicity *= 2;
    }
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

impl<F: PrimeField> Default for RelationParameters<F> {
    fn default() -> Self {
        Self {
            eta_1: Default::default(),
            eta_2: Default::default(),
            eta_3: Default::default(),
            beta: Default::default(),
            gamma: Default::default(),
            public_input_delta: Default::default(),
            alphas: [Default::default(); NUM_ALPHAS],
            gate_challenges: Default::default(),
        }
    }
}

impl<P: Pairing> Default for ProverMemory<P> {
    fn default() -> Self {
        Self {
            w_4: Default::default(),
            z_perm: Default::default(),
            lookup_inverses: Default::default(),
            z_perm_shift: Default::default(),
            witness_commitments: Default::default(),
            relation_parameters: Default::default(),
        }
    }
}

impl<P: Pairing> From<crate::oink::types::ProverMemory<P>> for ProverMemory<P> {
    fn from(prover_memory: crate::oink::types::ProverMemory<P>) -> Self {
        let relation_parameters = RelationParameters {
            eta_1: prover_memory.challenges.eta_1,
            eta_2: prover_memory.challenges.eta_2,
            eta_3: prover_memory.challenges.eta_3,
            beta: prover_memory.challenges.beta,
            gamma: prover_memory.challenges.gamma,
            public_input_delta: prover_memory.public_input_delta,
            alphas: prover_memory.challenges.alphas,
            gate_challenges: Default::default(),
        };

        Self {
            w_4: prover_memory.w_4,
            z_perm: prover_memory.z_perm,
            lookup_inverses: prover_memory.lookup_inverses,
            z_perm_shift: Default::default(), // TODO where does it come from?
            witness_commitments: WitnessCommitments::from(prover_memory.witness_commitments),
            relation_parameters,
        }
    }
}

impl<P: Pairing> From<crate::oink::types::WitnessCommitments<P>> for WitnessCommitments<P> {
    fn from(witness_commitments: crate::oink::types::WitnessCommitments<P>) -> Self {
        Self {
            w_l: witness_commitments.w_l,
            w_r: witness_commitments.w_r,
            w_o: witness_commitments.w_o,
            w_4: witness_commitments.w_4,
            z_perm: witness_commitments.z_perm,
            lookup_inverses: witness_commitments.lookup_inverses,
            lookup_read_counts: witness_commitments.lookup_read_counts,
            lookup_read_tags: witness_commitments.lookup_read_tags,
        }
    }
}
