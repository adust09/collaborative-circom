use ark_ec::pairing::Pairing;

pub(crate) struct SumcheckRound {
    pub(crate) round_size: usize,
}

impl SumcheckRound {
    pub(crate) fn new(initial_round_size: usize) -> Self {
        SumcheckRound {
            round_size: initial_round_size,
        }
    }

    pub(crate) fn compute_univariate<P: Pairing>(
        &self,
        round_index: usize,
        pow_polynomial: super::types::PowPolynomial<P::ScalarField>,
        alphas: [P::ScalarField; crate::NUM_ALPHAS],
        relation_parameters: crate::oink::verifier::RelationParameters<P>,
        polynomials: Vec<P::ScalarField>,
    ) {
        tracing::trace!("Sumcheck round {}", round_index);

        // Barretenberg uses multithreading here
        todo!()
    }

    pub(crate) fn partially_evaluate_poly<P: Pairing>(
        &self,
        polynomials: Vec<P::ScalarField>,
        round_challenge: P::ScalarField,
    ) {
        // Barretenberg uses multithreading here
        todo!()
    }
}
