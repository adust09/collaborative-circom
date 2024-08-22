struct SumcheckRound {
    round_size: usize,
}

impl SumcheckRound {
    fn new(initial_round_size: usize) -> Self {
        SumcheckRound {
            round_size: initial_round_size,
        }
    }

    fn compute_univariate(&self, round_index: usize) {
        tracing::trace!("Sumcheck round {}", round_index);

        // Barretenberg uses multithreading here
        todo!()
    }
}
