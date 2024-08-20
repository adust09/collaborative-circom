use crate::transcript::{self, Keccak256Transcript, Transcript};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{BigInt, Field};
use std::marker::PhantomData;
trait Flavor {}

struct OinkOutput<F: Flavor, P: Pairing> {
    relation_parameters: PhantomData<F>,
    commitments: PhantomData<P>,
    public_inputs: Vec<P::ScalarField>,
    alphas: PhantomData<P>,
}

struct OinkVerifier<F: Flavor, P: Pairing> {
    transcript: Keccak256Transcript<P>,
    key: PhantomData<F>,
    relation_parameters: PhantomData<P>,
    witness_comms: PhantomData<P>,
    public_inputs: Vec<P::ScalarField>,
}

/*
      @brief Reads the next element of type `T` from the transcript, with a predefined label, only used by verifier.

     @param label Human readable name for the challenge.
     @return deserialized element of type T

 template <class T> T receive_from_prover(const std::string& label)
    {
        const size_t element_size = TranscriptParams::template calc_num_bn254_frs<T>();
        ASSERT(num_frs_read + element_size <= proof_data.size());

        auto element_frs = std::span{ proof_data }.subspan(num_frs_read, element_size);
        num_frs_read += element_size;

        BaseTranscript::consume_prover_element_frs(label, element_frs);

        auto element = TranscriptParams::template convert_from_bn254_frs<T>(element_frs);

#ifdef LOG_INTERACTIONS
        if constexpr (Loggable<T>) {
            info("received: ", label, ": ", element);
        }
#endif
        return element;
    } */

//what is domain_separator

fn receive_from_prover() {
    todo!()
    // should probably be implemented in transcript.rs I guess (since proving also needs send_to_prover())
}

impl<F: Flavor, P: Pairing> OinkVerifier<F, P> {
    fn verify(&mut self) -> OinkOutput<F, P> {
        self.execute_preamble_round();
        self.execute_wire_commitments_round();
        self.execute_sorted_list_accumulator_round();
        self.execute_log_derivative_inverse_round();
        self.execute_grand_product_computation_round();
        let alphas = self.generate_alphas_round();

        OinkOutput {
            relation_parameters: self.relation_parameters.clone(),
            commitments: std::mem::take(&mut self.witness_comms),
            public_inputs: self.public_inputs.clone(),
            alphas,
        }
    }

    fn execute_preamble_round(&mut self) {
        let circuit_size: u32 = self
            .transcript
            .receive_from_prover(format!("{}circuit_size", domain_separator));
        let public_input_size: u32 = self
            .transcript
            .receive_from_prover(format!("{}public_input_size", domain_separator));
        let pub_inputs_offset: u32 = self
            .transcript
            .receive_from_prover(format!("{}pub_inputs_offset", domain_separator));

        assert_eq!(circuit_size, self.key.circuit_size);
        assert_eq!(public_input_size, self.key.num_public_inputs);
        assert_eq!(pub_inputs_offset, self.key.pub_inputs_offset);

        self.public_inputs.clear();
        for i in 0..public_input_size {
            let public_input_i: P::ScalarField = self
                .transcript
                .receive_from_prover(format!("{}public_input_{}", domain_separator, i));
            self.public_inputs.push(public_input_i);
        }
    }

    fn execute_wire_commitments_round(&mut self) {
        self.witness_comms.w_l = self
            .transcript
            .receive_from_prover(format!("{}{}", domain_separator, comm_labels.w_l));
        self.witness_comms.w_r = self
            .transcript
            .receive_from_prover(format!("{}{}", domain_separator, comm_labels.w_r));
        self.witness_comms.w_o = self
            .transcript
            .receive_from_prover(format!("{}{}", domain_separator, comm_labels.w_o));
    }

    fn execute_sorted_list_accumulator_round(&mut self) {
        let (eta, eta_two, eta_three) = self.transcript.get_challenges(
            format!("{}eta", domain_separator),
            format!("{}eta_two", domain_separator),
            format!("{}eta_three", domain_separator),
        );
        self.relation_parameters.eta = eta;
        self.relation_parameters.eta_two = eta_two;
        self.relation_parameters.eta_three = eta_three;

        self.witness_comms.lookup_read_counts = self.transcript.receive_from_prover(format!(
            "{}{}",
            domain_separator, comm_labels.lookup_read_counts
        ));
        self.witness_comms.lookup_read_tags = self.transcript.receive_from_prover(format!(
            "{}{}",
            domain_separator, comm_labels.lookup_read_tags
        ));
        self.witness_comms.w_4 = self
            .transcript
            .receive_from_prover(format!("{}{}", domain_separator, comm_labels.w_4));
    }

    fn execute_log_derivative_inverse_round(&mut self) {
        let (beta, gamma) = self.transcript.get_challenges(
            format!("{}beta", domain_separator),
            format!("{}gamma", domain_separator),
        );
        self.relation_parameters.beta = beta;
        self.relation_parameters.gamma = gamma;

        // receive from prover is wrt commitment to these things the method is called upon
        self.witness_comms.lookup_inverses = self.transcript.receive_from_prover(format!(
            "{}{}",
            domain_separator, comm_labels.lookup_inverses
        ));
    }

    fn execute_grand_product_computation_round(&mut self) {
        let public_input_delta = compute_public_input_delta::<Flavor>(
            &self.public_inputs,
            self.relation_parameters.beta,
            self.relation_parameters.gamma,
            self.key.circuit_size,
            self.key.pub_inputs_offset as usize,
        );

        self.relation_parameters.public_input_delta = public_input_delta;

        self.witness_comms.z_perm = self
            .transcript
            .receive_from_prover(format!("{}{}", domain_separator, comm_labels.z_perm));
    }

    fn generate_alphas_round(&self) -> RelationSeparator {
        let mut alphas = RelationSeparator::default();
        for idx in 0..alphas.len() {
            alphas[idx] = self
                .transcript
                .get_challenge(format!("{}alpha_{}", domain_separator, idx));
        }
        alphas
    }
}

fn compute_public_input_delta<P: Pairing>(
    public_inputs: Vec<P::ScalarField>,
    beta: P::ScalarField,
    gamma: P::ScalarField,
    domain_size: usize,
    offset: usize,
) -> P::ScalarField {
    let mut numerator = P::ScalarField::ONE;
    let mut denominator = P::ScalarField::ONE;
    let mut numerator_acc =
        gamma + (beta * P::ScalarField::from(domain_size as u64 + offset as u64));
    let mut denominator_acc = gamma - beta * P::ScalarField::from(1 + offset as u64);
    for input in public_inputs {
        numerator *= numerator_acc + input;
        denominator *= denominator_acc + input;
        numerator_acc += beta;
        denominator_acc -= beta;
    }
    numerator / denominator
}
