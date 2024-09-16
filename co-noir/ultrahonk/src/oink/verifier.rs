use crate::transcript::Poseidon2Transcript;
use crate::types::VerifyingKey;
use crate::types::WitnessCommitments;
use crate::{prover, NUM_ALPHAS};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use prover::HonkProofError;
use std::marker::PhantomData;

pub(crate) struct OinkOutput<P: Pairing + std::default::Default> {
    relation_parameters: RelationParameters<P>,
    commitments: WitnessCommitments<P>,
    public_inputs: Vec<P::ScalarField>,
    alphas: [P::ScalarField; NUM_ALPHAS],
    // transcript: Poseidon2Transcript<P>, todo: I think that should also be output?
}

// todo: where does the Verifier get the witness_comms from?
pub(crate) struct OinkVerifier<P: Pairing + std::default::Default> {
    transcript: Poseidon2Transcript<P::ScalarField>,
    key: VerifyingKey<P>,
    relation_parameters: RelationParameters<P>,
    witness_comms: WitnessCommitments<P>,
}

// todo: remove(?) this struct from OinkVerifier, these values get computed during verification
#[derive(Clone)]
pub(crate) struct RelationParameters<P: Pairing> {
    eta: P::ScalarField,
    eta_two: P::ScalarField,
    eta_three: P::ScalarField,
    beta: P::ScalarField,
    gamma: P::ScalarField,
    public_input_delta: P::ScalarField,
}

impl<P: Pairing + std::default::Default> OinkVerifier<P> {
    pub fn new(
        transcript: Poseidon2Transcript<P::ScalarField>,
        key: VerifyingKey<P>,
        relation_parameters: RelationParameters<P>,
        witness_comms: WitnessCommitments<P>,
    ) -> Self {
        Self {
            transcript,
            key,
            relation_parameters,
            witness_comms,
        }
    }
    //todo: maybe we also have to return the transcript (I think ultaverifier needs it?)
    pub(crate) fn verify(&mut self, public_inputs: Vec<P::ScalarField>) -> OinkOutput<P> {
        self.execute_preamble_round(&public_inputs);
        self.execute_wire_commitments_round();
        self.execute_sorted_list_accumulator_round();
        self.execute_log_derivative_inverse_round();
        self.execute_grand_product_computation_round(&public_inputs);
        let alphas = self.generate_alphas_round();

        OinkOutput {
            relation_parameters: self.relation_parameters.clone(),
            commitments: self.witness_comms.clone(),
            public_inputs,
            alphas,
            // transcript: self.transcript ???
        }
    }

    fn execute_preamble_round(&mut self, public_inputs: &[P::ScalarField]) {
        tracing::trace!("executing (verifying) preamble round");

        let circuit_size = self
            .transcript
            .receive_from_prover("circuit_size".to_string());
        let public_input_size = self
            .transcript
            .receive_from_prover("public_input_size".to_string());
        let pub_inputs_offset = self
            .transcript
            .receive_from_prover("pub_inputs_offset".to_string());

        // To do / To think: do we want to assert here with key vs transcript?
        assert_eq!(circuit_size, self.key.circuit_size); //"OinkVerifier::execute_preamble_round: proof circuit size does not match verification key!"
        assert_eq!(public_input_size, self.key.num_public_inputs); //"OinkVerifier::execute_preamble_round: public inputs size does not match verification key!"
        assert_eq!(pub_inputs_offset, self.key.pub_inputs_offset); //"OinkVerifier::execute_preamble_round: public inputs offset does not match verification key!"

        if self.key.num_public_inputs as usize != public_inputs.len() {
            todo!() //return error
        }
        for (i, public_input) in public_inputs.iter().enumerate() {
            public_inputs[i] = self
                .transcript
                .receive_from_prover(format!("public_input_{}", i));
        }
    }

    fn execute_wire_commitments_round(&mut self) {
        tracing::trace!("executing (verifying) wire commitments round");

        self.witness_comms.w_l = self.transcript.receive_from_prover("W_L".to_string());
        self.witness_comms.w_r = self.transcript.receive_from_prover("W_R".to_string());
        self.witness_comms.w_o = self.transcript.receive_from_prover("W_O".to_string());
    }

    fn execute_sorted_list_accumulator_round(&mut self) {
        tracing::trace!("executing (verifying) sorted list accumulator round");

        let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
        std::mem::swap(&mut transcript, &mut self.transcript);

        self.relation_parameters.eta = transcript.get_challenge();

        let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
        transcript.add_scalar(self.relation_parameters.eta);
        self.relation_parameters.eta_two = transcript.get_challenge();

        let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
        transcript.add_scalar(self.relation_parameters.eta_two);
        self.relation_parameters.eta_three = transcript.get_challenge();

        &mut self
            .transcript
            .add_scalar(self.relation_parameters.eta_three);

        self.witness_comms.lookup_read_counts = self
            .transcript
            .receive_from_prover("lookup_read_counts".to_string());
        self.witness_comms.lookup_read_tags = self
            .transcript
            .receive_from_prover("lookup_read_tags".to_string());
        self.witness_comms.w_4 = self.transcript.receive_from_prover("w_4".to_string());
    }

    fn execute_log_derivative_inverse_round(&mut self) {
        tracing::trace!("executing (verifying) log derivative inverse round");

        let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
        std::mem::swap(&mut transcript, &mut self.transcript);

        self.relation_parameters.beta = transcript.get_challenge();

        let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
        transcript.add_scalar(self.relation_parameters.beta);
        self.relation_parameters.gamma = transcript.get_challenge();

        &mut self.transcript.add_scalar(self.relation_parameters.gamma);
        self.witness_comms.lookup_inverses = self
            .transcript
            .receive_from_prover("lookup_inverses".to_string());
    }

    fn execute_grand_product_computation_round(&mut self, public_inputs: &[P::ScalarField]) {
        tracing::trace!("executing (verifying) grand product computation round");
        self.relation_parameters.public_input_delta = compute_public_input_delta::<P>(
            public_inputs,
            self.relation_parameters.beta,
            self.relation_parameters.gamma,
            self.key.circuit_size,
            self.key.pub_inputs_offset as usize,
        );
        self.witness_comms.z_perm = self.transcript.receive_from_prover("z_perm".to_string());

        // self.transcript.add_point(self.witness_comms.z_perm.into());
    }

    fn generate_alphas_round(&mut self) -> [P::ScalarField; NUM_ALPHAS] {
        tracing::trace!("generating (verifying) alphas round");
        let mut alphas: [P::ScalarField; NUM_ALPHAS] = [P::ScalarField::default(); NUM_ALPHAS];
        let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
        std::mem::swap(&mut transcript, &mut self.transcript);
        alphas[0] = transcript.get_challenge();
        for idx in 1..NUM_ALPHAS {
            let mut transcript = Poseidon2Transcript::<P::ScalarField>::default();
            transcript.add_scalar(alphas[idx - 1]);
            alphas[idx] = transcript.get_challenge();
        }
        alphas
    }
}

fn compute_public_input_delta<P: Pairing>(
    public_inputs: &[P::ScalarField],
    beta: P::ScalarField,
    gamma: P::ScalarField,
    domain_size: u32,
    offset: usize,
) -> P::ScalarField {
    tracing::trace!("computing public input delta");
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
