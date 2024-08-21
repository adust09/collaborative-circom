use crate::oink::prover::HonkProofError;
use crate::transcript::{self, Keccak256Transcript, Transcript};
use crate::types::VerifyingKey;
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{BigInt, Field};
use std::marker::PhantomData;

struct OinkOutput<P: Pairing> {
    relation_parameters: RelationParameters<P>,
    commitments: WitnessComms<P>,
    public_inputs: Vec<P::ScalarField>, //?
    alphas: PhantomData<P>,
}

struct OinkVerifier<P: Pairing> {
    transcript: Keccak256Transcript<P>,
    key: VerifyingKey<P>,
    relation_parameters: RelationParameters<P>,
    witness_comms: WitnessComms<P>,
    public_inputs: Vec<P::ScalarField>, //?
}

//types to be checked
struct WitnessComms<P: Pairing> {
    w_l: P::G1,
    w_r: P::G1,
    w_o: P::G1,
    w_4: P::G1,
    lookup_read_counts: P::G1,
    lookup_read_tags: P::G1,
    lookup_inverses: P::G1,
    z_perm: P::G1,
}

//types to be checked
struct RelationParameters<P: Pairing> {
    eta: P::ScalarField,
    eta_two: P::ScalarField,
    eta_three: P::ScalarField,
    beta: P::ScalarField,
    gamma: P::ScalarField,
    public_input_delta: P::ScalarField,
}

impl<P: Pairing> OinkVerifier<P> {
    fn verify(&mut self, public_inputs: Vec<P::ScalarField>) -> OinkOutput<P> {
        self.execute_preamble_round(&public_inputs);
        self.execute_wire_commitments_round();
        self.execute_sorted_list_accumulator_round();
        self.execute_log_derivative_inverse_round();
        self.execute_grand_product_computation_round();
        let alphas = self.generate_alphas_round();

        OinkOutput {
            relation_parameters: self.relation_parameters,
            commitments: self.witness_comms,
            public_inputs: self.public_inputs,
            alphas,
        }
    }

    fn execute_preamble_round(&mut self, public_inputs: &[P::ScalarField]) {
        tracing::trace!("executing (verifying) preamble round");

        self.transcript.add(self.key.circuit_size.to_le_bytes());
        self.transcript
            .add(self.key.num_public_inputs.to_le_bytes());
        self.transcript
            .add(self.key.pub_inputs_offset.to_le_bytes());

        //To do / To think: do we want to assert here with key vs transcript?
        // assert_eq!(circuit_size, self.key.circuit_size);
        // assert_eq!(public_input_size, self.key.num_public_inputs);
        // assert_eq!(pub_inputs_offset, self.key.pub_inputs_offset);

        if self.key.num_public_inputs as usize != public_inputs.len() {
            todo!()
        }

        for public_input in public_inputs {
            self.transcript.add_scalar(*public_input);
        }
    }

    fn execute_wire_commitments_round(&mut self) {
        tracing::trace!("executing (verifying) wire commitments round");

        self.transcript.add_point(self.witness_comms.w_l.into());
        self.transcript.add_point(self.witness_comms.w_r.into());
        self.transcript.add_point(self.witness_comms.w_o.into());
    }

    fn execute_sorted_list_accumulator_round(&mut self) {
        tracing::trace!("executing (verifying) sorted list accumulator round");

        let mut transcript = Keccak256Transcript::<P>::default();
        std::mem::swap(&mut transcript, &mut self.transcript);

        self.relation_parameters.eta = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(self.relation_parameters.eta);
        self.relation_parameters.eta_two = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(self.relation_parameters.eta_two);
        self.relation_parameters.eta_three = transcript.get_challenge();

        &mut self
            .transcript
            .add_scalar(self.relation_parameters.eta_three);

        &mut self
            .transcript
            .add_point(self.witness_comms.lookup_read_counts.into());
        &mut self
            .transcript
            .add_point(self.witness_comms.lookup_read_tags.into());
        &mut self.transcript.add_point(self.witness_comms.w_4.into());
    }

    fn execute_log_derivative_inverse_round(&mut self) {
        tracing::trace!("executing (verifying) log derivative inverse round");

        let mut transcript = Keccak256Transcript::<P>::default();
        std::mem::swap(&mut transcript, &mut self.transcript);

        self.relation_parameters.beta = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(self.relation_parameters.beta);
        self.relation_parameters.gamma = transcript.get_challenge();

        &mut self.transcript.add_scalar(self.relation_parameters.gamma);

        &mut self
            .transcript
            .add_point(self.witness_comms.lookup_inverses.into());
    }

    fn execute_grand_product_computation_round(&mut self) {
        tracing::trace!("executing (verifying) grand product computation round");
        self.relation_parameters.public_input_delta = compute_public_input_delta::<P>(
            self.public_inputs.clone(),
            self.relation_parameters.beta,
            self.relation_parameters.gamma,
            self.key.circuit_size,
            self.key.pub_inputs_offset as usize,
        );

        self.transcript.add_point(self.witness_comms.z_perm.into());
    }

    fn generate_alphas_round(&self) -> PhantomData<P> {
        // tracing::trace!("generating (verifying) alphas round");
        // let mut alphas = RelationSeparator::default();
        // alphas.iter_mut().enumerate().for_each(|(idx, alpha)| {
        //     *alpha = self.transcript.get_dummy("alpha_idx");
        // });
        // alphas
        todo!();
    }
}

fn compute_public_input_delta<P: Pairing>(
    public_inputs: Vec<P::ScalarField>,
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
