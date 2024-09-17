use crate::decider::types::RelationParameters;
use crate::honk_curve::HonkCurve;
use crate::transcript::TranscriptFieldType;
use crate::transcript::TranscriptType;
use crate::types::VerifyingKey;
use crate::types::WitnessCommitments;
use crate::NUM_ALPHAS;
use ark_ec::pairing::Pairing;
use ark_ff::Field;

pub(crate) struct OinkOutput<P: HonkCurve<TranscriptFieldType>> {
    relation_parameters: RelationParameters<P::ScalarField>,
    commitments: WitnessCommitments<P>,
    public_inputs: Vec<P::ScalarField>,
    pub(crate) alphas: [P::ScalarField; NUM_ALPHAS],
    // transcript: Poseidon2Transcript<P>, todo: I think that should also be output?
}

// todo: where does the Verifier get the witness_comms from?
pub(crate) struct OinkVerifier<P: HonkCurve<TranscriptFieldType>> {
    transcript: TranscriptType,
    key: VerifyingKey<P>,
    relation_parameters: RelationParameters<P::ScalarField>,
    witness_comms: WitnessCommitments<P>,
}

impl<P: HonkCurve<TranscriptFieldType>> Default for OinkVerifier<P> {
    fn default() -> Self {
        Self::new()
    }
}
impl<P: HonkCurve<TranscriptFieldType>> Default for OinkOutput<P> {
    fn default() -> Self {
        Self::new()
    }
}
impl<P: HonkCurve<TranscriptFieldType>> OinkOutput<P> {
    pub fn new() -> Self {
        Self {
            relation_parameters: todo!(),
            commitments: todo!(),
            public_inputs: todo!(),
            alphas: todo!(),
        }
    }
}
impl<P: HonkCurve<TranscriptFieldType>> OinkVerifier<P> {
    pub fn new() -> Self {
        Self {
            transcript: todo!(),
            key: todo!(),
            relation_parameters: todo!(),
            witness_comms: todo!(),
        }
    }
    //todo: maybe we also have to return the transcript (I think ultaverifier needs it?)
    pub(crate) fn verify(&mut self, public_inputs: Vec<P::ScalarField>) -> OinkOutput<P> {
        self.execute_preamble_round();
        self.execute_wire_commitments_round();
        self.execute_sorted_list_accumulator_round();
        self.execute_log_derivative_inverse_round();
        self.execute_grand_product_computation_round(&public_inputs);
        let alphas = self.generate_alphas_round();

        OinkOutput {
            relation_parameters: self.relation_parameters.to_owned(),
            commitments: self.witness_comms.to_owned(),
            public_inputs,
            alphas,
            // transcript: self.transcript ???
        }
    }

    fn execute_preamble_round(&mut self) {
        tracing::trace!("executing (verifying) preamble round");

        let circuit_size = self
            .transcript
            .receive_u64_from_prover("circuit_size".to_string())
            .expect("TODO");
        let public_input_size = self
            .transcript
            .receive_u64_from_prover("public_input_size".to_string())
            .expect("TODO");
        let pub_inputs_offset = self
            .transcript
            .receive_u64_from_prover("pub_inputs_offset".to_string())
            .expect("TODO");

        // To do / To think: do we want to assert here with key vs transcript?
        assert_eq!(circuit_size, self.key.circuit_size.into()); //"OinkVerifier::execute_preamble_round: proof circuit size does not match verification key!"
        assert_eq!(public_input_size, self.key.num_public_inputs.into()); //"OinkVerifier::execute_preamble_round: public inputs size does not match verification key!"
        assert_eq!(pub_inputs_offset, self.key.pub_inputs_offset.into()); //"OinkVerifier::execute_preamble_round: public inputs offset does not match verification key!"
        let mut public_inputs: Vec<P::ScalarField> = Vec::with_capacity(public_input_size as usize);
        for i in 0..public_input_size {
            let public_input = self
                .transcript
                .receive_fr_from_prover::<P>(format!("public_input_{}", i))
                .expect(&format!("Failed to receive public input at index {}", i));
            public_inputs.push(public_input);
        }
    }

    fn execute_wire_commitments_round(&mut self) {
        tracing::trace!("executing (verifying) wire commitments round");

        self.witness_comms.w_l = self
            .transcript
            .receive_point_from_prover::<P>("W_L".to_string())
            .expect("Failed to receive W_L")
            .into();
        self.witness_comms.w_r = self
            .transcript
            .receive_point_from_prover::<P>("W_R".to_string())
            .expect("Failed to receive W_R")
            .into();
        self.witness_comms.w_o = self
            .transcript
            .receive_point_from_prover::<P>("W_O".to_string())
            .expect("Failed to receive W_O")
            .into();
    }

    fn execute_sorted_list_accumulator_round(&mut self) {
        tracing::trace!("executing (verifying) sorted list accumulator round");

        self.relation_parameters.eta_1 = self.transcript.get_challenge::<P>("eta".to_string());

        self.relation_parameters.eta_2 = self.transcript.get_challenge::<P>("eta_two".to_string());

        self.relation_parameters.eta_3 =
            self.transcript.get_challenge::<P>("eta_three".to_string());

        self.witness_comms.lookup_read_counts = self
            .transcript
            .receive_point_from_prover::<P>("lookup_read_counts".to_string())
            .expect("Failed to receive lookup_read_counts")
            .into();
        self.witness_comms.lookup_read_tags = self
            .transcript
            .receive_point_from_prover::<P>("lookup_read_tags".to_string())
            .expect("Failed to receive lookup_read_tags")
            .into();
        self.witness_comms.w_4 = self
            .transcript
            .receive_point_from_prover::<P>("w_4".to_string())
            .expect("Failed to receive w_4")
            .into();
    }

    fn execute_log_derivative_inverse_round(&mut self) {
        tracing::trace!("executing (verifying) log derivative inverse round");

        self.relation_parameters.beta = self.transcript.get_challenge::<P>("beta".to_string());

        self.relation_parameters.gamma = self.transcript.get_challenge::<P>("gamma".to_string());

        self.witness_comms.lookup_inverses = self
            .transcript
            .receive_point_from_prover::<P>("lookup_inverses".to_string())
            .expect("Failed to receive lookup_inverses")
            .into();
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
        self.witness_comms.z_perm = self
            .transcript
            .receive_point_from_prover::<P>("z_perm".to_string())
            .expect("Failed to receive z_perm")
            .into();

        // self.transcript.add_point(self.witness_comms.z_perm.into());
    }

    fn generate_alphas_round(&mut self) -> [P::ScalarField; NUM_ALPHAS] {
        tracing::trace!("generating (verifying) alphas round");
        let mut alphas = [P::ScalarField::default(); NUM_ALPHAS];

        alphas[0] = self.transcript.get_challenge::<P>(format!("alpha_{}", 0));
        for idx in 1..NUM_ALPHAS {
            alphas[idx] = self.transcript.get_challenge::<P>(format!("alpha_{}", idx));
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
