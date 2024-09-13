use super::{sumcheck::SumcheckOutput, types::ProverMemory};
use crate::{
    field_convert::ConvertField,
    prover::HonkProofResult,
    transcript::{Keccak256Transcript, TranscriptFieldType},
    types::ProvingKey,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use std::marker::PhantomData;

pub struct Decider<P: Pairing>
where
    <P::G1Affine as AffineRepr>::BaseField: ConvertField<TranscriptFieldType>,
    P::ScalarField: ConvertField<TranscriptFieldType>,
{
    pub(super) memory: ProverMemory<P>,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Decider<P>
where
    <P::G1Affine as AffineRepr>::BaseField: ConvertField<TranscriptFieldType>,
    P::ScalarField: ConvertField<TranscriptFieldType>,
{
    pub fn new(memory: ProverMemory<P>) -> Self {
        Self {
            memory,
            phantom_data: PhantomData,
        }
    }

    /**
     * @brief Run Sumcheck to establish that ∑_i pow(\vec{β*})f_i(ω) = e*. This results in u = (u_1,...,u_d) sumcheck round
     * challenges and all evaluations at u being calculated.
     *
     */
    fn execute_relation_check_rounds(
        &self,
        transcript: &mut Keccak256Transcript,
        proving_key: &ProvingKey<P>,
    ) -> SumcheckOutput<P::ScalarField> {
        // This is just Sumcheck.prove
        self.sumcheck_prove(transcript, proving_key)
    }

    /**
     * @brief Execute the ZeroMorph protocol to produce an opening claim for the multilinear evaluations produced by
     * Sumcheck and then produce an opening proof with a univariate PCS.
     * @details See https://hackmd.io/dlf9xEwhTQyE3hiGbq4FsA?view for a complete description of the unrolled protocol.
     *
     * */
    fn execute_pcs_rounds(
        &mut self,
        transcript: &mut Keccak256Transcript,
        proving_key: &ProvingKey<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
    ) -> HonkProofResult<()> {
        let prover_opening_claim =
            self.zeromorph_prove(transcript, proving_key, sumcheck_output)?;
        todo!("construct the proof");
    }

    pub fn prove(
        mut self,
        proving_key: &ProvingKey<P>,
        mut transcript: Keccak256Transcript,
    ) -> HonkProofResult<()> {
        tracing::trace!("Decider prove");

        // Run sumcheck subprotocol.
        let sumcheck_output = self.execute_relation_check_rounds(&mut transcript, proving_key);

        // Fiat-Shamir: rho, y, x, z
        // Execute Zeromorph multilinear PCS
        self.execute_pcs_rounds(&mut transcript, proving_key, sumcheck_output)?;

        todo!("output the proof");
    }
}
