use super::{sumcheck::SumcheckOutput, types::ProverMemory, zeromorph::ZeroMorphOpeningClaim};
use crate::{
    honk_curve::HonkCurve,
    prover::HonkProofResult,
    transcript::{TranscriptFieldType, TranscriptType},
    types::ProvingKey,
};
use std::marker::PhantomData;

pub struct Decider<P: HonkCurve<TranscriptFieldType>> {
    pub(super) memory: ProverMemory<P>,
    phantom_data: PhantomData<P>,
}

impl<P: HonkCurve<TranscriptFieldType>> Decider<P> {
    pub fn new(memory: ProverMemory<P>) -> Self {
        Self {
            memory,
            phantom_data: PhantomData,
        }
    }

    fn compute_opening_proof(
        opening_claim: ZeroMorphOpeningClaim<P::ScalarField>,
        transcript: &mut TranscriptType,
        proving_key: &ProvingKey<P>,
    ) -> HonkProofResult<()> {
        let mut quotient = opening_claim.polynomial;
        let pair = opening_claim.opening_pair;
        quotient[0] -= pair.evaluation;
        // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
        quotient.factor_roots(&pair.challenge);
        let quotient_commitment = crate::commit(&quotient.coefficients, &proving_key.crs)?;
        // TODO(#479): for now we compute the KZG commitment directly to unify the KZG and IPA interfaces but in the
        // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
        // pthreads) or even the work queue itself
        transcript.send_point_to_verifier::<P>("KZG:W".to_string(), quotient_commitment.into());
        Ok(())
    }

    /**
     * @brief Run Sumcheck to establish that ∑_i pow(\vec{β*})f_i(ω) = e*. This results in u = (u_1,...,u_d) sumcheck round
     * challenges and all evaluations at u being calculated.
     *
     */
    fn execute_relation_check_rounds(
        &self,
        transcript: &mut TranscriptType,
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
        transcript: &mut TranscriptType,
        proving_key: &ProvingKey<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
    ) -> HonkProofResult<()> {
        let prover_opening_claim =
            self.zeromorph_prove(transcript, proving_key, sumcheck_output)?;
        Self::compute_opening_proof(prover_opening_claim, transcript, proving_key)
    }

    pub fn prove(
        mut self,
        proving_key: &ProvingKey<P>,
        mut transcript: TranscriptType,
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
