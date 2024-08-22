use crate::{
    transcript::Keccak256Transcript,
    types::{ProverCrs, ProverMemory, ProvingKey},
};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{Field, One, Zero};
use itertools::izip;
use std::{io, marker::PhantomData};

type HonkProofResult<T> = std::result::Result<T, HonkProofError>;

/// The errors that may arise during the computation of a co-PLONK proof.
#[derive(Debug, thiserror::Error)]
pub enum HonkProofError {
    /// Indicates that the witness is too small for the provided circuit.
    #[error("Cannot index into witness {0}")]
    CorruptedWitness(usize),
    /// Indicates that the crs is too small
    #[error("CRS too small")]
    CrsTooSmall,
    #[error(transparent)]
    IOError(#[from] io::Error),
}

pub struct Plonk<P: Pairing> {
    memory: ProverMemory<P>,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Plonk<P> {
    pub fn new() -> Self {
        Self {
            memory: ProverMemory::default(),
            phantom_data: PhantomData,
        }
    }

    fn commit(poly: &[P::ScalarField], crs: &ProverCrs<P>) -> HonkProofResult<P::G1> {
        if poly.len() > crs.monomials.len() {
            return Err(HonkProofError::CrsTooSmall);
        }
        Ok(P::G1::msm_unchecked(&crs.monomials, poly))
    }

    fn compute_w4(&mut self, proving_key: &ProvingKey<P>) {
        tracing::trace!("compute w4");
        // The memory record values are computed at the indicated indices as
        // w4 = w3 * eta^3 + w2 * eta^2 + w1 * eta + read_write_flag;

        debug_assert_eq!(
            proving_key.polynomials.witness.w_l.len(),
            proving_key.polynomials.witness.w_r.len()
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.w_l.len(),
            proving_key.polynomials.witness.w_o.len()
        );
        self.memory.w_4.resize(
            proving_key.polynomials.witness.w_l.len(),
            P::ScalarField::zero(),
        );

        // Compute read record values
        for gate_idx in proving_key.memory_read_records.iter() {
            let gate_idx = *gate_idx as usize;
            let target = &mut self.memory.w_4[gate_idx];
            *target += proving_key.polynomials.witness.w_l[gate_idx] * self.memory.challenges.eta_1
                + proving_key.polynomials.witness.w_r[gate_idx] * self.memory.challenges.eta_2
                + proving_key.polynomials.witness.w_o[gate_idx] * self.memory.challenges.eta_3;
        }

        // Compute write record values
        for gate_idx in proving_key.memory_write_records.iter() {
            let gate_idx = *gate_idx as usize;
            let target = &mut self.memory.w_4[gate_idx];
            *target += proving_key.polynomials.witness.w_l[gate_idx] * self.memory.challenges.eta_1
                + proving_key.polynomials.witness.w_r[gate_idx] * self.memory.challenges.eta_2
                + proving_key.polynomials.witness.w_o[gate_idx] * self.memory.challenges.eta_3
                + P::ScalarField::one();
        }
    }

    fn compute_read_term(&self, proving_key: &ProvingKey<P>, i: usize) -> P::ScalarField {
        tracing::trace!("compute read term");

        let gamma = &self.memory.challenges.gamma;
        let eta_1 = &self.memory.challenges.eta_1;
        let eta_2 = &self.memory.challenges.eta_2;
        let eta_3 = &self.memory.challenges.eta_3;
        let w_1 = &proving_key.polynomials.witness.w_l[i];
        let w_2 = &proving_key.polynomials.witness.w_r[i];
        let w_3 = &proving_key.polynomials.witness.w_o[i];
        let w_1_shift = &proving_key.polynomials.shifted.w_l[i];
        let w_2_shift = &proving_key.polynomials.shifted.w_r[i];
        let w_3_shift = &proving_key.polynomials.shifted.w_o[i];
        let table_index = &proving_key.polynomials.precomputed.q_o[i];
        let negative_column_1_step_size = &proving_key.polynomials.precomputed.q_r[i];
        let negative_column_2_step_size = &proving_key.polynomials.precomputed.q_m[i];
        let negative_column_3_step_size = &proving_key.polynomials.precomputed.q_c[i];

        // The wire values for lookup gates are accumulators structured in such a way that the differences w_i -
        // step_size*w_i_shift result in values present in column i of a corresponding table. See the documentation in
        // method get_lookup_accumulators() in  for a detailed explanation.
        let derived_table_entry_1 = *w_1 + gamma + *negative_column_1_step_size * w_1_shift;
        let derived_table_entry_2 = *w_2 + *negative_column_2_step_size * w_2_shift;
        let derived_table_entry_3 = *w_3 + *negative_column_3_step_size * w_3_shift;

        // (w_1 + \gamma q_2*w_1_shift) + η(w_2 + q_m*w_2_shift) + η₂(w_3 + q_c*w_3_shift) + η₃q_index.
        // deg 2 or 3
        derived_table_entry_1
            + derived_table_entry_2 * eta_1
            + derived_table_entry_3 * eta_2
            + *table_index * eta_3
    }

    // Compute table_1 + gamma + table_2 * eta + table_3 * eta_2 + table_4 * eta_3
    fn compute_write_term(&self, proving_key: &ProvingKey<P>, i: usize) -> P::ScalarField {
        tracing::trace!("compute write term");

        let gamma = &self.memory.challenges.gamma;
        let eta_1 = &self.memory.challenges.eta_1;
        let eta_2 = &self.memory.challenges.eta_2;
        let eta_3 = &self.memory.challenges.eta_3;
        let table_1 = &proving_key.polynomials.precomputed.table_1[i];
        let table_2 = &proving_key.polynomials.precomputed.table_2[i];
        let table_3 = &proving_key.polynomials.precomputed.table_3[i];
        let table_4 = &proving_key.polynomials.precomputed.table_4[i];

        *table_1 + gamma + *table_2 * eta_1 + *table_3 * eta_2 + *table_4 * eta_3
    }

    fn compute_logderivative_inverses(&mut self, proving_key: &ProvingKey<P>) {
        tracing::trace!("compute logderivative inverse");

        debug_assert_eq!(
            proving_key.polynomials.precomputed.q_lookup.len(),
            proving_key.circuit_size as usize
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.lookup_read_tags.len(),
            proving_key.circuit_size as usize
        );
        self.memory
            .lookup_inverses
            .resize(proving_key.circuit_size as usize, P::ScalarField::zero());

        const READ_TERMS: usize = 1;
        const WRITE_TERMS: usize = 1;
        // 1 + polynomial degree of this relation
        const LENGTH: usize = 5; // both subrelations are degree 4

        for (i, (q_lookup, lookup_read_tag)) in izip!(
            proving_key.polynomials.precomputed.q_lookup.iter(),
            proving_key.polynomials.witness.lookup_read_tags.iter(),
        )
        .enumerate()
        {
            if !(q_lookup.is_one() || lookup_read_tag.is_one()) {
                continue;
            }

            // READ_TERMS and WRITE_TERMS are 1, so we skip the loop
            let read_term = self.compute_read_term(proving_key, i);
            let write_term = self.compute_write_term(proving_key, i);
            self.memory.lookup_inverses[i] = read_term * write_term;
        }

        for inv in self.memory.lookup_inverses.iter_mut() {
            inv.inverse_in_place();
        }
    }

    fn compute_public_input_delta(
        &self,
        proving_key: &ProvingKey<P>,
        public_inputs: &[P::ScalarField],
    ) -> P::ScalarField {
        tracing::trace!("compute public input delta");

        // Let m be the number of public inputs x₀,…, xₘ₋₁.
        // Recall that we broke the permutation σ⁰ by changing the mapping
        //  (i) -> (n+i)   to   (i) -> (-(i+1))   i.e. σ⁰ᵢ = −(i+1)
        //
        // Therefore, the term in the numerator with ID¹ᵢ = n+i does not cancel out with any term in the denominator.
        // Similarly, the denominator contains an extra σ⁰ᵢ = −(i+1) term that does not appear in the numerator.
        // We expect the values of W⁰ᵢ and W¹ᵢ to be equal to xᵢ.
        // The expected accumulated product would therefore be equal to

        //   ∏ᵢ (γ + W¹ᵢ + β⋅ID¹ᵢ)        ∏ᵢ (γ + xᵢ + β⋅(n+i) )
        //  -----------------------  =  ------------------------
        //   ∏ᵢ (γ + W⁰ᵢ + β⋅σ⁰ᵢ )        ∏ᵢ (γ + xᵢ - β⋅(i+1) )

        // At the start of the loop for each xᵢ where i = 0, 1, …, m-1,
        // we have
        //      numerator_acc   = γ + β⋅(n+i) = γ + β⋅n + β⋅i
        //      denominator_acc = γ - β⋅(1+i) = γ - β   - β⋅i
        // at the end of the loop, add and subtract β to each term respectively to
        // set the expected value for the start of iteration i+1.
        // Note: The public inputs may be offset from the 0th index of the wires, for example due to the inclusion of an
        // initial zero row or Goblin-stlye ECC op gates. Accordingly, the indices i in the above formulas are given by i =
        // [0, m-1] + offset, i.e. i = offset, 1 + offset, …, m - 1 + offset.

        let mut num = P::ScalarField::one();
        let mut denom = P::ScalarField::one();
        let mut num_acc = self.memory.challenges.gamma
            + self.memory.challenges.beta
                * P::ScalarField::from(
                    (proving_key.circuit_size + proving_key.pub_inputs_offset) as u64,
                );
        let mut denom_acc = self.memory.challenges.gamma
            - self.memory.challenges.beta
                * P::ScalarField::from((1 + proving_key.pub_inputs_offset) as u64);

        for x_i in public_inputs.iter() {
            num *= (num_acc + x_i);
            denom *= (denom_acc + x_i);
            num_acc += self.memory.challenges.beta;
            denom_acc -= self.memory.challenges.beta;
        }
        num / denom
    }

    // Add circuit size public input size and public inputs to transcript
    fn execute_preamble_round(
        transcript: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
        public_inputs: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("executing preamble round");

        transcript.add(proving_key.circuit_size.to_le_bytes());
        transcript.add(proving_key.num_public_inputs.to_le_bytes());
        transcript.add(proving_key.pub_inputs_offset.to_le_bytes());

        if proving_key.num_public_inputs as usize != public_inputs.len() {
            return Err(HonkProofError::CorruptedWitness(public_inputs.len()));
        }

        for public_input in public_inputs {
            transcript.add_scalar(*public_input);
        }
        Ok(())
    }

    // Compute first three wire commitments
    fn execute_wire_commitments_round(
        &mut self,
        transcript: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing wire commitments round");

        // Commit to the first three wire polynomials of the instance
        // We only commit to the fourth wire polynomial after adding memory records

        self.memory.witness_commitments.w_l =
            Self::commit(&proving_key.polynomials.witness.w_l, &proving_key.crs)?;
        self.memory.witness_commitments.w_r =
            Self::commit(&proving_key.polynomials.witness.w_r, &proving_key.crs)?;
        self.memory.witness_commitments.w_o =
            Self::commit(&proving_key.polynomials.witness.w_o, &proving_key.crs)?;

        transcript.add_point(self.memory.witness_commitments.w_l.into());
        transcript.add_point(self.memory.witness_commitments.w_r.into());
        transcript.add_point(self.memory.witness_commitments.w_o.into());

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    // Compute sorted list accumulator and commitment
    fn execute_sorted_list_accumulator_round(
        &mut self,
        transcript_inout: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing sorted list accumulator round");

        // Get the challenges and refresh the transcript
        let mut transcript = Keccak256Transcript::<P>::default();
        std::mem::swap(&mut transcript, transcript_inout);

        self.memory.challenges.eta_1 = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(self.memory.challenges.eta_1);
        self.memory.challenges.eta_2 = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(self.memory.challenges.eta_2);
        self.memory.challenges.eta_3 = transcript.get_challenge();

        transcript_inout.add_scalar(self.memory.challenges.eta_3);

        self.compute_w4(proving_key);

        // Commit to lookup argument polynomials and the finalized (i.e. with memory records) fourth wire polynomial
        self.memory.witness_commitments.lookup_read_counts = Self::commit(
            &proving_key.polynomials.witness.lookup_read_counts,
            &proving_key.crs,
        )?;
        self.memory.witness_commitments.lookup_read_tags = Self::commit(
            &proving_key.polynomials.witness.lookup_read_tags,
            &proving_key.crs,
        )?;
        self.memory.witness_commitments.w_4 = Self::commit(&self.memory.w_4, &proving_key.crs)?;

        transcript_inout.add_point(self.memory.witness_commitments.lookup_read_counts.into());
        transcript_inout.add_point(self.memory.witness_commitments.lookup_read_tags.into());
        transcript_inout.add_point(self.memory.witness_commitments.w_4.into());

        Ok(())
    }

    // Fiat-Shamir: beta & gamma
    fn execute_log_derivative_inverse_round(
        &mut self,
        transcript_inout: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing log derivative inverse round");

        // Get the challenges and refresh the transcript
        let mut transcript = Keccak256Transcript::<P>::default();
        std::mem::swap(&mut transcript, transcript_inout);

        self.memory.challenges.beta = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(self.memory.challenges.beta);
        self.memory.challenges.gamma = transcript.get_challenge();

        transcript_inout.add_scalar(self.memory.challenges.gamma);

        self.compute_logderivative_inverses(proving_key);

        self.memory.witness_commitments.lookup_inverses =
            Self::commit(&self.memory.lookup_inverses, &proving_key.crs)?;

        transcript_inout.add_point(self.memory.witness_commitments.lookup_inverses.into());

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    // Compute grand product(s) and commitments.
    fn execute_grand_product_computation_round(
        &mut self,
        // transcript: &mut Keccak256Transcript<P>,
        proving_key: &ProvingKey<P>,
        public_inputs: &[P::ScalarField],
    ) {
        tracing::trace!("executing grand product computation round");

        self.memory.public_input_delta =
            self.compute_public_input_delta(proving_key, public_inputs);

        todo!()
    }

    pub fn prove(
        mut self,
        proving_key: ProvingKey<P>,
        public_inputs: Vec<P::ScalarField>,
    ) -> HonkProofResult<()> {
        tracing::trace!("prove");

        let mut transcript = Keccak256Transcript::default();

        // Add circuit size public input size and public inputs to transcript
        Self::execute_preamble_round(&mut transcript, &proving_key, &public_inputs)?;
        // Compute first three wire commitments
        self.execute_wire_commitments_round(&mut transcript, &proving_key)?;
        // Compute sorted list accumulator and commitment
        self.execute_sorted_list_accumulator_round(&mut transcript, &proving_key)?;
        // Fiat-Shamir: beta & gamma
        self.execute_log_derivative_inverse_round(&mut transcript, &proving_key)?;
        // Compute grand product(s) and commitments.

        todo!();

        Ok(())
    }
}
