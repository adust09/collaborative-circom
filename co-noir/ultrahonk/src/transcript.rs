use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use std::{collections::HashMap, ops::Index};

use crate::field_convert::ConvertField;

// TODO this whole file is copied from our co-Plonk and should probably be adapted

pub(crate) type TranscriptFieldType = ark_bn254::Fr;
pub(crate) type TranscriptType = Poseidon2Transcript<TranscriptFieldType>;

pub(super) struct Poseidon2Transcript<F>
where
    F: PrimeField,
{
    proof_data: Vec<F>,
    manifest: TranscriptManifest,
    num_frs_written: usize, // the number of bb::frs written to proof_data by the prover or the verifier
    round_number: usize,
    is_first_challenge: bool,
    current_round_data: Vec<F>,
    previous_challenge: F,
}

impl<F: PrimeField> Default for Poseidon2Transcript<F> {
    fn default() -> Self {
        Self {
            proof_data: Default::default(),
            manifest: Default::default(),
            num_frs_written: 0,
            round_number: 0,
            is_first_challenge: true,
            current_round_data: Default::default(),
            previous_challenge: Default::default(),
        }
    }
}

impl<F> Poseidon2Transcript<F>
where
    F: PrimeField,
{
    fn consume_prover_elements(&mut self, label: String, elements: &[F]) {
        // Add an entry to the current round of the manifest
        let len = elements.len();
        self.manifest.add_entry(self.round_number, label, len);
        self.current_round_data.extend(elements);
        self.num_frs_written += len;
    }

    fn convert_point<P>(element: P) -> Vec<F>
    where
        P: AffineRepr,
        P::BaseField: ConvertField<F>,
    {
        let (x, y) = if let Some((x, y)) = element.xy() {
            (*x, *y)
        } else {
            // we are at infinity
            (P::BaseField::zero(), P::BaseField::zero())
        };

        let mut res = x.convert_field();
        res.extend(y.convert_field());

        res
    }

    pub(super) fn send_to_verifier(&mut self, label: String, elements: &[F]) {
        self.proof_data.extend(elements);
        self.consume_prover_elements(label, elements);
    }

    pub(super) fn send_fr_to_verifier<G: ConvertField<F>>(&mut self, label: String, element: G) {
        let elements = element.convert_field();
        self.send_to_verifier(label, &elements);
    }

    pub(super) fn send_u64_to_verifier(&mut self, label: String, element: u64) {
        let el = F::from(element);
        self.send_to_verifier(label, &[el]);
    }

    pub(super) fn send_point_to_verifier<P>(&mut self, label: String, element: P)
    where
        P: AffineRepr,
        P::BaseField: ConvertField<F>,
    {
        let elements = Self::convert_point::<P>(element);
        self.send_to_verifier(label, &elements);
    }

    pub(super) fn send_fr_iter_to_verifier<
        'a,
        G: ConvertField<F>,
        I: IntoIterator<Item = &'a G>,
    >(
        &mut self,
        label: String,
        element: I,
    ) {
        let elements = element
            .into_iter()
            .flat_map(ConvertField::convert_field)
            .collect::<Vec<_>>();
        self.send_to_verifier(label, &elements);
    }

    fn get_next_challenge_buffer(&mut self) -> F {
        // Prevent challenge generation if this is the first challenge we're generating,
        // AND nothing was sent by the prover.
        if self.is_first_challenge {
            assert!(!self.current_round_data.is_empty());
        }
        // concatenate the previous challenge (if this is not the first challenge) with the current round data.
        // TODO(Adrian): Do we want to use a domain separator as the initial challenge buffer?
        // We could be cheeky and use the hash of the manifest as domain separator, which would prevent us from having
        // to domain separate all the data. (See https://safe-hash.dev)

        let mut full_buffer = Vec::new();
        std::mem::swap(&mut full_buffer, &mut self.current_round_data);

        if self.is_first_challenge {
            // Update is_first_challenge for the future
            self.is_first_challenge = false;
        } else {
            // if not the first challenge, we can use the previous_challenge
            full_buffer.insert(0, self.previous_challenge);
        }

        // Hash the full buffer with poseidon2, which is believed to be a collision resistant hash function and a random
        // oracle, removing the need to pre-hash to compress and then hash with a random oracle, as we previously did
        // with Pedersen and Blake3s.
        let new_challenge = Self::hash(full_buffer);

        // update previous challenge buffer for next time we call this function
        self.previous_challenge = new_challenge;
        new_challenge
    }

    pub(super) fn get_challenge<G>(&mut self, label: String) -> G
    where
        G: ConvertField<F>,
    {
        self.manifest.add_challenge(self.round_number, &[label]);
        let challenge = self.get_next_challenge_buffer();
        let res = ConvertField::convert_back(&challenge);
        self.round_number += 1;
        res
    }

    pub(super) fn get_challenges<G>(&mut self, labels: &[String]) -> Vec<G>
    where
        G: ConvertField<F>,
    {
        self.manifest.add_challenge(self.round_number, labels);
        let mut res = Vec::with_capacity(labels.len());
        for _ in 0..labels.len() {
            let challenge = self.get_next_challenge_buffer();
            let res_ = ConvertField::convert_back(&challenge);
            res.push(res_);
        }
        self.round_number += 1;
        res
    }

    fn hash(buffer: Vec<F>) -> F {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct RoundData {
    challenge_label: Vec<String>,
    entries: Vec<(String, usize)>,
}

impl RoundData {
    pub(crate) fn print(&self) {
        for label in self.challenge_label.iter() {
            println!("\tchallenge: {}", label);
        }
        for entry in self.entries.iter() {
            println!("\telement ({}): {}", entry.1, entry.0);
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct TranscriptManifest {
    manifest: HashMap<usize, RoundData>,
}

impl TranscriptManifest {
    pub(crate) fn print(&self) {
        for round in self.manifest.iter() {
            println!("Round: {}", round.0);
            round.1.print();
        }
    }

    pub(crate) fn add_challenge(&mut self, round: usize, labels: &[String]) {
        self.manifest
            .entry(round)
            .or_default()
            .challenge_label
            .extend_from_slice(labels);
    }

    pub(crate) fn add_entry(&mut self, round: usize, element_label: String, element_size: usize) {
        self.manifest
            .entry(round)
            .or_default()
            .entries
            .push((element_label, element_size));
    }

    pub(crate) fn size(&self) -> usize {
        self.manifest.len()
    }
}

impl Index<usize> for TranscriptManifest {
    type Output = RoundData;

    fn index(&self, index: usize) -> &Self::Output {
        &self.manifest[&index]
    }
}
