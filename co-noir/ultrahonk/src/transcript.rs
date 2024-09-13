use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, marker::PhantomData, num, ops::Index};

// TODO this whole file is copied from our co-Plonk and should probably be adapted

pub(super) type Keccak256Transcript<P> = Transcript<Keccak256, P>;

pub(super) struct Transcript<D, P>
where
    D: Digest,
    P: Pairing,
{
    proof_data: Vec<P::ScalarField>,
    manifest: TranscriptManifest,
    num_frs_written: usize, // the number of bb::frs written to proof_data by the prover or the verifier
    round_number: usize,
    is_first_challenge: bool,
    current_round_data: Vec<P::ScalarField>,
    previous_challenge: Vec<P::ScalarField>,
    phantom_data: PhantomData<D>,
}

impl<P: Pairing> Default for Keccak256Transcript<P> {
    fn default() -> Self {
        Self {
            proof_data: Default::default(),
            manifest: Default::default(),
            num_frs_written: 0,
            round_number: 0,
            is_first_challenge: true,
            current_round_data: Default::default(),
            previous_challenge: Default::default(),
            phantom_data: Default::default(),
        }
    }
}

impl<D, P> Transcript<D, P>
where
    D: Digest,
    P: Pairing,
{
    fn consume_prover_elements(&mut self, label: String, elements: &[P::ScalarField]) {
        // Add an entry to the current round of the manifest
        let len = elements.len();
        self.manifest.add_entry(self.round_number, label, len);
        self.current_round_data.extend(elements);
        self.num_frs_written += len;
    }

    pub(super) fn send_to_verifier(&mut self, label: String, elements: &[P::ScalarField]) {
        self.proof_data.extend(elements);
        self.consume_prover_elements(label, elements);
    }

    pub(super) fn send_fr_to_verifier(&mut self, label: String, element: P::ScalarField) {
        self.send_to_verifier(label, &[element]);
    }

    pub(super) fn send_u64_to_verifier(&mut self, label: String, element: u64) {
        let el = P::ScalarField::from(element);
        self.send_fr_to_verifier(label, el);
    }

    // pub(super) fn add_scalar(&mut self, scalar: P::ScalarField) {
    //     let mut buf = vec![];
    //     scalar
    //         .serialize_uncompressed(&mut buf)
    //         .expect("Can Fr write into Vec<u8>");
    //     buf.reverse();
    //     self.digest.update(&buf);
    // }

    // pub(super) fn add_point(&mut self, point: P::G1Affine) {
    //     let byte_len: usize = P::BaseField::MODULUS_BIT_SIZE
    //         .div_ceil(8)
    //         .try_into()
    //         .expect("u32 fits into usize");
    //     let mut buf = Vec::with_capacity(byte_len);
    //     if let Some((x, y)) = point.xy() {
    //         x.serialize_uncompressed(&mut buf)
    //             .expect("Can write Fq into Vec<u8>");
    //         buf.reverse();
    //         self.digest.update(&buf);
    //         buf.clear();
    //         y.serialize_uncompressed(&mut buf)
    //             .expect("Can write Fq into Vec<u8>");
    //         buf.reverse();
    //         self.digest.update(&buf);
    //     } else {
    //         // we are at infinity - in this case, snarkjs writes (MODULUS_BIT_SIZE / 8) Zero-bytes
    //         // to the input buffer. If we serialize with arkworks, we would
    //         // get (MODULUS_BIT_SIZE / 8 - 1) Zero-bytes with a trailing byte indicating the length of
    //         // the serialized group element, resulting in an incompatible hash. Therefore we simple resize
    //         // the buffer with Zeros and write it to the hash instance.
    //         buf.resize(byte_len * 2, 0);
    //         self.digest.update(&buf);
    //     }
    // }

    // pub(super) fn add(&mut self, data: impl AsRef<[u8]>) {
    //     self.digest.update(data);
    // }

    // pub(super) fn get_challenge(self) -> P::ScalarField {
    //     let bytes = self.digest.finalize();
    //     P::ScalarField::from_be_bytes_mod_order(&bytes)
    // }
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

    pub(crate) fn add_challenge(&mut self, round: usize, labels: Vec<String>) {
        self.manifest
            .entry(round)
            .or_insert_with(RoundData::default)
            .challenge_label
            .extend(labels);
    }

    pub(crate) fn add_entry(&mut self, round: usize, element_label: String, element_size: usize) {
        self.manifest
            .entry(round)
            .or_insert_with(RoundData::default)
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
