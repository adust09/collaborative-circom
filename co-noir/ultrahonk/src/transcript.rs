use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha3::{Digest, Keccak256};
use std::marker::PhantomData;

// TODO this whole file is copied from our co-Plonk and should probably be adapted

pub(super) type Keccak256Transcript<P> = Transcript<Keccak256, P>;

pub(super) struct Transcript<D, P>
where
    D: Digest,
    P: Pairing,
{
    digest: D,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Default for Keccak256Transcript<P> {
    fn default() -> Self {
        Self {
            digest: Default::default(),
            phantom_data: Default::default(),
        }
    }
}

impl<D, P> Transcript<D, P>
where
    D: Digest,
    P: Pairing,
{
    pub(super) fn add_scalar(&mut self, scalar: P::ScalarField) {
        let mut buf = vec![];
        scalar
            .serialize_uncompressed(&mut buf)
            .expect("Can Fr write into Vec<u8>");
        buf.reverse();
        self.digest.update(&buf);
    }

    pub(super) fn add_point(&mut self, point: P::G1Affine) {
        let byte_len: usize = P::BaseField::MODULUS_BIT_SIZE
            .div_ceil(8)
            .try_into()
            .expect("u32 fits into usize");
        let mut buf = Vec::with_capacity(byte_len);
        if let Some((x, y)) = point.xy() {
            x.serialize_uncompressed(&mut buf)
                .expect("Can write Fq into Vec<u8>");
            buf.reverse();
            self.digest.update(&buf);
            buf.clear();
            y.serialize_uncompressed(&mut buf)
                .expect("Can write Fq into Vec<u8>");
            buf.reverse();
            self.digest.update(&buf);
        } else {
            // we are at infinity - in this case, snarkjs writes (MODULUS_BIT_SIZE / 8) Zero-bytes
            // to the input buffer. If we serialize with arkworks, we would
            // get (MODULUS_BIT_SIZE / 8 - 1) Zero-bytes with a trailing byte indicating the length of
            // the serialized group element, resulting in an incompatible hash. Therefore we simple resize
            // the buffer with Zeros and write it to the hash instance.
            buf.resize(byte_len * 2, 0);
            self.digest.update(&buf);
        }
    }

    pub(super) fn add(&mut self, data: impl AsRef<[u8]>) {
        self.digest.update(data);
    }

    pub(super) fn get_challenge(self) -> P::ScalarField {
        let bytes = self.digest.finalize();
        P::ScalarField::from_be_bytes_mod_order(&bytes)
    }
}
