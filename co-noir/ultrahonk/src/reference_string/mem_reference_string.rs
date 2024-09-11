//  copied from barustenberg:

use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalDeserialize;

use super::VerifierReferenceString;

#[derive(Debug)]
pub(crate) struct VerifierMemReferenceString<P: Pairing> {
    g2_x: P::G2Affine,
}

impl<P: Pairing> VerifierMemReferenceString<P> {
    pub(crate) fn new(g2x: &[u8]) -> Self {
        let g2_x = match P::G2Affine::deserialize_uncompressed(g2x) {
            Ok(g2_x) => g2_x,
            Err(_) => panic!("Failed to deserialize g2_x"),
        };

        VerifierMemReferenceString { g2_x }
    }

    pub(crate) fn from_affline(_g2x: P::G2Affine) -> Self {
        VerifierMemReferenceString { g2_x: _g2x }
    }

    pub(crate) fn default() -> Self {
        VerifierMemReferenceString::from_affline(P::G2Affine::default())
    }
}

impl<P: Pairing> VerifierReferenceString<P> for VerifierMemReferenceString<P> {
    fn get_g2x(&self) -> P::G2Affine {
        self.g2_x
    }
}
