use ark_ff::{One, PrimeField};
use num_bigint::BigUint;

pub trait ConvertField<Des: PrimeField>: PrimeField {
    fn convert_field(&self) -> Vec<Des>;
}

impl ConvertField<ark_bn254::Fr> for ark_bn254::Fr {
    fn convert_field(&self) -> Vec<ark_bn254::Fr> {
        vec![self.to_owned()]
    }
}

impl ConvertField<ark_bn254::Fr> for ark_bn254::Fq {
    fn convert_field(&self) -> Vec<ark_bn254::Fr> {
        let (a, b) = bn254_fq_to_fr(self);
        vec![a, b]
    }
}

/**
* @brief Converts grumpkin::fr to 2 bb::fr elements
* @details First, this function must return 2 bb::fr elements because the grumpkin::fr field has a larger modulus than
* the bb::fr field, so we choose to send 1 grumpkin::fr element to 2 bb::fr elements to maintain injectivity.
* This function the reverse of convert_from_bn254_frs(std::span<const bb::fr> fr_vec, grumpkin::fr*) by merging the two
* pairs of limbs back into the 2 bb::fr elements. For the implementation, we want to minimize the number of constraints
* created by the circuit form, which happens to use 68 bit limbs to represent a grumpkin::fr (as a bigfield).
* Therefore, our mapping will split a grumpkin::fr into a 136 bit chunk for the lower two bigfield limbs and the upper
* chunk for the upper two limbs. The upper chunk ends up being 254 - 2*68 = 118 bits as a result. We manipulate the
* value using bitwise masks and shifts to obtain our two chunks.
* @param input
* @return std::array<bb::fr, 2>
*/
fn bn254_fq_to_fr(fq: &ark_bn254::Fq) -> (ark_bn254::Fr, ark_bn254::Fr) {
    // Goal is to slice up the 64 bit limbs of grumpkin::fr/uint256_t to mirror the 68 bit limbs of bigfield
    // We accomplish this by dividing the grumpkin::fr's value into two 68*2=136 bit pieces.
    const NUM_LIMB_BITS: u32 = 68;
    const LOWER_BITS: u32 = 2 * NUM_LIMB_BITS;
    const TOTAL_BITS: u32 = 254;
    let lower_mask = (BigUint::one() << LOWER_BITS) - BigUint::one();
    let value = BigUint::from(fq.0);

    debug_assert!(value < (BigUint::one() << TOTAL_BITS));

    let res0 = value.to_owned() & lower_mask;
    let res1 = value >> LOWER_BITS;

    debug_assert!(res1 < (BigUint::one() << (TOTAL_BITS - LOWER_BITS)));

    let res0 = ark_bn254::Fr::from(res0);
    let res1 = ark_bn254::Fr::from(res1);

    (res0, res1)
}
