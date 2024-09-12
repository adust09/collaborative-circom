mod crs;
pub(crate) mod decider;
pub(crate) mod oink;
pub mod prover;
mod transcript;
mod types;
pub mod verifier;

// from http://supertech.csail.mit.edu/papers/debruijn.pdf
pub(crate) fn get_msb(inp: u32) -> u8 {
    const MULTIPLY_DE_BRUIJNI_BIT_POSIITION: [u8; 32] = [
        0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30, 8, 12, 20, 28, 15, 17, 24, 7,
        19, 27, 23, 6, 26, 5, 4, 31,
    ];

    let mut v = inp | (inp >> 1);
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;

    MULTIPLY_DE_BRUIJNI_BIT_POSIITION[((v * 0x07C4ACDD) >> 27) as usize]
}

const NUM_SUBRELATIONS: usize = 18; // TODO is this correct?
pub(crate) const NUM_ALPHAS: usize = NUM_SUBRELATIONS - 1;
pub(crate) const CONST_PROOF_SIZE_LOG_N: usize = 28;
pub(crate) const N_MAX: usize = 1 << 25;
