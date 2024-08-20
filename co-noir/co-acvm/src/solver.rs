use std::collections::HashMap;

use acir::{circuit::Opcode, native_types::Expression};
use ark_ff::PrimeField;
use mpc_core::traits::PrimeFieldMpcProtocol;

type Index = usize;

type FieldShare<T, F> = <T as PrimeFieldMpcProtocol<F>>::FieldShare;
type FieldShareVec<T, F> = <T as PrimeFieldMpcProtocol<F>>::FieldShareVec;

mod assert_zero_solver;

#[derive(Debug, thiserror::Error)]
pub enum CoAcvmError {
    #[error("Expected at most one mul term, but got {0}")]
    TooManyMulTerm(usize),
}

struct CoSolver<T, F>
where
    T: PrimeFieldMpcProtocol<F>,
    F: PrimeField,
{
    driver: T,
    //there will a more fields added as we add functionality
    opcodes: Vec<Opcode<FieldShare<T, F>>>,
    //maybe this can be an array. lets see..
    witness_map: HashMap<Index, FieldShare<T, F>>,
}

impl<T, F> CoSolver<T, F>
where
    T: PrimeFieldMpcProtocol<F>,
    F: PrimeField,
{
    fn solve(&mut self) {
        for opcode in self.opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => self.solve_assert_zero(expr),
                _ => todo!("non assert zero opcode detected, not supported yet"),
            }
        }
    }
}
