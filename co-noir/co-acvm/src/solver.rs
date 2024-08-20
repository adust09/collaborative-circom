use std::{error, io};

use acir::circuit::Opcode;
use ark_ff::PrimeField;
use mpc_core::traits::{NoirWitnessExtensionProtocol, PrimeFieldMpcProtocol};

use crate::types::CoWitnessMap;

type Index = usize;

mod assert_zero_solver;

type CoAcvmResult<T> = std::result::Result<T, CoAcvmError>;

#[derive(Debug, thiserror::Error)]
pub enum CoAcvmError {
    #[error("Expected at most one mul term, but got {0}")]
    TooManyMulTerm(usize),
    #[error(transparent)]
    IOError(#[from] io::Error),
    #[error("unsolvable, too many unknown terms")]
    TooManyUnknowns,
}

struct CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    driver: T,
    //there will a more fields added as we add functionality
    opcodes: Vec<Opcode<F>>,
    //maybe this can be an array. lets see..
    witness_map: CoWitnessMap<T::AcvmType>,
}

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    fn solve(&mut self) -> CoAcvmResult<()> {
        let opcodes = std::mem::take(&mut self.opcodes);
        for opcode in opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => self.solve_assert_zero(expr)?,
                _ => todo!("non assert zero opcode detected, not supported yet"),
            }
        }
        Ok(())
    }
}
