use acir::native_types::Expression;
use ark_ff::PrimeField;
use mpc_core::traits::PrimeFieldMpcProtocol;

use super::{CoSolver, FieldShare};

impl<T, F> CoSolver<T, F>
where
    T: PrimeFieldMpcProtocol<F>,
    F: PrimeField,
{
    fn evaluate_mul_terms(&self, expr: &Expression<FieldShare<T, F>>) -> eyre::Result{
        if expr.mul_terms.len() == 1 {

        } else {

        }
    }

    fn evaluate_assert_zero(&self, expr: &Expression<FieldShare<T, F>>) {
        //evaluate mul terms
        self.evaluate_mul_terms(expr);
        //evaluate add terms
    }

    fn solve_assert_zero(&self, expr: &Expression<FieldShare<T, F>>) {
        //first evaluate the already existing terms
    }
}
