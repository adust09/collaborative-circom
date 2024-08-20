//![warn(missing_docs)]

use acvm::acir::circuit::ExpressionWidth;
pub use acvm::compiler::transform;

mod solver;

/// The default expression width defined used by the ACVM.
pub const CO_EXPRESSION_WIDTH: ExpressionWidth = ExpressionWidth::Bounded { width: 4 };

#[cfg(test)]
mod tests {
    #[test]
    fn test() {}
}
