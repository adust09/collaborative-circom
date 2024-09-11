use super::Relation;
use crate::decider::{
    types::{ProverUnivariates, RelationParameters},
    univariate::Univariate,
};
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, Zero};

#[derive(Clone, Debug, Default)]
pub(crate) struct UltraPermutationRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 6>,
    pub(crate) r1: Univariate<F, 3>,
}

pub(crate) struct UltraPermutationRelation {}

impl UltraPermutationRelation {
    fn compute_grand_product_numerator<P: Pairing>(
        input: &ProverUnivariates<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
    ) -> Univariate<P::ScalarField, 7> {
        let w_1 = &input.polys.witness.w_l;
        let w_2 = &input.polys.witness.w_r;
        let w_3 = &input.polys.witness.w_o;
        let w_4 = &input.w_4;
        let id_1 = &input.polys.precomputed.id_1;
        let id_2 = &input.polys.precomputed.id_2;
        let id_3 = &input.polys.precomputed.id_3;
        let id_4 = &input.polys.precomputed.id_4;

        let beta = &relation_parameters.beta;
        let gamma = &relation_parameters.gamma;

        // witness degree 4; full degree 8
        (id_1.to_owned() * beta + w_1 + gamma)
            * (id_2.to_owned() * beta + w_2 + gamma)
            * (id_3.to_owned() * beta + w_3 + gamma)
            * (id_4.to_owned() * beta + w_4 + gamma)
    }

    fn compute_grand_product_denominator<P: Pairing>(
        input: &ProverUnivariates<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
    ) -> Univariate<P::ScalarField, 7> {
        let w_1 = &input.polys.witness.w_l;
        let w_2 = &input.polys.witness.w_r;
        let w_3 = &input.polys.witness.w_o;
        let w_4 = &input.w_4;
        let sigma_1 = &input.polys.precomputed.sigma_1;
        let sigma_2 = &input.polys.precomputed.sigma_2;
        let sigma_3 = &input.polys.precomputed.sigma_3;
        let sigma_4 = &input.polys.precomputed.sigma_4;

        let beta = &relation_parameters.beta;
        let gamma = &relation_parameters.gamma;

        // witness degree 4; full degree 8
        (sigma_1.to_owned() * beta + w_1 + gamma)
            * (sigma_2.to_owned() * beta + w_2 + gamma)
            * (sigma_3.to_owned() * beta + w_3 + gamma)
            * (sigma_4.to_owned() * beta + w_4 + gamma)
    }
}

impl<P: Pairing> Relation<P> for UltraPermutationRelation {
    type Acc = UltraPermutationRelationAcc<P::ScalarField>;
    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<P::ScalarField>) -> bool {
        // If z_perm == z_perm_shift, this implies that none of the wire values for the present input are involved in
        // non-trivial copy constraints.
        (input.z_perm.to_owned() - &input.z_perm_shift).is_zero()
    }

    /**
    * @brief Compute contribution of the permutation relation for a given edge (internal function)
    *
    * @details This relation confirms faithful calculation of the grand
    * product polynomial \f$ Z_{\text{perm}}\f$.
    * In Sumcheck Prover Round, this method adds to accumulators evaluations of subrelations at the point
    \f$(u_0,\ldots, u_{i-1}, k, \vec\ell)\f$ for \f$ k=0,\ldots, D\f$, where \f$ \vec \ell\f$ is a point  on the
    Boolean hypercube \f$\{0,1\}^{d-1-i}\f$ and \f$ D \f$ is specified by the calling class. It does so by taking as
    input an array of Prover Polynomials partially evaluated at the points \f$(u_0,\ldots, u_{i-1}, k, \vec\ell)\f$ and
    computing point-wise evaluations of the sub-relations. \todo Protogalaxy Accumulation
    *
    * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
    * @param in an std::array containing the fully extended Univariate edges.
    * @param parameters contains beta, gamma, and public_input_delta, ....
    * @param scaling_factor optional term to scale the evaluation before adding to evals.
    */
    fn accumulate(
        input: &ProverUnivariates<P::ScalarField>,
        relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factor: &P::ScalarField,
    ) -> Self::Acc {
        tracing::trace!("Accumulate UltraPermutationRelation");

        let public_input_delta = &relation_parameters.public_input_delta;
        let z_perm = &input.z_perm;
        let z_perm_shift = &input.z_perm_shift;
        let lagrange_first = &input.polys.precomputed.lagrange_first;
        let lagrange_last = &input.polys.precomputed.lagrange_last;

        // witness degree: deg 5 - deg 5 = deg 5
        // total degree: deg 9 - deg 10 = deg 10

        let tmp = (((z_perm.to_owned() + lagrange_first)
            * Self::compute_grand_product_numerator::<P>(input, relation_parameters))
            - ((lagrange_last.to_owned() * public_input_delta + z_perm_shift)
                * Self::compute_grand_product_denominator::<P>(input, relation_parameters)))
            * scaling_factor;

        let mut r0 = Univariate::default();
        for i in 0..r0.evaluations.len() {
            r0.evaluations[i] = tmp.evaluations[i];
        }

        ///////////////////////////////////////////////////////////////////////

        let tmp = (lagrange_last.to_owned() * z_perm_shift) * scaling_factor;

        let mut r1 = Univariate::default();
        for i in 0..r1.evaluations.len() {
            r1.evaluations[i] = tmp.evaluations[i];
        }

        Self::Acc { r0, r1 }
    }
}
