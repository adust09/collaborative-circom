use acir::{acir_field::GenericFieldElement, native_types::WitnessStack};
use ark_bn254::Bn254;
use noirc_artifacts::program::ProgramArtifact;
use ultrahonk::parse::{acir_format::AcirFormat, crs::CrsParser};

#[test]
fn poseidon_test() {
    let program =
        std::fs::read_to_string("../../test_vectors/noir/poseidon/kat/poseidon.json").unwrap();
    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
        .expect("failed to parse program artifact");

    let witness_stack = std::fs::read("../../test_vectors/noir/poseidon/kat/poseidon.gz").unwrap();
    let witness_stack =
        WitnessStack::<GenericFieldElement<ark_bn254::Fr>>::try_from(witness_stack.as_slice())
            .unwrap();
    let witness = witness_stack.pop().unwrap().witness;

    todo!("witness_map_to_witness_vector");

    ///////////////////////////////////////////////////////////////////////////
    let circuit = program_artifact.bytecode.functions[0].clone();
    let constraint_system = AcirFormat::circuit_serde_to_acir_format(circuit, true);

    let crs = CrsParser::<Bn254>::get_crs("crs/bn254_g1.dat", "crs/bn254_g2.dat");
    ///////////////////////////////////////////////////////////////////////////
    todo!("Continue with the testcase")
}
