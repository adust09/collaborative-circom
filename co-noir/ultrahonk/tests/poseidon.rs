use acir::{acir_field::GenericFieldElement, native_types::WitnessStack};
use noirc_artifacts::program::ProgramArtifact;
use ultrahonk::parse::acir_format::AcirFormat;

#[test]
fn poseidon_test() {
    let program =
        std::fs::read_to_string("../../test_vectors/noir/poseidon/kat/poseidon.json").unwrap();
    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
        .expect("failed to parse program artifact");

    let witness = std::fs::read("../../test_vectors/noir/poseidon/kat/poseidon.gz").unwrap();
    let witness =
        WitnessStack::<GenericFieldElement<ark_bn254::Fr>>::try_from(witness.as_slice()).unwrap();

    ///////////////////////////////////////////////////////////////////////////
    let circuit = program_artifact.bytecode.functions[0].clone();
    let constraint_system = AcirFormat::circuit_serde_to_acir_format(circuit, true);

    todo!("Continue with the testcase")
}
