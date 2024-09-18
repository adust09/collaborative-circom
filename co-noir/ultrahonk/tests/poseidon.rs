use acir::{native_types::WitnessStack, FieldElement};
use noirc_artifacts::program::ProgramArtifact;

#[test]
fn poseidon_test() {
    let program =
        std::fs::read_to_string("../../test_vectors/noir/poseidon/kat/poseidon.json").unwrap();
    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
        .expect("failed to parse program artifact");

    let should_witness = std::fs::read("../../test_vectors/noir/poseidon/kat/poseidon.gz").unwrap();

    let should_witness = WitnessStack::<FieldElement>::try_from(should_witness.as_slice()).unwrap();
}
