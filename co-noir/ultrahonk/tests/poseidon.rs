use ark_bn254::Bn254;
use ultrahonk::parse::{crs::CrsParser, get_constraint_system_from_file, get_witness_from_file};

#[test]
fn poseidon_test() {
    const CRS_PATH_G1: &str = "crs/bn254_g1.dat";
    const CRS_PATH_G2: &str = "crs/bn254_g2.dat";
    const CIRCUIT_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.json";
    const WITNESS_FILE: &str = "../../test_vectors/noir/poseidon/kat/poseidon.gz";

    let crs = CrsParser::<Bn254>::get_crs(CRS_PATH_G1, CRS_PATH_G2);
    let circuit_serde_to_acir_format = get_constraint_system_from_file(CIRCUIT_FILE, true).unwrap();
    let witness = get_witness_from_file(WITNESS_FILE).unwrap();

    todo!("Continue with the testcase")
}
