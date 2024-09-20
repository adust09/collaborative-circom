# split input into shares
cargo run --release --bin co-circom -- split-input --circuit plonk/test_vectors/poseidon/circuit.circom --input plonk/test_vectors/poseidon/input.json --protocol REP3 --curve BN254 --out-dir plonk/test_vectors/poseidon --config plonk/test_vectors/poseidon/config.toml
# run witness extension in MPC
cargo run --release --bin co-circom -- generate-witness --input plonk/test_vectors/poseidon/input.json.0.shared --circuit plonk/test_vectors/poseidon/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party1.toml --out plonk/test_vectors/poseidon/witness.wtns.0.shared &
cargo run --release --bin co-circom -- generate-witness --input plonk/test_vectors/poseidon/input.json.1.shared --circuit plonk/test_vectors/poseidon/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party2.toml --out plonk/test_vectors/poseidon/witness.wtns.1.shared &
cargo run --release --bin co-circom -- generate-witness --input plonk/test_vectors/poseidon/input.json.2.shared --circuit plonk/test_vectors/poseidon/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party3.toml --out plonk/test_vectors/poseidon/witness.wtns.2.shared
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof plonk --witness plonk/test_vectors/poseidon/witness.wtns.0.shared --zkey plonk/test_vectors/poseidon/poseidon.zkey --protocol REP3 --curve BN254 --config ../configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof plonk --witness plonk/test_vectors/poseidon/witness.wtns.1.shared --zkey plonk/test_vectors/poseidon/poseidon.zkey --protocol REP3 --curve BN254 --config ../configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof plonk --witness plonk/test_vectors/poseidon/witness.wtns.2.shared --zkey plonk/test_vectors/poseidon/poseidon.zkey --protocol REP3 --curve BN254 --config ../configs/party3.toml --out proof.2.json
# verify proof
cargo run --release --bin co-circom -- verify plonk --proof proof.0.json --vk plonk/test_vectors/poseidon/verification_key.json --public-input public_input.json --curve BN254
