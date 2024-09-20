# split input into shares
cargo run --release --bin co-circom -- split-input --circuit groth16/test_vectors/multiplier2/circuit.circom --input groth16/test_vectors/multiplier2/input.json --protocol REP3 --curve BN254 --out-dir groth16/test_vectors/multiplier2
# run witness extension in MPC
cargo run --release --bin co-circom -- generate-witness --input groth16/test_vectors/multiplier2/input.json.0.shared --circuit groth16/test_vectors/multiplier2/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party1.toml --out groth16/test_vectors/multiplier2/witness.wtns.0.shared &
cargo run --release --bin co-circom -- generate-witness --input groth16/test_vectors/multiplier2/input.json.1.shared --circuit groth16/test_vectors/multiplier2/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party2.toml --out groth16/test_vectors/multiplier2/witness.wtns.1.shared &
cargo run --release --bin co-circom -- generate-witness --input groth16/test_vectors/multiplier2/input.json.2.shared --circuit groth16/test_vectors/multiplier2/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party3.toml --out groth16/test_vectors/multiplier2/witness.wtns.2.shared
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/multiplier2/witness.wtns.0.shared --zkey groth16/test_vectors/multiplier2/multiplier2.zkey --protocol REP3 --curve BN254 --config ../configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/multiplier2/witness.wtns.1.shared --zkey groth16/test_vectors/multiplier2/multiplier2.zkey --protocol REP3 --curve BN254 --config ../configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/multiplier2/witness.wtns.2.shared --zkey groth16/test_vectors/multiplier2/multiplier2.zkey --protocol REP3 --curve BN254 --config ../configs/party3.toml --out proof.2.json
# verify proof
cargo run --release --bin co-circom -- verify groth16 --proof proof.0.json --vk groth16/test_vectors/multiplier2/verification_key.json --public-input public_input.json --curve BN254
