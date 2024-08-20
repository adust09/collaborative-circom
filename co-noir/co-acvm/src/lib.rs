//![warn(missing_docs)]

use std::{collections::BTreeMap, path::Path};

use acvm::acir::circuit::ExpressionWidth;
pub use acvm::compiler::transform;
use noirc_abi::{
    input_parser::{Format, InputValue},
    Abi, InputMap, MAIN_RETURN_NAME,
};

mod solver;

/// The default expression width defined used by the ACVM.
pub const CO_EXPRESSION_WIDTH: ExpressionWidth = ExpressionWidth::Bounded { width: 4 };

/// Returns the circuit's parameters and its return value, if one exists.
pub(crate) fn read_inputs_from_file(
    path: &Path,
    abi: &Abi,
) -> color_eyre::Result<(InputMap, Option<InputValue>)> {
    if abi.is_empty() {
        return Ok((BTreeMap::new(), None));
    }

    let input_string = std::fs::read_to_string(path)?;
    let mut input_map = Format::Toml.parse(&input_string, abi)?;
    let return_value = input_map.remove(MAIN_RETURN_NAME);

    Ok((input_map, return_value))
}

#[cfg(test)]
mod tests {
    use noirc_artifacts::program::ProgramArtifact;

    #[test]
    fn program_artifact_parse() {
        let input_string = r#"{"noir_version":"0.33.0","hash":16226285208704693228,"abi":{"parameters":[{"name":"x","type":{"kind":"field"},"visibility":"private"},{"name":"y","type":{"kind":"field"},"visibility":"public"}],"return_type":null,"error_types":{}},"bytecode":"H4sIAAAAAAAA/7VUwQ3DIAyEhKb9dhM7QDC/rlJUsv8IjRSo3IRfzEmWEZaO47DRaofZ4qbOGEt+lWxhcS6HOaPFN8wxkQfn00JI6Ml/ZrI2k6MQUwwQ0dmMq492hR2cC64BtaCuQU4XVB91w0998BOuASV168a7dxE8duA1wk3a496GGSzEC6pjcxkl21zmoJOvW8Py27yXPDVqFY8thk4G12ngP2Q9y7D6xLRoeS3IKP+GqOKpzv58AckTiVriBQAA","debug_symbols":"lZBBCoQwEAT/0ucc1l1lIV9ZFhk1SiBMxERBgn93oviA3Kam69KdMJhunVrLow/QvwTne4rWs1DC63qFmThTiLRE6LpRMDxAN9WhMFpn5Pwef4WqTH+X6Z8yvS7RBTZaLHXO5OI5W7l/dhCM+3wn4p4=","file_map":{"57":{"source":"fn main(x: Field, y: pub Field) {\n    assert(x != y);\n}\n\n#[test]\nfn test_main() {\n    main(1, 2);\n\n    // Uncomment to make test fail\n    // main(1, 1);\n}\n","path":"/home/gruber/Work/hello_world/src/main.nr"}},"names":["main"]}"#;

        let program_artifact = serde_json::from_str::<ProgramArtifact>(input_string)
            .expect("faield to parse program artifact");

        println!("program_artifact = {program_artifact:?}");
    }
}
