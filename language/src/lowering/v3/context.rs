use crate::{lowering::LoweringFailure, semantic::v3::CheckedProgramV3};
use serde_json::{Value, json};
pub(super) fn versions_and_targets(
    value: &mut Value,
    checked: &CheckedProgramV3,
) -> Result<(), LoweringFailure> {
    value["schema_version"] = json!("2.0.0");
    value["language_version"] = json!("3.0.0");
    value["registry"]["schema_version"] = json!("2.0.0");
    value["registry"]["fingerprint"] = json!(jocky_ir::v2::identity::registry_fingerprint(
        checked.registry_snapshot()
    )?);
    value["targets"] = json!(checked.selected_targets().collect::<Vec<_>>());
    Ok(())
}
