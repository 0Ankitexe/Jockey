use crate::{lowering::LoweringFailure, semantic::v3::CheckedProgramV3};
use serde_json::Value;
/// Replace the synthetic legacy descriptor with its exact captured v2 descriptor.
pub(super) fn contracts(
    value: &mut Value,
    checked: &CheckedProgramV3,
) -> Result<(), LoweringFailure> {
    let contracts = value["contracts"]
        .as_array_mut()
        .ok_or(LoweringFailure::Invariant(None))?;
    for item in contracts {
        let module = item["module"]
            .as_str()
            .ok_or(LoweringFailure::Invariant(None))?;
        let name = item["name"]
            .as_str()
            .ok_or(LoweringFailure::Invariant(None))?;
        let contract = checked
            .registry_snapshot()
            .lookup(&format!("{module}.{name}"))
            .map_err(|_| LoweringFailure::Invariant(None))?;
        *item = serde_json::to_value(contract).map_err(|_| LoweringFailure::Invariant(None))?;
    }
    Ok(())
}
