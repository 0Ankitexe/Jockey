use crate::{lowering::LoweringFailure, semantic::v3::CheckedProgramV3};
use serde_json::{Value, json};
/// Restore exact portable platform summaries after the shared type/flow pass.
pub(super) fn metadata(
    value: &mut Value,
    checked: &CheckedProgramV3,
) -> Result<(), LoweringFailure> {
    let functions = value["functions"]
        .as_array_mut()
        .ok_or(LoweringFailure::Invariant(None))?;
    if functions.len() != checked.function_metadata().len() {
        return Err(LoweringFailure::Invariant(None));
    }
    for (function, summary) in functions.iter_mut().zip(checked.function_metadata()) {
        function["metadata"]["supported_platforms"] = json!(summary.supported_platforms);
    }
    let entry = value["entry"]
        .as_u64()
        .ok_or(LoweringFailure::Invariant(None))? as usize;
    value["entry_metadata"] = value["functions"][entry]["metadata"].clone();
    Ok(())
}
