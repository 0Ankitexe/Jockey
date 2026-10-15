//! Portable pure lowering reuses the exact checked registry snapshot.
mod context;
mod expressions;
mod statements;
use crate::{
    lowering::{BuildOptions, LoweringFailure},
    semantic::v3::CheckedProgramV3,
};
use jocky_ir::v2::VerifiedProgram;

pub fn lower(
    checked: &CheckedProgramV3,
    options: BuildOptions,
) -> Result<VerifiedProgram, LoweringFailure> {
    let old = crate::lowering::lower(checked.checked_core(), options)?;
    let mut value =
        serde_json::to_value(old.document()).map_err(|_| LoweringFailure::Invariant(None))?;
    context::versions_and_targets(&mut value, checked)?;
    expressions::contracts(&mut value, checked)?;
    statements::metadata(&mut value, checked)?;
    let mut document: jocky_ir::v2::IrDocument =
        serde_json::from_value(value).map_err(|_| LoweringFailure::Invariant(None))?;
    jocky_ir::v2::identity::assign_instruction_ids(&mut document)?;
    jocky_ir::v2::verify(document, checked.registry_snapshot()).map_err(Into::into)
}
