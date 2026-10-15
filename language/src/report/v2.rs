//! Additive check-report 2.0.0 with exact language and registry provenance.
use super::{CheckReport, ReportError};
use crate::{
    SourceFile,
    semantic::{CheckFailure, v3::CheckedProgramV3},
};
use jocky_forensic::contracts::v2::Registry;
use serde_json::{Value, json};

fn finish(mut value: Value, fingerprint: &str) -> Result<Vec<u8>, ReportError> {
    value["schema_version"] = json!("2.0.0");
    value["language_version"] = json!("3.0.0");
    value["registry"] = json!({"schema_version":"2.0.0","fingerprint":fingerprint});
    let mut bytes = serde_json::to_vec_pretty(&value).map_err(|_| ReportError::Serialization)?;
    bytes.push(b'\n');
    if bytes.len() > crate::semantic::limits::MAX_REPORT_BYTES {
        return Err(ReportError::ResourceLimit);
    }
    Ok(bytes)
}
pub fn from_checked(
    source: SourceFile<'_>,
    checked: &CheckedProgramV3,
) -> Result<Vec<u8>, ReportError> {
    let old = CheckReport::from_checked(source, checked.checked_core())?.to_pretty_json()?;
    let mut value: Value = serde_json::from_slice(&old).map_err(|_| ReportError::Serialization)?;
    let metadata = value["metadata"]
        .as_object_mut()
        .ok_or(ReportError::InvalidMetadata)?;
    metadata.insert(
        "selected_targets".into(),
        json!(checked.selected_targets().collect::<Vec<_>>()),
    );
    let functions = metadata
        .get_mut("functions")
        .and_then(Value::as_array_mut)
        .ok_or(ReportError::InvalidMetadata)?;
    for (item, summary) in functions.iter_mut().zip(checked.function_metadata()) {
        item["supported_platforms"] = json!(summary.supported_platforms);
    }
    if let Some(entry) = checked
        .function_metadata()
        .iter()
        .find(|m| m.name == checked.checked_core().entry_metadata().name())
    {
        metadata
            .get_mut("entry")
            .ok_or(ReportError::InvalidMetadata)?["supported_platforms"] =
            json!(entry.supported_platforms);
    }
    finish(value, checked.fingerprint())
}
pub fn from_failure(
    source: SourceFile<'_>,
    failure: &CheckFailure,
    registry: &Registry,
) -> Result<Vec<u8>, ReportError> {
    let old = CheckReport::from_failure(source, failure)?.to_pretty_json()?;
    let value: Value = serde_json::from_slice(&old).map_err(|_| ReportError::Serialization)?;
    let fingerprint = crate::semantic::v3::metadata::registry_fingerprint(registry)
        .map_err(|_| ReportError::InvalidMetadata)?;
    finish(value, &fingerprint)
}
