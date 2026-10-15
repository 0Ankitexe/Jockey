//! Pure report finalization. Integrity is not collection or authenticated origin.
use super::{
    canonical,
    identity::{IdentityKind, derive_id, digest},
    verify::verify_report,
};
use jocky_shared::collection::{
    Code, bounded_value,
    report::{CollectionReport, ManifestEntry},
};

mod failure;
pub use failure::failure;

fn body_digest(value: &impl serde::Serialize, maximum: usize) -> Result<String, Code> {
    let value = bounded_value(value, maximum).map_err(|e| e.code)?;
    digest(&canonical::body(&value, maximum)?)
}

/// Fill only derived integrity/length fields. Do not repair contradictory outcomes
/// or label failed observations complete. Caller-provided record order/IDs must agree.
pub fn finalize(mut report: CollectionReport, maximum: usize) -> Result<Vec<u8>, Code> {
    if report.records.len() > 10000 || report.errors.len() > 1000 {
        return Err(Code::ResourceLimit);
    }
    if maximum == 0 {
        return Err(Code::ResourceLimit);
    }
    report.manifest.entries.clear();
    report
        .manifest
        .entries
        .try_reserve_exact(report.records.len())
        .map_err(|_| Code::ResourceLimit)?;
    report.manifest.manifest_id =
        derive_id(IdentityKind::Manifest, &report.context.collection_id, 0)?;
    for (index, record) in report.records.iter_mut().enumerate() {
        if record.sequence != index as u64
            || record.record_id
                != derive_id(
                    IdentityKind::Record,
                    &report.context.collection_id,
                    index as u64,
                )?
        {
            return Err(Code::InvalidInput);
        }
        record.content_sha256 = body_digest(record, 98304)?;
        let value = bounded_value(&record, 98304).map_err(|e| e.code)?;
        let bytes = canonical::encode(&value, 98304)?;
        report.manifest.entries.push(ManifestEntry {
            record_id: record.record_id.clone(),
            sequence: record.sequence,
            byte_length: bytes.len() as u64,
            sha256: digest(&bytes)?,
        });
    }
    report.manifest.content_sha256 = body_digest(&report.manifest, maximum)?;
    for _ in 0..8 {
        report.content_sha256 = body_digest(&report, maximum)?;
        let value = bounded_value(&report, maximum).map_err(|e| e.code)?;
        let mut bytes = canonical::encode(&value, maximum.saturating_sub(1))?;
        let length = bytes.len().checked_add(1).ok_or(Code::ResourceLimit)?;
        if report.summary.report_bytes == length as u64 {
            bytes.try_reserve(1).map_err(|_| Code::ResourceLimit)?;
            bytes.push(b'\n');
            verify_report(&bytes)?;
            return Ok(bytes);
        }
        report.summary.report_bytes = length as u64;
    }
    Err(Code::InvalidInput)
}
