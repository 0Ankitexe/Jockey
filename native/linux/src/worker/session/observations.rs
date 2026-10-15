use super::Session;
use jocky_forensic::collection::{
    canonical,
    identity::{IdentityKind, derive_id, digest},
};
use jocky_shared::collection::{
    Code, bounded_value,
    outcomes::{Collector, ItemError},
    records::ForensicRecord,
};

impl Session {
    pub(super) fn record(&mut self, record: &ForensicRecord) -> Result<(), Code> {
        if self
            .launch
            .as_ref()
            .is_some_and(|l| self.records >= l.allowance.records)
        {
            return Err(Code::WorkerProtocol);
        }
        let ordinal = self
            .record_base
            .checked_add(self.records)
            .ok_or(Code::WorkerProtocol)?;
        if Some(record.collector.name) != self.collector
            || self.context.as_ref() != Some(&record.context)
            || ordinal >= self.limits.max_records
            || record.sequence != ordinal
            || record.record_id != derive_id(IdentityKind::Record, &self.collection, ordinal)?
            || self.collector == Some(Collector::System) && self.records != 0
        {
            return Err(Code::WorkerProtocol);
        }
        let mut value = bounded_value(record, 98304).map_err(|_| Code::WorkerProtocol)?;
        value
            .as_object_mut()
            .ok_or(Code::WorkerProtocol)?
            .remove("content_sha256");
        if digest(&canonical::encode(&value, 98304)?)? != record.content_sha256 {
            return Err(Code::WorkerProtocol);
        }
        let mut stack = vec![&value];
        while let Some(v) = stack.pop() {
            self.unavailable |= v.get("state").and_then(|v| v.as_str()) == Some("unavailable")
                && v.get("reason").and_then(|v| v.as_str()) != Some("NotRequested");
            if let Some(object) = v.as_object() {
                stack.extend(object.values());
            }
            if let Some(array) = v.as_array() {
                stack.extend(array);
            }
        }
        self.records += 1;
        Ok(())
    }
    pub(super) fn item_error(&mut self, error: &ItemError) -> Result<(), Code> {
        if self
            .launch
            .as_ref()
            .is_some_and(|l| self.errors >= l.allowance.errors)
        {
            return Err(Code::WorkerProtocol);
        }
        let ordinal = self
            .error_base
            .checked_add(self.errors)
            .ok_or(Code::WorkerProtocol)?;
        if Some(error.collector) != self.collector
            || ordinal >= self.limits.max_errors
            || error.code == Code::NotRequested
            || error.error_id != derive_id(IdentityKind::Error, &self.collection, ordinal)?
        {
            return Err(Code::WorkerProtocol);
        }
        self.errors += 1;
        Ok(())
    }
}
