//! Shared data-only doubles; these are never authority for a native constructor.
#![allow(dead_code)]

use std::collections::BTreeMap;

pub const EXPIRED_FROM: &str = "2020-01-01T00:00:00Z";
pub const EXPIRED_UNTIL: &str = "2020-01-01T01:00:00Z";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureFailure {
    NotFound,
    PermissionDenied,
    SourceDisappeared,
}

#[derive(Default)]
pub struct FixtureSources {
    pub calls: usize,
    values: BTreeMap<String, Result<Vec<u8>, FixtureFailure>>,
}

impl FixtureSources {
    pub fn insert(&mut self, key: &str, value: Result<Vec<u8>, FixtureFailure>) {
        self.values.insert(key.to_owned(), value);
    }

    pub fn read(&mut self, key: &str) -> Result<&[u8], FixtureFailure> {
        self.calls += 1;
        match self.values.get(key) {
            Some(Ok(bytes)) => Ok(bytes),
            Some(Err(reason)) => Err(*reason),
            None => Err(FixtureFailure::NotFound),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct FixtureClock {
    pub monotonic_ms: u64,
    pub utc_ms: i64,
}

impl FixtureClock {
    pub fn advance(&mut self, millis: u32) {
        self.monotonic_ms += u64::from(millis);
        self.utc_ms += i64::from(millis);
    }
}

pub fn expired_designation() -> serde_json::Value {
    serde_json::json!({
        "schema_version": "1.0.0",
        "designation_id": "10000000-0000-4000-8000-000000000001",
        "endpoint_id": "10000000-0000-4000-8000-000000000002",
        "kind": "isolated_vm",
        "label": "synthetic-test-only",
        "architecture": "x86_64",
        "abi": "gnu",
        "approved_operator_ids": ["10000000-0000-4000-8000-000000000003"],
        "valid_from": EXPIRED_FROM,
        "valid_until": EXPIRED_UNTIL,
        "lab_inventory_reference": "synthetic-test-only-not-an-endpoint-designation"
    })
}

pub fn expired_authorisation() -> serde_json::Value {
    serde_json::json!({
        "schema_version": "1.0.0",
        "authorisation_id": "10000000-0000-4000-8000-000000000004",
        "designation_id": "10000000-0000-4000-8000-000000000001",
        "operator_id": "10000000-0000-4000-8000-000000000003",
        "case_id": "10000000-0000-4000-8000-000000000005",
        "endpoint_id": "10000000-0000-4000-8000-000000000002",
        "approved_profile": "lab-small-v1",
        "valid_from": EXPIRED_FROM,
        "valid_until": EXPIRED_UNTIL,
        "scope": {
            "capabilities": ["system"],
            "source_groups": ["kernel_profile"],
            "roots": [],
            "event_window": {"start": EXPIRED_FROM, "end": EXPIRED_UNTIL}
        },
        "limits": {
            "max_records": 10000, "max_report_bytes": 10485760,
            "max_source_bytes": 67108864, "max_file_bytes": 16777216,
            "max_item_bytes": 65536, "max_errors": 1000,
            "max_entries": 20000, "max_depth": 16,
            "max_indicator_comparisons": 10000000, "timeout_ms": 60000,
            "operation_timeout_ms": 2000, "max_staging_bytes": 83886080,
            "max_memory_bytes": 268435456
        }
    })
}
