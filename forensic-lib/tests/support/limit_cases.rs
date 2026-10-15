//! Table-driven contract boundaries shared by offline limit suites.
#![allow(dead_code)]

use jocky_shared::collection::inputs::Limits;

pub struct NumericCase {
    pub field: &'static str,
    pub exact: u64,
    pub plus_one: u64,
}

pub fn hard_limits() -> Vec<NumericCase> {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/valid/collection/request.json"
    ))
    .unwrap();
    let limits: Limits = serde_json::from_value(value["limits"].clone()).unwrap();
    let value = serde_json::to_value(limits).unwrap();
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, limit)| NumericCase {
            field: Box::leak(key.clone().into_boxed_str()),
            exact: limit.as_u64().unwrap(),
            plus_one: limit.as_u64().unwrap() + 1,
        })
        .collect()
}

pub fn static_bounds() -> Vec<NumericCase> {
    [
        ("configuration_bytes_per_role", 65_536),
        ("configuration_bytes_total", 786_432),
        ("indicator_bytes", 524_288),
        ("sources", 64),
        ("roots", 16),
        ("paths", 256),
        ("indicators", 1_000),
        ("depth", 16),
        ("record_canonical_bytes", 98_304),
        ("worker_frame_bytes", 131_072),
        ("worker_chunk_bytes", 65_536),
        ("stderr_bytes", 16_384),
        ("failure_report_reserve", 65_536),
        ("parent_address_space", 67_108_864),
        ("worker_address_space", 201_326_592),
        ("aggregate_rss", 268_435_456),
    ]
    .into_iter()
    .map(|(field, exact)| NumericCase {
        field,
        exact,
        plus_one: exact + 1,
    })
    .collect()
}
