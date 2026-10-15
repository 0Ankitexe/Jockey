//! Ordering operates only on injected records, never native sources.
use jocky_forensic::collection::{
    identity::{IdentityKind, derive_id},
    normalize,
};
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    records::{ForensicRecord, Payload},
};
use serde_json::{Value, json};

fn record(text: &str, index: u64) -> ForensicRecord {
    let mut value: ForensicRecord = serde_json::from_str(text).unwrap();
    value.sequence = index;
    value.record_id = derive_id(IdentityKind::Record, &value.context.collection_id, index).unwrap();
    value
}

#[test]
fn source_keys_have_stable_order_without_rewriting_identity_or_observations() {
    for (text, pointer, low, high) in [
        (
            include_str!("../../fixtures/valid/collection/forensic-record--process.json"),
            "/payload/start_identity/value/start_ticks",
            json!("2"),
            json!("10"),
        ),
        (
            include_str!("../../fixtures/valid/collection/forensic-record--service.json"),
            "/payload/unit_name",
            json!("a.service"),
            json!("z.service"),
        ),
        (
            include_str!("../../fixtures/valid/collection/forensic-record--entry.json"),
            "/payload/location/relative_path",
            json!("a"),
            json!("z"),
        ),
        (
            include_str!("../../fixtures/valid/collection/forensic-record--metadata.json"),
            "/payload/location/relative_path",
            json!("a"),
            json!("z"),
        ),
        (
            include_str!("../../fixtures/valid/collection/forensic-record--log.json"),
            "/payload/event_time/value",
            json!("2020-01-01T00:00:00Z"),
            json!("2020-01-02T00:00:00Z"),
        ),
        (
            include_str!("../../fixtures/valid/collection/forensic-record--module.json"),
            "/payload/name",
            json!("a"),
            json!("z"),
        ),
    ] {
        let mut values = Vec::new();
        for (index, key) in [high, low].into_iter().enumerate() {
            let mut value: Value = serde_json::to_value(record(text, index as u64)).unwrap();
            *value.pointer_mut(pointer).unwrap() = key;
            values.push(serde_json::from_value(value).unwrap());
        }
        assert!(!normalize::is_ordered(&values).unwrap(), "{pointer}");
        let expected = vec![values[1].clone(), values[0].clone()];
        normalize::records(&mut values).unwrap();
        assert_eq!(values, expected, "{pointer}");
        normalize::records(&mut values).unwrap();
        assert_eq!(values, expected);
        assert!(normalize::is_ordered(&values).unwrap());
    }
}

#[test]
fn equal_time_events_keep_the_source_ordinal_not_message_order() {
    let first = record(
        include_str!("../../fixtures/valid/collection/forensic-record--log.json"),
        0,
    );
    let mut second = first.clone();
    second.sequence = 1;
    second.record_id = derive_id(IdentityKind::Record, &second.context.collection_id, 1).unwrap();
    let Payload::Event(event) = &mut second.payload else {
        unreachable!()
    };
    event.message = "a different earlier-sorting message".into();
    let expected = vec![first, second];
    let mut values = expected.clone();
    normalize::records(&mut values).unwrap();
    assert_eq!(values, expected);
}

#[test]
fn indicator_order_uses_matched_sequence_not_uuid_spelling_and_requires_a_reference() {
    let text = include_str!("../../fixtures/valid/collection/forensic-record--process.json");
    let mut first = record(text, 0);
    let mut second = record(text, 1);
    first.record_id = Uuid::parse("ffffffff-ffff-4fff-bfff-ffffffffffff").unwrap();
    second.record_id = Uuid::parse("00000000-0000-4000-8000-000000000000").unwrap();
    let mut matches = Vec::new();
    for (index, observed) in [&second, &first].into_iter().enumerate() {
        let mut matched = record(
            include_str!("../../fixtures/valid/collection/forensic-record--match.json"),
            index as u64 + 2,
        );
        let Payload::Indicator(indicator) = &mut matched.payload else {
            unreachable!()
        };
        indicator.matched_record_id = observed.record_id.clone();
        matches.push(matched);
    }
    let mut values = vec![first, second];
    values.extend(matches);
    assert!(!normalize::is_ordered(&values).unwrap());
    normalize::records(&mut values).unwrap();
    assert_eq!(values[2].sequence, 3);
    assert_eq!(values[3].sequence, 2);
    let Payload::Indicator(indicator) = &mut values[2].payload else {
        unreachable!()
    };
    indicator.matched_record_id = indicator.indicator_set_id.clone();
    assert_eq!(normalize::records(&mut values), Err(Code::InvalidInput));
}

#[test]
fn sorting_rejects_duplicate_ids_malformed_numeric_keys_and_oversized_batches() {
    let one = record(
        include_str!("../../fixtures/valid/collection/forensic-record--process.json"),
        0,
    );
    assert_eq!(
        normalize::records(&mut [one.clone(), one.clone()]),
        Err(Code::InvalidInput)
    );
    assert_eq!(
        normalize::records(&mut vec![one.clone(); 10001]),
        Err(Code::ResourceLimit)
    );
    for bad in ["01", "-1", "1.0", "", "184467440737095516150"] {
        let mut value = serde_json::to_value(&one).unwrap();
        value["payload"]["start_identity"]["value"]["start_ticks"] = json!(bad);
        let mut records = [serde_json::from_value(value).unwrap()];
        assert_eq!(normalize::records(&mut records), Err(Code::InvalidInput));
    }
    assert!(normalize::records(&mut []).is_ok());
}
