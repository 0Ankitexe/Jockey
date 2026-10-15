use jocky_shared::collection::{Code, bounded_value};
use serde::ser::{Serialize, SerializeSeq, Serializer};
use std::cell::Cell;

// Produces data lazily: a length check after to_value would consume the whole
// sequence. The bounded writer must stop asking for elements immediately.
struct Many<'a>(&'a Cell<usize>);
impl Serialize for Many<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        for _ in 0..100000 {
            self.0.set(self.0.get() + 1);
            seq.serialize_element(&"sensitive-looking-test-data")?;
        }
        seq.end()
    }
}

#[test]
fn serialization_stops_before_unbounded_tree_construction() {
    let visited = Cell::new(0);
    assert_eq!(
        bounded_value(&Many(&visited), 100).unwrap_err().code,
        Code::ResourceLimit
    );
    assert!(visited.get() < 5);
}

#[test]
fn bytes_depth_numbers_and_keys_have_the_same_strict_contract() {
    assert_eq!(bounded_value(&true, 4).unwrap(), serde_json::json!(true));
    assert_eq!(
        bounded_value(&true, 3).unwrap_err().code,
        Code::ResourceLimit
    );
    for value in [
        serde_json::json!(1.0),
        serde_json::json!(9007199254740992u64),
        serde_json::json!({"é": 1}),
    ] {
        assert_eq!(
            bounded_value(&value, 100).unwrap_err().code,
            Code::InvalidInput
        );
    }
    let mut nested = serde_json::json!("[\"{}\\]é");
    for _ in 0..16 {
        nested = serde_json::json!([nested]);
    }
    assert!(bounded_value(&nested, 1000).is_ok());
    nested = serde_json::json!([nested]);
    assert_eq!(
        bounded_value(&nested, 1000).unwrap_err().code,
        Code::ResourceLimit
    );
}

#[test]
fn report_dto_round_trip_uses_the_guard_and_retains_unicode_and_controls() {
    let document = jocky_shared::collection::decode(
        jocky_shared::collection::DocumentKind::Report,
        include_bytes!("../../fixtures/valid/collection/report.json"),
    )
    .unwrap();
    let value = bounded_value(&document, 10485760).unwrap();
    assert_eq!(value, document.to_value().unwrap());
    let mut text = String::new();
    for code in 0..128 {
        text.push(char::from_u32(code).unwrap());
    }
    text.push_str("é漢🦀");
    assert_eq!(bounded_value(&text, 1000).unwrap(), serde_json::json!(text));
    assert_eq!(
        bounded_value(&document, 1).unwrap_err().code,
        Code::ResourceLimit
    );
}

#[test]
fn document_serialization_honors_its_own_wire_ceiling() {
    use jocky_shared::collection::{Document, DocumentKind, decode};
    let mut document = decode(
        DocumentKind::Designation,
        include_bytes!("../../fixtures/valid/collection/endpoint-designation.json"),
    )
    .unwrap();
    let Document::Designation(value) = &mut document else {
        panic!("fixture kind");
    };
    value.label = "x".repeat(65536);
    assert!(
        document
            .to_value()
            .is_err_and(|e| e.code == Code::ResourceLimit)
    );
}

struct Recursive<'a>(&'a Cell<usize>);
impl Serialize for Recursive<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.set(self.0.get() + 1);
        let mut seq = serializer.serialize_seq(Some(1))?;
        seq.serialize_element(&Recursive(self.0))?;
        seq.end()
    }
}

#[test]
fn excessive_recursion_is_stopped_before_a_deep_tree_exists() {
    let visited = Cell::new(0);
    assert_eq!(
        bounded_value(&Recursive(&visited), 1000).unwrap_err().code,
        Code::ResourceLimit
    );
    assert_eq!(visited.get(), 17);
}

#[test]
fn retained_node_limit_is_independent_of_byte_limit() {
    let exact = vec![(); 131071];
    assert!(bounded_value(&exact, 10485760).is_ok());
    assert_eq!(
        bounded_value(&vec![(); 131072], 10485760).unwrap_err().code,
        Code::ResourceLimit
    );
}

#[test]
fn serializer_failure_is_redacted_and_does_not_produce_a_partial_value() {
    struct Fails;
    impl Serialize for Fails {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("PRIVATE-EVIDENCE-CANARY"))
        }
    }
    let error = bounded_value(&Fails, 1000).unwrap_err();
    assert_eq!(error.code, Code::InvalidInput);
    assert!(!format!("{error:?} {error}").contains("PRIVATE-EVIDENCE-CANARY"));
}
