use jocky_forensic::collection::{
    ClockReading, InputSet, ValidatedCollectionContext, admit, clock::Clock,
};
use jocky_shared::collection::{
    Code,
    identity::{UtcTime, Uuid},
    inputs::PathRef,
};
use serde_json::{Value, json};

pub struct Frozen(pub ClockReading);
impl Default for Frozen {
    fn default() -> Self {
        Self(ClockReading {
            utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
            monotonic_ms: 0,
        })
    }
}
impl Clock for Frozen {
    fn read(&mut self) -> Result<ClockReading, Code> {
        Ok(self.0.clone())
    }
}
pub fn scratch() -> tempfile::TempDir {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .canonicalize()
        .unwrap();
    tempfile::Builder::new()
        .prefix("v5-confinement-")
        .tempdir_in(base)
        .unwrap()
}
pub fn path(relative: &str) -> PathRef {
    PathRef::new(
        Uuid::parse("10000000-0000-4000-8000-000000000090").unwrap(),
        relative,
    )
    .unwrap()
}
pub fn values(root: &str, relative: &str) -> [Value; 4] {
    let mut values: [Value; 4] = [
        include_str!("../../../../fixtures/valid/collection/endpoint-designation.json"),
        include_str!("../../../../fixtures/valid/collection/authorisation.json"),
        include_str!("../../../../fixtures/valid/collection/policy.json"),
        include_str!("../../../../fixtures/valid/collection/request.json"),
    ]
    .map(|s| serde_json::from_str(s).unwrap());
    let reference = path(relative);
    for index in [1, 2] {
        values[index]["scope"]["roots"] = json!([{"root_id":reference.root_id,"absolute_path":root,"purposes":["files","persistence"]}]);
        values[index]["scope"]["capabilities"] = json!(["files"]);
        values[index]["scope"]["source_groups"] = json!([]);
    }
    values[2]["sources"] = json!([]);
    values[3]["source_ids"] = json!([]);
    values[3]["collectors"] = json!(["files"]);
    values[3]["capabilities"] = json!(["files"]);
    values[3]["paths"] = json!([reference]);
    values
}
pub fn context(values: &[Value; 4]) -> ValidatedCollectionContext {
    let raw = values.each_ref().map(|v| serde_json::to_vec(v).unwrap());
    admit(
        InputSet {
            designation: &raw[0],
            authorisation: Some(&raw[1]),
            policy: &raw[2],
            request: &raw[3],
            indicators: None,
        },
        Frozen::default().0,
    )
    .unwrap()
}
