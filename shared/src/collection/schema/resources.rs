//! One immutable inventory for the build guard and runtime. Order is DocumentKind.
pub struct EmbeddedSchema {
    pub path: &'static str,
    pub contents: &'static str,
}

macro_rules! schema {
    ($path:literal) => {
        EmbeddedSchema {
            path: $path,
            contents: include_str!(concat!("../../../", $path)),
        }
    };
}

pub const SCHEMAS: [EmbeddedSchema; 14] = [
    schema!("schemas/collection/v1/types.schema.json"),
    schema!("schemas/collection/v1/endpoint-designation.schema.json"),
    schema!("schemas/collection/v1/authorisation.schema.json"),
    schema!("schemas/collection/v1/policy.schema.json"),
    schema!("schemas/collection/v1/request.schema.json"),
    schema!("schemas/collection/v1/indicator-set.schema.json"),
    schema!("schemas/collection/v1/endpoint-observation.schema.json"),
    schema!("schemas/collection/v1/report.schema.json"),
    schema!("schemas/collection/v1/status.schema.json"),
    schema!("schemas/collection/v1/worker.schema.json"),
    schema!("schemas/collection/v1/lab-scenario.schema.json"),
    schema!("schemas/v2/forensic-record.schema.json"),
    schema!("schemas/v2/evidence-manifest.schema.json"),
    schema!("schemas/collection/v1_1/worker-launch.schema.json"),
];
