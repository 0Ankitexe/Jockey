use super::{DecodeReason, InputError, inputs::*, records::*, report::*, worker::WorkerFrame};
use serde_json::Value;

macro_rules! documents {
    ($(($variant:ident, $ty:ty, $name:literal, $limit:literal)),* $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum DocumentKind { $($variant),* }
        impl DocumentKind {
            pub const ALL: [Self;13] = [$(Self::$variant),*];
            pub const fn name(self) -> &'static str { match self { $(Self::$variant=>$name),* } }
            pub const fn maximum_bytes(self) -> usize { match self { $(Self::$variant=>$limit),* } }
            pub const fn version(self) -> &'static str {
                match self { Self::Record | Self::Manifest => "2.0.0", _=>"1.0.0" }
            }
        }
        #[derive(Clone, Debug, PartialEq, serde::Serialize)]
        #[serde(untagged)]
        pub enum Document { $($variant(Box<$ty>)),* }
        impl Document {
            pub fn kind(&self) -> DocumentKind { match self { $(Self::$variant(_)=>DocumentKind::$variant),* } }
            pub fn to_value(&self) -> Result<Value, InputError> {
                super::bounded_value(self, self.kind().maximum_bytes())
            }
            pub(crate) fn from_value(kind: DocumentKind, value: Value) -> Result<Self, InputError> {
                match kind { $(DocumentKind::$variant => serde_json::from_value(value).map(Box::new).map(Self::$variant)),* }
                    .map_err(|_| InputError::new(DecodeReason::Schema))
            }
        }
    };
}
documents!(
    (Types, Types, "types", 65536),
    (
        Designation,
        EndpointDesignation,
        "endpoint-designation",
        65536
    ),
    (Authorisation, LabAuthorisation, "authorisation", 65536),
    (Policy, CollectorPolicy, "policy", 65536),
    (Request, CollectionRequest, "request", 65536),
    (Indicators, IndicatorSet, "indicator-set", 524288),
    (Endpoint, EndpointObservation, "endpoint-observation", 65536),
    (Report, CollectionReport, "report", 10485760),
    (Status, Status, "status", 16384),
    (Worker, WorkerFrame, "worker", 131072),
    (LabScenario, LabScenario, "lab-scenario", 65536),
    (Record, ForensicRecord, "forensic-record", 98304),
    (Manifest, EvidenceManifest, "evidence-manifest", 10485760)
);
