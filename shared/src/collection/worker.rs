//! Private IPC wire types only; framing, ownership and handshakes are native responsibilities.
use super::identity::Uuid;
use super::inputs::CollectionVersion;
use super::outcomes::{Code, Collector, CollectorOutcome, ItemError, WorkUsed};
use super::records::{ForensicRecord, LocalContext};

vocabulary!(InputRole { Designation => "designation", Authorisation => "authorisation", Policy => "policy", Request => "request", Indicators => "indicators" });
vocabulary!(Job { Collect => "collect", Publish => "publish" });
wire!(InputDescriptor {
    role: InputRole,
    byte_length: u64,
    sha256: String
});
wire!(Chunk {
    offset: u64,
    data: String
});
wire!(Commit {
    byte_length: u64,
    sha256: String
});
wire!(Ready { job: Job });
wire!(Cancel { code: Code });
wire!(CreatedIdentity {
    device_id: String,
    inode: String
});

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "job", rename_all = "snake_case", deny_unknown_fields)]
pub enum Start {
    Collect {
        collector: Collector,
        inputs: Vec<InputDescriptor>,
        input_byte_length: u64,
        input_sha256: String,
    },
    Publish {
        context: LocalContext,
        output_descriptor: u32,
        output_name: String,
        report_byte_length: u64,
        report_sha256: String,
    },
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "job", rename_all = "snake_case", deny_unknown_fields)]
pub enum Done {
    Collect {
        outcome: CollectorOutcome,
        usage: WorkUsed,
    },
    Publish {
        code: super::report::StatusCode,
        sha256: Option<String>,
        byte_length: Option<u64>,
        created_identity: Option<CreatedIdentity>,
    },
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Body {
    Start(Start),
    StartChunk(Chunk),
    StartCommit(Commit),
    Ready(Ready),
    Record(Box<ForensicRecord>),
    ItemError(ItemError),
    Progress(WorkUsed),
    PublishChunk(Chunk),
    PublishCommit(Commit),
    Done(Done),
    Cancel(Cancel),
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerFrame {
    pub schema_version: CollectionVersion,
    pub frame_seq: u64,
    pub collection_id: Uuid,
    #[serde(flatten)]
    pub body: Body,
}
