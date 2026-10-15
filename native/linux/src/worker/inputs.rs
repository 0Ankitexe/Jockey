//! Input transfer integrity, not a live permit or trusted-peer handshake.
use super::chunks::ChunkTransfer;
use jocky_forensic::collection::{InputSet, identity::digest};
use jocky_shared::collection::{
    Code, Document, DocumentKind, decode,
    identity::Uuid,
    outcomes::Collector,
    records::{ContextMode, LocalContext},
    worker::{Chunk, Commit, InputDescriptor, InputRole, Start},
};
use std::{collections::BTreeSet, ops::Range};

pub(crate) struct InputTransfer {
    collection: Uuid,
    collector: Collector,
    descriptors: Vec<InputDescriptor>,
    transfer: ChunkTransfer,
}
pub(crate) struct VerifiedInputs {
    collector: Collector,
    bytes: Vec<u8>,
    ranges: [Range<usize>; 5],
    context: LocalContext,
    fingerprint: jocky_shared::collection::report::Inputs,
}
fn index(role: InputRole) -> usize {
    match role {
        InputRole::Designation => 0,
        InputRole::Authorisation => 1,
        InputRole::Policy => 2,
        InputRole::Request => 3,
        InputRole::Indicators => 4,
    }
}
fn kind(role: InputRole) -> DocumentKind {
    match role {
        InputRole::Designation => DocumentKind::Designation,
        InputRole::Authorisation => DocumentKind::Authorisation,
        InputRole::Policy => DocumentKind::Policy,
        InputRole::Request => DocumentKind::Request,
        InputRole::Indicators => DocumentKind::Indicators,
    }
}
impl InputTransfer {
    pub fn new(collection: Uuid, start: &Start) -> Result<Self, Code> {
        let Start::Collect {
            collector,
            inputs,
            input_byte_length,
            input_sha256,
        } = start
        else {
            return Err(Code::WorkerProtocol);
        };
        if !(4..=5).contains(&inputs.len()) {
            return Err(Code::WorkerProtocol);
        }
        let mut seen = BTreeSet::new();
        let mut length = 0u64;
        for input in inputs {
            if !seen.insert(input.role)
                || input.byte_length == 0
                || input.byte_length > kind(input.role).maximum_bytes() as u64
                || input.sha256.len() != 64
                || !input
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Code::WorkerProtocol);
            }
            length = length
                .checked_add(input.byte_length)
                .ok_or(Code::WorkerProtocol)?;
        }
        if length != *input_byte_length
            || [
                InputRole::Designation,
                InputRole::Authorisation,
                InputRole::Policy,
                InputRole::Request,
            ]
            .iter()
            .any(|r| !seen.contains(r))
        {
            return Err(Code::WorkerProtocol);
        }
        let transfer = ChunkTransfer::new(
            &Commit {
                byte_length: length,
                sha256: input_sha256.clone(),
            },
            786432,
        )?;
        Ok(Self {
            collection,
            collector: *collector,
            descriptors: inputs.clone(),
            transfer,
        })
    }
    pub fn push(&mut self, chunk: &Chunk) -> Result<(), Code> {
        self.transfer.push(chunk)
    }
    pub fn commit(&mut self, commit: &Commit) -> Result<VerifiedInputs, Code> {
        let bytes = self.transfer.commit(commit)?;
        let mut offset = 0;
        let mut ranges = std::array::from_fn(|_| 0..0);
        let mut context = None;
        for input in &self.descriptors {
            let end = offset + input.byte_length as usize;
            let raw = bytes.get(offset..end).ok_or(Code::WorkerProtocol)?;
            if digest(raw)? != input.sha256 {
                return Err(Code::WorkerProtocol);
            }
            let document = decode(kind(input.role), raw).map_err(|_| Code::WorkerProtocol)?;
            if let Document::Request(request) = document {
                if request.collection_id != self.collection
                    || !request.collectors.contains(&self.collector)
                {
                    return Err(Code::WorkerProtocol);
                }
                context = Some(LocalContext {
                    mode: ContextMode::LocalLab,
                    collection_id: request.collection_id,
                    case_id: request.case_id,
                    operator_id: request.operator_id,
                    endpoint_id: request.endpoint_id,
                    designation_id: request.designation_id,
                    authorisation_id: request.authorisation_id,
                    policy_id: request.policy_id,
                });
            }
            ranges[index(input.role)] = offset..end;
            offset = end;
        }
        let input_set = InputSet {
            designation: &bytes[ranges[0].clone()],
            authorisation: Some(&bytes[ranges[1].clone()]),
            policy: &bytes[ranges[2].clone()],
            request: &bytes[ranges[3].clone()],
            indicators: (!ranges[4].is_empty()).then(|| &bytes[ranges[4].clone()]),
        };
        let fingerprint = input_set.fingerprint().map_err(|_| Code::WorkerProtocol)?;
        Ok(VerifiedInputs {
            collector: self.collector,
            bytes,
            ranges,
            context: context.ok_or(Code::WorkerProtocol)?,
            fingerprint,
        })
    }
}
impl VerifiedInputs {
    pub fn fingerprint(&self) -> &jocky_shared::collection::report::Inputs {
        &self.fingerprint
    }
    /// Identity binding from the request. Still requires full authority admission.
    pub fn context(&self) -> &LocalContext {
        &self.context
    }
    pub fn collector(&self) -> Collector {
        self.collector
    }
    /// Caller must still perform full cross-document/lifetime admission and
    /// bind the parent's original deadline before any worker source operation.
    pub fn inputs(&self) -> InputSet<'_> {
        let get = |i: usize| &self.bytes[self.ranges[i].clone()];
        InputSet {
            designation: get(0),
            authorisation: Some(get(1)),
            policy: get(2),
            request: get(3),
            indicators: (!self.ranges[4].is_empty()).then(|| get(4)),
        }
    }
}
