//! Bounded transfer integrity. Committed bytes still require role/admission checks.
use base64::{Engine, engine::general_purpose::STANDARD};
use jocky_forensic::collection::identity::digest;
use jocky_shared::collection::{
    Code,
    worker::{Chunk, Commit},
};

pub(crate) struct ChunkTransfer {
    expected: Commit,
    bytes: Vec<u8>,
    closed: bool,
}
impl ChunkTransfer {
    /// `maximum` must be the caller's already reserved transfer quota.
    /// This helper does not reserve supervisor/worker budget on its behalf.
    pub fn new(expected: &Commit, maximum: u64) -> Result<Self, Code> {
        if maximum > 10485760
            || expected.byte_length == 0
            || expected.byte_length > maximum
            || expected.sha256.len() != 64
            || !expected
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Code::WorkerProtocol);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected.byte_length as usize)
            .map_err(|_| Code::ResourceLimit)?;
        Ok(Self {
            expected: expected.clone(),
            bytes,
            closed: false,
        })
    }
    pub fn push(&mut self, chunk: &Chunk) -> Result<(), Code> {
        if self.closed {
            return Err(Code::WorkerProtocol);
        }
        let result = self.push_inner(chunk);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn push_inner(&mut self, chunk: &Chunk) -> Result<(), Code> {
        if chunk.offset != self.bytes.len() as u64
            || chunk.data.is_empty()
            || chunk.data.len() > 87384
        {
            return Err(Code::WorkerProtocol);
        }
        // Maximum encoded length can represent 65538 bytes; verify the actual
        // decoded cap separately. STANDARD rejects noncanonical trailing bits.
        let mut decoded = [0u8; 65538];
        let n = STANDARD
            .decode_slice(&chunk.data, &mut decoded)
            .map_err(|_| Code::WorkerProtocol)?;
        if n == 0 || n > 65536 || self.bytes.len() + n > self.expected.byte_length as usize {
            return Err(Code::WorkerProtocol);
        }
        self.bytes.extend_from_slice(&decoded[..n]);
        Ok(())
    }
    pub fn commit(&mut self, commit: &Commit) -> Result<Vec<u8>, Code> {
        if self.closed {
            return Err(Code::WorkerProtocol);
        }
        self.closed = true;
        if commit != &self.expected
            || self.bytes.len() as u64 != self.expected.byte_length
            || digest(&self.bytes)? != self.expected.sha256
        {
            self.bytes = Vec::new();
            return Err(Code::WorkerProtocol);
        }
        Ok(std::mem::take(&mut self.bytes))
    }
    fn close(&mut self) {
        self.closed = true;
        self.bytes = Vec::new();
    }
}
