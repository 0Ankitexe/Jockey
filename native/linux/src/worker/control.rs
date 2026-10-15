//! Additive launch framing only. A decoded document proves no native ownership.
use jocky_shared::collection::{
    Code, bounded_value,
    launch::{WorkerLaunch, decode_launch},
};
const MAXIMUM: usize = 65536;

pub(crate) fn encode_launch(launch: &WorkerLaunch) -> Result<Vec<u8>, Code> {
    let value = bounded_value(launch, MAXIMUM).map_err(|e| e.code)?;
    let raw = jocky_forensic::collection::canonical::encode(&value, MAXIMUM)?;
    decode_launch(&raw).map_err(|_| Code::WorkerProtocol)?;
    let mut packet = Vec::new();
    packet
        .try_reserve_exact(raw.len() + 4)
        .map_err(|_| Code::ResourceLimit)?;
    packet.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    packet.extend_from_slice(&raw);
    Ok(packet)
}
pub(crate) struct LaunchDecoder {
    header: [u8; 4],
    header_used: usize,
    expected: usize,
    raw: Vec<u8>,
    delivered: bool,
    closed: bool,
}
impl LaunchDecoder {
    pub fn new() -> Self {
        Self {
            header: [0; 4],
            header_used: 0,
            expected: 0,
            raw: Vec::new(),
            delivered: false,
            closed: false,
        }
    }
    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<WorkerLaunch>), Code> {
        if self.closed || self.delivered {
            return Err(Code::WorkerProtocol);
        }
        let result = self.read(input);
        if result.is_err() {
            self.closed = true;
            self.raw.clear();
        }
        result
    }
    fn read(&mut self, input: &[u8]) -> Result<(usize, Option<WorkerLaunch>), Code> {
        let mut consumed = 0;
        if self.header_used < 4 {
            let n = (4 - self.header_used).min(input.len());
            self.header[self.header_used..self.header_used + n].copy_from_slice(&input[..n]);
            self.header_used += n;
            consumed += n;
            if self.header_used < 4 {
                return Ok((consumed, None));
            }
            self.expected = u32::from_be_bytes(self.header) as usize;
            if self.expected == 0 || self.expected > MAXIMUM {
                return Err(Code::WorkerProtocol);
            }
            self.raw
                .try_reserve_exact(self.expected)
                .map_err(|_| Code::ResourceLimit)?;
        }
        let n = (self.expected - self.raw.len()).min(input.len() - consumed);
        self.raw.extend_from_slice(&input[consumed..consumed + n]);
        consumed += n;
        if self.raw.len() != self.expected {
            return Ok((consumed, None));
        }
        let launch = decode_launch(&self.raw).map_err(|_| Code::WorkerProtocol)?;
        self.raw.clear();
        self.delivered = true;
        Ok((consumed, Some(launch)))
    }
    pub fn finish(&mut self) -> Result<(), Code> {
        let completed = self.delivered && !self.closed;
        self.closed = true;
        self.raw.clear();
        if completed {
            Ok(())
        } else {
            Err(Code::WorkerProtocol)
        }
    }
}
