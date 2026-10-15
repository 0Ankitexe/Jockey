//! Incremental length framing only. A decoded frame is NOT an execution permit.
use jocky_shared::collection::{
    Code, Document, DocumentKind, decode, identity::Uuid, worker::WorkerFrame,
};
use std::io::{Read, Write};

const MAX_FRAME: usize = 131072;
const READ_CHUNK: usize = 65536;

/// Write one already validated frame. The caller must give the owned IPC
/// channel a finite write deadline; a short write is never a sent frame.
pub(crate) fn write_frame(writer: &mut impl Write, frame: &WorkerFrame) -> Result<(), Code> {
    let packet = encode_frame(frame)?;
    writer.write_all(&packet).map_err(|_| Code::WorkerFailed)
}

/// Read exactly one bounded frame without buffering any bytes of the next one.
/// The caller owns a finite read deadline and must treat timeout/EOF as a lost
/// worker, not as an empty successful response.
pub(crate) fn read_frame(
    reader: &mut impl Read,
    decoder: &mut FrameDecoder,
) -> Result<WorkerFrame, Code> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).map_err(|_| {
        decoder.abort();
        Code::WorkerFailed
    })?;
    decoder.push(&header)?;
    let length = u32::from_be_bytes(header) as usize;
    // Decoder rejected zero/oversize before any payload allocation.
    let mut remaining = length;
    let mut chunk = [0u8; READ_CHUNK];
    while remaining > 0 {
        let size = remaining.min(chunk.len());
        reader.read_exact(&mut chunk[..size]).map_err(|_| {
            decoder.abort();
            Code::WorkerFailed
        })?;
        let (used, frame) = decoder.push(&chunk[..size])?;
        if used != size {
            return Err(Code::WorkerProtocol);
        }
        remaining -= size;
        if let Some(frame) = frame {
            if remaining != 0 {
                return Err(Code::WorkerProtocol);
            }
            return Ok(frame);
        }
    }
    Err(Code::WorkerProtocol)
}

/// Produce a complete validated packet before a transport writes any prefix.
/// Transport deadlines/partial-write handling are separate supervisor duties.
pub(crate) fn encode_frame(frame: &WorkerFrame) -> Result<Vec<u8>, Code> {
    record_bound(frame)?;
    let value = jocky_shared::collection::bounded_value(frame, MAX_FRAME).map_err(|error| {
        if error.code == Code::ResourceLimit {
            Code::ResourceLimit
        } else {
            Code::WorkerProtocol
        }
    })?;
    let bytes =
        jocky_forensic::collection::canonical::encode(&value, MAX_FRAME).map_err(|code| {
            if code == Code::ResourceLimit {
                code
            } else {
                Code::WorkerProtocol
            }
        })?;
    decode(DocumentKind::Worker, &bytes).map_err(|_| Code::WorkerProtocol)?;
    let mut packet = Vec::new();
    packet
        .try_reserve_exact(bytes.len() + 4)
        .map_err(|_| Code::ResourceLimit)?;
    packet.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    packet.extend_from_slice(&bytes);
    Ok(packet)
}

fn record_bound(frame: &WorkerFrame) -> Result<(), Code> {
    if let jocky_shared::collection::worker::Body::Record(record) = &frame.body {
        if record.context.collection_id != frame.collection_id {
            return Err(Code::WorkerProtocol);
        }
        let value = jocky_shared::collection::bounded_value(record.as_ref(), 98304)
            .map_err(|_| Code::WorkerProtocol)?;
        jocky_forensic::collection::canonical::encode(&value, 98304)
            .map_err(|_| Code::WorkerProtocol)?;
    }
    Ok(())
}

/// Holds at most one encoded frame, never buffers a caller's whole stream.
/// Any framing/schema/identity/sequence failure permanently closes this decoder.
pub(crate) struct FrameDecoder {
    collection: Uuid,
    next: u64,
    header: [u8; 4],
    header_used: usize,
    expected: usize,
    payload: Vec<u8>,
    closed: bool,
}
impl FrameDecoder {
    pub fn new(collection: Uuid) -> Self {
        Self {
            collection,
            next: 0,
            header: [0; 4],
            header_used: 0,
            expected: 0,
            payload: Vec::new(),
            closed: false,
        }
    }

    /// Returns consumed bytes and at most one frame. The caller retains any tail.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(usize, Option<WorkerFrame>), Code> {
        if self.closed {
            return Err(Code::WorkerProtocol);
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.closed = true;
            self.payload = Vec::new();
        }
        result
    }
    fn abort(&mut self) {
        self.closed = true;
        self.payload.clear();
    }
    fn push_inner(&mut self, bytes: &[u8]) -> Result<(usize, Option<WorkerFrame>), Code> {
        let mut used = 0;
        if self.header_used < 4 {
            let count = (4 - self.header_used).min(bytes.len());
            self.header[self.header_used..self.header_used + count]
                .copy_from_slice(&bytes[..count]);
            self.header_used += count;
            used += count;
            if self.header_used != 4 {
                return Ok((used, None));
            }
            self.expected = u32::from_be_bytes(self.header) as usize;
            if self.expected == 0 || self.expected > MAX_FRAME {
                return Err(Code::WorkerProtocol);
            }
            self.payload
                .try_reserve_exact(self.expected)
                .map_err(|_| Code::ResourceLimit)?;
        }
        let count = (self.expected - self.payload.len()).min(bytes.len() - used);
        self.payload.extend_from_slice(&bytes[used..used + count]);
        used += count;
        if self.payload.len() != self.expected {
            return Ok((used, None));
        }
        let Document::Worker(frame) =
            decode(DocumentKind::Worker, &self.payload).map_err(|_| Code::WorkerProtocol)?
        else {
            return Err(Code::WorkerProtocol);
        };
        if frame.collection_id != self.collection || frame.frame_seq != self.next {
            return Err(Code::WorkerProtocol);
        }
        record_bound(&frame)?;
        self.next = self.next.checked_add(1).ok_or(Code::WorkerProtocol)?;
        self.header_used = 0;
        self.expected = 0;
        self.payload.clear();
        Ok((used, Some(*frame)))
    }
    /// Transport EOF, not a successful job acknowledgement. Job completion must
    /// independently require the correctly ordered and verified Done message.
    pub fn finish(&mut self) -> Result<(), Code> {
        let clean = !self.closed && self.header_used == 0;
        self.closed = true;
        self.payload = Vec::new();
        if clean {
            Ok(())
        } else {
            Err(Code::WorkerProtocol)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversize_header_is_rejected_without_payload_allocation() {
        let id = Uuid::parse("10000000-0000-4000-8000-000000000007").unwrap();
        let mut decoder = FrameDecoder::new(id);
        assert_eq!(decoder.payload.capacity(), 0);
        assert!(decoder.push(&u32::MAX.to_be_bytes()).is_err());
        assert_eq!(decoder.payload.capacity(), 0);
        assert!(decoder.closed);
    }
}
