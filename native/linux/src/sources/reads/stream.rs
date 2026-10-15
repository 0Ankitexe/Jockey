//! Zero-size pseudo-file/text reads need a bounded EOF proof, not size guessing.
use super::{Reader, checked};
use crate::sources::operation::Operation;
use jocky_forensic::collection::budget::Counter;
use jocky_shared::collection::Code;

pub(in crate::sources) fn bounded(
    reader: &mut dyn Reader,
    maximum: u64,
    op: &mut Operation<'_, '_>,
) -> Result<Vec<u8>, Code> {
    op.check()?;
    checked(reader, op)?;
    if maximum == 0 || maximum > 65536 {
        return Err(Code::ResourceLimit);
    }
    op.permit.require_item(maximum)?;
    // One extra source byte distinguishes an exact-size item from truncation.
    // It is charged if observed, never retained as successful prefix evidence.
    let capacity = usize::try_from(maximum + 1).map_err(|_| Code::ResourceLimit)?;
    op.permit
        .charge(Counter::RetainedBytes, capacity as u64 + 65536)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Code::ResourceLimit)?;
    let mut buffer = [0u8; 65536];
    loop {
        op.check()?;
        checked(reader, op)?;
        let available = op.permit.remaining(Counter::SourceBytes)?;
        let size = buffer
            .len()
            .min(capacity - bytes.len())
            .min(available as usize);
        if size == 0 {
            op.permit.charge(Counter::SourceBytes, 1)?;
            return Err(Code::ResourceLimit);
        }
        match reader.read(&mut buffer[..size]) {
            Ok(n) if n <= size => {
                op.permit.charge(Counter::SourceBytes, n as u64)?;
                op.check()?;
                checked(reader, op)?;
                if n == 0 {
                    return Ok(bytes);
                }
                if bytes.len() + n > maximum as usize {
                    op.permit.charge(Counter::Errors, 1)?;
                    return Err(Code::ResourceLimit);
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            Ok(_) => {
                op.permit.charge(Counter::Errors, 1)?;
                op.check()?;
                return Err(Code::WorkerProtocol);
            }
            Err(code) => {
                op.permit.charge(Counter::Errors, 1)?;
                op.check()?;
                return Err(code);
            }
        }
    }
}
