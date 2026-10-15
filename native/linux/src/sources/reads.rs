//! Charged ordinary-file reads. This private helper cannot admit a live endpoint.
use super::{error, operation::Operation, paths::ReadableFile};
use jocky_forensic::collection::{budget::Counter, cancellation::Cancellation, clock::Clock};
use jocky_shared::collection::Code;

pub(in crate::sources) trait Reader {
    fn verify(&mut self, op: &mut Operation<'_, '_>) -> Result<(), Code>;
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Code>;
}
struct FileReader<'a, 'root, 'ctx>(&'a ReadableFile<'root, 'ctx>);
impl Reader for FileReader<'_, '_, '_> {
    fn verify(&mut self, op: &mut Operation<'_, '_>) -> Result<(), Code> {
        self.0.verify(op)
    }
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Code> {
        rustix::io::read(self.0.fd(), buffer).map_err(error)
    }
}

/// Returns the complete observed interval or an error, never a successful prefix.
/// The owned worker must enforce the external bound on a blocked kernel call.
pub(crate) fn read_all(
    file: &ReadableFile<'_, '_>,
    maximum: u64,
    clock: &mut dyn Clock,
    cancel: &dyn Cancellation,
) -> Result<Vec<u8>, Code> {
    let maximum = maximum.min(file.maximum_file_bytes());
    let mut op = file.begin(clock, cancel)?;
    exact(&mut FileReader(file), file.size(), maximum, &mut op)
}
fn checked(reader: &mut dyn Reader, op: &mut Operation<'_, '_>) -> Result<(), Code> {
    match reader.verify(op) {
        Ok(()) => Ok(()),
        Err(code) => {
            // Time/cancellation has already stopped the context and takes
            // precedence. A source failure consumes the bounded error quota.
            op.permit.charge(Counter::Errors, 1)?;
            Err(code)
        }
    }
}
fn exact(
    reader: &mut dyn Reader,
    expected: u64,
    maximum: u64,
    op: &mut Operation<'_, '_>,
) -> Result<Vec<u8>, Code> {
    op.check()?;
    checked(reader, op)?;
    if maximum == 0 || expected > maximum || maximum > 16777216 {
        return Err(Code::ResourceLimit);
    }
    let expected = usize::try_from(expected).map_err(|_| Code::ResourceLimit)?;
    op.permit
        .charge(Counter::RetainedBytes, expected as u64 + 65536)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| Code::ResourceLimit)?;
    let mut buffer = [0u8; 65536];
    while bytes.len() < expected {
        op.check()?;
        checked(reader, op)?;
        let available = op.permit.remaining(Counter::SourceBytes)?;
        let size = buffer
            .len()
            .min(expected - bytes.len())
            .min(available as usize);
        if size == 0 {
            // Sticky exhaustion prevents future evidence work too.
            op.permit.charge(Counter::SourceBytes, 1)?;
            return Err(Code::ResourceLimit);
        }
        let result = reader.read(&mut buffer[..size]);
        match result {
            Ok(n) if n <= size => {
                // Charge bytes actually obtained before checking a clock that
                // may have expired during I/O. Previously read costs never vanish.
                op.permit.charge(Counter::SourceBytes, n as u64)?;
                op.check()?;
                checked(reader, op)?;
                if n == 0 {
                    op.permit.charge(Counter::Errors, 1)?;
                    return Err(Code::SourceChanged);
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
    op.check()?;
    checked(reader, op)?;
    // Stable descriptor size is the EOF proof; no extra evidence byte is read.
    Ok(bytes)
}

#[cfg(test)]
mod tests;

pub(super) mod stream;
#[cfg(test)]
use stream::bounded;
