//! Bound trusted wire-DTO serialization before allocating a JSON value tree.
//! `Write` is an in-memory interface here; there is no filesystem or network I/O.
use super::{DecodeReason, InputError, decode::read_json};
use std::io::{self, Write};

/// Serialize a wire DTO within the collection JSON byte/depth/node limits.
/// This is not a sandbox for a caller's arbitrary `Serialize` implementation.
pub fn bounded_value<T: serde::Serialize + ?Sized>(
    value: &T,
    maximum: usize,
) -> Result<serde_json::Value, InputError> {
    let maximum = maximum.min(10485760);
    let mut writer = Buffer {
        bytes: Vec::new(),
        maximum,
        depth: 0,
        in_string: false,
        escaped: false,
        failure: None,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return Err(InputError::new(
            writer.failure.unwrap_or(DecodeReason::Json),
        ));
    }
    read_json(&writer.bytes, maximum)
}

struct Buffer {
    bytes: Vec<u8>,
    maximum: usize,
    depth: usize,
    in_string: bool,
    escaped: bool,
    failure: Option<DecodeReason>,
}
impl Buffer {
    fn fail(&mut self, reason: DecodeReason) -> io::Error {
        self.failure = Some(reason);
        io::Error::other("collection serialization rejected")
    }
}
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() {
            return Err(io::Error::other("collection serialization rejected"));
        }
        let Some(length) = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.maximum)
        else {
            return Err(self.fail(DecodeReason::Size));
        };
        // serde_json writes container starts before descending. Stop excessive
        // nesting while streaming, not after recursively building a Value.
        for byte in bytes {
            if self.in_string {
                if self.escaped {
                    self.escaped = false;
                } else if *byte == b'\\' {
                    self.escaped = true;
                } else if *byte == b'"' {
                    self.in_string = false;
                }
            } else {
                match byte {
                    b'"' => self.in_string = true,
                    b'[' | b'{' => {
                        self.depth += 1;
                        if self.depth > 16 {
                            return Err(self.fail(DecodeReason::Depth));
                        }
                    }
                    b']' | b'}' => self.depth = self.depth.saturating_sub(1),
                    _ => {}
                }
            }
        }
        if length > self.bytes.capacity() {
            let capacity = length
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.maximum);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| self.fail(DecodeReason::Allocation))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
