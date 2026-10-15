use super::{Code, context::OperationPermit};

/// Adapter calls consume a current permit; implementation must recheck before every chunk.
pub trait Source {
    fn read(&mut self, permit: &mut OperationPermit<'_>, maximum: usize)
    -> Result<ReadChunk, Code>;
}
pub struct ReadChunk {
    pub bytes: Vec<u8>,
    pub end_of_source: bool,
}
