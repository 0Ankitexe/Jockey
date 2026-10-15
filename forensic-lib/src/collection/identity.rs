use jocky_shared::collection::{Code, identity::Uuid};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug)]
pub enum IdentityKind {
    Record,
    Manifest,
    Error,
}
pub fn derive_id(kind: IdentityKind, collection: &Uuid, ordinal: u64) -> Result<Uuid, Code> {
    if ordinal > 9007199254740991 || (matches!(kind, IdentityKind::Manifest) && ordinal != 0) {
        return Err(Code::InvalidInput);
    }
    let tag: &[u8] = match kind {
        IdentityKind::Record => b"JOCKY-V5-RECORD-ID\0",
        IdentityKind::Manifest => b"JOCKY-V5-MANIFEST-ID\0",
        IdentityKind::Error => b"JOCKY-V5-ERROR-ID\0",
    };
    let mut hash = Sha256::new();
    hash.update(tag);
    hash.update(collection.bytes());
    if !matches!(kind, IdentityKind::Manifest) {
        hash.update(ordinal.to_be_bytes());
    }
    let mut bytes = hash.finalize();
    bytes[6] = (bytes[6] & 15) | 128;
    bytes[8] = (bytes[8] & 63) | 128;
    let hex = bytes[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Uuid::parse(&format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
    .map_err(|_| Code::InvalidInput)
}
pub fn digest(bytes: &[u8]) -> Result<String, Code> {
    if bytes.len() > 10485760 {
        return Err(Code::ResourceLimit);
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
