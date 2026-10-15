//! Fixed SHA-256 framing and UUIDv8 identity; never entropy, clock or host input.
use crate::{
    diagnostic::{DiagnosticCode as Code, Failure},
    limits,
    v2::model::{self, IrDocument},
};
use jocky_forensic::contracts::v2::{FunctionContract, Registry};
use serde_json::json;
use sha2::{Digest, Sha256};

pub fn source_hash(bytes: &[u8]) -> Result<String, Failure> {
    limits::require(bytes.len(), limits::SOURCE_BYTES)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(crate) fn canonical_contract(c: &FunctionContract) -> FunctionContract {
    let mut result = c.clone();
    result.supported_platforms.sort();
    result.possible_errors.sort_by_key(|e| e.code);
    result
}

/// Hash the complete validated registry, not merely the referenced subset.
pub fn registry_fingerprint(registry: &Registry) -> Result<String, Failure> {
    let functions = registry
        .functions()
        .map(canonical_contract)
        .collect::<Vec<_>>();
    let value = json!({"schema_version":model::REGISTRY_VERSION,"functions":functions});
    let bytes = serde_json::to_vec(&value).map_err(|_| Failure::at(Code::Contract, "/registry"))?;
    limits::require(bytes.len(), 1024 * 1024)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn header(document: &IrDocument) -> Result<(), Failure> {
    limits::require(document.source.label.len(), limits::LABEL_BYTES)?;
    limits::require(document.source.byte_length, limits::SOURCE_BYTES)?;
    if document.schema_version != model::SCHEMA_VERSION
        || document.language_version != model::LANGUAGE_VERSION
        || document.registry.schema_version != model::REGISTRY_VERSION
    {
        return Err(Failure::at(Code::Version, ""));
    }
    if !hex_digest(&document.source.sha256) || !hex_digest(&document.registry.fingerprint) {
        return Err(Failure::at(Code::Identity, "/source"));
    }
    let seed = document
        .build_seed
        .parse::<u64>()
        .map_err(|_| Failure::at(Code::Schema, "/build_seed"))?;
    if seed.to_string() != document.build_seed {
        return Err(Failure::at(Code::Schema, "/build_seed"));
    }
    Ok(())
}

struct Inputs<'a> {
    fields: [&'a str; 7],
}
impl<'a> Inputs<'a> {
    fn new(document: &'a IrDocument) -> Self {
        Self {
            fields: [
                &document.source.sha256,
                &document.source.label,
                &document.language_version,
                &document.schema_version,
                &document.registry.schema_version,
                &document.registry.fingerprint,
                &document.build_seed,
            ],
        }
    }
    fn id(&self, function: usize, region: usize, instruction: usize) -> String {
        let mut hash = Sha256::new();
        hash.update(b"JOCKY-IR-ID-v2\0");
        for field in self.fields.into_iter().chain(
            [
                function.to_string(),
                region.to_string(),
                instruction.to_string(),
            ]
            .iter()
            .map(String::as_str),
        ) {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        let mut bytes = hash.finalize();
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex = bytes[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    }
}
pub(crate) fn instruction_id(document: &IrDocument, f: usize, r: usize, i: usize) -> String {
    Inputs::new(document).id(f, r, i)
}

/// Fill IDs in untrusted builder data. This does not verify or grant success.
pub fn assign_instruction_ids(document: &mut IrDocument) -> Result<(), Failure> {
    header(document)?;
    crate::v2::verify::census(document)?;
    // Borrow only the immutable header while assigning bounded instruction IDs.
    let fields = [
        document.source.sha256.clone(),
        document.source.label.clone(),
        document.language_version.clone(),
        document.schema_version.clone(),
        document.registry.schema_version.clone(),
        document.registry.fingerprint.clone(),
        document.build_seed.clone(),
    ];
    let inputs = Inputs {
        fields: fields.each_ref().map(String::as_str),
    };
    for (f, function) in document.functions.iter_mut().enumerate() {
        for (r, region) in function.regions.iter_mut().enumerate() {
            for (i, instruction) in region.instructions.iter_mut().enumerate() {
                instruction.id = inputs.id(f, r, i);
            }
        }
    }
    Ok(())
}
