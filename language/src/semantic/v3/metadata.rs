//! Metadata is descriptive: no privilege, facility or source availability grant.
use super::super::{CheckFailure, CheckedProgram, ResourceFailure, ResourceKind};
use crate::ast_v3::ParsedSourceV3;
use jocky_forensic::contracts::v2::Registry;
use jocky_shared::compiler::{Capability, Privilege, v2::Platform};
use sha2::{Digest, Sha256};
#[derive(Clone, Debug)]
pub struct FunctionMetadataV3 {
    pub name: String,
    pub required_privilege: Privilege,
    pub capabilities: Vec<Capability>,
    pub supported_platforms: Vec<Platform>,
    pub unavailable_dependencies: Vec<String>,
}
pub(super) fn summaries(
    syntax: &ParsedSourceV3,
    checked: &CheckedProgram,
    registry: &Registry,
) -> Vec<FunctionMetadataV3> {
    syntax
        .program
        .functions
        .iter()
        .zip(checked.function_metadata())
        .map(|(decl, summary)| {
            let dependencies: Vec<String> = summary
                .unavailable_dependencies()
                .map(str::to_owned)
                .collect();
            let mut platforms = Platform::ALL.to_vec();
            for name in &dependencies {
                if let Ok(contract) = registry.lookup(name) {
                    platforms.retain(|p| contract.supported_platforms.contains(p));
                }
            }
            FunctionMetadataV3 {
                name: format!("{}.{}", syntax.program.module.name.text, decl.name.text),
                required_privilege: summary.required_privilege(),
                capabilities: summary.capabilities().to_vec(),
                supported_platforms: platforms,
                unavailable_dependencies: dependencies,
            }
        })
        .collect()
}
pub(crate) fn registry_fingerprint(registry: &Registry) -> Result<String, CheckFailure> {
    let mut functions = registry.functions().cloned().collect::<Vec<_>>();
    for f in &mut functions {
        f.supported_platforms.sort();
        f.possible_errors.sort_by_key(|e| e.code);
    }
    let value = serde_json::json!({"schema_version":"2.0.0","functions":functions});
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| ResourceFailure::new(ResourceKind::RegistryBytes, None))?;
    if bytes.len() > 1_048_576 {
        return Err(ResourceFailure::new(ResourceKind::RegistryBytes, None).into());
    }
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}
