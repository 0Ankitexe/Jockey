//! Portable static checking over the v3 AST and exact v2 registry snapshot.
pub(crate) mod metadata;
mod resolve;
use super::{CheckFailure, CheckedProgram};
use crate::{
    SourceFile,
    ast::{Program, TargetDeclaration, TargetPlatformNode},
    ast_v3::ParsedSourceV3,
    source::ParsedSource,
};
use jocky_forensic::contracts::v2::Registry;
use jocky_shared::compiler::v2::Platform;

/// Constructed only after the portable parser, v2 target rules and full legacy
/// type/flow engine succeed. No native-provider or execution interface exists.
#[derive(Debug)]
pub struct CheckedProgramV3 {
    syntax: ParsedSourceV3,
    checked: CheckedProgram,
    registry: Registry,
    metadata: Vec<metadata::FunctionMetadataV3>,
    fingerprint: String,
}
impl CheckedProgramV3 {
    pub fn syntax(&self) -> &ParsedSourceV3 {
        &self.syntax
    }
    pub fn registry_snapshot(&self) -> &Registry {
        &self.registry
    }
    pub fn checked_core(&self) -> &CheckedProgram {
        &self.checked
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn function_metadata(&self) -> &[metadata::FunctionMetadataV3] {
        &self.metadata
    }
    pub fn selected_targets(&self) -> impl Iterator<Item = Platform> + '_ {
        self.syntax.program.target.platforms.iter().map(|p| p.kind)
    }
}

pub fn analyze(
    source: SourceFile<'_>,
    registry: &Registry,
) -> Result<CheckedProgramV3, CheckFailure> {
    super::limits::require(super::ResourceKind::SourceBytes, source.text.len(), None)?;
    let syntax = crate::parse_source_v3(source).map_err(CheckFailure::Syntax)?;
    let mapped = ParsedSource {
        program: Program {
            span: syntax.program.span,
            module: syntax.program.module.clone(),
            target: TargetDeclaration {
                span: syntax.program.target.span,
                platforms: {
                    let mut values = Vec::new();
                    for p in &syntax.program.target.platforms {
                        let mapped = match p.kind {
                            Platform::Windows => TargetPlatformNode::Windows { span: p.span },
                            Platform::Ubuntu | Platform::Linux => {
                                TargetPlatformNode::Ubuntu { span: p.span }
                            }
                        };
                        if !values.iter().any(|v| {
                            matches!(
                                (v, &mapped),
                                (
                                    TargetPlatformNode::Windows { .. },
                                    TargetPlatformNode::Windows { .. }
                                ) | (
                                    TargetPlatformNode::Ubuntu { .. },
                                    TargetPlatformNode::Ubuntu { .. }
                                )
                            )
                        }) {
                            values.push(mapped);
                        }
                    }
                    values
                },
            },
            functions: syntax.program.functions.clone(),
            run: syntax.program.run.clone(),
        },
        profile: syntax.profile.clone(),
    };
    super::limits::census(&mapped)?;
    resolve::check_targets(&syntax, registry)?;
    let compatible = resolve::legacy_view(registry)?;
    let checked = super::analyze_parsed(source, &compatible, mapped)?;
    let metadata = metadata::summaries(&syntax, &checked, registry);
    let fingerprint = metadata::registry_fingerprint(registry)?;
    Ok(CheckedProgramV3 {
        syntax,
        checked,
        registry: registry.clone(),
        metadata,
        fingerprint,
    })
}
