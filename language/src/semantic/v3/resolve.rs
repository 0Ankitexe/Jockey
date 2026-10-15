//! Static target validation includes calls in unreachable and uncalled functions.
use super::super::{CheckFailure, SemanticDiagnostics, diagnostic::Cause};
use crate::{
    ast::{Block, Expression, QualifiedName, Statement},
    ast_v3::ParsedSourceV3,
};
use jocky_forensic::contracts::{Registry as LegacyRegistry, v2::Registry};
use jocky_shared::compiler::v2::Platform;

pub(super) fn check_targets(
    syntax: &ParsedSourceV3,
    registry: &Registry,
) -> Result<(), CheckFailure> {
    let selected: Vec<_> = syntax
        .program
        .target
        .platforms
        .iter()
        .map(|p| p.kind)
        .collect();
    let mut diagnostics = SemanticDiagnostics::default();
    for function in &syntax.program.functions {
        walk_block(&function.body, &selected, registry, &mut diagnostics);
    }
    if diagnostics.has_errors() {
        Err(CheckFailure::Semantic(diagnostics))
    } else {
        Ok(())
    }
}
fn walk_block(
    block: &Block,
    selected: &[Platform],
    registry: &Registry,
    diagnostics: &mut SemanticDiagnostics,
) {
    let mut blocks = vec![block];
    while let Some(block) = blocks.pop() {
        for statement in &block.statements {
            let mut expressions = Vec::new();
            match statement {
                Statement::Let { value, .. } | Statement::Return { value, .. } => {
                    expressions.push(value)
                }
                Statement::Call {
                    callee, arguments, ..
                } => {
                    check_name(callee, selected, registry, diagnostics);
                    expressions.extend(arguments);
                }
                Statement::If {
                    condition,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    expressions.push(condition);
                    blocks.push(then_branch);
                    if let Some(other) = else_branch {
                        blocks.push(other);
                    }
                }
                Statement::For {
                    collection, body, ..
                } => {
                    expressions.push(collection);
                    blocks.push(body);
                }
            }
            for root in expressions {
                let mut stack = vec![root];
                while let Some(expression) = stack.pop() {
                    if let Expression::Call {
                        callee, arguments, ..
                    } = expression
                    {
                        stack.extend(arguments);
                        check_name(callee, selected, registry, diagnostics);
                    }
                }
            }
        }
    }
}

fn check_name(
    callee: &QualifiedName,
    selected: &[Platform],
    registry: &Registry,
    diagnostics: &mut SemanticDiagnostics,
) {
    let name = callee
        .segments
        .iter()
        .map(|s| s.text.as_str())
        .collect::<Vec<_>>()
        .join(".");
    if let Ok(contract) = registry.lookup(&name)
        && selected
            .iter()
            .any(|p| !contract.supported_platforms.contains(p))
    {
        diagnostics.push(callee.span, Cause::UnsupportedTarget(name));
    }
}

pub(super) fn legacy_view(registry: &Registry) -> Result<LegacyRegistry, CheckFailure> {
    let mut functions = Vec::new();
    for contract in registry.functions() {
        let mut value = serde_json::to_value(contract).map_err(|_| {
            super::super::ResourceFailure::new(super::super::ResourceKind::RegistryBytes, None)
        })?;
        let mut platforms = Vec::new();
        if contract.supported_platforms.contains(&Platform::Windows) {
            platforms.push("windows");
        }
        if contract
            .supported_platforms
            .iter()
            .any(|p| matches!(p, Platform::Ubuntu | Platform::Linux))
        {
            platforms.push("ubuntu");
        }
        value["supported_platforms"] = serde_json::json!(platforms);
        functions.push(value);
    }
    let document = serde_json::json!({"schema_version":"1.0.0","functions":functions});
    LegacyRegistry::from_json(&document.to_string()).map_err(|_| {
        super::super::ResourceFailure::new(super::super::ResourceKind::RegistryBytes, None).into()
    })
}
