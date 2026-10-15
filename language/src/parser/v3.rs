//! Strict portable parser with original byte spans and no legacy fallback.
use super::{JockyParser, Rule, builder, recovery};
use crate::{
    DiagnosticSet, LabProfileDeclaration, SourceFile, Span,
    ast_v3::{ParsedSourceV3, ProgramV3, TargetDeclaration, TargetPlatformNode},
    diagnostic::{ResourceLimitFailure, ResourceLimitKind},
    lexer::{LexicalError, preflight},
};
use jocky_shared::compiler::v2::Platform;
use pest::{Parser as _, error::InputLocation, iterators::Pair};

pub(crate) fn parse_source(source: SourceFile<'_>) -> Result<ParsedSourceV3, DiagnosticSet> {
    let lexical = match preflight(source.text) {
        Ok(lexical) => lexical,
        Err(LexicalError::ResourceLimit { span, .. }) => {
            return Err(DiagnosticSet::from_one(
                ResourceLimitFailure::new(ResourceLimitKind::NestingDepth, span).into_diagnostic(),
            ));
        }
    };
    match JockyParser::parse(Rule::program_v3, source.text) {
        Ok(mut pairs) => {
            let pair = pairs
                .next()
                .ok_or_else(|| super::internal_build_failure(Span::new(0, 0)))?;
            build(pair, source.text.len())
        }
        Err(error) => {
            let offset = match error.location {
                InputLocation::Pos(p) | InputLocation::Span((p, _)) => p,
            };
            Err(recovery::recover(source, &lexical, offset))
        }
    }
}
fn span(pair: &Pair<'_, Rule>) -> Span {
    Span::new(pair.as_span().start(), pair.as_span().end())
}
fn build(pair: Pair<'_, Rule>, length: usize) -> Result<ParsedSourceV3, DiagnosticSet> {
    let mut module = None;
    let mut target = None;
    let mut functions = Vec::new();
    let mut run = None;
    let mut profile = None;
    for child in pair.into_inner() {
        match child.as_rule() {
            Rule::module_declaration => {
                module = Some(
                    builder::build_module(child)
                        .map_err(|e| super::internal_build_failure(e.span))?,
                )
            }
            Rule::target_declaration_v3 => target = Some(build_target(child)?),
            Rule::function_declaration => functions.push(
                builder::build_function(child)
                    .map_err(|e| super::internal_build_failure(e.span))?,
            ),
            Rule::run_statement => {
                run = Some(
                    builder::build_run(child).map_err(|e| super::internal_build_failure(e.span))?,
                )
            }
            Rule::lab_profile_declaration => {
                let decl_span = span(&child);
                let name = child
                    .into_inner()
                    .find(|p| p.as_rule() == Rule::lab_keyword)
                    .ok_or_else(|| super::internal_build_failure(decl_span))?;
                profile = Some(LabProfileDeclaration {
                    name_span: span(&name),
                    span: decl_span,
                });
            }
            Rule::EOI => (),
            _ => return Err(super::internal_build_failure(span(&child))),
        }
    }
    let invalid = || super::internal_build_failure(Span::new(0, length));
    Ok(ParsedSourceV3 {
        program: ProgramV3 {
            span: Span::new(0, length),
            module: module.ok_or_else(invalid)?,
            target: target.ok_or_else(invalid)?,
            functions,
            run,
        },
        profile,
    })
}
fn build_target(pair: Pair<'_, Rule>) -> Result<TargetDeclaration, DiagnosticSet> {
    let target_span = span(&pair);
    let selector = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::target_selector_v3)
        .ok_or_else(|| super::internal_build_failure(target_span))?;
    let platforms = selector
        .into_inner()
        .map(|p| {
            let kind = match p.as_rule() {
                Rule::windows_keyword => Platform::Windows,
                Rule::ubuntu_keyword => Platform::Ubuntu,
                Rule::linux_keyword => Platform::Linux,
                _ => return Err(super::internal_build_failure(span(&p))),
            };
            Ok(TargetPlatformNode {
                kind,
                span: span(&p),
            })
        })
        .collect::<Result<Vec<_>, DiagnosticSet>>()?;
    Ok(TargetDeclaration {
        platforms,
        span: target_span,
    })
}
