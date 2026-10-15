//! Explicit v3/v2 compiler dispatch, with no native collector dependency.
use super::{
    AstFormat, CliError, DiagnosticFormat, ProcessOutcome, SourceReader,
    execute::{ReadFailure, finish_cli_error},
};
use crate::{
    SourceFile, escape_filename, parse_source_v3, render_diagnostics,
    report::{self, RenderError},
    semantic::{CheckFailure, limits::MAX_SOURCE_BYTES, v3},
};
use jocky_forensic::contracts::v2::{Registry, builtin_registry};
use std::{
    io::{self, Write},
    path::Path,
};

pub(super) fn source<R: SourceReader>(
    path: &str,
    action: Action,
    reader: &mut R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ProcessOutcome {
    let bytes = match reader.read_bounded(Path::new(path), MAX_SOURCE_BYTES) {
        Ok(bytes) => bytes,
        Err(ReadFailure::ResourceLimit) => {
            return finish_cli_error(CliError::SourceTooLarge, Some(path), stderr);
        }
        Err(ReadFailure::Input(io::ErrorKind::NotFound)) => {
            return finish_cli_error(CliError::InputNotFound, Some(path), stderr);
        }
        Err(_) => return finish_cli_error(CliError::InputUnreadable, Some(path), stderr),
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(v) => v,
        Err(_) => return finish_cli_error(CliError::InvalidUtf8, Some(path), stderr),
    };
    let source = SourceFile::new(path, text);
    match action {
        Action::Parse(format) => match parse_source_v3(source) {
            Ok(parsed) => {
                let bytes = match format {
                    None => format!("parsed: {}\n", escape_filename(path)).into_bytes(),
                    Some(AstFormat::Json) => match parsed.to_pretty_json() {
                        Ok(v) => v,
                        Err(_) => return finish_cli_error(CliError::OutputFailure, None, stderr),
                    },
                };
                write(stdout, stderr, &bytes, ProcessOutcome::Success)
            }
            Err(diagnostics) => write_error(
                stderr,
                render_diagnostics(source, &diagnostics).as_bytes(),
                ProcessOutcome::SyntaxFailure,
            ),
        },
        Action::Check(format) => {
            let registry = match builtin_registry() {
                Ok(v) => v,
                Err(_) => return finish_cli_error(CliError::InvalidRegistry, None, stderr),
            };
            let result = v3::analyze(source, registry);
            if format == DiagnosticFormat::Json {
                let bytes = match &result {
                    Ok(checked) => report::v2::from_checked(source, checked),
                    Err(error) => report::v2::from_failure(source, error, registry),
                };
                let status = match result {
                    Ok(_) => ProcessOutcome::Success,
                    Err(CheckFailure::Resource(_)) => ProcessOutcome::CommandOrHostFailure,
                    Err(_) => ProcessOutcome::SyntaxFailure,
                };
                return match bytes {
                    Ok(bytes) => write(stdout, stderr, &bytes, status),
                    Err(_) => finish_cli_error(CliError::OutputFailure, None, stderr),
                };
            }
            let (rendered, status) = match result {
                Ok(checked) => (
                    report::render_semantic(source, checked.checked_core().warnings()),
                    ProcessOutcome::Success,
                ),
                Err(error) => {
                    let status = if matches!(error, CheckFailure::Resource(_)) {
                        ProcessOutcome::CommandOrHostFailure
                    } else {
                        ProcessOutcome::SyntaxFailure
                    };
                    (report::render_failure(source, &error), status)
                }
            };
            match rendered {
                Ok(value) => write_error(stderr, value.as_bytes(), status),
                Err(RenderError::ResourceLimit) => {
                    finish_cli_error(CliError::ReportTooLarge, None, stderr)
                }
                Err(_) => finish_cli_error(CliError::OutputFailure, None, stderr),
            }
        }
    }
}
pub(super) enum Action {
    Parse(Option<AstFormat>),
    Check(DiagnosticFormat),
}
fn write(
    out: &mut dyn Write,
    stderr: &mut dyn Write,
    bytes: &[u8],
    status: ProcessOutcome,
) -> ProcessOutcome {
    if out.write_all(bytes).is_ok() && out.flush().is_ok() {
        status
    } else {
        finish_cli_error(CliError::OutputFailure, None, stderr)
    }
}
pub(super) fn modules(
    name: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ProcessOutcome {
    let registry = match builtin_registry() {
        Ok(v) => v,
        Err(_) => return finish_cli_error(CliError::InvalidRegistry, None, stderr),
    };
    let result = match name {
        None => list(registry),
        Some(name) => match describe(registry, name) {
            Some(v) => v,
            None => return finish_cli_error(CliError::ModuleNotFound, Some(name), stderr),
        },
    };
    write(stdout, stderr, result.as_bytes(), ProcessOutcome::Success)
}
fn list(registry: &Registry) -> String {
    registry
        .functions()
        .map(|f| format!("{} {} unavailable\n", f.qualified_name(), f.version))
        .collect()
}
fn describe(registry: &Registry, name: &str) -> Option<String> {
    let f = registry.lookup(name).ok()?;
    let parameters = f
        .parameters
        .iter()
        .map(|p| format!("{}: {}", p.name, p.r#type))
        .collect::<Vec<_>>()
        .join(", ");
    let targets = f
        .supported_platforms
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "module: {}\nname: {}\nversion: {}\nparameters: ({parameters})\nresult: {}\nsupported_platforms: {targets}\nrequired_privilege: {}\ncapability: {}\nread_only: {}\nlab_only: {}\navailability: unavailable\n",
        f.module,
        f.name,
        f.version,
        f.result,
        f.required_privilege,
        f.capability,
        f.read_only,
        f.lab_only
    ))
}

fn write_error(stderr: &mut dyn Write, bytes: &[u8], status: ProcessOutcome) -> ProcessOutcome {
    if stderr.write_all(bytes).is_ok() && stderr.flush().is_ok() {
        status
    } else {
        ProcessOutcome::CommandOrHostFailure
    }
}
