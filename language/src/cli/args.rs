use std::ffi::OsString;

pub const USAGE: &str = concat!(
    "Usage:\n",
    "  jockyc parse <file>\n",
    "  jockyc parse <file> --emit-ast json\n",
    "  jockyc check <file>\n",
    "  jockyc check <file> --diagnostic-format human|json\n",
    "  jockyc modules list\n",
    "  jockyc modules describe <qualified-name>\n",
    "  jockyc build-ir <file> --output <file.json>\n",
    "  jockyc verify-ir <file.json>\n",
    "  jockyc parse <file> --language-version 3.0.0 [--emit-ast json]\n",
    "  jockyc check <file> --language-version 3.0.0 [--diagnostic-format human|json]\n",
    "  jockyc build-ir <file> --language-version 3.0.0 --output <file.json>\n",
    "  jockyc modules list --registry-version 2.0.0\n",
    "  jockyc modules describe <qualified-name> --registry-version 2.0.0\n",
    "  jockyc run-fixture <file> --fixture <fixture-directory>\n",
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AstFormat {
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticFormat {
    Human,
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    PortableParse {
        path: String,
        emit_ast: Option<AstFormat>,
    },
    PortableCheck {
        path: String,
        format: DiagnosticFormat,
    },
    PortableBuildIr {
        path: String,
        output: String,
    },
    PortableModulesList,
    PortableModulesDescribe {
        name: String,
    },
    PortableRunFixture {
        path: String,
        directory: String,
    },
    RunFixture {
        path: String,
        directory: String,
    },
    VerifyIr {
        path: String,
    },
    BuildIr {
        path: String,
        output: String,
    },
    Parse {
        path: String,
        emit_ast: Option<AstFormat>,
    },
    Check {
        path: String,
        format: DiagnosticFormat,
    },
    ModulesList,
    ModulesDescribe {
        name: String,
    },
}

impl Command {
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::PortableParse { path, .. }
            | Self::PortableCheck { path, .. }
            | Self::PortableBuildIr { path, .. }
            | Self::PortableRunFixture { path, .. }
            | Self::Parse { path, .. }
            | Self::RunFixture { path, .. }
            | Self::Check { path, .. }
            | Self::BuildIr { path, .. }
            | Self::VerifyIr { path } => Some(path),
            Self::ModulesList
            | Self::ModulesDescribe { .. }
            | Self::PortableModulesList
            | Self::PortableModulesDescribe { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliError {
    InvalidCommand,
    UnsupportedVersion,
    InvalidPathEncoding,
    InputNotFound,
    InputUnreadable,
    InvalidUtf8,
    ResourceLimit,
    SourceTooLarge,
    ReportTooLarge,
    InvalidRegistry,
    ModuleNotFound,
    OutputFailure,
}

impl CliError {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::InvalidCommand => "invalid-command",
            Self::UnsupportedVersion => "unsupported-version",
            Self::InvalidPathEncoding => "invalid-path-encoding",
            Self::InputNotFound => "input-not-found",
            Self::InputUnreadable => "input-unreadable",
            Self::InvalidUtf8 => "invalid-utf8",
            Self::ResourceLimit | Self::SourceTooLarge | Self::ReportTooLarge => "resource-limit",
            Self::InvalidRegistry => "invalid-registry",
            Self::ModuleNotFound => "module-not-found",
            Self::OutputFailure => "output-failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutcome {
    Success,
    SyntaxFailure,
    CommandOrHostFailure,
}

impl ProcessOutcome {
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::SyntaxFailure => 1,
            Self::CommandOrHostFailure => 2,
        }
    }
}

/// Parse arguments after the executable name into the implemented command set.
pub fn args_os<I>(arguments: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, path, option, version]
            if command == "parse" && option == "--language-version" && version == "3.0.0" =>
        {
            Ok(Command::PortableParse {
                path: portable_path(path)?,
                emit_ast: None,
            })
        }
        [command, path, option, version, emit, format]
            if command == "parse"
                && option == "--language-version"
                && version == "3.0.0"
                && emit == "--emit-ast"
                && format == "json" =>
        {
            Ok(Command::PortableParse {
                path: portable_path(path)?,
                emit_ast: Some(AstFormat::Json),
            })
        }
        [command, path, option, version]
            if command == "check" && option == "--language-version" && version == "3.0.0" =>
        {
            Ok(Command::PortableCheck {
                path: portable_path(path)?,
                format: DiagnosticFormat::Human,
            })
        }
        [command, path, option, version, diagnostic, format]
            if command == "check"
                && option == "--language-version"
                && version == "3.0.0"
                && diagnostic == "--diagnostic-format"
                && (format == "human" || format == "json") =>
        {
            Ok(Command::PortableCheck {
                path: portable_path(path)?,
                format: if format == "json" {
                    DiagnosticFormat::Json
                } else {
                    DiagnosticFormat::Human
                },
            })
        }
        [command, path, option, version, output, destination]
            if command == "build-ir"
                && option == "--language-version"
                && version == "3.0.0"
                && output == "--output" =>
        {
            Ok(Command::PortableBuildIr {
                path: portable_path(path)?,
                output: portable_path(destination)?,
            })
        }
        [command, action, option, version]
            if command == "modules"
                && action == "list"
                && option == "--registry-version"
                && version == "2.0.0" =>
        {
            Ok(Command::PortableModulesList)
        }
        [command, action, name, option, version]
            if command == "modules"
                && action == "describe"
                && option == "--registry-version"
                && version == "2.0.0" =>
        {
            Ok(Command::PortableModulesDescribe {
                name: portable_path(name)?,
            })
        }
        [command, path, option, directory, version_option, version]
            if command == "run-fixture"
                && option == "--fixture"
                && version_option == "--language-version"
                && version == "3.0.0" =>
        {
            Ok(Command::PortableRunFixture {
                path: portable_path(path)?,
                directory: portable_path(directory)?,
            })
        }
        [command, path, version_option, version, option, directory]
            if command == "run-fixture"
                && version_option == "--language-version"
                && version == "3.0.0"
                && option == "--fixture" =>
        {
            Ok(Command::PortableRunFixture {
                path: portable_path(path)?,
                directory: portable_path(directory)?,
            })
        }
        [command, path, option, directory] if command == "run-fixture" && option == "--fixture" => {
            let path = utf8_path(path)?;
            let directory = utf8_path(directory)?;
            if path.is_empty()
                || directory.is_empty()
                || path.starts_with('-')
                || directory.starts_with('-')
            {
                return Err(CliError::InvalidCommand);
            }
            Ok(Command::RunFixture { path, directory })
        }
        [command, path] if command == "verify-ir" => {
            let path = utf8_path(path)?;
            if path.is_empty() || path.starts_with('-') {
                return Err(CliError::InvalidCommand);
            }
            Ok(Command::VerifyIr { path })
        }
        [command, path, option, output] if command == "build-ir" && option == "--output" => {
            let path = utf8_path(path)?;
            let output = utf8_path(output)?;
            if path.is_empty()
                || output.is_empty()
                || path.starts_with('-')
                || output.starts_with('-')
            {
                return Err(CliError::InvalidCommand);
            }
            Ok(Command::BuildIr { path, output })
        }
        [command, action] if command == "modules" && action == "list" => Ok(Command::ModulesList),
        [command, action, name] if command == "modules" && action == "describe" => {
            let name = name.to_str().ok_or(CliError::InvalidCommand)?;
            if name.starts_with('-') {
                return Err(CliError::InvalidCommand);
            }
            Ok(Command::ModulesDescribe {
                name: name.to_owned(),
            })
        }
        [command, path] if command == "parse" => Ok(Command::Parse {
            path: utf8_path(path)?,
            emit_ast: None,
        }),
        [command, path, option, format]
            if command == "parse" && option == "--emit-ast" && format == "json" =>
        {
            Ok(Command::Parse {
                path: utf8_path(path)?,
                emit_ast: Some(AstFormat::Json),
            })
        }
        [command, path] if command == "check" => Ok(Command::Check {
            path: utf8_path(path)?,
            format: DiagnosticFormat::Human,
        }),
        [command, path, option, format]
            if command == "check"
                && option == "--diagnostic-format"
                && (format == "human" || format == "json") =>
        {
            Ok(Command::Check {
                path: utf8_path(path)?,
                format: if format == "json" {
                    DiagnosticFormat::Json
                } else {
                    DiagnosticFormat::Human
                },
            })
        }
        _ => Err(CliError::InvalidCommand),
    }
}

// Only an exact supported shape selects JSON before the path's UTF-8 check.
pub(super) fn is_json_check(arguments: &[OsString]) -> bool {
    matches!(arguments, [command, _, option, format] if command == "check" && option == "--diagnostic-format" && format == "json")
        || matches!(arguments, [command, _, option, version, diagnostic, format] if command == "check" && option == "--language-version" && version == "3.0.0" && diagnostic == "--diagnostic-format" && format == "json")
}

fn utf8_path(path: &OsString) -> Result<String, CliError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(CliError::InvalidPathEncoding)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    #[test]
    fn fixture_shape_requires_explicit_source_and_directory_only() {
        let command = args_os(
            ["run-fixture", "source.jky", "--fixture", "fixtures/ubuntu"].map(OsString::from),
        )
        .unwrap();
        assert_eq!(
            command,
            Command::RunFixture {
                path: "source.jky".into(),
                directory: "fixtures/ubuntu".into()
            }
        );
        assert_eq!(command.path(), Some("source.jky"));
        for args in [
            ["run-fixture", "", "--fixture", "dir"],
            ["run-fixture", "source", "--fixture", ""],
            ["run-fixture", "source", "--fixture", "--live"],
            ["run-fixture", "--source", "--fixture", "dir"],
            ["run-fixture", "source", "--provider", "dir"],
        ] {
            assert_eq!(
                args_os(args.map(OsString::from)),
                Err(CliError::InvalidCommand)
            );
        }
    }
    #[test]
    fn verify_shape_has_exactly_one_explicit_artifact() {
        let command = args_os(["verify-ir", "artifact.json"].map(OsString::from)).unwrap();
        assert_eq!(
            command,
            Command::VerifyIr {
                path: "artifact.json".into()
            }
        );
        assert_eq!(command.path(), Some("artifact.json"));
        for args in [
            vec!["verify-ir"],
            vec!["verify-ir", ""],
            vec!["verify-ir", "--help"],
            vec!["verify-ir", "a", "b"],
        ] {
            assert_eq!(
                args_os(args.into_iter().map(OsString::from)),
                Err(CliError::InvalidCommand)
            );
        }
    }
    #[test]
    fn module_commands_have_no_source_path_and_accept_only_exact_shapes() {
        let list = args_os(["modules", "list"].map(OsString::from)).unwrap();
        assert_eq!(list, Command::ModulesList);
        assert_eq!(list.path(), None);
        let describe =
            args_os(["modules", "describe", "forensic.process.list"].map(OsString::from)).unwrap();
        assert_eq!(
            describe,
            Command::ModulesDescribe {
                name: "forensic.process.list".into()
            }
        );
        assert_eq!(describe.path(), None);
        for operation in ["parse", "check"] {
            assert_eq!(
                args_os([operation, "a.jky"].map(OsString::from))
                    .unwrap()
                    .path(),
                Some("a.jky")
            );
        }
        for invalid in [
            vec!["modules"],
            vec!["modules", "describe"],
            vec!["modules", "list", "extra"],
            vec!["modules", "describe", "name", "extra"],
            vec!["modules", "describe", "--help"],
            vec!["modules", "--registry", "file"],
            vec!["modules", "name", "describe"],
        ] {
            assert_eq!(
                args_os(invalid.into_iter().map(OsString::from)),
                Err(CliError::InvalidCommand)
            );
        }
    }
    #[test]
    #[cfg(unix)]
    fn non_utf8_module_name_is_a_command_error_without_lossy_decoding() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(
            args_os([
                OsString::from("modules"),
                OsString::from("describe"),
                OsString::from_vec(vec![0xff])
            ]),
            Err(CliError::InvalidCommand)
        );
    }
}

fn portable_path(value: &OsString) -> Result<String, CliError> {
    let text = utf8_path(value)?;
    if text.is_empty() || text.starts_with('-') {
        Err(CliError::InvalidCommand)
    } else {
        Ok(text)
    }
}
