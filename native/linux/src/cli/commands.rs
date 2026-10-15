use super::{args::Command, config};
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    report::{Stage, StatusCode, SuccessCode},
};

pub(crate) struct Reply {
    pub(crate) code: StatusCode,
    pub(crate) stage: Stage,
    pub(crate) identifiers: Option<(Uuid, Uuid, Uuid)>,
    pub(crate) report: Option<(String, u64)>,
    pub(crate) interrupted: bool,
}
impl Reply {
    fn success(code: SuccessCode, stage: Stage) -> Self {
        Self {
            code: StatusCode::Success(code),
            stage,
            identifiers: None,
            report: None,
            interrupted: false,
        }
    }
    fn error(code: Code, stage: Stage) -> Self {
        Self {
            code: StatusCode::Error(code),
            stage,
            identifiers: None,
            report: None,
            interrupted: false,
        }
    }
}

pub(super) fn execute(command: Command) -> Reply {
    match command {
        Command::Help => Reply::success(SuccessCode::Help, Stage::Arguments),
        Command::Version => Reply::success(SuccessCode::Version, Stage::Build),
        Command::WorkerDirect => Reply::error(Code::NotImplemented, Stage::Admission),
        Command::Collect {
            required,
            indicators,
            output,
        } => {
            let result = (|| {
                let start = super::clock::read().map_err(|code| (code, Stage::Admission, false))?;
                let paths = config::ConfigPaths::new(
                    required.each_ref().map(String::as_str),
                    indicators.as_deref(),
                )
                .map_err(|code| (code, Stage::Configuration, false))?;
                let configuration = config::read_configuration(&paths)
                    .map_err(|code| (code, Stage::Configuration, false))?;
                config::validate_output(&output)
                    .map_err(|code| (code, Stage::Configuration, false))?;
                super::collect::execute(&configuration, &output, start)
            })();
            match result {
                Ok(reply) => reply,
                Err((code, stage, interrupted)) => {
                    let mut reply = Reply::error(code, stage);
                    reply.interrupted = interrupted;
                    reply
                }
            }
        }
        Command::Validate {
            required,
            indicators,
        } => {
            let result = (|| {
                let paths = config::ConfigPaths::new(
                    required.each_ref().map(String::as_str),
                    indicators.as_deref(),
                )?;
                let configuration = config::read_configuration(&paths)?;
                let now = super::clock::read()?;
                configuration.validate(now)
            })();
            match result {
                Ok(ids) => {
                    let mut reply = Reply::success(SuccessCode::InputsValid, Stage::Validation);
                    reply.identifiers = Some((ids.collection_id, ids.endpoint_id, ids.case_id));
                    reply
                }
                Err(code) => Reply::error(code, Stage::Configuration),
            }
        }
        Command::VerifyReport(path) => {
            let result = config::read_report(&path).and_then(|raw| {
                jocky_forensic::collection::verify::verify_report(&raw)
                    .map(|report| (report, raw.len() as u64))
            });
            match result {
                Ok((report, length)) => {
                    let mut reply = Reply::success(SuccessCode::ReportValid, Stage::Verification);
                    reply.identifiers = Some((
                        report.context.collection_id,
                        report.context.endpoint_id,
                        report.context.case_id,
                    ));
                    reply.report = Some((report.content_sha256, length));
                    reply
                }
                Err(code) => Reply::error(code, Stage::Verification),
            }
        }
    }
}
