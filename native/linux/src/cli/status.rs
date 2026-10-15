use super::{args, commands};
use jocky_shared::collection::{
    Code,
    inputs::CollectionVersion,
    report::{Stage, Status, StatusCode},
};

pub struct Output {
    pub exit: u8,
    pub bytes: Vec<u8>,
    pub stderr: bool,
}

/// One bounded typed status. Writing it to a broken pipe remains the binary's
/// responsibility and must never result in exit 0.
pub fn run(args: &[String]) -> Output {
    let reply = match args::parse(args) {
        Ok(command) => commands::execute(command),
        Err(code) => commands::Reply {
            code: StatusCode::Error(code),
            stage: Stage::Arguments,
            identifiers: None,
            report: None,
            interrupted: false,
        },
    };
    render(reply)
}

/// Private status seam for offline precedence and exit-code tests.
pub(crate) fn render(reply: commands::Reply) -> Output {
    let reply = if matches!(
        reply.code,
        StatusCode::Success(
            jocky_shared::collection::report::SuccessCode::PublishedComplete
                | jocky_shared::collection::report::SuccessCode::PublishedPartial
                | jocky_shared::collection::report::SuccessCode::PublishedFailed
        )
    ) && reply.report.as_ref().is_none_or(|(digest, length)| {
        *length == 0
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) {
        commands::Reply {
            code: StatusCode::Error(Code::WorkerProtocol),
            stage: Stage::Finalization,
            identifiers: reply.identifiers,
            report: None,
            interrupted: reply.interrupted,
        }
    } else {
        reply
    };
    let (collection_id, endpoint_id, case_id) = match reply.identifiers {
        Some((collection, endpoint, case)) => (Some(collection), Some(endpoint), Some(case)),
        None => (None, None, None),
    };
    let (report_digest, byte_length) = match reply.report {
        Some((digest, length)) => (Some(digest), Some(length)),
        None => (None, None),
    };
    let stderr = matches!(
        reply.code,
        StatusCode::Error(_)
            | StatusCode::Success(jocky_shared::collection::report::SuccessCode::PublishedFailed)
    );
    let exit = if reply.interrupted && reply.code == StatusCode::Error(Code::Cancelled) {
        130
    } else {
        match reply.code {
            StatusCode::Success(
                jocky_shared::collection::report::SuccessCode::PublishedPartial,
            ) => 2,
            StatusCode::Success(jocky_shared::collection::report::SuccessCode::PublishedFailed) => {
                5
            }
            StatusCode::Success(_) => 0,
            StatusCode::Error(Code::NotImplemented | Code::Unsupported) => 4,
            StatusCode::Error(
                Code::InvalidInput
                | Code::UnsupportedVersion
                | Code::MissingAuthorisation
                | Code::AuthorisationDenied
                | Code::AuthorisationExpired
                | Code::ScopeDenied
                | Code::AliasDenied
                | Code::OutputExists
                | Code::NotFound,
            ) => 3,
            StatusCode::Error(_) => 5,
        }
    };
    let status = Status {
        schema_version: CollectionVersion::V1,
        code: reply.code,
        stage: reply.stage,
        collection_id,
        endpoint_id,
        case_id,
        report_digest,
        byte_length,
        residue_ordinal: None,
    };
    let mut bytes = match serde_json::to_vec(&status) {
        Ok(bytes) if bytes.len() <= 8192 => bytes,
        _ => return Output {
            exit: 5,
            bytes: b"{\"schema_version\":\"1.0.0\",\"code\":\"ResourceLimit\",\"stage\":\"finalization\"}\n".to_vec(),
            stderr: true,
        },
    };
    bytes.push(b'\n');
    Output {
        exit,
        bytes,
        stderr,
    }
}
