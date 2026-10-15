//! Private product worker entry; callable only through the reserved binary argument.
use jocky_shared::collection::{Code, launch::WorkerLaunch, worker::Job};
use std::os::{
    fd::{AsFd, OwnedFd},
    unix::net::UnixStream,
};

/// The binary calls this only for its reserved private argument. Ordinary
/// stdio is a direct invocation and remains on the typed CLI rejection path.
/// An owned socket that fails any later check is a private protocol failure.
#[cfg(target_os = "linux")]
pub(crate) fn run_if_owned_channel() -> Option<u8> {
    use rustix::net::{AddressFamily, SocketType, sockopt};
    use std::{os::unix::net::UnixStream, time::Duration};
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if sockopt::socket_domain(&stdin).ok() != Some(AddressFamily::UNIX)
        || sockopt::socket_type(&stdin).ok() != Some(SocketType::STREAM)
    {
        return None;
    }
    let run = (|| {
        if std::env::vars_os().next().is_some()
            || std::env::current_dir().map_err(|_| Code::WorkerProtocol)?
                != std::path::Path::new("/")
        {
            return Err(Code::WorkerProtocol);
        }
        let mut reader = UnixStream::from(
            stdin
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| Code::WorkerProtocol)?,
        );
        let mut writer = UnixStream::from(
            stdout
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| Code::WorkerProtocol)?,
        );
        reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| Code::WorkerProtocol)?;
        writer
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| Code::WorkerProtocol)?;
        let (launch, handles) = super::entry::receive_owned_launch(&mut reader, &writer)?;
        match launch.job {
            Job::Collect => run_collect(&mut reader, &mut writer, &launch, &handles),
            Job::Publish => run_publish(&mut reader, &mut writer, &launch, &handles),
        }
    })();
    Some(match run {
        Ok(()) => 0,
        Err(code) => {
            use std::io::Write;
            let _ = writeln!(std::io::stderr().lock(), "WorkerEntry:{}", code.as_str());
            3
        }
    })
}

fn run_collect(
    reader: &mut UnixStream,
    writer: &mut UnixStream,
    launch: &WorkerLaunch,
    handles: &[OwnedFd],
) -> Result<(), Code> {
    let mut clock = NativeClock;
    let mut admitted = super::start::receive_committed(reader, launch, &mut clock)?;
    use super::order::Direction;
    use jocky_shared::collection::{
        inputs::CollectionVersion,
        outcomes::WorkUsed,
        worker::{Body, Done, Job, Ready, WorkerFrame},
    };
    let ready = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Ready(Ready { job: Job::Collect }),
    };
    admitted.session.accept(Direction::Worker, &ready)?;
    super::protocol::write_frame(writer, &ready)?;
    let zero = WorkUsed {
        entries: 0,
        indicator_comparisons: 0,
        errors: 0,
        source_bytes: 0,
        staging_bytes: 0,
        retained_bytes: 0,
    };
    let mut next_seq = 1;
    let result = if handles.is_empty()
        && admitted.collector != jocky_shared::collection::outcomes::Collector::Services
    {
        None
    } else {
        use jocky_shared::collection::outcomes::Collector;
        match admitted.collector {
            Collector::System => Some(crate::collectors::system::collect_owned(
                &admitted.context,
                launch,
                handles,
                &mut clock,
            )?),
            Collector::Processes => Some(crate::collectors::processes::collect_owned(
                &admitted.context,
                launch,
                handles,
                &mut clock,
            )?),
            Collector::Connections => Some(crate::collectors::connections::collect_owned(
                &admitted.context,
                launch,
                handles,
                &mut clock,
            )?),
            Collector::Files => Some(crate::collectors::files::collect_owned(
                &admitted.context,
                launch,
                handles,
                &mut clock,
            )?),
            Collector::Services => Some(crate::collectors::services::collect_owned(
                &admitted.context,
                launch,
                &mut clock,
            )?),
            Collector::Persistence => Some(crate::collectors::persistence::collect_owned(
                &admitted.context,
                launch,
                handles,
                &mut clock,
            )?),
            Collector::Events => Some(crate::collectors::events::collect_owned(
                &admitted.context,
                launch,
                handles,
                &mut clock,
            )?),
            Collector::Drivers => Some(crate::collectors::drivers::collect_owned(
                &admitted.context,
                launch,
                handles,
                &mut clock,
            )?),
            _ => None,
        }
    };
    if let Some(result) = &result {
        for record in &result.records {
            let frame = WorkerFrame {
                schema_version: CollectionVersion::V1,
                frame_seq: next_seq,
                collection_id: launch.collection_id.clone(),
                body: Body::Record(Box::new(record.clone())),
            };
            admitted.session.accept(Direction::Worker, &frame)?;
            super::protocol::write_frame(writer, &frame)?;
            next_seq += 1;
        }
        for error in &result.errors {
            let frame = WorkerFrame {
                schema_version: CollectionVersion::V1,
                frame_seq: next_seq,
                collection_id: launch.collection_id.clone(),
                body: Body::ItemError(error.clone()),
            };
            admitted.session.accept(Direction::Worker, &frame)?;
            super::protocol::write_frame(writer, &frame)?;
            next_seq += 1;
        }
    }
    let done = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: next_seq,
        collection_id: launch.collection_id.clone(),
        body: Body::Done(Done::Collect {
            outcome: result
                .as_ref()
                .map(|part| part.outcome.clone())
                .unwrap_or_else(|| {
                    jocky_forensic::collection::outcome::unsupported(admitted.collector)
                }),
            usage: result.map(|part| part.usage).unwrap_or(zero),
        }),
    };
    admitted.session.accept(Direction::Worker, &done)?;
    super::protocol::write_frame(writer, &done)?;
    admitted.session.finish()?;
    admitted.decoder.finish()?;
    Ok(())
}

fn run_publish(
    reader: &mut UnixStream,
    writer: &mut UnixStream,
    launch: &WorkerLaunch,
    handles: &[OwnedFd],
) -> Result<(), Code> {
    use super::{
        accounting::PublicationQuota,
        order::Direction,
        protocol::{self, FrameDecoder},
        session::{Receipt, Session},
    };
    use jocky_shared::collection::{
        inputs::CollectionVersion,
        report::{StatusCode, SuccessCode},
        worker::{Body, Done, Ready, Start, WorkerFrame},
    };
    let [output] = handles else {
        return Err(Code::WorkerProtocol);
    };
    let mut session = Session::for_launch(launch)?;
    let mut decoder = FrameDecoder::new(launch.collection_id.clone());
    let start = protocol::read_frame(reader, &mut decoder)?;
    let Body::Start(Start::Publish {
        context,
        output_descriptor,
        output_name,
        report_byte_length,
        report_sha256,
    }) = &start.body
    else {
        return Err(Code::WorkerProtocol);
    };
    if *output_descriptor != launch.descriptors[0].fd {
        return Err(Code::WorkerProtocol);
    }
    session.accept(Direction::Parent, &start)?;
    let mut last = crate::cli::clock::read()?;
    let mut check_deadline = || {
        let now = crate::cli::clock::read()?;
        let deadline = launch
            .invocation_origin
            .monotonic_ms
            .checked_add(launch.global_limits.timeout_ms)
            .ok_or(Code::ResourceLimit)?;
        if now.monotonic_ms < last.monotonic_ms
            || now.utc.unix_nanos() < last.utc.unix_nanos()
            || now.monotonic_ms < launch.launch_observed.monotonic_ms
            || now.utc.unix_nanos() < launch.launch_observed.utc.unix_nanos()
        {
            return Err(Code::ClockUncertain);
        }
        if now.monotonic_ms >= deadline {
            return Err(Code::Timeout);
        }
        last = now;
        Ok(())
    };
    check_deadline()?;
    let ready = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Ready(Ready { job: Job::Publish }),
    };
    session.accept(Direction::Worker, &ready)?;
    protocol::write_frame(writer, &ready)?;
    // Transfer has a byte ceiling and an invocation deadline. A separate
    // frame-count ceiling would reject legal short chunks before commit.
    let raw = loop {
        check_deadline()?;
        let frame = protocol::read_frame(reader, &mut decoder)?;
        let receipt = session.accept(Direction::Parent, &frame)?;
        if let Receipt::Report(raw) = receipt {
            break raw;
        }
    };
    let mut quota = PublicationQuota::new(&launch.global_limits)?;
    let installed = crate::publication::install_transferred_detailed(
        output.as_fd(),
        output_name,
        &raw,
        context,
        &mut quota,
        &mut check_deadline,
    );
    let (code, sha256, byte_length, created_identity) = match installed {
        Ok(identity) => (
            StatusCode::Success(SuccessCode::PublishedComplete),
            Some(report_sha256.clone()),
            Some(*report_byte_length),
            Some(identity),
        ),
        Err(failure) => (
            StatusCode::Error(match failure.code {
                Code::OutputExists | Code::CleanupIncomplete => failure.code,
                _ => Code::PublicationFailed,
            }),
            None,
            None,
            failure.created_identity,
        ),
    };
    let done = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 1,
        collection_id: launch.collection_id.clone(),
        body: Body::Done(Done::Publish {
            code,
            sha256,
            byte_length,
            created_identity,
        }),
    };
    session.accept(Direction::Worker, &done)?;
    protocol::write_frame(writer, &done)?;
    session.finish()?;
    decoder.finish()?;
    Ok(())
}

#[cfg(target_os = "linux")]
struct NativeClock;
#[cfg(target_os = "linux")]
impl jocky_forensic::collection::clock::Clock for NativeClock {
    fn read(&mut self) -> Result<jocky_forensic::collection::ClockReading, Code> {
        crate::cli::clock::read()
    }
}
