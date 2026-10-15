//! Pure decoders for data supplied by already admitted fixed sources.
use crate::{
    collection::Collected,
    sources::{
        procfs::{FixedMount, MountKind, Query},
        system::{machine_architecture, read_release},
    },
};
use jocky_forensic::collection::{
    ValidatedCollectionContext,
    budget::Counter,
    clock::Clock,
    context::OperationTarget,
    identity::{IdentityKind, derive_id},
};
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    identity::{ClockBasis, TimeObservation},
    launch::{HandleKind, WorkerLaunch},
    outcomes::{
        Collector, CollectorOutcome, CollectorStatus, Coverage, FacilityState, Field, ItemError,
    },
    records::{Adapter, Category, OsFamily, Payload, ProvenanceKind, SystemProfile},
};
use rustix::fd::{AsFd, OwnedFd};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Release {
    pub id: String,
    pub version: String,
}

pub(crate) fn parse_os_release(raw: &[u8]) -> Result<Release, Code> {
    if raw.len() > 65_536 {
        return Err(Code::ResourceLimit);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding)?;
    let mut id = None;
    let mut version = None;
    let mut build = None;
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(Code::MalformedSource);
        };
        if !key.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
            return Err(Code::MalformedSource);
        }
        let value = if value.starts_with('"') {
            value
                .strip_prefix('"')
                .and_then(|tail| tail.strip_suffix('"'))
                .ok_or(Code::MalformedSource)?
        } else if value.contains('"') {
            return Err(Code::MalformedSource);
        } else {
            value
        };
        if value.is_empty() || value.len() > 256 || value.contains(['\0', '\n', '\r']) {
            return Err(Code::MalformedSource);
        }
        match key {
            "ID" => {
                if id.replace(value.to_owned()).is_some() {
                    return Err(Code::MalformedSource);
                }
            }
            "VERSION_ID" => {
                if version.replace(value.to_owned()).is_some() {
                    return Err(Code::MalformedSource);
                }
            }
            "BUILD_ID" if build.replace(value.to_owned()).is_some() => {
                return Err(Code::MalformedSource);
            }
            _ => {}
        }
    }
    let id: String = id.ok_or(Code::MalformedSource)?;
    if !id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(Code::MalformedSource);
    }
    let version = version.or(build).ok_or(Code::MalformedSource)?;
    Ok(Release { id, version })
}

pub(crate) fn select_release(
    primary: Result<&[u8], Code>,
    fallback: Result<&[u8], Code>,
) -> Result<Release, Code> {
    match primary {
        Ok(raw) => parse_os_release(raw),
        Err(Code::NotFound) => fallback.and_then(parse_os_release),
        Err(code) => Err(code),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KernelLine {
    pub release: String,
    pub full_version: String,
}

pub(crate) fn parse_kernel_line(raw: &[u8]) -> Result<KernelLine, Code> {
    if raw.len() > 65_536 {
        return Err(Code::ResourceLimit);
    }
    let value = std::str::from_utf8(raw)
        .map_err(|_| Code::UnsupportedEncoding)?
        .trim_end_matches('\n');
    let release = value
        .strip_prefix("Linux version ")
        .and_then(|tail| tail.split_ascii_whitespace().next())
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(Code::MalformedSource)?;
    Ok(KernelLine {
        release: release.to_owned(),
        full_version: value.to_owned(),
    })
}

pub(crate) struct ProfileRaw<'a> {
    pub kernel_version: Result<&'a [u8], Code>,
    pub hostname: Result<&'a [u8], Code>,
    pub boot_id: Result<&'a [u8], Code>,
    pub primary_release: Result<&'a [u8], Code>,
    pub fallback_release: Result<&'a [u8], Code>,
    pub architecture: Result<&'a str, Code>,
}

pub(crate) struct ProfileSnapshot {
    pub payload: SystemProfile,
    pub failures: Vec<(&'static str, Code)>,
}

fn field<T>(
    result: Result<T, Code>,
    name: &'static str,
    failures: &mut Vec<(&'static str, Code)>,
) -> Field<T> {
    match result {
        Ok(value) => Field::Available { value },
        Err(reason) => {
            failures.push((name, reason));
            Field::Unavailable { reason }
        }
    }
}

fn small_text(raw: &[u8]) -> Result<String, Code> {
    if raw.len() > 65_536 {
        return Err(Code::ResourceLimit);
    }
    let value = std::str::from_utf8(raw)
        .map_err(|_| Code::UnsupportedEncoding)?
        .trim_end_matches('\n');
    if value.is_empty() || value.len() > 256 || value.contains(['\0', '\r', '\n']) {
        return Err(Code::MalformedSource);
    }
    Ok(value.to_owned())
}

pub(crate) fn decode_profile(raw: ProfileRaw<'_>) -> ProfileSnapshot {
    let mut failures = Vec::new();
    let kernel = raw.kernel_version.and_then(parse_kernel_line);
    let release = select_release(raw.primary_release, raw.fallback_release);
    let kernel_release = field(
        kernel.as_ref().map(|v| v.release.clone()).map_err(|c| *c),
        "kernel_release",
        &mut failures,
    );
    let kernel_version = field(
        kernel.map(|v| v.full_version),
        "kernel_version",
        &mut failures,
    );
    let distribution_id = field(
        release.as_ref().map(|v| v.id.clone()).map_err(|c| *c),
        "distribution_id",
        &mut failures,
    );
    let distribution_version = field(
        release.map(|v| v.version),
        "distribution_version",
        &mut failures,
    );
    ProfileSnapshot {
        payload: SystemProfile {
            os_family: OsFamily::Linux,
            kernel_release,
            kernel_version,
            architecture: field(
                raw.architecture.and_then(|v| small_text(v.as_bytes())),
                "architecture",
                &mut failures,
            ),
            hostname: field(raw.hostname.and_then(small_text), "hostname", &mut failures),
            distribution_id,
            distribution_version,
            boot_id: field(
                raw.boot_id.and_then(|bytes| {
                    let value = small_text(bytes)?;
                    Uuid::parse(&value).map_err(|_| Code::MalformedSource)
                }),
                "boot_id",
                &mut failures,
            ),
        },
        failures,
    }
}

fn borrowed(raw: &Result<Vec<u8>, Code>) -> Result<&[u8], Code> {
    raw.as_ref().map(Vec::as_slice).map_err(|code| *code)
}

pub(crate) fn collect_owned(
    context: &ValidatedCollectionContext,
    launch: &WorkerLaunch,
    handles: &[OwnedFd],
    clock: &mut dyn Clock,
) -> Result<Collected, Code> {
    let source_id = context
        .sources()
        .iter()
        .find(|source| {
            source.definition().kind()
                == jocky_shared::collection::inputs::SourceKind::KernelProfile
        })
        .ok_or(Code::ScopeDenied)?
        .definition()
        .id()
        .clone();
    let find = |kind: HandleKind| {
        launch
            .descriptors
            .iter()
            .zip(handles)
            .find_map(|(binding, handle)| {
                (binding.kind == kind && binding.subject_id.as_ref() == Some(&source_id))
                    .then_some(handle)
            })
    };
    let proc = find(HandleKind::ProcMount).ok_or(Code::WorkerProtocol)?;
    let mount = FixedMount::inherited(
        context,
        &source_id,
        MountKind::Proc,
        proc.as_fd()
            .try_clone_to_owned()
            .map_err(|_| Code::WorkerProtocol)?,
        clock,
        &false,
    )?;
    let kernel = mount.read(Query::KernelVersion, clock, &false);
    let hostname = mount.read(Query::KernelHostname, clock, &false);
    let boot = mount.read(Query::BootId, clock, &false);
    let primary = find(HandleKind::OsRelease)
        .ok_or(Code::NotFound)
        .and_then(|fd| read_release(context, &source_id, fd.as_fd(), clock, &false));
    let fallback = find(HandleKind::OsReleaseFallback)
        .ok_or(Code::NotFound)
        .and_then(|fd| read_release(context, &source_id, fd.as_fd(), clock, &false));
    let architecture = machine_architecture(context, &source_id, clock, &false);
    let snapshot = decode_profile(ProfileRaw {
        kernel_version: borrowed(&kernel),
        hostname: borrowed(&hostname),
        boot_id: borrowed(&boot),
        primary_release: borrowed(&primary),
        fallback_release: borrowed(&fallback),
        architecture: architecture.as_deref().map_err(|code| *code),
    });
    let now = clock.read()?;
    let observed = TimeObservation {
        value: now.utc,
        basis: ClockBasis::LocalClock,
        uncertainty_ms: None,
        clock_uncertain: false,
    };
    let record = super::record::make(
        context,
        Collector::System,
        Adapter::KernelProfile,
        Category::System,
        ProvenanceKind::KernelProfile,
        source_id.clone(),
        super::record::facility_scope(source_id.clone()),
        Payload::System(snapshot.payload),
        launch.record_base,
        observed,
    )?;
    let mut errors = Vec::new();
    let mut error_limit_hit = false;
    for (field, code) in snapshot.failures {
        if errors.len() as u64 >= launch.allowance.errors {
            error_limit_hit = true;
            break;
        }
        let ordinal = launch.error_base + errors.len() as u64;
        errors.push(ItemError {
            error_id: derive_id(
                IdentityKind::Error,
                &context.identity().collection_id,
                ordinal,
            )?,
            collector: Collector::System,
            source_id: Some(source_id.clone()),
            item_ref: 0,
            field_path: Some(format!("/payload/{field}")),
            code,
            retryable: false,
            counted_omission: false,
        });
    }
    let now = clock.read()?;
    let mut permit = context.permit(OperationTarget::Source(&source_id), &now, false)?;
    permit.charge(Counter::Records, 1)?;
    permit.charge(Counter::Errors, errors.len() as u64)?;
    drop(permit);
    let usage = super::usage(context)?;
    let partial = !errors.is_empty() || error_limit_hit;
    let reason = if error_limit_hit {
        Some(Code::ResourceLimit)
    } else {
        errors.first().map(|error| error.code)
    };
    Ok(Collected {
        outcome: CollectorOutcome {
            collector: Collector::System,
            status: if partial {
                CollectorStatus::Partial
            } else {
                CollectorStatus::Complete
            },
            coverage: vec![Coverage {
                source_id,
                state: if partial {
                    FacilityState::Partial
                } else {
                    FacilityState::Supported
                },
                reason: if partial { reason } else { None },
            }],
            accepted_records: 1,
            omitted_records: Some(0),
            omitted_reason: None,
            errors: errors.len() as u64,
            stop_reason: reason,
        },
        usage,
        records: vec![record],
        errors,
    })
}
