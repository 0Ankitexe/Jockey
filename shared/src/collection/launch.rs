//! Untrusted local launch metadata. No process, clock or native authority is created.
use super::{
    DecodeReason, InputError,
    identity::{UtcTime, Uuid},
    inputs::{CollectionVersion, Limits},
    worker::Job,
};
use std::collections::BTreeSet;

vocabulary!(LaunchVersion { V1_1 => "1.1.0" });
vocabulary!(ClockBasis { LinuxMonotonic => "linux_clock_monotonic" });
vocabulary!(HandleKind {
    OrdinaryRoot => "ordinary_root", ProcMount => "proc_mount", SysMount => "sys_mount",
    OsRelease => "os_release", OsReleaseFallback => "os_release_fallback",
    SystemdSocket => "systemd_socket", OutputDirectory => "output_directory"
});
wire!(ClockPair {
    utc: UtcTime,
    monotonic_ms: u64
});
wire!(ParentIdentity {
    pid: u32,
    uid: u32,
    start_ticks: String
});
wire!(ObjectIdentity { device_id: String, inode: String, mount_id: Option<String> });
wire!(DescriptorBinding { kind: HandleKind, subject_id: Option<Uuid>, fd: u32, object: ObjectIdentity });
wire!(WorkAllowance {
    records: u64,
    report_bytes: u64,
    source_bytes: u64,
    errors: u64,
    entries: u64,
    indicator_comparisons: u64,
    staging_bytes: u64,
    retained_bytes: u64
});
wire!(WorkerLaunch {
    schema_version: LaunchVersion, worker_schema_version: CollectionVersion,
    collection_id: Uuid, job: Job, clock_basis: ClockBasis,
    invocation_origin: ClockPair, launch_observed: ClockPair, parent: ParentIdentity,
    start_sha256: String, record_base: u64, error_base: u64, global_limits: Limits,
    allowance: WorkAllowance, descriptors: Vec<DescriptorBinding>,
    config_exclusions: Vec<ObjectIdentity>
});

/// Strict bounded decoding plus intrinsic cross-field checks, not native admission.
pub fn decode_launch(bytes: &[u8]) -> Result<WorkerLaunch, InputError> {
    let value = super::decode::read_json(bytes, 65536)?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|v| v != "1.1.0")
    {
        return Err(InputError::new(DecodeReason::Version));
    }
    super::schema::validate_launch(&value)?;
    super::validation::wire_values(&value)?;
    let launch: WorkerLaunch =
        serde_json::from_value(value).map_err(|_| InputError::new(DecodeReason::Schema))?;
    validate(&launch)?;
    Ok(launch)
}
fn number(s: &str) -> Result<u64, InputError> {
    s.parse().map_err(|_| InputError::new(DecodeReason::Number))
}
fn object(value: &ObjectIdentity) -> Result<(u64, u64), InputError> {
    if let Some(mount) = &value.mount_id {
        number(mount)?;
    }
    Ok((number(&value.device_id)?, number(&value.inode)?))
}
fn validate(v: &WorkerLaunch) -> Result<(), InputError> {
    let invalid = || InputError::new(DecodeReason::Context);
    let l = &v.global_limits;
    let a = &v.allowance;
    number(&v.parent.start_ticks)?;
    if v.launch_observed.monotonic_ms < v.invocation_origin.monotonic_ms
        || v.launch_observed.utc.unix_nanos() < v.invocation_origin.utc.unix_nanos()
        || v.record_base
            .checked_add(a.records)
            .is_none_or(|n| n > l.max_records)
        || v.error_base
            .checked_add(a.errors)
            .is_none_or(|n| n > l.max_errors)
        || a.report_bytes > l.max_report_bytes
        || a.source_bytes > l.max_source_bytes
        || a.entries > l.max_entries
        || a.indicator_comparisons > l.max_indicator_comparisons
        || a.staging_bytes > l.max_staging_bytes
        || a.retained_bytes > l.max_memory_bytes - l.max_memory_bytes / 4
        || l.operation_timeout_ms > l.timeout_ms - 6000
    {
        return Err(invalid());
    }
    let mut fds = BTreeSet::new();
    let mut subjects = BTreeSet::new();
    for d in &v.descriptors {
        object(&d.object)?;
        if !fds.insert(d.fd)
            || !subjects.insert((d.kind, &d.subject_id))
            || (d.kind == HandleKind::OutputDirectory) != d.subject_id.is_none()
            || d.kind != HandleKind::SystemdSocket && d.object.mount_id.is_none()
            || v.job == Job::Collect && d.kind == HandleKind::OutputDirectory
        {
            return Err(invalid());
        }
    }
    let mut configs = BTreeSet::new();
    for c in &v.config_exclusions {
        if !configs.insert(object(c)?) || c.mount_id.is_none() {
            return Err(invalid());
        }
    }
    if v.job == Job::Publish
        && (v.descriptors.len() != 1
            || v.descriptors[0].kind != HandleKind::OutputDirectory
            || a.records != 0
            || a.source_bytes != 0
            || a.errors != 0
            || a.entries != 0
            || a.indicator_comparisons != 0)
    {
        return Err(invalid());
    }
    Ok(())
}
