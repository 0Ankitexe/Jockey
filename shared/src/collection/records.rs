//! Closed evidence payloads; available facts are distinct from unavailable fields.
use super::identity::{TimeObservation, UtcTime, Uuid};
use super::inputs::{CollectionVersion, EvidenceVersion, PathRef, RulesVersion, StartupFormat};
use super::outcomes::{Collector, Coverage, Field};
use std::collections::BTreeMap;

vocabulary!(OsFamily { Linux => "linux", Windows => "windows" });
vocabulary!(NamespaceScope { Current => "current" });
vocabulary!(ContextMode { LocalLab => "local_lab" });
vocabulary!(Severity { Informational => "informational", Low => "low", Medium => "medium", High => "high", Critical => "critical", Unknown => "unknown" });
vocabulary!(Category { System => "system", Process => "process", Network => "network", File => "file", Event => "event", Persistence => "persistence", Driver => "driver", Indicator => "indicator" });
vocabulary!(RecordType { Profile => "profile", Process => "process", Service => "service", Connection => "connection", Entry => "entry", Metadata => "metadata", Log => "log", Module => "module", Match => "match" });
vocabulary!(Adapter {
    KernelProfile => "linux.kernel-profile-v1", Processes => "linux.proc-processes-v1",
    Network => "linux.proc-net-v1", Systemd => "linux.systemd-v1", Startup => "linux.startup-v1",
    Files => "linux.scoped-file-v1", Journal => "linux.journal-v1", TextLog => "linux.rfc5424-v1",
    Modules => "linux.modules-v1", Indicators => "pure.exact-indicators-v1"
});
vocabulary!(ProvenanceKind {
    KernelProfile => "kernel_profile", ProcProcesses => "proc_processes", ProcNet => "proc_net",
    SysModules => "sys_modules", SystemdBus => "systemd_bus", JournalFile => "journal_file",
    TextLog => "text_log", StartupDirectory => "startup_directory", ScopedFile => "scoped_file",
    SuppliedIndicatorSet => "supplied_indicator_set"
});

wire!(LocalContext {
    mode: ContextMode,
    collection_id: Uuid,
    case_id: Uuid,
    operator_id: Uuid,
    endpoint_id: Uuid,
    designation_id: Uuid,
    authorisation_id: Uuid,
    policy_id: Uuid
});
wire!(Distribution { id: Field<String>, version: Field<String> });
wire!(EndpointObservation {
    schema_version: CollectionVersion, endpoint_id: Uuid, os_family: OsFamily,
    architecture: Field<String>, distribution: Distribution, kernel_release: Field<String>,
    abi: Field<String>, namespace_scope: NamespaceScope, observed_at: TimeObservation,
    facilities: Vec<Coverage>
});
wire!(CollectorIdentity {
    name: Collector,
    version: String,
    adapter: Adapter
});
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceScope {
    Facility {
        source_id: Uuid,
        namespace: NamespaceScope,
    },
    Path {
        path: PathRef,
    },
    Indicators {
        indicator_set_id: Uuid,
    },
}
wire!(Provenance {
    source_id: Uuid, source_kind: ProvenanceKind, observed_start: TimeObservation,
    observed_end: TimeObservation, policy_sha256: String, authorisation_sha256: String,
    request_sha256: String, source_scope: SourceScope, indicator_set_sha256: Option<String>,
    rules_version: Option<RulesVersion>
});
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum DetailValue {
    Text(String),
    Count(u64),
}
wire!(Details { linux: BTreeMap<String, DetailValue> });

wire!(SystemProfile {
    os_family: OsFamily, kernel_release: Field<String>, kernel_version: Field<String>,
    architecture: Field<String>, hostname: Field<String>, distribution_id: Field<String>,
    distribution_version: Field<String>, boot_id: Field<Uuid>
});
wire!(ProcessIdentity {
    boot_id: Uuid,
    pid: u64,
    start_ticks: String
});
wire!(ProcessRecord {
    pid: u64, parent_pid: Field<u64>, uid: Field<u64>, command: Field<String>,
    executable: Field<String>, start_identity: Field<ProcessIdentity>
});
wire!(ServiceRecord {
    unit_name: String, description: Field<String>, load_state: Field<String>,
    active_state: Field<String>, sub_state: Field<String>, unit_file_state: Field<String>
});
vocabulary!(Protocol { Tcp => "tcp", Udp => "udp" });
vocabulary!(AddressFamily { Ipv4 => "ipv4", Ipv6 => "ipv6" });
wire!(ConnectionRecord {
    protocol: Protocol, family: AddressFamily, local_address: String, local_port: u16,
    remote_address: String, remote_port: u16, state: String, uid: Field<u64>,
    socket_inode: String, owners: Field<Vec<ProcessIdentity>>, namespace: Field<String>
});
wire!(PersistenceRecord {
    kind: StartupFormat, location: PathRef, enabled_state: Field<String>,
    referenced_targets: Field<Vec<String>>, content_sha256: Field<String>
});
vocabulary!(ReadStability { StableObserved => "stable_observed", Changed => "changed", NotRead => "not_read" });
wire!(FileRecord {
    location: PathRef, size_bytes: Field<u64>, mode: Field<u64>, uid: Field<u64>, gid: Field<u64>,
    mtime: Field<UtcTime>, ctime: Field<UtcTime>, sha256: Field<String>, read_stability: ReadStability
});
vocabulary!(TimeBasis { SourceUtc => "source_utc", SourceOffset => "source_offset" });
wire!(EventRecord {
    source_id: Uuid, event_time: Field<UtcTime>, time_basis: TimeBasis,
    severity: Field<String>, message: String, domain: Field<String>
});
wire!(DriverRecord {
    name: String, size_bytes: Field<u64>, reference_count: Field<u64>, state: String,
    version: Field<String>, source_version: Field<String>
});
vocabulary!(IndicatorKind { Sha256 => "sha256", Path => "path", IpAddress => "ip_address", Domain => "domain" });
wire!(IndicatorMatch {
    indicator_id: Uuid,
    indicator_set_id: Uuid,
    rules_version: RulesVersion,
    matched_record_id: Uuid,
    field_path: String,
    kind: IndicatorKind
});
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Payload {
    System(SystemProfile),
    Process(ProcessRecord),
    Service(ServiceRecord),
    Connection(ConnectionRecord),
    Persistence(PersistenceRecord),
    File(FileRecord),
    Event(EventRecord),
    Driver(DriverRecord),
    Indicator(IndicatorMatch),
}
wire!(ForensicRecord {
    schema_version: EvidenceVersion,
    record_id: Uuid,
    context: LocalContext,
    collected_at: TimeObservation,
    collector: CollectorIdentity,
    category: Category,
    severity: Severity,
    record_type: RecordType,
    sequence: u64,
    provenance: Provenance,
    payload: Payload,
    details: Details,
    content_sha256: String
});
