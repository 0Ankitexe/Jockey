//! Untrusted input DTOs; authority admission belongs to forensic-lib.
use super::identity::{UtcTime, Uuid};
use super::outcomes::{Capability, Collector};
use super::{DecodeReason, InputError};

vocabulary!(CollectionVersion { V1 => "1.0.0" });
vocabulary!(EvidenceVersion { V2 => "2.0.0" });
vocabulary!(Profile { LabSmallV1 => "lab-small-v1" });
vocabulary!(DesignationKind { IsolatedVm => "isolated_vm" });
vocabulary!(Architecture { X86_64 => "x86_64" });
vocabulary!(Abi { Gnu => "gnu" });
vocabulary!(RootPurpose { Files => "files", Logs => "logs", Persistence => "persistence", Journal => "journal" });
vocabulary!(SourceKind {
    KernelProfile => "kernel_profile", ProcProcesses => "proc_processes", ProcNet => "proc_net",
    SysModules => "sys_modules", SystemdBus => "systemd_bus", JournalFile => "journal_file",
    TextLog => "text_log", StartupDirectory => "startup_directory"
});
vocabulary!(StartupFormat { SystemdUnits => "systemd_units", SystemdTimers => "systemd_timers", Cron => "cron", Autostart => "autostart" });
vocabulary!(LogFormat { Rfc5424 => "rfc5424" });
vocabulary!(RulesVersion { ExactV1 => "exact-v1" });

wire!(Types {
    schema_version: CollectionVersion
});
wire!(RootGrant { root_id: Uuid, absolute_path: String, purposes: Vec<RootPurpose> });
wire!(PathRef {
    root_id: Uuid,
    relative_path: String
});
impl PathRef {
    pub fn new(root_id: Uuid, relative_path: &str) -> Result<Self, InputError> {
        validate_relative(relative_path)?;
        Ok(Self {
            root_id,
            relative_path: relative_path.to_owned(),
        })
    }
}
pub(crate) fn validate_relative(path: &str) -> Result<(), InputError> {
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\0')
        || path.split('/').count() > 16
        || path.split('/').any(|s| matches!(s, "" | "." | ".."))
    {
        return Err(InputError::new(DecodeReason::Path));
    }
    Ok(())
}
wire!(UtcWindow {
    start: UtcTime,
    end: UtcTime
});
wire!(Limits {
    max_records: u64,
    max_report_bytes: u64,
    max_source_bytes: u64,
    max_file_bytes: u64,
    max_item_bytes: u64,
    max_errors: u64,
    max_entries: u64,
    max_depth: u64,
    max_indicator_comparisons: u64,
    timeout_ms: u64,
    operation_timeout_ms: u64,
    max_staging_bytes: u64,
    max_memory_bytes: u64
});
wire!(Scope { capabilities: Vec<Capability>, source_groups: Vec<SourceKind>, roots: Vec<RootGrant>, event_window: UtcWindow });
wire!(EndpointDesignation {
    schema_version: CollectionVersion, designation_id: Uuid, endpoint_id: Uuid,
    kind: DesignationKind, label: String, architecture: Architecture, abi: Abi,
    approved_operator_ids: Vec<Uuid>, valid_from: UtcTime, valid_until: UtcTime,
    lab_inventory_reference: String
});
wire!(LabAuthorisation {
    schema_version: CollectionVersion,
    authorisation_id: Uuid,
    designation_id: Uuid,
    operator_id: Uuid,
    case_id: Uuid,
    endpoint_id: Uuid,
    approved_profile: Profile,
    valid_from: UtcTime,
    valid_until: UtcTime,
    scope: Scope,
    limits: Limits
});
wire!(CollectorPolicy {
    schema_version: CollectionVersion, policy_id: Uuid, endpoint_id: Uuid,
    approved_profile: Profile, valid_from: UtcTime, valid_until: UtcTime,
    scope: Scope, limits: Limits, sources: Vec<SourceRef>
});

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceRef {
    KernelProfile {
        source_id: Uuid,
    },
    ProcProcesses {
        source_id: Uuid,
    },
    ProcNet {
        source_id: Uuid,
    },
    SysModules {
        source_id: Uuid,
    },
    SystemdBus {
        source_id: Uuid,
        unix_path: String,
    },
    JournalFile {
        source_id: Uuid,
        path: PathRef,
    },
    TextLog {
        source_id: Uuid,
        path: PathRef,
        format: LogFormat,
    },
    StartupDirectory {
        source_id: Uuid,
        path: PathRef,
        format: StartupFormat,
    },
}
impl SourceRef {
    pub fn id(&self) -> &Uuid {
        match self {
            Self::KernelProfile { source_id }
            | Self::ProcProcesses { source_id }
            | Self::ProcNet { source_id }
            | Self::SysModules { source_id }
            | Self::SystemdBus { source_id, .. }
            | Self::JournalFile { source_id, .. }
            | Self::TextLog { source_id, .. }
            | Self::StartupDirectory { source_id, .. } => source_id,
        }
    }
    pub const fn kind(&self) -> SourceKind {
        match self {
            Self::KernelProfile { .. } => SourceKind::KernelProfile,
            Self::ProcProcesses { .. } => SourceKind::ProcProcesses,
            Self::ProcNet { .. } => SourceKind::ProcNet,
            Self::SysModules { .. } => SourceKind::SysModules,
            Self::SystemdBus { .. } => SourceKind::SystemdBus,
            Self::JournalFile { .. } => SourceKind::JournalFile,
            Self::TextLog { .. } => SourceKind::TextLog,
            Self::StartupDirectory { .. } => SourceKind::StartupDirectory,
        }
    }
}
wire!(CollectionRequest {
    schema_version: CollectionVersion, collection_id: Uuid, designation_id: Uuid,
    authorisation_id: Uuid, policy_id: Uuid, operator_id: Uuid, case_id: Uuid,
    endpoint_id: Uuid, profile: Profile, capabilities: Vec<Capability>,
    collectors: Vec<Collector>, source_ids: Vec<Uuid>, paths: Vec<PathRef>,
    event_window: UtcWindow, limits: Limits, indicator_set_id: Option<Uuid>
});
wire!(IndicatorSet {
    schema_version: CollectionVersion, indicator_set_id: Uuid, case_id: Uuid,
    revision: String, rules_version: RulesVersion, indicators: Vec<Indicator>
});
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Indicator {
    Sha256 { indicator_id: Uuid, value: String },
    Path { indicator_id: Uuid, value: PathRef },
    IpAddress { indicator_id: Uuid, value: String },
    Domain { indicator_id: Uuid, value: String },
}
impl Indicator {
    pub fn id(&self) -> &Uuid {
        match self {
            Self::Sha256 { indicator_id, .. }
            | Self::Path { indicator_id, .. }
            | Self::IpAddress { indicator_id, .. }
            | Self::Domain { indicator_id, .. } => indicator_id,
        }
    }
}
vocabulary!(LabScenarioKind { Checkpoint => "checkpoint", LabSmall => "lab-small" });
vocabulary!(HarnessAction {
    CreateBenignProcesses => "create_benign_processes", BindLoopbackTcp => "bind_loopback_tcp",
    CreateSampleFiles => "create_sample_files", EmitBenignLogMarkers => "emit_benign_log_markers",
    CleanupOwnedObjects => "cleanup_owned_objects"
});
wire!(LabScenario {
    schema_version: CollectionVersion, approval_id: Uuid, inventory_id: Uuid,
    designation_id: Uuid, authorisation_id: Uuid, endpoint_id: Uuid, case_id: Uuid,
    operator_id: Uuid, valid_from: UtcTime, valid_until: UtcTime, scenario: LabScenarioKind,
    collector_sha256: String, owned_scratch_root: String, output_root: String,
    allowed_actions: Vec<HarnessAction>, cold_preparation_reference: String
});
