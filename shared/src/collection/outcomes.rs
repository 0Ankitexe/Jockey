use super::identity::Uuid;

vocabulary!(Code {
    InvalidInput => "InvalidInput", UnsupportedVersion => "UnsupportedVersion",
    MissingAuthorisation => "MissingAuthorisation", AuthorisationDenied => "AuthorisationDenied",
    AuthorisationExpired => "AuthorisationExpired", ScopeDenied => "ScopeDenied",
    PermissionDenied => "PermissionDenied", Unsupported => "Unsupported",
    NotImplemented => "NotImplemented", NotFound => "NotFound",
    FacilityUnavailable => "FacilityUnavailable", UnsupportedFormat => "UnsupportedFormat",
    UnsupportedEncoding => "UnsupportedEncoding", UnknownTimezone => "UnknownTimezone",
    MalformedSource => "MalformedSource", SourceChanged => "SourceChanged",
    SourceDisappeared => "SourceDisappeared", AmbiguousOwner => "AmbiguousOwner",
    ResourceLimit => "ResourceLimit", Timeout => "Timeout", Cancelled => "Cancelled",
    ClockUncertain => "ClockUncertain", WorkerProtocol => "WorkerProtocol",
    WorkerFailed => "WorkerFailed", PublicationFailed => "PublicationFailed",
    OutputExists => "OutputExists", AliasDenied => "AliasDenied",
    CleanupIncomplete => "CleanupIncomplete", NotRequested => "NotRequested"
});

vocabulary!(Capability {
    System => "system", Processes => "processes", Network => "network", Files => "files",
    Events => "events", Persistence => "persistence", Drivers => "drivers", Indicators => "indicators"
});
vocabulary!(Collector {
    System => "system", Processes => "processes", Services => "services", Connections => "connections",
    Persistence => "persistence", Files => "files", Events => "events", Drivers => "drivers", Indicators => "indicators"
});
vocabulary!(CollectorStatus {
    Complete => "complete", Partial => "partial", Unsupported => "unsupported",
    Unavailable => "unavailable", PermissionDenied => "permission_denied", Failed => "failed"
});
vocabulary!(FacilityState {
    Supported => "supported", Unsupported => "unsupported", PermissionDenied => "permission_denied",
    Unavailable => "unavailable", Partial => "partial"
});

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Field<T> {
    Available { value: T },
    Unavailable { reason: Code },
}

wire!(Coverage { source_id: Uuid, state: FacilityState, reason: Option<Code> });
wire!(ItemError {
    error_id: Uuid, collector: Collector, source_id: Option<Uuid>, item_ref: u64,
    field_path: Option<String>, code: Code, retryable: bool, counted_omission: bool
});
wire!(CollectorOutcome {
    collector: Collector, status: CollectorStatus, coverage: Vec<Coverage>,
    accepted_records: u64, omitted_records: Option<u64>, omitted_reason: Option<Code>,
    errors: u64, stop_reason: Option<Code>
});
wire!(WorkUsed {
    entries: u64,
    indicator_comparisons: u64,
    errors: u64,
    source_bytes: u64,
    staging_bytes: u64,
    retained_bytes: u64
});
