//! Shared record envelope for already admitted, observed core facts.
use jocky_forensic::collection::{
    ValidatedCollectionContext, canonical,
    identity::{IdentityKind, derive_id, digest},
};
use jocky_shared::collection::{
    Code, bounded_value,
    identity::{TimeObservation, Uuid},
    inputs::EvidenceVersion,
    outcomes::Collector,
    records::{
        Adapter, Category, CollectorIdentity, Details, ForensicRecord, NamespaceScope, Payload,
        Provenance, ProvenanceKind, Severity, SourceScope,
    },
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn make(
    context: &ValidatedCollectionContext,
    collector: Collector,
    adapter: Adapter,
    category: Category,
    kind: ProvenanceKind,
    source_id: Uuid,
    scope: SourceScope,
    payload: Payload,
    sequence: u64,
    observed: TimeObservation,
) -> Result<ForensicRecord, Code> {
    if sequence >= context.limits().max_records {
        return Err(Code::ResourceLimit);
    }
    let record_type = match &payload {
        Payload::System(_) => jocky_shared::collection::records::RecordType::Profile,
        Payload::Process(_) => jocky_shared::collection::records::RecordType::Process,
        Payload::Connection(_) => jocky_shared::collection::records::RecordType::Connection,
        Payload::File(_) => jocky_shared::collection::records::RecordType::Metadata,
        Payload::Service(_) => jocky_shared::collection::records::RecordType::Service,
        Payload::Persistence(_) => jocky_shared::collection::records::RecordType::Entry,
        Payload::Event(_) => jocky_shared::collection::records::RecordType::Log,
        Payload::Driver(_) => jocky_shared::collection::records::RecordType::Module,
        Payload::Indicator(_) => jocky_shared::collection::records::RecordType::Match,
    };
    let inputs = context.input_provenance();
    let mut record = ForensicRecord {
        schema_version: EvidenceVersion::V2,
        record_id: derive_id(
            IdentityKind::Record,
            &context.identity().collection_id,
            sequence,
        )?,
        context: context.identity().clone(),
        collected_at: observed.clone(),
        collector: CollectorIdentity {
            name: collector,
            version: "1.0.0".to_owned(),
            adapter,
        },
        category,
        severity: Severity::Informational,
        record_type,
        sequence,
        provenance: Provenance {
            source_id,
            source_kind: kind,
            observed_start: observed.clone(),
            observed_end: observed,
            policy_sha256: inputs.policy.sha256.clone(),
            authorisation_sha256: inputs.authorisation.sha256.clone(),
            request_sha256: inputs.request.sha256.clone(),
            source_scope: scope,
            indicator_set_sha256: None,
            rules_version: None,
        },
        payload,
        details: Details {
            linux: Default::default(),
        },
        content_sha256: "0".repeat(64),
    };
    let mut value = bounded_value(&record, 98_304).map_err(|e| e.code)?;
    value
        .as_object_mut()
        .ok_or(Code::InvalidInput)?
        .remove("content_sha256");
    record.content_sha256 = digest(&canonical::encode(&value, 98_304)?)?;
    Ok(record)
}

pub(crate) fn facility_scope(source_id: Uuid) -> SourceScope {
    SourceScope::Facility {
        source_id,
        namespace: NamespaceScope::Current,
    }
}
