//! Common bounded report assembly for separately admitted facility facts.
use crate::collection::Collected;
use jocky_forensic::collection::{
    ValidatedCollectionContext,
    budget::Counter,
    clock::Clock,
    context::OperationTarget,
    identity::{IdentityKind, derive_id},
};
use jocky_shared::collection::{
    Code,
    identity::{ClockBasis, TimeObservation, Uuid},
    launch::WorkerLaunch,
    outcomes::{Collector, CollectorOutcome, CollectorStatus, Coverage, FacilityState, ItemError},
    records::{Adapter, Category, Payload, ProvenanceKind, SourceScope},
};

pub(crate) struct Fact {
    pub payload: Payload,
    pub adapter: Adapter,
    pub category: Category,
    pub kind: ProvenanceKind,
    pub scope: SourceScope,
}
pub(crate) struct SourceFacts {
    pub id: Uuid,
    pub facts: Vec<Fact>,
    pub issues: Vec<Code>,
    pub unavailable: Option<Code>,
}
impl SourceFacts {
    pub fn complete(id: Uuid, facts: Vec<Fact>) -> Self {
        Self {
            id,
            facts,
            issues: Vec::new(),
            unavailable: None,
        }
    }
    pub fn unavailable(id: Uuid, code: Code) -> Self {
        Self {
            id,
            facts: Vec::new(),
            issues: Vec::new(),
            unavailable: Some(code),
        }
    }
}
fn state(code: Code) -> FacilityState {
    match code {
        Code::Unsupported | Code::NotImplemented => FacilityState::Unsupported,
        Code::PermissionDenied => FacilityState::PermissionDenied,
        _ => FacilityState::Unavailable,
    }
}
fn fatal(code: Code) -> bool {
    matches!(
        code,
        Code::ResourceLimit
            | Code::Timeout
            | Code::Cancelled
            | Code::AuthorisationExpired
            | Code::ClockUncertain
            | Code::ScopeDenied
            | Code::WorkerProtocol
    )
}

pub(crate) fn assemble(
    context: &ValidatedCollectionContext,
    launch: &WorkerLaunch,
    clock: &mut dyn Clock,
    collector: Collector,
    sources: Vec<SourceFacts>,
) -> Result<Collected, Code> {
    if sources.is_empty() {
        return Ok(Collected {
            outcome: jocky_forensic::collection::outcome::unsupported(collector),
            usage: super::usage(context)?,
            records: Vec::new(),
            errors: Vec::new(),
        });
    }
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut coverage = Vec::new();
    let mut omissions = 0u64;
    let mut reason = None;
    for source in sources {
        let mut failure = source.unavailable;
        if failure.is_none() && !source.issues.is_empty() {
            failure = Some(source.issues[0]);
        }
        if let Some(code) = failure {
            if fatal(code) {
                return Err(code);
            }
            reason.get_or_insert(code);
        }
        for fact in source.facts {
            if records.len() as u64 >= launch.allowance.records {
                return Err(Code::ResourceLimit);
            }
            let ordinal = launch.record_base + records.len() as u64;
            let now = clock.read()?;
            let observed = TimeObservation {
                value: now.utc,
                basis: ClockBasis::LocalClock,
                uncertainty_ms: None,
                clock_uncertain: false,
            };
            let record = super::record::make(
                context,
                collector,
                fact.adapter,
                fact.category,
                fact.kind,
                source.id.clone(),
                fact.scope,
                fact.payload,
                ordinal,
                observed,
            )?;
            let mut permit =
                context.permit(OperationTarget::Source(&source.id), &clock.read()?, false)?;
            permit.charge(Counter::Records, 1)?;
            records.push(record);
        }
        let issue_codes: Vec<_> = source
            .issues
            .into_iter()
            .chain(source.unavailable)
            .collect();
        omissions += issue_codes.len() as u64;
        for code in issue_codes {
            if errors.len() as u64 >= launch.allowance.errors {
                return Err(Code::ResourceLimit);
            }
            let ordinal = launch.error_base + errors.len() as u64;
            let mut permit =
                context.permit(OperationTarget::Source(&source.id), &clock.read()?, false)?;
            permit.charge(Counter::Errors, 1)?;
            errors.push(ItemError {
                error_id: derive_id(
                    IdentityKind::Error,
                    &context.identity().collection_id,
                    ordinal,
                )?,
                collector,
                source_id: Some(source.id.clone()),
                item_ref: ordinal,
                field_path: None,
                code,
                retryable: false,
                counted_omission: true,
            });
        }
        coverage.push(Coverage {
            source_id: source.id.clone(),
            state: match failure {
                None => FacilityState::Supported,
                Some(_) if records.iter().any(|r| r.provenance.source_id == source.id) => {
                    FacilityState::Partial
                }
                Some(code) => state(code),
            },
            reason: failure,
        });
    }
    coverage.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    let status = if reason.is_none() {
        CollectorStatus::Complete
    } else if !records.is_empty() {
        CollectorStatus::Partial
    } else if reason == Some(Code::Unsupported) {
        CollectorStatus::Unsupported
    } else if reason == Some(Code::PermissionDenied) {
        CollectorStatus::PermissionDenied
    } else {
        CollectorStatus::Unavailable
    };
    Ok(Collected {
        outcome: CollectorOutcome {
            collector,
            status,
            coverage,
            accepted_records: records.len() as u64,
            omitted_records: Some(omissions),
            omitted_reason: reason,
            errors: errors.len() as u64,
            stop_reason: reason,
        },
        usage: super::usage(context)?,
        records,
        errors,
    })
}

pub(crate) fn exclusions(
    launch: &WorkerLaunch,
) -> Result<crate::sources::metadata::Exclusions, Code> {
    use crate::sources::metadata::{Exclusions, ObjectId};
    Exclusions::new(
        &launch
            .config_exclusions
            .iter()
            .map(|id| {
                Ok(ObjectId {
                    device: id.device_id.parse().map_err(|_| Code::WorkerProtocol)?,
                    inode: id.inode.parse().map_err(|_| Code::WorkerProtocol)?,
                })
            })
            .collect::<Result<Vec<_>, Code>>()?,
    )
}
