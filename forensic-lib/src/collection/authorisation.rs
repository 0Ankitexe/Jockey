use super::{
    ClockReading, InputSet, ValidatedCollectionContext, budget::Budget, clock::Lifetime, policy,
};
use jocky_shared::collection::{
    Code,
    identity::UtcTime,
    records::{ContextMode, LocalContext},
};

/// Logical local admission only: not remote authentication or proof of VM identity.
/// The native configuration reader must enforce owner/mode/descriptor trust first.
pub fn admit(raw: InputSet<'_>, now: ClockReading) -> Result<ValidatedCollectionContext, Code> {
    admit_for_invocation(raw, now.clone(), now)
}

/// Admit against the current clock while retaining the whole invocation's
/// original clock origin. Native callers capture `start` before configuration
/// reading; revalidation and child setup must never restart that deadline.
pub fn admit_for_invocation(
    raw: InputSet<'_>,
    start: ClockReading,
    now: ClockReading,
) -> Result<ValidatedCollectionContext, Code> {
    let mut input = raw.decode()?;
    let (d, a, p, r) = (
        &input.designation,
        &input.authorisation,
        &input.policy,
        &input.request,
    );
    if a.designation_id != d.designation_id
        || a.endpoint_id != d.endpoint_id
        || p.endpoint_id != d.endpoint_id
        || !d.approved_operator_ids.contains(&a.operator_id)
        || r.designation_id != d.designation_id
        || r.authorisation_id != a.authorisation_id
        || r.policy_id != p.policy_id
        || r.operator_id != a.operator_id
        || r.case_id != a.case_id
        || r.endpoint_id != d.endpoint_id
        || r.profile != a.approved_profile
        || r.profile != p.approved_profile
        || a.valid_from.unix_nanos() < d.valid_from.unix_nanos()
        || a.valid_until.unix_nanos() > d.valid_until.unix_nanos()
    {
        return Err(Code::AuthorisationDenied);
    }
    if now.monotonic_ms < start.monotonic_ms || now.utc.unix_nanos() < start.utc.unix_nanos() {
        return Err(Code::ClockUncertain);
    }
    if [
        (&d.valid_from, &d.valid_until),
        (&a.valid_from, &a.valid_until),
        (&p.valid_from, &p.valid_until),
    ]
    .iter()
    .any(|(from, _)| now.utc.unix_nanos() < from.unix_nanos())
    {
        return Err(Code::AuthorisationDenied);
    }
    let expiry: [&UtcTime; 3] = [&d.valid_until, &a.valid_until, &p.valid_until];
    let expiry = expiry
        .into_iter()
        .min_by_key(|v| v.unix_nanos())
        .ok_or(Code::InvalidInput)?
        .clone();
    if now.utc.unix_nanos() >= expiry.unix_nanos() {
        return Err(Code::AuthorisationExpired);
    }
    match (&r.indicator_set_id, &input.indicators) {
        (None, None) => {}
        (Some(expected), Some(actual))
            if expected == &actual.indicator_set_id && actual.case_id == r.case_id => {}
        _ => return Err(Code::AuthorisationDenied),
    }
    let mut lifetime = Lifetime::new(&r.limits, start.clone(), expiry)?;
    lifetime.check(&now, false)?;
    let budget = Budget::new(r.limits.clone())?;
    let identity = LocalContext {
        mode: ContextMode::LocalLab,
        collection_id: r.collection_id.clone(),
        case_id: r.case_id.clone(),
        operator_id: r.operator_id.clone(),
        endpoint_id: r.endpoint_id.clone(),
        designation_id: r.designation_id.clone(),
        authorisation_id: r.authorisation_id.clone(),
        policy_id: r.policy_id.clone(),
    };
    super::normalize::inputs(&mut input)?;
    let scope = policy::intersect(&input)?;
    ValidatedCollectionContext::new(input, scope, identity, budget, lifetime, start)
}
