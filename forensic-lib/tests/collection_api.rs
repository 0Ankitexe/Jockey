use jocky_forensic::collection::{
    ClockReading, InputSet, ValidatedCollectionContext, admit, collector::CollectorRequest,
};
use jocky_shared::collection::{Code, identity::UtcTime, inputs::Indicator};
use serde_json::{Value, json};

fn inputs() -> [Value; 5] {
    [
        include_str!("../../fixtures/valid/collection/endpoint-designation.json"),
        include_str!("../../fixtures/valid/collection/authorisation.json"),
        include_str!("../../fixtures/valid/collection/policy.json"),
        include_str!("../../fixtures/valid/collection/request.json"),
        include_str!("../../fixtures/valid/collection/indicator-set.json"),
    ]
    .map(|v| serde_json::from_str(v).unwrap())
}
fn attempt(values: &[Value; 5], indicators: bool) -> Result<ValidatedCollectionContext, Code> {
    let bytes = values.each_ref().map(|v| serde_json::to_vec(v).unwrap());
    admit(
        InputSet {
            designation: &bytes[0],
            authorisation: Some(&bytes[1]),
            policy: &bytes[2],
            request: &bytes[3],
            indicators: indicators.then_some(bytes[4].as_slice()),
        },
        ClockReading {
            utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
            monotonic_ms: 0,
        },
    )
}

#[test]
fn typed_requests_are_bound_to_admitted_collector_and_source_kind() {
    let context = attempt(&inputs(), false).unwrap();
    assert_eq!(
        CollectorRequest::System(&context.sources()[0]).validate(&context),
        Ok(())
    );
    assert_eq!(
        CollectorRequest::Processes(&context.sources()[0]).validate(&context),
        Err(Code::ScopeDenied)
    );
    assert_eq!(
        CollectorRequest::Files(&[]).validate(&context),
        Err(Code::ScopeDenied)
    );
    let mut other = inputs();
    other[3]["source_ids"][0] = json!("10000000-0000-4000-8000-000000000099");
    other[2]["sources"][0]["source_id"] = other[3]["source_ids"][0].clone();
    let other = attempt(&other, false).unwrap();
    assert_eq!(
        CollectorRequest::System(&other.sources()[0]).validate(&context),
        Err(Code::ScopeDenied)
    );
}

#[test]
fn indicator_inputs_are_bound_normalized_and_not_an_execution_feature() {
    let mut values = inputs();
    for index in [1, 2] {
        values[index]["scope"]["capabilities"] = json!(["system", "indicators"]);
    }
    values[3]["capabilities"] = json!(["system", "indicators"]);
    values[3]["collectors"] = json!(["system", "indicators"]);
    values[3]["indicator_set_id"] = values[4]["indicator_set_id"].clone();
    values[4]["indicators"] = json!([
        {"indicator_id":"10000000-0000-4000-8000-000000000021","kind":"domain","value":"EXAMPLE.invalid."},
        {"indicator_id":"10000000-0000-4000-8000-000000000020","kind":"ip_address","value":"2001:0db8:0:0:0:0:0:1"}
    ]);
    let context = attempt(&values, true).unwrap();
    let set = context.indicators().unwrap();
    assert!(
        matches!(&set.definition().indicators[0], Indicator::IpAddress {value, ..} if value=="2001:db8::1")
    );
    assert!(
        matches!(&set.definition().indicators[1], Indicator::Domain {value, ..} if value=="example.invalid")
    );
    assert_eq!(CollectorRequest::Indicators(set).validate(&context), Ok(()));
    let digest = context
        .input_provenance()
        .indicators
        .as_ref()
        .unwrap()
        .sha256
        .clone();
    values[4]["indicators"].as_array_mut().unwrap().reverse();
    assert_eq!(
        attempt(&values, true)
            .unwrap()
            .input_provenance()
            .indicators
            .as_ref()
            .unwrap()
            .sha256,
        digest
    );
    values[4]["case_id"] = json!("10000000-0000-4000-8000-000000000099");
    assert!(matches!(
        attempt(&values, true),
        Err(Code::AuthorisationDenied)
    ));
}

#[test]
fn minimum_failure_report_contains_no_fabricated_observations() {
    use jocky_forensic::collection::{
        report::{failure, finalize},
        verify::verify_report,
    };
    use jocky_shared::collection::report::{ReportKind, SummaryStatus, WorkerCleanup};
    let context = attempt(&inputs(), false).unwrap();
    let report = failure(
        &context,
        ReportKind::SyntheticTest,
        context.started_at().clone(),
        Code::ResourceLimit,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let bytes = finalize(report, context.failure_report_reserve()).unwrap();
    let report = verify_report(&bytes).unwrap();
    assert!(report.endpoint.is_none() && report.records.is_empty() && report.errors.is_empty());
    assert!(report.summary.omitted_unknown);
    assert_eq!(report.summary.status, SummaryStatus::Failed);
    assert_eq!(report.inputs, *context.input_provenance());
    assert_eq!(
        failure(
            &context,
            ReportKind::SyntheticTest,
            context.started_at().clone(),
            Code::NotRequested,
            WorkerCleanup::NotStarted
        )
        .unwrap_err(),
        Code::InvalidInput
    );
}

#[test]
fn failure_envelope_preserves_charged_work_and_cannot_discard_accepted_evidence() {
    use jocky_forensic::collection::{budget::Counter, context::OperationTarget, report::failure};
    use jocky_shared::collection::report::{ReportKind, WorkerCleanup};
    let context = attempt(&inputs(), false).unwrap();
    let now = ClockReading {
        utc: context.started_at().value.clone(),
        monotonic_ms: 0,
    };
    let mut permit = context
        .permit(
            OperationTarget::Source(context.sources()[0].definition().id()),
            &now,
            false,
        )
        .unwrap();
    permit.charge(Counter::SourceBytes, 10).unwrap();
    permit.charge(Counter::Entries, 2).unwrap();
    permit.charge(Counter::Errors, 1).unwrap();
    assert!(matches!(
        failure(
            &context,
            ReportKind::SyntheticTest,
            context.started_at().clone(),
            Code::ResourceLimit,
            WorkerCleanup::NotStarted
        ),
        Err(Code::ResourceLimit)
    ));
    drop(permit);
    let failed = failure(
        &context,
        ReportKind::SyntheticTest,
        context.started_at().clone(),
        Code::ResourceLimit,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    assert_eq!(failed.summary.source_bytes, 10);
    assert_eq!(failed.summary.work_used.entries, 2);
    assert_eq!(failed.summary.work_used.errors, 1);
    assert!(failed.errors.is_empty());
    let verified = jocky_forensic::collection::verify::verify_report(
        &jocky_forensic::collection::report::finalize(failed, context.failure_report_reserve())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(verified.summary.work_used.errors, 1);
    let mut permit = context
        .permit(
            OperationTarget::Source(context.sources()[0].definition().id()),
            &now,
            false,
        )
        .unwrap();
    permit.charge(Counter::Records, 1).unwrap();
    drop(permit);
    assert!(matches!(
        failure(
            &context,
            ReportKind::SyntheticTest,
            context.started_at().clone(),
            Code::ResourceLimit,
            WorkerCleanup::NotStarted
        ),
        Err(Code::InvalidInput)
    ));
}

#[test]
fn injected_source_clock_and_cancellation_have_no_ambient_fallback() {
    use jocky_forensic::collection::{
        budget::Counter,
        cancellation::Cancellation,
        clock::Clock,
        context::{OperationPermit, OperationTarget},
        sources::{ReadChunk, Source},
    };
    struct Frozen(ClockReading);
    impl Clock for Frozen {
        fn read(&mut self) -> Result<ClockReading, Code> {
            Ok(self.0.clone())
        }
    }
    struct DataSource {
        clock: Frozen,
        calls: usize,
        cancelled: bool,
    }
    impl Source for DataSource {
        fn read(
            &mut self,
            permit: &mut OperationPermit<'_>,
            maximum: usize,
        ) -> Result<ReadChunk, Code> {
            permit.renew(&self.clock.read()?, self.cancelled.cancelled())?;
            if maximum < 4 {
                return Err(Code::ResourceLimit);
            }
            permit.charge(Counter::SourceBytes, 4)?;
            self.calls += 1;
            Ok(ReadChunk {
                bytes: b"data".to_vec(),
                end_of_source: true,
            })
        }
    }
    let now = ClockReading {
        utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
        monotonic_ms: 0,
    };
    let mut source = DataSource {
        clock: Frozen(now.clone()),
        calls: 0,
        cancelled: false,
    };
    let mut invalid = inputs();
    invalid[3]["endpoint_id"] = json!("10000000-0000-4000-8000-000000000099");
    assert!(attempt(&invalid, false).is_err());
    assert_eq!(source.calls, 0);
    let context = attempt(&inputs(), false).unwrap();
    let mut permit = context
        .permit(
            OperationTarget::Source(context.sources()[0].definition().id()),
            &now,
            false,
        )
        .unwrap();
    let read = source.read(&mut permit, 4).unwrap();
    assert_eq!(read.bytes, b"data");
    assert!(read.end_of_source);
    assert_eq!(source.calls, 1);
    source.cancelled = true;
    assert!(matches!(source.read(&mut permit, 4), Err(Code::Cancelled)));
    source.cancelled = false;
    assert!(matches!(source.read(&mut permit, 4), Err(Code::Cancelled)));
    assert_eq!(source.calls, 1);
}

#[test]
fn platform_boundary_can_report_unsupported_without_faking_a_record() {
    use jocky_forensic::collection::{
        CollectorOutcome, ForensicRecord, PlatformCollector, RecordSink, outcome,
    };
    struct Unavailable;
    impl PlatformCollector for Unavailable {
        fn collect(
            &mut self,
            context: &ValidatedCollectionContext,
            request: &CollectorRequest<'_>,
            _: &mut dyn RecordSink,
        ) -> CollectorOutcome {
            request.validate(context).unwrap();
            outcome::unsupported(request.collector())
        }
    }
    struct CountSink(usize);
    impl RecordSink for CountSink {
        fn accept(&mut self, _: ForensicRecord) -> Result<(), Code> {
            self.0 += 1;
            Err(Code::NotImplemented)
        }
    }
    let context = attempt(&inputs(), false).unwrap();
    let mut sink = CountSink(0);
    let result = Unavailable.collect(
        &context,
        &CollectorRequest::System(&context.sources()[0]),
        &mut sink,
    );
    assert_eq!(result.stop_reason, Some(Code::Unsupported));
    assert_eq!(result.accepted_records, 0);
    assert!(result.omitted_records.is_none());
    assert_eq!(sink.0, 0);
}

#[test]
fn operation_deadline_does_not_restart_at_each_chunk_or_with_a_new_permit_after_stop() {
    use jocky_forensic::collection::{budget::Counter, context::OperationTarget};
    let context = attempt(&inputs(), false).unwrap();
    let target = OperationTarget::Source(context.sources()[0].definition().id());
    let mut now = ClockReading {
        utc: context.started_at().value.clone(),
        monotonic_ms: 0,
    };
    let mut permit = context.permit(target, &now, false).unwrap();
    assert_eq!(permit.deadline_ms(), 2000);
    now.monotonic_ms = 1999;
    permit.renew(&now, false).unwrap();
    assert_eq!(permit.deadline_ms(), 2000);
    permit.charge(Counter::SourceBytes, 1).unwrap();
    now.monotonic_ms = 2000;
    assert_eq!(permit.renew(&now, false), Err(Code::Timeout));
    assert_eq!(permit.charge(Counter::SourceBytes, 1), Err(Code::Timeout));
    drop(permit);
    assert!(matches!(
        context.permit(target, &now, false),
        Err(Code::Timeout)
    ));
}

#[test]
fn narrowed_operation_limits_and_global_cutoff_cannot_be_extended() {
    use jocky_forensic::collection::context::OperationTarget;
    let mut values = inputs();
    values[3]["limits"]["operation_timeout_ms"] = json!(1);
    let context = attempt(&values, false).unwrap();
    let target = OperationTarget::Source(context.sources()[0].definition().id());
    let now = ClockReading {
        utc: context.started_at().value.clone(),
        monotonic_ms: 0,
    };
    let permit = context.permit(target, &now, false).unwrap();
    assert_eq!(permit.deadline_ms(), 1);
    drop(permit);
    let context = attempt(&inputs(), false).unwrap();
    let target = OperationTarget::Source(context.sources()[0].definition().id());
    let mut now = ClockReading {
        utc: context.started_at().value.clone(),
        monotonic_ms: 53999,
    };
    let mut permit = context.permit(target, &now, false).unwrap();
    assert_eq!(permit.deadline_ms(), 54000);
    // Wall-clock forward jumps can shorten an already active operation too.
    now.utc = UtcTime::parse("2020-01-01T00:59:59.9995Z").unwrap();
    assert_eq!(permit.renew(&now, false), Err(Code::AuthorisationExpired));
}

#[test]
fn rejected_atomic_charges_stop_the_context_and_preserve_prior_work_in_failure_reports() {
    use jocky_forensic::collection::{
        budget::Counter,
        context::OperationTarget,
        report::{failure, finalize},
        verify::verify_report,
    };
    use jocky_shared::collection::report::{ReportKind, WorkerCleanup};
    let context = attempt(&inputs(), false).unwrap();
    let target = OperationTarget::Source(context.sources()[0].definition().id());
    let now = ClockReading {
        utc: context.started_at().value.clone(),
        monotonic_ms: 0,
    };
    let mut permit = context.permit(target, &now, false).unwrap();
    permit
        .charge_many(&[(Counter::SourceBytes, 10), (Counter::Entries, 2)])
        .unwrap();
    assert_eq!(
        permit.charge_many(&[(Counter::Entries, 1), (Counter::SourceBytes, u64::MAX)]),
        Err(Code::ResourceLimit)
    );
    assert_eq!(permit.charge_many(&[]), Err(Code::ResourceLimit));
    drop(permit);
    assert!(matches!(
        context.permit(target, &now, false),
        Err(Code::ResourceLimit)
    ));
    let report = failure(
        &context,
        ReportKind::SyntheticTest,
        context.started_at().clone(),
        Code::ResourceLimit,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let checked =
        verify_report(&finalize(report, context.failure_report_reserve()).unwrap()).unwrap();
    assert_eq!(checked.summary.source_bytes, 10);
    assert_eq!(checked.summary.work_used.entries, 2);
}

#[test]
fn path_scope_returns_only_the_root_and_path_selected_by_admission() {
    use jocky_forensic::collection::context::OperationTarget;
    use jocky_shared::collection::{identity::Uuid, inputs::PathRef};
    let root_id = Uuid::parse("10000000-0000-4000-8000-000000000090").unwrap();
    let path = PathRef::new(root_id.clone(), "allowed/sample").unwrap();
    let root = json!({"root_id": root_id, "absolute_path":"/synthetic/case", "purposes":["files","logs","persistence","journal"]});
    let mut values = inputs();
    for index in [1, 2] {
        values[index]["scope"]["roots"] = json!([root]);
        values[index]["scope"]["capabilities"] = json!(["files"]);
        values[index]["scope"]["source_groups"] = json!([]);
    }
    values[2]["sources"] = json!([]);
    values[3]["source_ids"] = json!([]);
    values[3]["collectors"] = json!(["files"]);
    values[3]["capabilities"] = json!(["files"]);
    values[3]["paths"] = json!([path]);
    let context = attempt(&values, false).unwrap();
    let admitted = context.path_scope(OperationTarget::File(&path)).unwrap();
    assert_eq!(admitted.path(), &path);
    assert_eq!(admitted.root().absolute_path, "/synthetic/case");
    let other = PathRef::new(root_id, "not-requested").unwrap();
    assert!(matches!(
        context.path_scope(OperationTarget::File(&other)),
        Err(Code::ScopeDenied)
    ));
    assert!(matches!(
        context.path_scope(OperationTarget::Indicators),
        Err(Code::ScopeDenied)
    ));

    for (kind, collector, capability, format) in [
        ("journal_file", "events", "events", None),
        ("text_log", "events", "events", Some("rfc5424")),
        (
            "startup_directory",
            "persistence",
            "persistence",
            Some("cron"),
        ),
    ] {
        let id = Uuid::parse("10000000-0000-4000-8000-000000000091").unwrap();
        let mut source = json!({"source_id":id,"kind":kind,"path":path});
        if let Some(format) = format {
            source["format"] = json!(format);
        }
        for index in [1, 2] {
            values[index]["scope"]["source_groups"] = json!([kind]);
            values[index]["scope"]["capabilities"] = json!([capability]);
        }
        values[2]["sources"] = json!([source]);
        values[3]["source_ids"] = json!([id]);
        values[3]["collectors"] = json!([collector]);
        values[3]["capabilities"] = json!([capability]);
        values[3]["paths"] = json!([]);
        let context = attempt(&values, false).unwrap();
        assert_eq!(
            context
                .path_scope(OperationTarget::Source(&id))
                .unwrap()
                .path(),
            &path
        );
        assert!(matches!(
            context.path_scope(OperationTarget::File(&path)),
            Err(Code::ScopeDenied)
        ));
    }
    let context = attempt(&inputs(), false).unwrap();
    let id = context.sources()[0].definition().id();
    assert!(matches!(
        context.path_scope(OperationTarget::Source(id)),
        Err(Code::ScopeDenied)
    ));
}
