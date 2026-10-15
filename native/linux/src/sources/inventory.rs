//! Bounded alias ledger for retained ordinary roots, not fixed-facility admission.
use super::{
    capabilities::OutputDirectory,
    metadata::{Exclusions, ObjectId},
    paths::ConfinedRoot,
};
use jocky_forensic::collection::{
    ValidatedCollectionContext, cancellation::Cancellation, clock::Clock, context::OperationTarget,
};
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    inputs::{PathRef, SourceKind, SourceRef},
    outcomes::{Collector, FacilityState},
};

/// Standalone native implementation metadata. This is deliberately separate
/// from the fixture language catalogue and from an observed facility result.
pub(crate) const NATIVE_ADAPTER_VERSION: &str = "1.0.0";
pub(crate) const RUNTIME_FACILITY_VERSION: &str = "1.0.0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeAdapterDescriptor {
    pub version: &'static str,
    pub collector: Collector,
    pub source: Option<SourceKind>,
    pub compiled: bool,
}
pub(crate) fn native_adapters() -> [NativeAdapterDescriptor; 10] {
    use Collector as C;
    use SourceKind as S;
    let item = |collector, source, compiled| NativeAdapterDescriptor {
        version: NATIVE_ADAPTER_VERSION,
        collector,
        source,
        compiled,
    };
    [
        item(C::System, Some(S::KernelProfile), true),
        item(C::Processes, Some(S::ProcProcesses), true),
        item(C::Services, Some(S::SystemdBus), true),
        item(C::Connections, Some(S::ProcNet), true),
        item(C::Persistence, Some(S::StartupDirectory), true),
        item(C::Files, None, true),
        item(C::Events, Some(S::TextLog), true),
        item(C::Events, Some(S::JournalFile), cfg!(feature = "journal")),
        item(C::Drivers, Some(S::SysModules), true),
        item(C::Indicators, None, true),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeFacilityDescriptor {
    pub version: &'static str,
    pub source_id: Uuid,
    pub state: FacilityState,
    pub reason: Option<Code>,
}
pub(crate) fn observed_facilities(
    coverage: &[jocky_shared::collection::outcomes::Coverage],
) -> Vec<RuntimeFacilityDescriptor> {
    coverage
        .iter()
        .map(|item| RuntimeFacilityDescriptor {
            version: RUNTIME_FACILITY_VERSION,
            source_id: item.source_id.clone(),
            state: item.state,
            reason: item.reason,
        })
        .collect()
}

/// The native capabilities for one already admitted invocation. This owns all
/// descriptor pins; a later worker must receive authenticated handles rather
/// than reopening any of these pathnames from request data.
pub(crate) struct ResolvedCapabilities<'ctx> {
    output: OutputDirectory<'ctx>,
    roots: Vec<(PathRef, ConfinedRoot<'ctx>)>,
    fixed: Vec<(Uuid, FixedFacility)>,
}

impl<'ctx> ResolvedCapabilities<'ctx> {
    pub fn admit(
        context: &'ctx ValidatedCollectionContext,
        configuration: &[ObjectId],
        output_path: &str,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Self, Code> {
        // A selected target is required before the first native metadata call.
        let target = context
            .paths()
            .first()
            .map(|path| OperationTarget::File(path.path()))
            .or_else(|| {
                context
                    .sources()
                    .first()
                    .map(|source| OperationTarget::Source(source.definition().id()))
            })
            .ok_or(Code::ScopeDenied)?;
        let output = OutputDirectory::open(context, target, output_path, clock, cancel)?;
        let mut inventory = Inventory::new(configuration, &output)?;
        let mut roots = Vec::new();
        let mut fixed = Vec::new();

        for path in context.paths() {
            if roots.iter().any(|(selected, _)| selected == path.path()) {
                continue;
            }
            let root = ConfinedRoot::open(
                context,
                OperationTarget::File(path.path()),
                inventory.exclusions(),
                clock,
                cancel,
            )?;
            inventory.add(&root)?;
            roots.push((path.path().clone(), root));
        }
        for source in context.sources() {
            let definition = source.definition();
            match definition {
                SourceRef::JournalFile { path, .. }
                | SourceRef::TextLog { path, .. }
                | SourceRef::StartupDirectory { path, .. } => {
                    let root = ConfinedRoot::open(
                        context,
                        OperationTarget::Source(definition.id()),
                        inventory.exclusions(),
                        clock,
                        cancel,
                    )?;
                    inventory.add(&root)?;
                    roots.push((path.clone(), root));
                }
                _ => fixed.push((
                    definition.id().clone(),
                    selected_fixed(context, definition.id(), clock, cancel)?,
                )),
            }
        }
        output.check_unchanged(clock, cancel)?;
        Ok(Self {
            output,
            roots,
            fixed,
        })
    }

    pub fn output(&self) -> &OutputDirectory<'ctx> {
        &self.output
    }

    pub fn ordinary_roots(&self) -> &[(PathRef, ConfinedRoot<'ctx>)] {
        &self.roots
    }

    pub fn fixed_facilities(&self) -> &[(Uuid, FixedFacility)] {
        &self.fixed
    }
}

/// A fixed facility is a source selected by the sealed case context. The
/// paths are code-owned literals, never request- or distro-derived locations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FixedFacility {
    pub kind: SourceKind,
    pub primary: &'static str,
    pub secondary: Option<&'static str>,
}

pub(crate) fn selected_fixed(
    context: &ValidatedCollectionContext,
    id: &Uuid,
    clock: &mut dyn Clock,
    cancel: &dyn Cancellation,
) -> Result<FixedFacility, Code> {
    // The permit check runs before any native source lookup. It is dropped
    // without I/O; the eventual source must obtain its own current permit.
    context.permit(
        OperationTarget::Source(id),
        &clock.read()?,
        cancel.cancelled(),
    )?;
    let source = context
        .sources()
        .iter()
        .find(|source| source.definition().id() == id)
        .ok_or(Code::ScopeDenied)?;
    fixed(source.definition())
}

fn fixed(source: &SourceRef) -> Result<FixedFacility, Code> {
    let (primary, secondary) = match source {
        SourceRef::KernelProfile { .. } => ("/proc", Some("/usr/lib/os-release")),
        SourceRef::ProcProcesses { .. } | SourceRef::ProcNet { .. } => ("/proc", None),
        SourceRef::SysModules { .. } => ("/proc", Some("/sys")),
        SourceRef::SystemdBus { unix_path, .. } if unix_path == "/run/dbus/system_bus_socket" => {
            ("/run/dbus/system_bus_socket", None)
        }
        SourceRef::SystemdBus { .. } => return Err(Code::ScopeDenied),
        _ => return Err(Code::Unsupported),
    };
    Ok(FixedFacility {
        kind: source.kind(),
        primary,
        secondary,
    })
}

pub(crate) struct Inventory {
    output_path: String,
    output_lineage: Vec<ObjectId>,
    excluded: Exclusions,
    roots: Vec<(Uuid, String, Vec<ObjectId>)>,
    closed: bool,
}
impl Inventory {
    pub fn new(configuration: &[ObjectId], output: &OutputDirectory<'_>) -> Result<Self, Code> {
        let (path, lineage) = output.identity();
        Self::create(configuration, path, lineage)
    }
    fn create(configuration: &[ObjectId], path: &str, lineage: &[ObjectId]) -> Result<Self, Code> {
        if configuration.len() > 5 || lineage.is_empty() || lineage.len() > 257 {
            return Err(Code::ResourceLimit);
        }
        if configuration
            .iter()
            .enumerate()
            .any(|(n, id)| configuration[..n].contains(id))
            || configuration.iter().any(|id| lineage.contains(id))
        {
            return Err(Code::AliasDenied);
        }
        let mut ids = configuration.to_vec();
        ids.push(*lineage.last().ok_or(Code::InvalidInput)?);
        Ok(Self {
            output_path: path.into(),
            output_lineage: lineage.to_vec(),
            excluded: Exclusions::new(&ids)?,
            roots: Vec::new(),
            closed: false,
        })
    }
    pub fn exclusions(&self) -> Exclusions {
        self.excluded.clone()
    }
    pub fn add(&mut self, root: &ConfinedRoot<'_>) -> Result<(), Code> {
        let (path, lineage) = root.identity();
        let result = self.insert(root.root_id(), path, lineage);
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    fn insert(&mut self, id: &Uuid, path: &str, lineage: &[ObjectId]) -> Result<(), Code> {
        if self.closed {
            return Err(Code::AliasDenied);
        }
        if lineage.len() > 257 {
            return Err(Code::ResourceLimit);
        }
        let object = *lineage.last().ok_or(Code::InvalidInput)?;
        let output = *self.output_lineage.last().ok_or(Code::InvalidInput)?;
        if overlaps(path, &self.output_path)
            || lineage.contains(&output)
            || self.output_lineage.contains(&object)
        {
            return Err(Code::AliasDenied);
        }
        self.excluded.check(object)?;
        for (prior_id, prior_path, prior_lineage) in &self.roots {
            let prior_object = *prior_lineage.last().ok_or(Code::InvalidInput)?;
            if prior_id == id {
                return if prior_path == path && prior_lineage == lineage {
                    Ok(())
                } else {
                    Err(Code::SourceChanged)
                };
            }
            if prior_lineage.contains(&object)
                || lineage.contains(&prior_object)
                || overlaps(prior_path, path)
            {
                return Err(Code::AliasDenied);
            }
        }
        if self.roots.len() == 128 {
            return Err(Code::ResourceLimit);
        }
        self.roots.push((id.clone(), path.into(), lineage.to_vec()));
        Ok(())
    }
}
fn overlaps(a: &str, b: &str) -> bool {
    fn under(a: &str, b: &str) -> bool {
        a == b || a.strip_prefix(b).is_some_and(|s| s.starts_with('/'))
    }
    under(a, b) || under(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn object(inode: u64) -> ObjectId {
        ObjectId { device: 1, inode }
    }
    fn id(n: u64) -> Uuid {
        Uuid::parse(&format!("10000000-0000-4000-8000-{n:012}")).unwrap()
    }
    #[test]
    fn fixed_facilities_never_use_a_supplied_bus_path_or_distro_name() {
        let good = SourceRef::SystemdBus {
            source_id: id(1),
            unix_path: "/run/dbus/system_bus_socket".into(),
        };
        assert_eq!(fixed(&good).unwrap().primary, "/run/dbus/system_bus_socket");
        let bad = SourceRef::SystemdBus {
            source_id: id(1),
            unix_path: "/tmp/other-bus".into(),
        };
        assert_eq!(fixed(&bad), Err(Code::ScopeDenied));
        assert_eq!(
            fixed(&SourceRef::ProcProcesses { source_id: id(2) })
                .unwrap()
                .primary,
            "/proc"
        );
    }
    #[test]
    fn component_boundaries_and_physical_ancestry_both_detect_overlap() {
        assert!(!overlaps("/case/files", "/case/files-other"));
        for (path, lineage) in [
            ("/alias", vec![object(0), object(4)]),
            ("/parent", vec![object(0), object(1)]),
        ] {
            let mut inventory =
                Inventory::create(&[], "/output", &[object(0), object(1), object(4)]).unwrap();
            assert_eq!(
                inventory.insert(&id(1), path, &lineage),
                Err(Code::AliasDenied)
            );
        }
    }

    #[test]
    fn source_roots_reject_nested_paths_in_either_order_but_allow_siblings() {
        for (first, second) in [
            ("/case/files", "/case/files/sub"),
            ("/case/files/sub", "/case/files"),
        ] {
            let mut inventory = Inventory::create(&[], "/output", &[object(0), object(4)]).unwrap();
            inventory
                .insert(&id(1), first, &[object(0), object(5)])
                .unwrap();
            assert_eq!(
                inventory.insert(&id(2), second, &[object(0), object(6)]),
                Err(Code::AliasDenied)
            );
        }
        let mut inventory = Inventory::create(&[], "/output", &[object(0), object(4)]).unwrap();
        inventory
            .insert(&id(1), "/case/files", &[object(0), object(5)])
            .unwrap();
        assert_eq!(
            inventory.insert(&id(2), "/case/files-other", &[object(0), object(6)]),
            Ok(())
        );
    }
    #[test]
    fn source_roots_reject_physical_ancestry_with_distinct_names() {
        for (first, second) in [
            (
                ("/case/a", vec![object(0), object(5)]),
                ("/case/b", vec![object(0), object(5), object(6)]),
            ),
            (
                ("/case/b", vec![object(0), object(5), object(6)]),
                ("/case/a", vec![object(0), object(5)]),
            ),
        ] {
            let mut inventory = Inventory::create(&[], "/output", &[object(0), object(4)]).unwrap();
            inventory.insert(&id(1), first.0, &first.1).unwrap();
            assert_eq!(
                inventory.insert(&id(2), second.0, &second.1),
                Err(Code::AliasDenied)
            );
        }
    }
    #[test]
    fn repeated_root_is_allowed_but_new_id_alias_and_rebinding_fail() {
        let mut inventory = Inventory::create(&[], "/output", &[object(0), object(4)]).unwrap();
        assert_eq!(
            inventory.insert(&id(1), "/files", &[object(0), object(5)]),
            Ok(())
        );
        assert_eq!(
            inventory.insert(&id(1), "/files", &[object(0), object(5)]),
            Ok(())
        );
        assert_eq!(
            inventory.insert(&id(2), "/alias", &[object(0), object(5)]),
            Err(Code::AliasDenied)
        );
        assert_eq!(
            inventory.insert(&id(1), "/files", &[object(0), object(6)]),
            Err(Code::SourceChanged)
        );
    }
    #[test]
    fn invalid_duplicate_config_id_and_oversized_inventory_fail_closed() {
        assert!(matches!(
            Inventory::create(&[object(1), object(1)], "/output", &[object(0), object(4)]),
            Err(Code::AliasDenied)
        ));
        assert!(matches!(
            Inventory::create(&[object(4)], "/output", &[object(0), object(4)]),
            Err(Code::AliasDenied)
        ));
        assert!(matches!(
            Inventory::create(&[object(1); 6], "/output", &[object(0), object(4)]),
            Err(Code::ResourceLimit)
        ));
        let mut inventory = Inventory::create(&[], "/output", &[object(0), object(4)]).unwrap();
        for n in 0..128 {
            inventory
                .insert(&id(n), &format!("/files/{n}"), &[object(0), object(n + 10)])
                .unwrap();
        }
        assert_eq!(
            inventory.insert(&id(129), "/last", &[object(0), object(999)]),
            Err(Code::ResourceLimit)
        );
    }
}
