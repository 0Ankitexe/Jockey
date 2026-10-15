//! Closed, read-only systemd bus inventory. The real transport connects only
//! to the approved system bus Unix socket after source admission.
use jocky_forensic::collection::{
    ValidatedCollectionContext, budget::Counter, cancellation::Cancellation, clock::Clock,
    context::OperationTarget,
};
use jocky_shared::collection::{Code, identity::Uuid};
use std::collections::BTreeMap;
use std::time::Duration;

const SOCKET: &str = "/run/dbus/system_bus_socket";
const DESTINATION: &str = "org.freedesktop.systemd1";
const MANAGER: &str = "/org/freedesktop/systemd1";
const MAX_ROWS: usize = 512;
const MAX_REPLY_BYTES: usize = 1_048_576;
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const MAX_QUEUE: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Property {
    Description,
    LoadState,
    ActiveState,
    SubState,
}
impl Property {
    fn name(self) -> &'static str {
        match self {
            Self::Description => "Description",
            Self::LoadState => "LoadState",
            Self::ActiveState => "ActiveState",
            Self::SubState => "SubState",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BusCall {
    ListUnits,
    ListUnitFiles,
    Get {
        object_path: String,
        property: Property,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BusRoute<'a> {
    pub destination: &'static str,
    pub path: &'a str,
    pub interface: &'static str,
    pub member: &'static str,
    pub no_auto_start: bool,
}
pub(crate) fn route(call: &BusCall) -> Result<BusRoute<'_>, Code> {
    let (path, interface, member) = match call {
        BusCall::ListUnits => (MANAGER, "org.freedesktop.systemd1.Manager", "ListUnits"),
        BusCall::ListUnitFiles => (MANAGER, "org.freedesktop.systemd1.Manager", "ListUnitFiles"),
        BusCall::Get {
            object_path: path, ..
        } if object_path(path) => (path.as_str(), "org.freedesktop.DBus.Properties", "Get"),
        BusCall::Get { .. } => return Err(Code::MalformedSource),
    };
    Ok(BusRoute {
        destination: DESTINATION,
        path,
        interface,
        member,
        no_auto_start: true,
    })
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnitFact {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub object_path: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnitFileFact {
    pub name: String,
    pub state: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BusReply {
    Units(Vec<UnitFact>),
    UnitFiles(Vec<UnitFileFact>),
    Text(String),
}
pub(crate) trait BusTransport {
    fn call(&mut self, call: BusCall) -> Result<BusReply, Code>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub units: Vec<UnitFact>,
    pub files: Vec<UnitFileFact>,
    pub properties: BTreeMap<(String, Property), Result<String, Code>>,
}

fn unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b':' | b'\\')
        })
        && !name.contains("..")
}
fn object_path(path: &str) -> bool {
    path.starts_with("/org/freedesktop/systemd1/unit/")
        && path.len() <= 512
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_'))
        && !path.contains("//")
}
fn text(value: &str) -> bool {
    value.len() <= 4096 && !value.contains(['\0', '\n', '\r'])
}
fn reply_size(reply: &BusReply) -> usize {
    match reply {
        BusReply::Units(units) => units.iter().fold(0usize, |size, unit| {
            size.saturating_add(unit.name.len())
                .saturating_add(unit.description.len())
                .saturating_add(unit.load_state.len())
                .saturating_add(unit.active_state.len())
                .saturating_add(unit.sub_state.len())
                .saturating_add(unit.object_path.len())
        }),
        BusReply::UnitFiles(files) => files.iter().fold(0usize, |size, file| {
            size.saturating_add(file.name.len())
                .saturating_add(file.state.len())
        }),
        BusReply::Text(value) => value.len(),
    }
}
fn bound(reply: &BusReply) -> Result<usize, Code> {
    let size = reply_size(reply);
    if size > MAX_REPLY_BYTES {
        return Err(Code::ResourceLimit);
    }
    match reply {
        BusReply::Units(units) => {
            if units.len() > MAX_ROWS {
                return Err(Code::ResourceLimit);
            }
            for unit in units {
                if !unit_name(&unit.name)
                    || !object_path(&unit.object_path)
                    || !text(&unit.description)
                    || !text(&unit.load_state)
                    || !text(&unit.active_state)
                    || !text(&unit.sub_state)
                {
                    return Err(Code::MalformedSource);
                }
            }
        }
        BusReply::UnitFiles(files) => {
            if files.len() > MAX_ROWS {
                return Err(Code::ResourceLimit);
            }
            for file in files {
                if !unit_name(&file.name) || !text(&file.state) {
                    return Err(Code::MalformedSource);
                }
            }
        }
        BusReply::Text(value) => {
            if !text(value) {
                return Err(Code::MalformedSource);
            }
        }
    }
    Ok(size)
}

fn bound_transport(reply: &BusReply) -> Result<usize, Code> {
    let size = reply_size(reply);
    let rows = match reply {
        BusReply::Units(rows) => rows.len(),
        BusReply::UnitFiles(rows) => rows.len(),
        BusReply::Text(_) => 0,
    };
    if size > MAX_REPLY_BYTES || rows > MAX_ROWS {
        Err(Code::ResourceLimit)
    } else {
        Ok(size)
    }
}

/// Query a closed inventory method set through an injected transport. The
/// caller supplying a real transport must have already checked the source
/// permit; no method name or destination comes from a policy or reply.
pub(crate) fn query(bus: &mut impl BusTransport) -> Result<Snapshot, Code> {
    let BusReply::Units(units) = bus.call(BusCall::ListUnits)? else {
        return Err(Code::WorkerProtocol);
    };
    bound(&BusReply::Units(units.clone()))?;
    let BusReply::UnitFiles(files) = bus.call(BusCall::ListUnitFiles)? else {
        return Err(Code::WorkerProtocol);
    };
    bound(&BusReply::UnitFiles(files.clone()))?;
    let mut properties = BTreeMap::new();
    for unit in &units {
        for property in [
            Property::Description,
            Property::LoadState,
            Property::ActiveState,
            Property::SubState,
        ] {
            let answer = bus.call(BusCall::Get {
                object_path: unit.object_path.clone(),
                property,
            });
            let value = match answer {
                Ok(BusReply::Text(value)) if text(&value) => Ok(value),
                Ok(BusReply::Text(_)) => Err(Code::MalformedSource),
                Ok(_) => Err(Code::WorkerProtocol),
                Err(code) => Err(code),
            };
            properties.insert((unit.name.clone(), property), value);
        }
    }
    Ok(Snapshot {
        units,
        files,
        properties,
    })
}

/// Native inventory uses fields already returned by ListUnits. This keeps
/// collection within the bounded invocation window on hosts with many units.
pub(crate) fn query_listed(bus: &mut impl BusTransport) -> Result<(Snapshot, bool), Code> {
    let BusReply::Units(raw_units) = bus.call(BusCall::ListUnits)? else {
        return Err(Code::WorkerProtocol);
    };
    if raw_units.len() > MAX_ROWS
        || reply_size(&BusReply::Units(raw_units.clone())) > MAX_REPLY_BYTES
    {
        return Err(Code::ResourceLimit);
    }
    let mut malformed = false;
    let mut seen = std::collections::BTreeSet::new();
    let units: Vec<_> = raw_units
        .into_iter()
        .filter(|row| row.name.ends_with(".service"))
        .filter(|row| {
            let valid = unit_name(&row.name)
                && object_path(&row.object_path)
                && text(&row.description)
                && text(&row.load_state)
                && text(&row.active_state)
                && text(&row.sub_state)
                && seen.insert(row.name.clone());
            malformed |= !valid;
            valid
        })
        .collect();
    let BusReply::UnitFiles(raw_files) = bus.call(BusCall::ListUnitFiles)? else {
        return Err(Code::WorkerProtocol);
    };
    if raw_files.len() > MAX_ROWS
        || reply_size(&BusReply::UnitFiles(raw_files.clone())) > MAX_REPLY_BYTES
    {
        return Err(Code::ResourceLimit);
    }
    let mut seen_files = std::collections::BTreeSet::new();
    let files: Vec<_> = raw_files
        .into_iter()
        .filter(|row| row.name.ends_with(".service"))
        .filter(|row| {
            let valid =
                unit_name(&row.name) && text(&row.state) && seen_files.insert(row.name.clone());
            malformed |= !valid;
            valid
        })
        .collect();
    Ok((
        Snapshot {
            units,
            files,
            properties: BTreeMap::new(),
        },
        malformed,
    ))
}

/// Open only the systemd bus selected in the sealed context. This function
/// does not infer availability from distribution metadata.
pub(crate) fn connect_admitted<'a>(
    context: &'a ValidatedCollectionContext,
    source_id: &'a Uuid,
    clock: &'a mut dyn Clock,
    cancel: &'a dyn Cancellation,
) -> Result<AdmittedBus<'a>, Code> {
    context.permit(
        OperationTarget::Source(source_id),
        &clock.read()?,
        cancel.cancelled(),
    )?;
    let selected = context.sources().iter().any(|source| {
        matches!(source.definition(), jocky_shared::collection::inputs::SourceRef::SystemdBus { source_id: id, unix_path } if id == source_id && unix_path == SOCKET)
    });
    if !selected {
        return Err(Code::ScopeDenied);
    }
    let transport = ZbusTransport::connect(SOCKET)?;
    context.permit(
        OperationTarget::Source(source_id),
        &clock.read()?,
        cancel.cancelled(),
    )?;
    Ok(AdmittedBus {
        transport,
        context,
        source_id,
        clock,
        cancel,
    })
}

pub(crate) struct AdmittedBus<'a> {
    transport: ZbusTransport,
    context: &'a ValidatedCollectionContext,
    source_id: &'a Uuid,
    clock: &'a mut dyn Clock,
    cancel: &'a dyn Cancellation,
}
impl BusTransport for AdmittedBus<'_> {
    fn call(&mut self, call: BusCall) -> Result<BusReply, Code> {
        let mut permit = self.context.permit(
            OperationTarget::Source(self.source_id),
            &self.clock.read()?,
            self.cancel.cancelled(),
        )?;
        let result = self.transport.call(call);
        if result.is_err() {
            permit.charge(Counter::Errors, 1)?;
        }
        if let Ok(reply) = &result {
            permit.charge(Counter::SourceBytes, reply_size(reply) as u64)?;
            bound_transport(reply)?;
        }
        permit.renew(&self.clock.read()?, self.cancel.cancelled())?;
        result
    }
}

pub(crate) struct ZbusTransport {
    runtime: tokio::runtime::Runtime,
    connection: zbus::Connection,
}
impl ZbusTransport {
    fn connect(path: &str) -> Result<Self, Code> {
        if path != SOCKET {
            return Err(Code::ScopeDenied);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Code::FacilityUnavailable)?;
        let connection = runtime.block_on(async {
            let stream = tokio::time::timeout(CALL_TIMEOUT, tokio::net::UnixStream::connect(path))
                .await
                .map_err(|_| Code::Timeout)?
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::PermissionDenied => Code::PermissionDenied,
                    std::io::ErrorKind::NotFound => Code::Unsupported,
                    _ => Code::FacilityUnavailable,
                })?;
            tokio::time::timeout(
                CALL_TIMEOUT,
                zbus::connection::Builder::unix_stream(stream)
                    .method_timeout(CALL_TIMEOUT)
                    .build(),
            )
            .await
            .map_err(|_| Code::Timeout)?
            .map_err(|_| Code::FacilityUnavailable)
        })?;
        let mut connection = connection;
        connection.set_max_queued(MAX_QUEUE);
        Ok(Self {
            runtime,
            connection,
        })
    }
}
impl BusTransport for ZbusTransport {
    fn call(&mut self, call: BusCall) -> Result<BusReply, Code> {
        use zbus::proxy::{CacheProperties, MethodFlags, Proxy};
        use zbus::zvariant::{OwnedObjectPath, OwnedValue};
        type UnitRow = (
            String,
            String,
            String,
            String,
            String,
            String,
            OwnedObjectPath,
            u32,
            String,
            OwnedObjectPath,
        );
        let connection = &self.connection;
        self.runtime.block_on(async {
            let selected = route(&call)?;
            if !selected.no_auto_start {
                return Err(Code::WorkerProtocol);
            }
            let proxy = zbus::proxy::Builder::<Proxy<'_>>::new(connection)
                .destination(selected.destination)
                .map_err(|_| Code::WorkerProtocol)?
                .path(selected.path)
                .map_err(|_| Code::WorkerProtocol)?
                .interface(selected.interface)
                .map_err(|_| Code::WorkerProtocol)?
                .cache_properties(CacheProperties::No)
                .build()
                .await
                .map_err(|_| Code::FacilityUnavailable)?;
            let flags = MethodFlags::NoAutoStart.into();
            let answer = tokio::time::timeout(CALL_TIMEOUT, async {
                match call {
                    BusCall::ListUnits => {
                        let rows: Vec<UnitRow> = proxy
                            .call_with_flags(selected.member, flags, &())
                            .await
                            .map_err(map_bus)?
                            .ok_or(Code::WorkerProtocol)?;
                        Ok(BusReply::Units(
                            rows.into_iter()
                                .map(
                                    |(
                                        name,
                                        description,
                                        load_state,
                                        active_state,
                                        sub_state,
                                        _,
                                        object_path,
                                        _,
                                        _,
                                        _,
                                    )| UnitFact {
                                        name,
                                        description,
                                        load_state,
                                        active_state,
                                        sub_state,
                                        object_path: object_path.to_string(),
                                    },
                                )
                                .collect(),
                        ))
                    }
                    BusCall::ListUnitFiles => {
                        let rows: Vec<(String, String)> = proxy
                            .call_with_flags(selected.member, flags, &())
                            .await
                            .map_err(map_bus)?
                            .ok_or(Code::WorkerProtocol)?;
                        Ok(BusReply::UnitFiles(
                            rows.into_iter()
                                .map(|(name, state)| UnitFileFact { name, state })
                                .collect(),
                        ))
                    }
                    BusCall::Get { property, .. } => {
                        let value: OwnedValue = proxy
                            .call_with_flags(
                                selected.member,
                                flags,
                                &("org.freedesktop.systemd1.Unit", property.name()),
                            )
                            .await
                            .map_err(map_bus)?
                            .ok_or(Code::WorkerProtocol)?;
                        String::try_from(value)
                            .map(BusReply::Text)
                            .map_err(|_| Code::MalformedSource)
                    }
                }
            })
            .await
            .map_err(|_| Code::Timeout)??;
            Ok(answer)
        })
    }
}

fn map_bus(error: zbus::Error) -> Code {
    match error {
        zbus::Error::MethodError(name, _, _) if name.as_str().ends_with("AccessDenied") => {
            Code::PermissionDenied
        }
        zbus::Error::MethodError(name, _, _)
            if name.as_str().ends_with("ServiceUnknown")
                || name.as_str().ends_with("NameHasNoOwner") =>
        {
            Code::Unsupported
        }
        zbus::Error::MethodError(name, _, _) if name.as_str().ends_with("NoSuchUnit") => {
            Code::NotFound
        }
        _ => Code::FacilityUnavailable,
    }
}
