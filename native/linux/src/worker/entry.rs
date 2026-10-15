//! Decode one launch document from an already owned, bounded control channel.
//! This parses untrusted metadata only. Peer, descriptor, clock and authority
//! checks are separate mandatory steps before a worker may acknowledge Start.
use jocky_shared::collection::{
    Code,
    launch::{WorkerLaunch, decode_launch},
};
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, OwnedFd};

const MAX_LAUNCH: usize = 65536;

pub(crate) fn receive_launch(reader: &mut impl Read) -> Result<WorkerLaunch, Code> {
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|_| Code::WorkerProtocol)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_LAUNCH {
        return Err(Code::WorkerProtocol);
    }
    let mut raw = Vec::new();
    raw.try_reserve_exact(length)
        .map_err(|_| Code::ResourceLimit)?;
    raw.resize(length, 0);
    reader
        .read_exact(&mut raw)
        .map_err(|_| Code::WorkerProtocol)?;
    decode_launch(&raw).map_err(|_| Code::WorkerProtocol)
}

/// The first permitted private entry step. A launch document is not trusted
/// until both inherited directions are Unix sockets owned by the actual,
/// unchanged parent process. This still does not validate authority or admit
/// evidence reads; the worker must do those checks after input commit.
#[cfg(target_os = "linux")]
pub(crate) fn receive_from_owned_parent(
    reader: &mut (impl Read + AsFd),
    writer: impl AsFd,
) -> Result<WorkerLaunch, Code> {
    super::peer::require_parent_channel(&*reader)?;
    super::peer::require_parent_channel(&writer)?;
    let launch = receive_launch(reader)?;
    super::peer::require_parent(&*reader, &launch.parent)?;
    super::peer::require_parent(writer, &launch.parent)?;
    Ok(launch)
}

/// First real private-entry transition: authenticate the parent, apply the
/// worker's address-space ceiling and compare transferred kernel objects with
/// their claimed identities. The reader must be unbuffered (an owned `File`
/// duplicate of stdin works); a buffered stdin reader could swallow ancillary
/// data while reading the launch packet. Input commitment/current authority
/// and per-source relationships remain required before Ready or evidence I/O.
#[cfg(target_os = "linux")]
pub(crate) fn receive_owned_launch(
    reader: &mut (impl Read + AsFd),
    writer: impl AsFd,
) -> Result<(WorkerLaunch, Vec<OwnedFd>), Code> {
    let launch = receive_from_owned_parent(reader, writer)?;
    let (_, worker_limit) =
        super::resource::split_address_space(launch.global_limits.max_memory_bytes)?;
    super::resource::limit_worker_address_space(worker_limit)?;
    let handles = if launch.descriptors.is_empty() {
        Vec::new()
    } else {
        super::handles::receive(&*reader, launch.descriptors.len())?
    };
    super::handles::verify_objects(&launch.descriptors, &handles, &launch.config_exclusions)?;
    Ok((launch, handles))
}
