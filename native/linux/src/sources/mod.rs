//! Private descriptor foundation. No constructor is exposed by the live CLI.
pub(crate) mod capabilities;
pub(crate) mod inventory;
pub(crate) mod journal;
pub(crate) mod journal_snapshot;
pub(crate) mod metadata;
mod operation;
pub(crate) mod paths;
pub(crate) mod procfs;
pub(crate) mod reads;
pub(crate) mod system;
pub(crate) mod systemd;
pub(crate) mod text_log;

fn error(error: rustix::io::Errno) -> jocky_shared::collection::Code {
    use jocky_shared::collection::Code;
    use rustix::io::Errno;
    match error {
        Errno::ACCESS | Errno::PERM => Code::PermissionDenied,
        Errno::NOENT => Code::NotFound,
        Errno::LOOP | Errno::XDEV | Errno::NOTDIR => Code::AliasDenied,
        Errno::NOSYS | Errno::NOTSUP | Errno::INVAL => Code::Unsupported,
        Errno::NOMEM | Errno::MFILE | Errno::NFILE => Code::ResourceLimit,
        Errno::AGAIN => Code::SourceChanged,
        _ => Code::FacilityUnavailable,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn syscall_failures_map_to_typed_reasons_without_fallback() {
        use jocky_shared::collection::Code;
        use rustix::io::Errno;
        for (errno, expected) in [
            (Errno::NOSYS, Code::Unsupported),
            (Errno::INVAL, Code::Unsupported),
            (Errno::NOTSUP, Code::Unsupported),
            (Errno::ACCESS, Code::PermissionDenied),
            (Errno::PERM, Code::PermissionDenied),
            (Errno::NOENT, Code::NotFound),
            (Errno::LOOP, Code::AliasDenied),
            (Errno::XDEV, Code::AliasDenied),
            (Errno::NOTDIR, Code::AliasDenied),
            (Errno::NOMEM, Code::ResourceLimit),
            (Errno::MFILE, Code::ResourceLimit),
            (Errno::NFILE, Code::ResourceLimit),
            (Errno::AGAIN, Code::SourceChanged),
            (Errno::IO, Code::FacilityUnavailable),
        ] {
            assert_eq!(super::error(errno), expected);
        }
    }
}
