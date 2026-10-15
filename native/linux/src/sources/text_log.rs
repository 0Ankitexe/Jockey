//! Source-specific admission over already scoped log bytes.
use jocky_shared::collection::Code;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogSource {
    Syslog,
    Auth,
    Approved,
}

/// The caller supplies a confined, charged, complete read from an approved
/// `SourceRef::TextLog`. The two source roles never fall back to each other.
pub(crate) fn stable_bytes(
    _role: LogSource,
    source: Result<&[u8], Code>,
    same_identity: bool,
) -> Result<&[u8], Code> {
    let raw = source?;
    if !same_identity {
        return Err(Code::SourceChanged);
    }
    if raw.len() > 65_536 {
        return Err(Code::ResourceLimit);
    }
    Ok(raw)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    #[test]
    fn each_source_preserves_missing_denied_empty_and_rotation() {
        for role in [LogSource::Syslog, LogSource::Auth] {
            assert_eq!(
                stable_bytes(role, Err(Code::NotFound), true),
                Err(Code::NotFound)
            );
            assert_eq!(
                stable_bytes(role, Err(Code::PermissionDenied), true),
                Err(Code::PermissionDenied)
            );
            assert_eq!(stable_bytes(role, Ok(b""), true), Ok(b"".as_slice()));
            assert_eq!(stable_bytes(role, Ok(b""), false), Err(Code::SourceChanged));
        }
    }
}

/// Confined complete read for one explicitly selected RFC5424 text source.
/// The approved root and source permit are retained by `ConfinedRoot`; no
/// fallback pathname, alternate format or host log discovery is attempted.
pub(crate) fn read_admitted(
    _role: LogSource,
    root: &super::paths::ConfinedRoot<'_>,
    path: &jocky_shared::collection::inputs::PathRef,
    clock: &mut dyn jocky_forensic::collection::clock::Clock,
    cancel: &dyn jocky_forensic::collection::cancellation::Cancellation,
) -> Result<Vec<u8>, Code> {
    if root.root_id() != &path.root_id {
        return Err(Code::ScopeDenied);
    }
    let pin = root.pin_file(&path.relative_path, clock, cancel)?;
    let readable = pin.reopen(clock, cancel)?;
    let raw = super::reads::read_all(&readable, 65_536, clock, cancel)?;
    readable.check_unchanged(clock, cancel)?;
    Ok(raw)
}
