use super::{lines, not_requested, record, validated_location};
use jocky_shared::collection::{
    Code,
    inputs::{PathRef, StartupFormat},
    records::PersistenceRecord,
};

fn parse(raw: &[u8], location: PathRef, timer: bool) -> Result<PersistenceRecord, Code> {
    validated_location(&location, if timer { ".timer" } else { ".service" })?;
    let mut section = "";
    let mut targets = Vec::new();
    let mut assignment = false;
    let mut exec_seen = false;
    for line in lines(raw)? {
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') {
            section = line
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .ok_or(Code::MalformedSource)?;
            if !matches!(section, "Unit" | "Service" | "Timer" | "Install") {
                return Err(Code::UnsupportedFormat);
            }
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(Code::MalformedSource)?;
        assignment = true;
        let value = value.trim();
        if value.is_empty() || section.is_empty() {
            return Err(Code::MalformedSource);
        }
        match (section, key.trim()) {
            ("Service", "ExecStart") if !timer => {
                if exec_seen {
                    return Err(Code::MalformedSource);
                }
                exec_seen = true;
                targets.push(value.into());
            }
            ("Timer", "Unit") if timer => {
                targets.push(value.into());
            }
            ("Install", "WantedBy" | "RequiredBy" | "Also") => {
                targets.extend(value.split_ascii_whitespace().map(str::to_owned));
            }
            ("Timer", "OnCalendar" | "OnBootSec" | "OnUnitActiveSec") if timer => {}
            ("Unit", "Description" | "After" | "Requires" | "Wants") => {}
            // Other bounded directives remain inert metadata. A unit file is
            // an inventory item, not a command or authority to follow a path.
            _ => {}
        }
    }
    if !assignment {
        return Err(Code::MalformedSource);
    }
    record(
        if timer {
            StartupFormat::SystemdTimers
        } else {
            StartupFormat::SystemdUnits
        },
        location,
        raw,
        targets,
        not_requested(),
    )
}

pub(crate) fn parse_unit(raw: &[u8], location: PathRef) -> Result<PersistenceRecord, Code> {
    parse(raw, location, false)
}
pub(crate) fn parse_timer(raw: &[u8], location: PathRef) -> Result<PersistenceRecord, Code> {
    parse(raw, location, true)
}
