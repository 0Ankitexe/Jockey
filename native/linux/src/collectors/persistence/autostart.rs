use super::{lines, record};
use jocky_shared::collection::{
    Code,
    inputs::{PathRef, StartupFormat},
    outcomes::Field,
    records::PersistenceRecord,
};

pub(crate) fn parse(raw: &[u8], location: PathRef) -> Result<PersistenceRecord, Code> {
    if !location.relative_path.ends_with(".desktop") {
        return Err(Code::ScopeDenied);
    }
    let mut in_entry = false;
    let mut app = false;
    let mut exec = None;
    let mut hidden = None;
    for line in lines(raw)? {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if line != "[Desktop Entry]" || in_entry {
                return Err(Code::UnsupportedFormat);
            }
            in_entry = true;
            continue;
        }
        if !in_entry {
            return Err(Code::MalformedSource);
        }
        let (key, value) = line.split_once('=').ok_or(Code::MalformedSource)?;
        if value.is_empty() {
            return Err(Code::MalformedSource);
        }
        match key {
            "Type" => {
                if app {
                    return Err(Code::MalformedSource);
                }
                app = value == "Application";
                if !app {
                    return Err(Code::UnsupportedFormat);
                }
            }
            "Exec" => {
                if exec.replace(value.to_owned()).is_some() {
                    return Err(Code::MalformedSource);
                }
            }
            "Hidden" => {
                if hidden.replace(value).is_some() || !matches!(value, "true" | "false") {
                    return Err(Code::MalformedSource);
                }
            }
            "Name" | "OnlyShowIn" | "NotShowIn" | "TryExec" => {}
            // Vendor keys are preserved only in the content digest.
            _ => {}
        }
    }
    if !app {
        return Err(Code::MalformedSource);
    }
    let exec = exec.ok_or(Code::MalformedSource)?;
    let state = if hidden == Some("true") {
        "disabled"
    } else {
        "declared"
    };
    record(
        StartupFormat::Autostart,
        location,
        raw,
        vec![exec],
        Field::Available {
            value: state.into(),
        },
    )
}
