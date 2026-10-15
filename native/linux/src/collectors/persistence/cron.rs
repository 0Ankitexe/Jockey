use super::{lines, not_requested, record};
use jocky_shared::collection::{
    Code,
    inputs::{PathRef, StartupFormat},
    records::PersistenceRecord,
};

pub(crate) fn parse(raw: &[u8], location: PathRef) -> Result<PersistenceRecord, Code> {
    let mut targets = Vec::new();
    for line in lines(raw)? {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('@') {
            return Err(Code::UnsupportedFormat);
        }
        if line.contains('=') && !line.contains(' ') {
            continue;
        } // environment metadata, never evaluated
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 6 {
            return Err(Code::MalformedSource);
        }
        if fields[..5].iter().any(|field| {
            !field
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'*' | b',' | b'-' | b'/'))
        }) {
            return Err(Code::UnsupportedFormat);
        }
        let command = fields[5..].join(" ");
        targets.push(command);
    }
    if targets.is_empty() {
        return Err(Code::MalformedSource);
    }
    record(StartupFormat::Cron, location, raw, targets, not_requested())
}
