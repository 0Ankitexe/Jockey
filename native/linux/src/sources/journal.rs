//! Optional native journal read from worker-private staged file names only.
#[cfg(feature = "journal")]
use super::journal_snapshot::JOURNAL_CAP;
use super::journal_snapshot::StagedJournal;
use jocky_shared::collection::Code;

#[derive(Clone, Debug)]
pub(crate) struct JournalFact {
    pub micros: u64,
    pub message: Vec<u8>,
    pub priority: Option<Vec<u8>>,
}

#[cfg(feature = "journal")]
pub(crate) fn read_staged(
    stage: &StagedJournal,
    mut charge_expanded: impl FnMut(u64) -> Result<(), Code>,
) -> Result<Vec<JournalFact>, Code> {
    let name = stage.named_path();
    let mut expanded = stage.copied();
    let mut journal = systemd::journal::OpenFilesOptions::default()
        .open_files([name.as_str()])
        .map_err(|_| Code::FacilityUnavailable)?;
    // libsystemd has opened the named copy. Remove its directory entry now so
    // a killed worker cannot leave journal contents behind in TMPDIR.
    std::fs::remove_file(&name).map_err(|_| Code::FacilityUnavailable)?;
    journal
        .set_data_threshold(4096)
        .map_err(|_| Code::FacilityUnavailable)?;
    let mut out = Vec::new();
    for _ in 0..10_001 {
        charge_expanded(0)?; // renew authority/deadline before every native step
        if journal.next().map_err(|_| Code::FacilityUnavailable)? == 0 {
            return Ok(out);
        }
        if out.len() >= 10_000 {
            return Err(Code::ResourceLimit);
        }
        let micros = journal
            .timestamp_usec()
            .map_err(|_| Code::FacilityUnavailable)?;
        let message = journal
            .get_data("MESSAGE")
            .map_err(|_| Code::FacilityUnavailable)?
            .and_then(|field| field.value().map(|v| v.to_vec()))
            .ok_or(Code::MalformedSource)?;
        charge_expanded(message.len() as u64)?;
        expanded = expanded
            .checked_add(message.len() as u64)
            .ok_or(Code::ResourceLimit)?;
        if expanded > JOURNAL_CAP {
            return Err(Code::ResourceLimit);
        }
        if message.len() > 4096 {
            return Err(Code::ResourceLimit);
        }
        let priority = journal
            .get_data("PRIORITY")
            .map_err(|_| Code::FacilityUnavailable)?
            .and_then(|field| field.value().map(|v| v.to_vec()));
        if let Some(ref bytes) = priority {
            charge_expanded(bytes.len() as u64)?;
            expanded = expanded
                .checked_add(bytes.len() as u64)
                .ok_or(Code::ResourceLimit)?;
            if expanded > JOURNAL_CAP {
                return Err(Code::ResourceLimit);
            }
        }
        out.push(JournalFact {
            micros,
            message,
            priority,
        });
    }
    Err(Code::ResourceLimit)
}

#[cfg(not(feature = "journal"))]
pub(crate) fn read_staged(
    _stage: &StagedJournal,
    _charge_expanded: impl FnMut(u64) -> Result<(), Code>,
) -> Result<Vec<JournalFact>, Code> {
    Err(Code::Unsupported)
}
