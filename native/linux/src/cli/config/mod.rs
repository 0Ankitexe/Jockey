//! Read only explicit input documents. No evidence sources, default search paths or live permit.
use jocky_forensic::collection::{
    ClockReading, InputSet, ValidatedCollectionContext, admit, admit_for_invocation,
};
use jocky_shared::collection::{Code, identity::Uuid};
use rustix::fd::AsFd;

mod paths;
pub use paths::ConfigPaths;
pub(crate) use paths::validate_output;
#[cfg(target_os = "linux")]
mod files;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

struct InputFile {
    _file: std::fs::File,
    bytes: Vec<u8>,
    identity: FileIdentity,
}
pub struct Configuration {
    files: [InputFile; 4],
    indicators: Option<InputFile>,
}
impl std::fmt::Debug for Configuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Configuration")
            .field("input_count", &(4 + usize::from(self.indicators.is_some())))
            .finish_non_exhaustive()
    }
}
#[derive(Debug, PartialEq)]
pub struct ValidatedInputs {
    pub collection_id: Uuid,
    pub endpoint_id: Uuid,
    pub case_id: Uuid,
}
impl Configuration {
    pub(crate) fn admit_for_invocation(
        &self,
        start: ClockReading,
        now: ClockReading,
    ) -> Result<ValidatedCollectionContext, Code> {
        admit_for_invocation(self.input_set(), start, now)
    }
    pub(crate) fn documents(&self) -> Vec<(jocky_shared::collection::worker::InputRole, &[u8])> {
        use jocky_shared::collection::worker::InputRole;
        let mut docs = vec![
            (InputRole::Designation, self.files[0].bytes.as_slice()),
            (InputRole::Authorisation, self.files[1].bytes.as_slice()),
            (InputRole::Policy, self.files[2].bytes.as_slice()),
            (InputRole::Request, self.files[3].bytes.as_slice()),
        ];
        if let Some(indicators) = &self.indicators {
            docs.push((InputRole::Indicators, indicators.bytes.as_slice()));
        }
        docs
    }
    pub(crate) fn object_ids(&self) -> Vec<crate::sources::metadata::ObjectId> {
        self.identities()
            .map(|id| crate::sources::metadata::ObjectId {
                device: id.device,
                inode: id.inode,
            })
            .collect()
    }
    pub(crate) fn exclusions(
        &self,
    ) -> Result<Vec<jocky_shared::collection::launch::ObjectIdentity>, Code> {
        self.files
            .iter()
            .chain(self.indicators.iter())
            .map(|file| super::collect::object_identity(file._file.as_fd()))
            .collect()
    }
    pub fn identities(&self) -> impl Iterator<Item = FileIdentity> + '_ {
        self.files
            .iter()
            .chain(self.indicators.iter())
            .map(|f| f.identity)
    }
    /// Logical validation returns identifiers only, never reusable native authority.
    pub fn validate(&self, now: ClockReading) -> Result<ValidatedInputs, Code> {
        let context = admit(self.input_set(), now)?;
        Ok(ValidatedInputs {
            collection_id: context.identity().collection_id.clone(),
            endpoint_id: context.identity().endpoint_id.clone(),
            case_id: context.identity().case_id.clone(),
        })
    }
    fn input_set(&self) -> InputSet<'_> {
        InputSet {
            designation: &self.files[0].bytes,
            authorisation: Some(&self.files[1].bytes),
            policy: &self.files[2].bytes,
            request: &self.files[3].bytes,
            indicators: self.indicators.as_ref().map(|f| f.bytes.as_slice()),
        }
    }
}

/// Does not designate a VM or perform collection. The binary still fails closed.
pub fn read_configuration(paths: &ConfigPaths) -> Result<Configuration, Code> {
    #[cfg(target_os = "linux")]
    {
        files::read(paths)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (&paths.required, &paths.indicators);
        Err(Code::Unsupported)
    }
}

/// Logical verification reads no referenced source and creates no authority.
pub fn read_report(path: &str) -> Result<Vec<u8>, Code> {
    #[cfg(target_os = "linux")]
    {
        files::read_report(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(Code::Unsupported)
    }
}
