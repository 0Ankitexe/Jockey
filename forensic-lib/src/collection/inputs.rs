use jocky_shared::collection::{Code, Document, DocumentKind, decode, inputs::*};

/// Explicit configuration bytes. File trust is additionally enforced by the native reader.
pub struct InputSet<'a> {
    pub designation: &'a [u8],
    pub authorisation: Option<&'a [u8]>,
    pub policy: &'a [u8],
    pub request: &'a [u8],
    pub indicators: Option<&'a [u8]>,
}

pub(crate) struct DecodedInputs {
    pub designation: EndpointDesignation,
    pub authorisation: LabAuthorisation,
    pub policy: CollectorPolicy,
    pub request: CollectionRequest,
    pub indicators: Option<IndicatorSet>,
}
impl InputSet<'_> {
    /// Normalized identity/digest metadata, without granting authority. Native
    /// callers still need current admission plus trusted file/process ownership.
    pub fn fingerprint(self) -> Result<jocky_shared::collection::report::Inputs, Code> {
        let mut input = self.decode()?;
        super::normalize::inputs(&mut input)?;
        provenance(&input)
    }
    pub(crate) fn decode(self) -> Result<DecodedInputs, Code> {
        let grant = self.authorisation.ok_or(Code::MissingAuthorisation)?;
        let bytes = [
            self.designation,
            grant,
            self.policy,
            self.request,
            self.indicators.unwrap_or(&[]),
        ];
        let total = bytes.iter().try_fold(0usize, |n, b| {
            n.checked_add(b.len()).ok_or(Code::ResourceLimit)
        })?;
        if total > 786432 {
            return Err(Code::ResourceLimit);
        }
        let decode = |kind, b| decode(kind, b).map_err(|e| e.code);
        let Document::Designation(designation) =
            decode(DocumentKind::Designation, self.designation)?
        else {
            return Err(Code::InvalidInput);
        };
        let Document::Authorisation(authorisation) = decode(DocumentKind::Authorisation, grant)?
        else {
            return Err(Code::InvalidInput);
        };
        let Document::Policy(policy) = decode(DocumentKind::Policy, self.policy)? else {
            return Err(Code::InvalidInput);
        };
        let Document::Request(request) = decode(DocumentKind::Request, self.request)? else {
            return Err(Code::InvalidInput);
        };
        let indicators = if let Some(raw) = self.indicators {
            let Document::Indicators(value) = decode(DocumentKind::Indicators, raw)? else {
                return Err(Code::InvalidInput);
            };
            Some(*value)
        } else {
            None
        };
        Ok(DecodedInputs {
            designation: *designation,
            authorisation: *authorisation,
            policy: *policy,
            request: *request,
            indicators,
        })
    }
}

/// An admitted ordinary path, not a string-to-path conversion or OS handle.
#[derive(Clone, Debug)]
pub struct ApprovedPath {
    pub(crate) root: RootGrant,
    pub(crate) path: PathRef,
}
impl ApprovedPath {
    pub fn root(&self) -> &RootGrant {
        &self.root
    }
    pub fn path(&self) -> &PathRef {
        &self.path
    }
}
/// One selected fixed facility. Construction is private to admission.
#[derive(Clone, Debug)]
pub struct ApprovedSource(pub(crate) SourceRef);
impl ApprovedSource {
    pub fn definition(&self) -> &SourceRef {
        &self.0
    }
}

pub(crate) fn provenance(
    input: &DecodedInputs,
) -> Result<jocky_shared::collection::report::Inputs, Code> {
    use jocky_shared::collection::{
        identity::Uuid,
        report::{InputProvenance, Inputs},
    };
    fn document(id: &Uuid, value: &impl serde::Serialize) -> Result<InputProvenance, Code> {
        let value = jocky_shared::collection::bounded_value(value, 524288).map_err(|e| e.code)?;
        Ok(InputProvenance {
            id: id.clone(),
            schema_version: CollectionVersion::V1,
            sha256: super::identity::digest(&super::canonical::encode(&value, 524288)?)?,
        })
    }
    Ok(Inputs {
        designation: document(&input.designation.designation_id, &input.designation)?,
        authorisation: document(&input.authorisation.authorisation_id, &input.authorisation)?,
        policy: document(&input.policy.policy_id, &input.policy)?,
        request: document(&input.request.collection_id, &input.request)?,
        indicators: input
            .indicators
            .as_ref()
            .map(|v| document(&v.indicator_set_id, v))
            .transpose()?,
    })
}
