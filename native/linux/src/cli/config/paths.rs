use jocky_shared::collection::Code;

/// Validated explicit UTF-8 paths; construction performs no filesystem operations.
pub struct ConfigPaths {
    pub(super) required: [String; 4],
    pub(super) indicators: Option<String>,
}
impl ConfigPaths {
    /// Role order: designation, authorisation, endpoint policy, request.
    pub fn new(required: [&str; 4], indicators: Option<&str>) -> Result<Self, Code> {
        let mut paths = std::collections::BTreeSet::new();
        for path in required.into_iter().chain(indicators) {
            validate(path)?;
            if !paths.insert(path) {
                return Err(Code::AliasDenied);
            }
        }
        Ok(Self {
            required: required.map(str::to_owned),
            indicators: indicators.map(str::to_owned),
        })
    }
}
pub(super) fn validate(path: &str) -> Result<(), Code> {
    if !path.starts_with('/')
        || path.len() > 4096
        || path.contains('\0')
        || path[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
        || path[1..].split('/').count() > 256
    {
        Err(Code::InvalidInput)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_output(path: &str) -> Result<(), Code> {
    validate(path)?;
    let (parent, name) = path.rsplit_once('/').ok_or(Code::InvalidInput)?;
    if parent.is_empty() || name.is_empty() || name.len() > 255 {
        return Err(Code::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maximum_path_and_component_bounds_are_explicit() {
        assert!(validate(&format!("/{}", "a".repeat(4095))).is_ok());
        assert_eq!(
            validate(&format!("/{}", "a".repeat(4096))),
            Err(Code::InvalidInput)
        );
        assert!(validate(&format!("/{}", vec!["a"; 256].join("/"))).is_ok());
        assert_eq!(
            validate(&format!("/{}", vec!["a"; 257].join("/"))),
            Err(Code::InvalidInput)
        );
        assert_eq!(validate_output("/owned/report.json"), Ok(()));
        for bad in [
            "/",
            "/report.json",
            "/owned/",
            "/owned/../report",
            "relative/report",
        ] {
            assert_eq!(validate_output(bad), Err(Code::InvalidInput));
        }
    }
}
