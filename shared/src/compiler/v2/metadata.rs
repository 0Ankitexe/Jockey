//! Target selector is distinct from observed distribution and facility support.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Ubuntu,
    Linux,
}
impl Platform {
    pub const ALL: [Self; 3] = [Self::Windows, Self::Ubuntu, Self::Linux];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Ubuntu => "ubuntu",
            Self::Linux => "linux",
        }
    }
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "windows" => Some(Self::Windows),
            "ubuntu" => Some(Self::Ubuntu),
            "linux" => Some(Self::Linux),
            _ => None,
        }
    }
}
impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsFamily {
    Windows,
    Linux,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selector {
    pub family: OsFamily,
    pub distribution: Option<&'static str>,
}
impl Platform {
    pub const fn selector(self) -> Selector {
        match self {
            Self::Windows => Selector {
                family: OsFamily::Windows,
                distribution: None,
            },
            Self::Ubuntu => Selector {
                family: OsFamily::Linux,
                distribution: Some("ubuntu"),
            },
            Self::Linux => Selector {
                family: OsFamily::Linux,
                distribution: None,
            },
        }
    }
}
