//! Owned, independent portable target envelope; legacy AST remains strict.
use crate::{
    LabProfileDeclaration, Span,
    ast::{FunctionDeclaration, ModuleDeclaration, RunStatement},
};
use jocky_shared::compiler::v2::Platform;
use serde::Serialize;

pub const AST_SCHEMA_VERSION: &str = "3.0.0";
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TargetPlatformNode {
    pub kind: Platform,
    pub span: Span,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TargetDeclaration {
    pub platforms: Vec<TargetPlatformNode>,
    pub span: Span,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProgramV3 {
    pub span: Span,
    pub module: ModuleDeclaration,
    pub target: TargetDeclaration,
    pub functions: Vec<FunctionDeclaration>,
    pub run: Option<RunStatement>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedSourceV3 {
    pub program: ProgramV3,
    pub profile: Option<LabProfileDeclaration>,
}
impl ParsedSourceV3 {
    pub fn to_pretty_json(&self) -> Result<Vec<u8>, crate::EmitError> {
        #[derive(Serialize)]
        struct Profile {
            name: &'static str,
            name_span: Span,
            span: Span,
        }
        #[derive(Serialize)]
        struct Document<'a> {
            schema_version: &'static str,
            program: &'a ProgramV3,
            profile: Option<Profile>,
        }
        let value = Document {
            schema_version: AST_SCHEMA_VERSION,
            program: &self.program,
            profile: self.profile.as_ref().map(|p| Profile {
                name: "lab",
                name_span: p.name_span,
                span: p.span,
            }),
        };
        let mut bytes = serde_json::to_vec_pretty(&value).map_err(crate::EmitError::Serialize)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}
