use super::{DecodeReason, DocumentKind, InputError};
use jsonschema::{Registry, Resource, Retrieve, Uri, Validator};
use serde_json::Value;
use std::sync::OnceLock;

mod resources;
use resources::SCHEMAS;
struct Deny;
impl Retrieve for Deny {
    fn retrieve(&self, _: &Uri<String>) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("unknown collection schema".into())
    }
}
struct Embedded {
    schemas: Vec<Value>,
    registry: Registry,
}

fn embedded() -> Result<Embedded, InputError> {
    let error = || InputError::new(DecodeReason::Schema);
    let schemas = SCHEMAS
        .iter()
        .map(|s| {
            let value: Value = serde_json::from_str(s.contents).map_err(|_| error())?;
            if value["$id"] != format!("https://jocky.dev/{}", s.path) {
                return Err(error());
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let resources = schemas
        .iter()
        .map(|s| {
            Ok((
                s["$id"].as_str().ok_or_else(error)?.to_owned(),
                Resource::from_contents(s.clone()).map_err(|_| error())?,
            ))
        })
        .collect::<Result<Vec<_>, InputError>>()?;
    let registry = Registry::options()
        .retriever(Deny)
        .build(resources)
        .map_err(|_| error())?;
    Ok(Embedded { schemas, registry })
}

fn build(kind: DocumentKind) -> Result<Validator, InputError> {
    build_entry(kind as usize)
}

fn build_entry(index: usize) -> Result<Validator, InputError> {
    static EMBEDDED: OnceLock<Result<Embedded, InputError>> = OnceLock::new();
    let embedded = EMBEDDED.get_or_init(embedded).as_ref().map_err(|e| *e)?;
    jsonschema::draft202012::options()
        .with_retriever(Deny)
        .with_registry(embedded.registry.clone())
        .should_validate_formats(true)
        // Complete immutable definitions are checked by the mandatory build
        // guard. This entry compiles the same rules at runtime without retaining
        // the recursive meta-schema's definition-validation cache (ADR-0019).
        .build(&serde_json::json!({"$ref": embedded.schemas[index]["$id"]}))
        .map_err(|_| InputError::new(DecodeReason::Schema))
}

pub(crate) fn validate_launch(value: &Value) -> Result<(), InputError> {
    static CACHE: OnceLock<Result<Validator, InputError>> = OnceLock::new();
    let validator = CACHE
        .get_or_init(|| build_entry(13))
        .as_ref()
        .map_err(|e| *e)?;
    if validator.is_valid(value) {
        Ok(())
    } else {
        Err(InputError::new(DecodeReason::Schema))
    }
}
pub(crate) fn validate(kind: DocumentKind, value: &Value) -> Result<(), InputError> {
    static CACHE: [OnceLock<Result<Validator, InputError>>; 13] = [const { OnceLock::new() }; 13];
    let validator = CACHE[kind as usize]
        .get_or_init(|| build(kind))
        .as_ref()
        .map_err(|e| *e)?;
    if !validator.is_valid(value) {
        return Err(InputError::new(DecodeReason::Schema));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
