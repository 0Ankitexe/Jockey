//! Pure build guard, also exercised by integration tests; never linked at runtime.
use jsonschema::{Registry, Resource, Retrieve, Uri};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildFailure {
    Json,
    Identity,
    Definition,
    Reference,
}

struct Deny;
impl Retrieve for Deny {
    fn retrieve(&self, _: &Uri<String>) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("unknown embedded schema".into())
    }
}

pub fn check(sources: &[(&str, &str)]) -> Result<(), BuildFailure> {
    if sources.is_empty() {
        return Err(BuildFailure::Identity);
    }
    let mut seen = BTreeSet::new();
    let mut schemas = Vec::new();
    for (path, text) in sources {
        let schema: Value = serde_json::from_str(text).map_err(|_| BuildFailure::Json)?;
        let id = schema["$id"].as_str().ok_or(BuildFailure::Identity)?;
        if id != format!("https://jocky.dev/{path}") || !seen.insert(id.to_owned()) {
            return Err(BuildFailure::Identity);
        }
        jsonschema::draft202012::meta::validate(&schema).map_err(|_| BuildFailure::Definition)?;
        schemas.push(schema);
    }
    let resources = schemas
        .iter()
        .map(|s| {
            Ok((
                s["$id"].as_str().ok_or(BuildFailure::Identity)?.to_owned(),
                Resource::from_contents(s.clone()).map_err(|_| BuildFailure::Definition)?,
            ))
        })
        .collect::<Result<Vec<_>, BuildFailure>>()?;
    let registry = Registry::options()
        .retriever(Deny)
        .build(resources)
        .map_err(|_| BuildFailure::Reference)?;
    for schema in &schemas {
        references(
            schema,
            schema["$id"].as_str().ok_or(BuildFailure::Identity)?,
            &registry,
            true,
        )?;
        jsonschema::draft202012::options()
            .with_retriever(Deny)
            .with_registry(registry.clone())
            .should_validate_formats(true)
            .build(schema)
            .map_err(|_| BuildFailure::Reference)?;
    }
    Ok(())
}

// This inventory uses flat resource IDs and ordinary $ref only. Reject new
// scoping mechanisms until their build/runtime equivalence is reviewed.
fn references(
    value: &Value,
    id: &str,
    registry: &Registry,
    root: bool,
) -> Result<(), BuildFailure> {
    match value {
        Value::Object(fields) => {
            if (!root && fields.contains_key("$id"))
                || fields.contains_key("$dynamicRef")
                || fields.contains_key("$recursiveRef")
            {
                return Err(BuildFailure::Definition);
            }
            if let Some(reference) = fields.get("$ref") {
                let resolved = registry
                    .try_resolver(id)
                    .map_err(|_| BuildFailure::Reference)?
                    .lookup(reference.as_str().ok_or(BuildFailure::Reference)?)
                    .map_err(|_| BuildFailure::Reference)?;
                if !matches!(resolved.contents(), Value::Object(_) | Value::Bool(_)) {
                    return Err(BuildFailure::Reference);
                }
            }
            for child in fields.values() {
                references(child, id, registry, false)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                references(child, id, registry, false)?;
            }
        }
        _ => {}
    }
    Ok(())
}
