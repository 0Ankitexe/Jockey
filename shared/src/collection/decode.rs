//! Bounded strict decoding. Errors deliberately contain no input strings or OS messages.
use super::{Code, Document, DocumentKind};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeReason {
    Json,
    DuplicateKey,
    Depth,
    Size,
    Number,
    Schema,
    Version,
    Identifier,
    Timestamp,
    Path,
    Context,
    Allocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputError {
    pub code: Code,
    pub reason: DecodeReason,
}
impl InputError {
    pub const fn new(reason: DecodeReason) -> Self {
        let code = match reason {
            DecodeReason::Version => Code::UnsupportedVersion,
            DecodeReason::Size | DecodeReason::Depth | DecodeReason::Allocation => {
                Code::ResourceLimit
            }
            _ => Code::InvalidInput,
        };
        Self { code, reason }
    }
}
impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.as_str())
    }
}
impl std::error::Error for InputError {}

/// Decode untrusted wire data, not a permit. Live admission must additionally bind
/// designation, authority, local policy, request, current identity/time and scope.
pub fn decode(kind: DocumentKind, bytes: &[u8]) -> Result<Document, InputError> {
    let value = read_json(bytes, kind.maximum_bytes())?;
    if value
        .get("schema_version")
        .and_then(Value::as_str)
        .is_some_and(|v| v != kind.version())
    {
        return Err(InputError::new(DecodeReason::Version));
    }
    super::schema::validate(kind, &value)?;
    super::validation::wire_values(&value)?;
    let document = Document::from_value(kind, value)?;
    super::validation::document(&document)?;
    Ok(document)
}

pub(crate) fn read_json(bytes: &[u8], maximum: usize) -> Result<Value, InputError> {
    if bytes.len() > maximum {
        return Err(InputError::new(DecodeReason::Size));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| InputError::new(DecodeReason::Json))?;
    let mut decoder = serde_json::Deserializer::from_str(text);
    let mut state = State {
        nodes: 0,
        failure: None,
    };
    let value = Seed {
        depth: 0,
        state: &mut state,
    }
    .deserialize(&mut decoder);
    if let Some(reason) = state.failure {
        return Err(InputError::new(reason));
    }
    let value = value.map_err(|_| InputError::new(DecodeReason::Json))?;
    decoder
        .end()
        .map_err(|_| InputError::new(DecodeReason::Json))?;
    Ok(value)
}

struct State {
    nodes: usize,
    failure: Option<DecodeReason>,
}
impl State {
    fn fail<T, E: de::Error>(&mut self, reason: DecodeReason) -> Result<T, E> {
        self.failure = Some(reason);
        Err(E::custom("invalid collection JSON"))
    }
}
struct Seed<'a> {
    depth: usize,
    state: &'a mut State,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        // Bounded retention: at most 131072 value/key nodes. This is an internal
        // allocation guard, not a promise that every maximum-size report fits.
        self.state.nodes += 1;
        if self.state.nodes > 131072 {
            return self.state.fail(DecodeReason::Allocation);
        }
        d.deserialize_any(self)
    }
}
impl Seed<'_> {
    fn container<E: de::Error>(&mut self) -> Result<(), E> {
        if self.depth >= 16 {
            self.state.fail(DecodeReason::Depth)
        } else {
            Ok(())
        }
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded collection JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        if v.unsigned_abs() > 9007199254740991 {
            return self.state.fail(DecodeReason::Number);
        }
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        if v > 9007199254740991 {
            return self.state.fail(DecodeReason::Number);
        }
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> {
        self.state.fail(DecodeReason::Number)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Value, A::Error> {
        self.container()?;
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            depth: self.depth + 1,
            state: self.state,
        })? {
            if values.try_reserve(1).is_err() {
                return self.state.fail(DecodeReason::Allocation);
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<Value, A::Error> {
        self.container()?;
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return self.state.fail(DecodeReason::DuplicateKey);
            }
            if !key.is_ascii() || key.contains('\0') {
                return self.state.fail(DecodeReason::Json);
            }
            self.state.nodes += 1;
            if self.state.nodes > 131072 {
                return self.state.fail(DecodeReason::Allocation);
            }
            let value = map.next_value_seed(Seed {
                depth: self.depth + 1,
                state: self.state,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_depth_node_and_integer_boundaries_are_checked() {
        assert!(read_json(b"null", 4).is_ok());
        assert_eq!(
            read_json(b"null", 3).unwrap_err().reason,
            DecodeReason::Size
        );
        assert!(read_json(b"[-9007199254740991,9007199254740991]", 100).is_ok());
        for raw in [
            b"9007199254740992".as_slice(),
            b"-9007199254740992",
            b"-0",
            b"1.0",
            b"1e0",
        ] {
            assert_eq!(
                read_json(raw, 100).unwrap_err().reason,
                DecodeReason::Number
            );
        }
        let exact = format!("[{}null]", "null,".repeat(131070));
        assert!(read_json(exact.as_bytes(), 10485760).is_ok());
        let excess = format!("[{}null]", "null,".repeat(131071));
        assert_eq!(
            read_json(excess.as_bytes(), 10485760).unwrap_err().reason,
            DecodeReason::Allocation
        );
        assert_eq!(
            read_json(br#"{"x":{"a":1,"a":2}}"#, 100)
                .unwrap_err()
                .reason,
            DecodeReason::DuplicateKey
        );
    }
}
