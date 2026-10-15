//! JOCKY-CJSON-1, not a claim of general RFC 8785 conformance.
use jocky_shared::collection::Code;
use serde_json::Value;

struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
    nodes: usize,
    omit_root_key: Option<&'static str>,
}
impl Writer {
    fn push(&mut self, bytes: &[u8]) -> Result<(), Code> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.maximum)
        {
            return Err(Code::ResourceLimit);
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| Code::ResourceLimit)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn string(&mut self, text: &str) -> Result<(), Code> {
        self.push(b"\"")?;
        for c in text.chars() {
            match c {
                '"' => self.push(b"\\\"")?,
                '\\' => self.push(b"\\\\")?,
                '\u{8}' => self.push(b"\\b")?,
                '\t' => self.push(b"\\t")?,
                '\n' => self.push(b"\\n")?,
                '\u{c}' => self.push(b"\\f")?,
                '\r' => self.push(b"\\r")?,
                c if (c as u32) < 32 => self.push(format!("\\u{:04x}", c as u32).as_bytes())?,
                c => {
                    let mut buffer = [0; 4];
                    self.push(c.encode_utf8(&mut buffer).as_bytes())?;
                }
            }
        }
        self.push(b"\"")
    }
    fn value(&mut self, value: &Value, depth: usize) -> Result<(), Code> {
        self.nodes += 1;
        if self.nodes > 131072 || depth > 16 {
            return Err(Code::ResourceLimit);
        }
        match value {
            Value::Null => self.push(b"null"),
            Value::Bool(true) => self.push(b"true"),
            Value::Bool(false) => self.push(b"false"),
            Value::Number(n) => {
                let valid = n
                    .as_i64()
                    .is_some_and(|n| n.unsigned_abs() <= 9007199254740991)
                    || n.as_u64().is_some_and(|n| n <= 9007199254740991);
                if !valid {
                    return Err(Code::InvalidInput);
                }
                self.push(n.to_string().as_bytes())
            }
            Value::String(text) => self.string(text),
            Value::Array(values) => {
                if depth == 16 {
                    return Err(Code::ResourceLimit);
                }
                self.push(b"[")?;
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        self.push(b",")?;
                    }
                    self.value(value, depth + 1)?;
                }
                self.push(b"]")
            }
            Value::Object(values) => {
                if depth == 16
                    || self
                        .nodes
                        .checked_add(values.len())
                        .is_none_or(|n| n > 131072)
                {
                    return Err(Code::ResourceLimit);
                }
                self.nodes += values.len();
                let mut keys = Vec::new();
                keys.try_reserve(values.len())
                    .map_err(|_| Code::ResourceLimit)?;
                for key in values.keys() {
                    if !key.is_ascii() {
                        return Err(Code::InvalidInput);
                    }
                    if depth != 0 || Some(key.as_str()) != self.omit_root_key {
                        keys.push(key);
                    }
                }
                keys.sort_unstable();
                self.push(b"{")?;
                for (i, key) in keys.into_iter().enumerate() {
                    if i > 0 {
                        self.push(b",")?;
                    }
                    self.string(key)?;
                    self.push(b":")?;
                    self.value(&values[key], depth + 1)?;
                }
                self.push(b"}")
            }
        }
    }
}

pub fn encode(value: &Value, maximum: usize) -> Result<Vec<u8>, Code> {
    encode_inner(value, maximum, None)
}

/// Digest projection without cloning the report's entire object graph.
pub(crate) fn body(value: &Value, maximum: usize) -> Result<Vec<u8>, Code> {
    if !value
        .as_object()
        .is_some_and(|v| v.contains_key("content_sha256"))
    {
        return Err(Code::InvalidInput);
    }
    encode_inner(value, maximum, Some("content_sha256"))
}

fn encode_inner(
    value: &Value,
    maximum: usize,
    omit_root_key: Option<&'static str>,
) -> Result<Vec<u8>, Code> {
    let mut writer = Writer {
        bytes: Vec::new(),
        maximum: maximum.min(10485760),
        nodes: 0,
        omit_root_key,
    };
    writer.value(value, 0)?;
    Ok(writer.bytes)
}
