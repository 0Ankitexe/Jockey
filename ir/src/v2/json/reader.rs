use crate::{
    diagnostic::{DiagnosticCode as Code, Failure},
    limits::{self, Budget, charge, require},
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub(crate) fn read_json(bytes: &[u8], maximum: usize) -> Result<Value, Failure> {
    read_json_metered(bytes, maximum, Budget::default()).map(|(value, _)| value)
}

pub(crate) fn read_json_metered(
    bytes: &[u8],
    maximum: usize,
    budget: Budget,
) -> Result<(Value, Budget), Failure> {
    require(bytes.len(), maximum)?;
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::at(Code::Json, ""))?;
    let mut context = Context {
        budget,
        nodes: 0,
        problem: None,
    };
    let mut decoder = serde_json::Deserializer::from_str(text);
    let result = Seed {
        depth: 0,
        context: &mut context,
    }
    .deserialize(&mut decoder);
    if let Some(problem) = context.problem {
        return Err(problem);
    }
    let value = result.map_err(|_| Failure::at(Code::Json, ""))?;
    decoder.end().map_err(|_| Failure::at(Code::Json, ""))?;
    Ok((value, context.budget))
}

struct Context {
    budget: Budget,
    nodes: usize,
    problem: Option<Failure>,
}
impl Context {
    fn check<E: de::Error>(&mut self, result: Result<(), Failure>) -> Result<(), E> {
        result.map_err(|e| {
            self.problem = Some(e);
            E::custom("bounded compiler JSON")
        })
    }
    fn scalar<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        let r = self.budget.bytes(bytes);
        self.check(r)
    }
}
struct Seed<'a> {
    depth: usize,
    context: &'a mut Context,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        let result = charge(&mut self.context.nodes, 1, limits::JSON_NODES)
            .and_then(|()| self.context.budget.entries(1));
        self.context.check(result)?;
        decoder.deserialize_any(self)
    }
}
impl Seed<'_> {
    fn container<E: de::Error>(&mut self) -> Result<(), E> {
        self.context
            .check(require(self.depth + 1, limits::JSON_DEPTH))
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded compiler JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("finite JSON number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        self.context.scalar(v.len())?;
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        self.context.scalar(v.len())?;
        Ok(Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Value, A::Error> {
        self.container()?;
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            depth: self.depth + 1,
            context: self.context,
        })? {
            let cost = self.context.budget.references(1);
            self.context.check(cost)?;
            if values.try_reserve(1).is_err() {
                self.context.check(Err(Failure::resource()))?;
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<Value, A::Error> {
        self.container()?;
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            self.context.scalar(key.len())?;
            if values.contains_key(&key) {
                self.context.problem = Some(Failure::at(Code::Json, ""));
                return Err(de::Error::custom("duplicate compiler JSON key"));
            }
            let cost = self.context.budget.references(1);
            self.context.check(cost)?;
            let value = map.next_value_seed(Seed {
                depth: self.depth + 1,
                context: self.context,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
