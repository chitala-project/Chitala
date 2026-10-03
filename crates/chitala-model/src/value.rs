//! Payload values. v0.1 payloads are flat maps `text → (bool | int | text)`:
//! no floats and no nesting, so the canonical CBOR encoding is unambiguous.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParamValue {
    Bool(bool),
    Int(i64),
    Text(String),
}

pub type Payload = BTreeMap<String, ParamValue>;

impl ParamValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            ParamValue::Bool(_) => "boolean",
            ParamValue::Int(_) => "integer",
            ParamValue::Text(_) => "text",
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ParamValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            ParamValue::Int(i) => Some(*i),
            _ => None,
        }
    }
}

impl fmt::Display for ParamValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamValue::Bool(b) => write!(f, "{b}"),
            ParamValue::Int(i) => write!(f, "{i}"),
            ParamValue::Text(t) => write!(f, "{t:?}"),
        }
    }
}

impl From<bool> for ParamValue {
    fn from(b: bool) -> Self {
        ParamValue::Bool(b)
    }
}

impl From<i64> for ParamValue {
    fn from(i: i64) -> Self {
        ParamValue::Int(i)
    }
}

impl From<&str> for ParamValue {
    fn from(s: &str) -> Self {
        ParamValue::Text(s.to_string())
    }
}

impl From<String> for ParamValue {
    fn from(s: String) -> Self {
        ParamValue::Text(s)
    }
}

/// Build a payload from `(name, value)` pairs.
pub fn payload<I, K, V>(items: I) -> Payload
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<ParamValue>,
{
    items.into_iter().map(|(k, v)| (k.into(), v.into())).collect()
}
