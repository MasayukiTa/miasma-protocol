/// Minimal bencode parser — enough for BT DHT/metadata messages.
///
/// Supports integers, byte strings, lists, and dictionaries.
/// Only what we need for the bridge; not a full production parser.
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

impl Value {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self { Value::Bytes(b) => Some(b), _ => None }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self { Value::Int(i) => Some(*i), _ => None }
    }
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        match self { Value::Dict(d) => Some(d), _ => None }
    }
    pub fn as_list(&self) -> Option<&Vec<Value>> {
        match self { Value::List(l) => Some(l), _ => None }
    }
    pub fn dict_get(&self, key: &[u8]) -> Option<&Value> {
        self.as_dict()?.get(key)
    }
}

/// Decode one bencoded value from the beginning of `data`.
/// Returns `(value, remaining_bytes)`.
pub fn decode(data: &[u8]) -> Result<(Value, &[u8]), String> {
    if data.is_empty() {
        return Err("empty input".into());
    }
    match data[0] {
        b'i' => decode_int(&data[1..]),
        b'l' => decode_list(&data[1..]),
        b'd' => decode_dict(&data[1..]),
        b'0'..=b'9' => decode_bytes(data),
        c => Err(format!("unexpected byte 0x{c:02x}")),
    }
}

/// Encode a `Value` to bytes.
pub fn encode(v: &Value) -> Vec<u8> {
    match v {
        Value::Int(i) => format!("i{i}e").into_bytes(),
        Value::Bytes(b) => {
            let mut out = format!("{}:", b.len()).into_bytes();
            out.extend_from_slice(b);
            out
        }
        Value::List(items) => {
            let mut out = vec![b'l'];
            for item in items { out.extend(encode(item)); }
            out.push(b'e');
            out
        }
        Value::Dict(map) => {
            let mut out = vec![b'd'];
            for (k, v) in map {
                out.extend(encode(&Value::Bytes(k.clone())));
                out.extend(encode(v));
            }
            out.push(b'e');
            out
        }
    }
}

fn decode_int(data: &[u8]) -> Result<(Value, &[u8]), String> {
    let end = data.iter().position(|&b| b == b'e')
        .ok_or("unterminated integer")?;
    let s = std::str::from_utf8(&data[..end]).map_err(|e| e.to_string())?;
    let i = s.parse::<i64>().map_err(|e| e.to_string())?;
    Ok((Value::Int(i), &data[end + 1..]))
}

fn decode_bytes(data: &[u8]) -> Result<(Value, &[u8]), String> {
    let colon = data.iter().position(|&b| b == b':')
        .ok_or("missing colon in string")?;
    let len_str = std::str::from_utf8(&data[..colon]).map_err(|e| e.to_string())?;
    let len = len_str.parse::<usize>().map_err(|e| e.to_string())?;
    let start = colon + 1;
    let end = start + len;
    if end > data.len() {
        return Err(format!("string too short: need {len}, have {}", data.len() - start));
    }
    Ok((Value::Bytes(data[start..end].to_vec()), &data[end..]))
}

fn decode_list(data: &[u8]) -> Result<(Value, &[u8]), String> {
    let mut items = Vec::new();
    let mut rest = data;
    while !rest.is_empty() && rest[0] != b'e' {
        let (v, r) = decode(rest)?;
        items.push(v);
        rest = r;
    }
    if rest.is_empty() { return Err("unterminated list".into()); }
    Ok((Value::List(items), &rest[1..]))
}

fn decode_dict(data: &[u8]) -> Result<(Value, &[u8]), String> {
    let mut map = BTreeMap::new();
    let mut rest = data;
    while !rest.is_empty() && rest[0] != b'e' {
        let (k, r) = decode_bytes(rest)?;
        let key = match k { Value::Bytes(b) => b, _ => unreachable!() };
        let (v, r2) = decode(r)?;
        map.insert(key, v);
        rest = r2;
    }
    if rest.is_empty() { return Err("unterminated dict".into()); }
    Ok((Value::Dict(map), &rest[1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_int() {
        let v = Value::Int(42);
        let (v2, _) = decode(&encode(&v)).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn roundtrip_bytes() {
        let v = Value::Bytes(b"hello".to_vec());
        let (v2, _) = decode(&encode(&v)).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn decode_dict_basic() {
        let data = b"d3:fooi42ee";
        let (v, rest) = decode(data).unwrap();
        assert!(rest.is_empty());
        assert_eq!(v.dict_get(b"foo").and_then(|v| v.as_int()), Some(42));
    }
}
