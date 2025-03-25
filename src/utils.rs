use base64::{Engine, engine::general_purpose};
use rand::{RngCore, rngs::OsRng};
use std::collections::HashMap;
use url::form_urlencoded;

use crate::{
    constants::{
        DID_DELIMITER, DID_METHOD, DID_PREFIX, MULTICODEC_ED25519_BASE, MULTICODEC_ED25519_HEADER,
    },
    error::Error,
};

#[derive(Debug, PartialEq)]
pub struct UriParameters {
    pub protocol: String,
    pub topic: String,
    pub version: u32,
    pub sym_key: String,
    pub relay: RelayProtocolOptions,
    pub methods: Option<Vec<String>>,
    pub expiry_timestamp: Option<u64>,
}

#[derive(Debug, PartialEq)]
pub struct RelayProtocolOptions {
    pub protocol: String,
    pub data: Option<String>,
}

pub fn parse_uri(mut input: String) -> Result<UriParameters, Error> {
    if !input.contains("wc:") {
        if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(&input) {
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                if decoded_str.contains("wc:") {
                    input = decoded_str;
                }
            }
        }
    }

    // Strip schema prefixes
    if input.contains("wc://") {
        input = input.replacen("wc://", "", 1);
    } else if input.contains("wc:") {
        input = input.replacen("wc:", "", 1);
    }

    let (protocol, path, query_string) = if let Some(path_start) = input.find(':') {
        let protocol = &input[..path_start];
        let path = &input[path_start + 1..];
        let query_string = "";
        (protocol, path, query_string)
    } else {
        let path_start = 0;
        let path_end = input.find('?').ok_or(Error::PathEndNotFound)?;
        let protocol = "";
        let path = &input[path_start..path_end];
        let query_string = &input[path_end + 1..];
        (protocol, path, query_string)
    };

    let required_values: Vec<&str> = path.split('@').collect();

    if required_values.len() != 2 {
        return Err(Error::InvalidUri);
    }

    let mut query_params: HashMap<String, String> = HashMap::new();
    for (key, value) in form_urlencoded::parse(query_string.as_bytes()) {
        query_params.insert(key.into(), value.into());
    }

    let methods = query_params
        .get("methods")
        .map(|m| m.split(',').map(|s| s.to_string()).collect());

    Ok(UriParameters {
        protocol: protocol.to_string(),
        topic: parse_topic(required_values[0]),
        version: required_values[1].parse()?,
        sym_key: query_params
            .get("symKey")
            .ok_or(Error::SymKeyNotMentioned)?
            .to_string(),
        relay: parse_relay_params(&query_params)?,
        methods,
        expiry_timestamp: query_params
            .get("expiryTimestamp")
            .and_then(|v| v.parse().ok()),
    })
}

#[allow(clippy::manual_strip)]
pub fn parse_topic(topic: &str) -> String {
    if topic.starts_with("//") {
        topic[2..].to_string()
    } else {
        topic.to_string()
    }
}

pub fn parse_relay_params(params: &HashMap<String, String>) -> Result<RelayProtocolOptions, Error> {
    let protocol_key = "relay-protocol";
    let data_key = "relay-data";

    let protocol = params
        .get(protocol_key)
        .ok_or(Error::RelayProtocolNotMentioned)?
        .clone();
    let data = params.get(data_key).cloned();

    Ok(RelayProtocolOptions { protocol, data })
}

pub fn random_bytes32() -> [u8; 32] {
    let mut random_value = [0u8; 32];
    OsRng.fill_bytes(&mut random_value);
    random_value
}

pub fn encode_iss(public_key: [u8; 32]) -> String {
    let header = bs58::decode(MULTICODEC_ED25519_HEADER)
        .into_vec()
        .expect("Failed to decode Base58");

    let combined = bs58::encode([header, public_key.to_vec()].concat()).into_string();

    // 2. Base58-encode the combined bytes
    let encoded = bs58::encode(combined).into_string();

    // 3. Prepend the base prefix ("z")
    let multicodec = format!("{}{}", MULTICODEC_ED25519_BASE, encoded);

    // 4. Construct the final DID string: "did:key:z..."
    [DID_PREFIX, DID_METHOD, &multicodec].join(DID_DELIMITER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = parse_uri(
            "wc:b29dcadbdad95479378331a2563baa512a71c014c30015387798a29f95aa44ee@2?relay-protocol=irn&symKey=761ab2f7f9deae2d5d18f887d2a8d812da0ec5fda0d0df8cc7ec1969832c0da2&expiryTimestamp=1742817708&methods=wc_sessionAuthenticate".to_string(),
        );
        assert_eq!(
            result,
            Ok(UriParameters {
                protocol: "".to_string(),
                topic: "b29dcadbdad95479378331a2563baa512a71c014c30015387798a29f95aa44ee"
                    .to_string(),
                version: 2,
                sym_key: "761ab2f7f9deae2d5d18f887d2a8d812da0ec5fda0d0df8cc7ec1969832c0da2"
                    .to_string(),
                relay: RelayProtocolOptions {
                    protocol: "irn".to_string(),
                    data: None,
                },
                methods: Some(vec!["wc_sessionAuthenticate".to_string()]),
                expiry_timestamp: Some(1742817708)
            })
        );
    }
}
