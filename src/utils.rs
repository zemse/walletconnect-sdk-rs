/// Utils
///
/// Some helpful utils
///
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::{hex, signers::k256::sha2::Sha256};
use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::{Hkdf, hmac::digest::Digest};
use rand::{RngCore, rngs::OsRng};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::form_urlencoded;

use crate::{
    constants::{
        DID_DELIMITER, DID_METHOD, DID_PREFIX, MULTICODEC_ED25519_BASE,
        MULTICODEC_ED25519_HEADER,
    },
    error::{Error, Result},
};

#[derive(Debug, PartialEq)]
pub struct UriParameters {
    pub protocol: String,
    pub topic: String,
    pub version: u32,
    pub sym_key: [u8; 32],
    pub relay: RelayProtocolOptions,
    pub methods: Option<Vec<String>>,
    pub expiry_timestamp: Option<u64>,
}

#[derive(Debug, PartialEq)]
pub struct RelayProtocolOptions {
    pub protocol: String,
    pub data: Option<String>,
}

impl From<String> for UriParameters {
    fn from(uri: String) -> Self {
        parse_uri(uri).unwrap()
    }
}

pub fn parse_uri(mut input: String) -> Result<UriParameters> {
    if !input.contains("wc:") {
        let decoded_str = Base64UrlUnpadded::decode_vec(&input)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok());
        if let Some(decoded) = decoded_str.filter(|s| s.contains("wc:")) {
            input = decoded;
        }
    }

    if input.contains("wc://") {
        input = input.replacen("wc://", "", 1);
    } else if input.contains("wc:") {
        input = input.replacen("wc:", "", 1);
    }

    let (protocol, path, query_string) =
        if let Some(path_start) = input.find(':') {
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
        sym_key: hex::decode_to_array::<String, 32>(
            query_params
                .get("symKey")
                .cloned()
                .ok_or(Error::SymKeyNotMentioned)?,
        )?,
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

pub fn parse_relay_params(
    params: &HashMap<String, String>,
) -> Result<RelayProtocolOptions> {
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

pub fn encode_iss(public_key: &[u8; 32]) -> String {
    let header = bs58::decode(MULTICODEC_ED25519_HEADER)
        .into_vec()
        .expect("Failed to decode Base58");

    let encoded =
        bs58::encode([header, public_key.to_vec()].concat()).into_string();

    let multicodec = format!("{MULTICODEC_ED25519_BASE}{encoded}");

    [DID_PREFIX, DID_METHOD, &multicodec].join(DID_DELIMITER)
}

pub fn derive_sym_key(private_key: [u8; 32], public_key: [u8; 32]) -> [u8; 32] {
    let private = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(public_key);

    let shared_secret = private.diffie_hellman(&public);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

    let mut okm = [0u8; 32];
    hk.expand(&[], &mut okm).expect("hkdf expand failed");
    okm
}

pub fn sha256(data: [u8; 32]) -> [u8; 32] {
    Sha256::digest(data)
        .as_slice()
        .try_into()
        .expect("Sha256 output wrong length")
}

pub const MINUTES: u64 = 60;
pub const HOURS: u64 = 60 * MINUTES;
pub const DAYS: u64 = 24 * HOURS;

pub fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn str_timestamp() -> Result<String> {
    let now = OffsetDateTime::now_utc();
    Ok(now.format(&Rfc3339)?)
}

// pub fn deserialize_str<T: DeserializeOwned>(s: &str) -> crate::Result<T> {
//     serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(s))
//         .map_err(|e| crate::Error::SerdePathToError(Box::new(e)))
// }

#[cfg(test)]
mod tests {
    use alloy::hex;

    use super::*;

    #[test]
    fn test_parse_uri() {
        let result = parse_uri(
            "wc:b29dcadbdad95479378331a2563baa512a71c014c30015387798a29f95aa44ee@2?relay-protocol=irn&symKey=761ab2f7f9deae2d5d18f887d2a8d812da0ec5fda0d0df8cc7ec1969832c0da2&expiryTimestamp=1742817708&methods=wc_sessionAuthenticate".to_string(),
        );
        assert_eq!(
            result.unwrap(),
            UriParameters {
                protocol: "".to_string(),
                topic: "b29dcadbdad95479378331a2563baa512a71c014c30015387798a29f95aa44ee"
                    .to_string(),
                version: 2,
                sym_key: hex!("761ab2f7f9deae2d5d18f887d2a8d812da0ec5fda0d0df8cc7ec1969832c0da2"),
                relay: RelayProtocolOptions {
                    protocol: "irn".to_string(),
                    data: None,
                },
                methods: Some(vec!["wc_sessionAuthenticate".to_string()]),
                expiry_timestamp: Some(1742817708)
            }
        );
    }

    #[test]
    fn test_derive_sym_key() {
        let pvt_key = hex::decode_to_array::<_, 32>(
            "093783eba4c8c199edd82275f49f46057282eaf716c1fbdaa92076124d16688c",
        )
        .unwrap();
        let pbk_key = hex::decode_to_array::<_, 32>(
            "33e6420c23ee4d98b671d8de75a1990dd88be34542d4428ad01686a283feb33e",
        )
        .unwrap();

        let expected_sym_key = derive_sym_key(pvt_key, pbk_key);
        println!("{:?}", hex::encode(expected_sym_key));
    }
}
