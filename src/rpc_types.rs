use crate::error::Result;
use serde::{Deserialize, Serialize};
use serde_json::Number;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    String(String),
    Number(Number),
}

impl From<String> for Id {
    fn from(value: String) -> Self {
        Id::String(value)
    }
}

impl From<u128> for Id {
    fn from(value: u128) -> Self {
        Id::String(value.to_string())
    }
}

impl Id {
    #[allow(dead_code)]
    fn to_u128(&self) -> Result<u128> {
        match self {
            Id::String(s) => Ok(s.parse::<u128>()?),
            Id::Number(n) => n.as_u128().ok_or("number too big".into()),
        }
    }
}

/// A basic JSON-RPC 2.0 request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest<ParamType = Value> {
    pub jsonrpc: String,
    pub method: JsonRpcMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ParamType>, // Could be array or object
    pub id: Id,
}

/// A basic JSON-RPC 2.0 response with either a result or an error.
#[derive(Deserialize, Debug)]
pub struct JsonRpcResponse {
    #[allow(dead_code)]
    pub jsonrpc: String,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<JsonRpcError>,
    #[serde(default)]
    #[allow(dead_code)]
    pub id: Option<u64>,
}

/// A JSON-RPC error object (code, message, and optional data).
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchMessageResult {
    #[serde(rename = "hasMore")]
    pub has_more: bool,
    pub messages: Vec<EncryptedMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub attestation: String,
    pub message: String,
    #[serde(rename = "publishedAt")]
    pub published_at: u64,
    pub tag: u32,
    pub topic: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum JsonRpcMethod {
    #[serde(rename = "irn_publish")]
    IrnPublish,

    #[serde(rename = "irn_subscribe")]
    IrnSubscribe,

    #[serde(rename = "irn_fetchMessages")]
    IrnFetchMessages,

    #[serde(rename = "wc_sessionPropose")]
    SessionPropose,

    #[serde(rename = "wc_sessionAuthenticate")]
    SessionAuthenticate,
}

#[derive(Clone, Debug)]
pub enum JsonRpcParam {
    SessionPropose(session_propose::Params),
    SessionAuthenticate(session_authenticate::Params),
}

impl JsonRpcParam {
    pub fn as_session_propose(&self) -> Option<&session_propose::Params> {
        match self {
            JsonRpcParam::SessionPropose(params) => Some(params),
            _ => None,
        }
    }

    pub fn as_session_authenticate(
        &self,
    ) -> Option<&session_authenticate::Params> {
        match self {
            JsonRpcParam::SessionAuthenticate(params) => Some(params),
            _ => None,
        }
    }
}

pub mod session_propose {
    use super::*;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Params {
        #[serde(rename = "requiredNamespaces")]
        pub required_namespaces: HashMap<String, Namespace>,
        #[serde(rename = "optionalNamespaces")]
        pub optional_namespaces: HashMap<String, Namespace>,
        pub relays: Vec<Relay>,
        #[serde(rename = "pairingTopic")]
        pub pairing_topic: String,
        pub proposer: Proposer,
        #[serde(rename = "expiryTimestamp")]
        pub expiry_timestamp: u64,
        pub id: u64,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Namespace {
        pub chains: Vec<String>,
        pub methods: Vec<String>,
        pub events: Vec<String>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Relay {
        pub protocol: String,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Proposer {
        #[serde(rename = "publicKey")]
        pub public_key: String,
        pub metadata: Metadata,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Metadata {
        pub name: String,
        pub description: String,
        pub url: String,
        pub icons: Vec<String>,
    }
}

pub mod session_authenticate {
    use super::*;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Params {
        #[serde(rename = "authPayload")]
        pub auth_payload: AuthPayload,
        pub requester: Requester,
        #[serde(rename = "expiryTimestamp")]
        pub expiry_timestamp: u64,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct AuthPayload {
        #[serde(rename = "type")]
        pub payload_type: String,
        pub chains: Vec<String>,
        pub statement: String,
        pub aud: String,
        pub domain: String,
        pub version: String,
        pub nonce: String,
        pub iat: String,
        pub resources: Vec<String>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Requester {
        #[serde(rename = "publicKey")]
        pub public_key: String,
        pub metadata: Metadata,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Metadata {
        pub name: String,
        pub description: String,
        pub url: String,
        pub icons: Vec<String>,
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc_types::{
        JsonRpcMethod, session_authenticate, session_propose,
    };

    use super::{Id, JsonRpcRequest};

    #[test]
    fn test_decode_id() {
        let result = serde_json::from_str::<Id>("\"1234\"").unwrap();
        println!("result {result:?}");

        let result = serde_json::from_str::<Id>("1234").unwrap();
        println!("result {result:?}");
    }

    #[test]
    fn test_decode_wc_session_propose() {
        let req = "{\"id\":1743510684985756,\"jsonrpc\":\"2.0\",\"method\":\"wc_sessionPropose\",\"params\":{\"requiredNamespaces\":{},\"optionalNamespaces\":{\"eip155\":{\"chains\":[\"eip155:137\",\"eip155:1\",\"eip155:10\",\"eip155:324\",\"eip155:42161\",\"eip155:8453\",\"eip155:84532\",\"eip155:1301\",\"eip155:80094\",\"eip155:11155111\",\"eip155:100\",\"eip155:295\",\"eip155:1313161554\",\"eip155:5000\"],\"methods\":[\"personal_sign\",\"eth_accounts\",\"eth_requestAccounts\",\"eth_sendRawTransaction\",\"eth_sendTransaction\",\"eth_sign\",\"eth_signTransaction\",\"eth_signTypedData\",\"eth_signTypedData_v3\",\"eth_signTypedData_v4\",\"wallet_addEthereumChain\",\"wallet_getAssets\",\"wallet_getCallsStatus\",\"wallet_getCapabilities\",\"wallet_getPermissions\",\"wallet_grantPermissions\",\"wallet_registerOnboarding\",\"wallet_requestPermissions\",\"wallet_revokePermissions\",\"wallet_scanQRCode\",\"wallet_sendCalls\",\"wallet_switchEthereumChain\",\"wallet_watchAsset\"],\"events\":[\"chainChanged\",\"accountsChanged\"]}},\"relays\":[{\"protocol\":\"irn\"}],\"pairingTopic\":\"d0bb3bf179a70fd10245144ac7355c52a767806c9b2d852b99fc7be935934882\",\"proposer\":{\"publicKey\":\"04f1c07b7205c273b6af5b85ac267cbe28c22d036873ffe4621abc4d9213430e\",\"metadata\":{\"name\":\"AppKit Lab\",\"description\":\"AppKit Lab is the test environment for Reown's AppKit\",\"url\":\"https://appkit-lab.reown.com\",\"icons\":[\"https://appkit-lab.reown.com/favicon.svg\"]}},\"expiryTimestamp\":1743510984,\"id\":1743510684985756}}";

        let decoded = serde_json::from_str::<
            JsonRpcRequest<session_propose::Params>,
        >(req)
        .unwrap();

        println!("Decoded: {decoded:?}");

        assert_eq!(decoded.id.to_u128().unwrap(), 1743510684985756);
        assert_eq!(decoded.method, JsonRpcMethod::SessionPropose);
        assert_eq!(decoded.jsonrpc, "2.0");
        assert!(decoded.params.is_some());
        let params = decoded.params.unwrap();
        assert_eq!(
            params.pairing_topic,
            "d0bb3bf179a70fd10245144ac7355c52a767806c9b2d852b99fc7be935934882"
        );
        assert_eq!(
            params.proposer.public_key,
            "04f1c07b7205c273b6af5b85ac267cbe28c22d036873ffe4621abc4d9213430e"
        )
    }

    #[test]
    fn test_decode_wc_session_authenticate() {
        let req = "{\"id\":1743510684985985,\"jsonrpc\":\"2.0\",\"method\":\"wc_sessionAuthenticate\",\"params\":{\"authPayload\":{\"type\":\"caip122\",\"chains\":[\"eip155:137\",\"eip155:1\",\"eip155:10\",\"eip155:324\",\"eip155:42161\",\"eip155:8453\",\"eip155:84532\",\"eip155:1301\",\"eip155:80094\",\"eip155:11155111\",\"eip155:100\",\"eip155:295\",\"eip155:1313161554\",\"eip155:5000\"],\"statement\":\"Please sign with your account\",\"aud\":\"https://appkit-lab.reown.com\",\"domain\":\"appkit-lab.reown.com\",\"version\":\"1\",\"nonce\":\"cfab4ebf5b80e510b9812b06fb62af56ca7e2c0115d4b88bdeec024313451e6f\",\"iat\":\"2025-04-01T12:31:24.985Z\",\"resources\":[\"urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvZXRoX2FjY291bnRzIjpbe31dLCJyZXF1ZXN0L2V0aF9yZXF1ZXN0QWNjb3VudHMiOlt7fV0sInJlcXVlc3QvZXRoX3NlbmRSYXdUcmFuc2FjdGlvbiI6W3t9XSwicmVxdWVzdC9ldGhfc2VuZFRyYW5zYWN0aW9uIjpbe31dLCJyZXF1ZXN0L2V0aF9zaWduIjpbe31dLCJyZXF1ZXN0L2V0aF9zaWduVHJhbnNhY3Rpb24iOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGEiOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjMiOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjQiOlt7fV0sInJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XSwicmVxdWVzdC93YWxsZXRfYWRkRXRoZXJldW1DaGFpbiI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ2V0QXNzZXRzIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9nZXRDYWxsc1N0YXR1cyI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ2V0Q2FwYWJpbGl0aWVzIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9nZXRQZXJtaXNzaW9ucyI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ3JhbnRQZXJtaXNzaW9ucyI6W3t9XSwicmVxdWVzdC93YWxsZXRfcmVnaXN0ZXJPbmJvYXJkaW5nIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9yZXF1ZXN0UGVybWlzc2lvbnMiOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3Jldm9rZVBlcm1pc3Npb25zIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9zY2FuUVJDb2RlIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9zZW5kQ2FsbHMiOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3N3aXRjaEV0aGVyZXVtQ2hhaW4iOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3dhdGNoQXNzZXQiOlt7fV19fX0\"]},\"requester\":{\"publicKey\":\"04f1c07b7205c273b6af5b85ac267cbe28c22d036873ffe4621abc4d9213430e\",\"metadata\":{\"name\":\"AppKit Lab\",\"description\":\"AppKit Lab is the test environment for Reown's AppKit\",\"url\":\"https://appkit-lab.reown.com\",\"icons\":[\"https://appkit-lab.reown.com/favicon.svg\"]}},\"expiryTimestamp\":1743514284}}";

        let decoded = serde_json::from_str::<
            JsonRpcRequest<session_authenticate::Params>,
        >(req)
        .unwrap();

        println!("Decoded: {decoded:?}");

        assert_eq!(decoded.id.to_u128().unwrap(), 1743510684985985);
        assert_eq!(decoded.method, JsonRpcMethod::SessionAuthenticate);
        assert_eq!(decoded.jsonrpc, "2.0");
        assert!(decoded.params.is_some());
        let params = decoded.params.unwrap();
        assert_eq!(
            params.requester.public_key,
            "04f1c07b7205c273b6af5b85ac267cbe28c22d036873ffe4621abc4d9213430e"
        )
    }
}
