/// Types
///
/// All the RPC types and logic to encode and decode. There are some tests with
/// actual payloads to ensure that the logic works.
///
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::str::FromStr;

use alloy::rpc::types::TransactionRequest;
use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Number;
use serde_json::Value;

use crate::cacao::Cacao;
use crate::error::Result;
use crate::message::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    String(String),
    Number(Number),
    U128(u128),
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
            Id::U128(n) => Ok(*n),
        }
    }
}

impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        self.to_u128().unwrap().eq(&other.to_u128().unwrap())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest<ParamType = Value> {
    pub jsonrpc: String,
    pub method: JsonRpcMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ParamType>,
    pub id: Id,
}

impl Display for JsonRpcRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcResponse<ResultType = Value> {
    #[allow(dead_code)]
    pub jsonrpc: String,
    #[serde(default)]
    pub result: Option<ResultType>,
    #[serde(default)]
    pub error: Option<JsonRpcError>,
    #[serde(default)]
    #[allow(dead_code)]
    pub id: Option<Id>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FetchMessageResult {
    #[serde(rename = "hasMore")]
    pub has_more: bool,
    pub messages: Vec<EncryptedMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub topic: String,
    pub message: String,
    pub tag: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<bool>,
    #[serde(rename = "publishedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<u64>,
    // TODO verify this thing on every response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
}

impl EncryptedMessage {
    pub fn new(topic: String, message: String, tag: IrnTag, ttl: u64) -> Self {
        Self {
            topic,
            message,
            tag: tag as u16,
            ttl: Some(ttl),
            prompt: Some(false),
            published_at: None,
            attestation: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrnTag {
    SessionPropose = 1100,
    SessionSettle = 1101,
    SessionProposeResponse = 1102,
    SessionPing = 1114,
    SessionPingResponse = 1115,
    SessionAuthenticate = 1116,
    SessionAuthenticateResponse = 1117,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum JsonRpcMethod {
    #[serde(rename = "irn_publish")]
    IrnPublish,

    #[serde(rename = "irn_subscribe")]
    IrnSubscribe,

    #[serde(rename = "irn_fetchMessages")]
    IrnFetchMessages,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum WcMethod {
    #[serde(rename = "wc_sessionPropose")]
    SessionPropose,

    #[serde(rename = "wc_sessionAuthenticate")]
    SessionAuthenticate,

    #[serde(rename = "wc_sessionSettle")]
    SessionSettle,

    #[serde(rename = "wc_sessionRequest")]
    SessionRequest,

    None,
}

impl Display for WcMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_plain::to_string(self).unwrap())
    }
}

impl FromStr for WcMethod {
    type Err = crate::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        serde_plain::from_str(s).map_err(|e| e.into())
    }
}

#[derive(Clone, Debug)]
pub enum WcParams {
    SessionPropose(SessionProposeParams),
    SessionAuthenticate(SessionAuthenticateParams),
    SessionSettle(SessionSettleParams),
    SessionRequest(SessionRequestParams),
    Result(Value),
}

impl Serialize for WcParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            WcParams::SessionPropose(p) => p.serialize(serializer),
            WcParams::SessionAuthenticate(p) => p.serialize(serializer),
            WcParams::SessionSettle(p) => p.serialize(serializer),
            WcParams::SessionRequest(p) => p.serialize(serializer),
            WcParams::Result(v) => v.serialize(serializer),
        }
    }
}

impl WcParams {
    pub fn method(&self) -> WcMethod {
        match self {
            Self::SessionPropose(_) => WcMethod::SessionPropose,
            Self::SessionSettle(_) => WcMethod::SessionSettle,
            Self::SessionAuthenticate(_) => WcMethod::SessionAuthenticate,
            Self::SessionRequest(_) => WcMethod::SessionRequest,
            Self::Result(_) => WcMethod::None,
        }
    }

    pub fn into_value(self) -> crate::Result<Value> {
        Ok(serde_json::to_value(self)?)
    }

    pub fn as_session_propose(&self) -> Option<&SessionProposeParams> {
        match self {
            WcParams::SessionPropose(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_session_authenticate(
        &self,
    ) -> Option<&SessionAuthenticateParams> {
        match self {
            WcParams::SessionAuthenticate(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_session_settle(&self) -> Option<&SessionSettleParams> {
        match self {
            WcParams::SessionSettle(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_session_request(&self) -> Option<&SessionRequestParams> {
        match self {
            WcParams::SessionRequest(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_result<R>(&self) -> Option<R>
    where
        R: DeserializeOwned,
    {
        match self {
            WcParams::Result(v) => serde_json::from_value::<R>(v.clone()).ok(),
            _ => None,
        }
    }
}

pub type WcMessage = Message<WcMethod, WcParams>;

impl Message {
    pub fn decode(self) -> crate::Result<WcMessage> {
        WcMessage::try_from(self)
    }
}

impl FromStr for WcMessage {
    type Err = crate::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let message = serde_json::from_str::<Message>(s)?;
        message.decode()
    }
}

impl WcMessage {
    pub fn from_value(value: Value) -> Result<WcMessage> {
        serde_json::from_value::<Message>(value)?.decode()
    }

    pub fn into_raw(self) -> crate::Result<Message> {
        Ok(Message {
            jsonrpc: self.jsonrpc,
            method: self.method.map(|m| m.to_string()),
            params: self.params.map(serde_json::to_value).transpose()?,
            result: None,
            id: self.id,
        })
    }
}

impl TryFrom<Message> for WcMessage {
    type Error = crate::Error;

    fn try_from(msg: Message) -> std::result::Result<Self, Self::Error> {
        let method = match &msg.method {
            Some(m) => WcMethod::from_str(m).map_err(|e| {
                crate::Error::InternalError3(
                    "Invalid method",
                    format!("{m} {e:?}"),
                )
            })?,
            None => WcMethod::None,
        };
        if method != WcMethod::None && msg.params.is_none() {
            return Err(crate::Error::InternalError3(
                "Params is none",
                serde_json::to_string(&msg).unwrap(),
            ));
        }
        let wc_params = match method {
            WcMethod::SessionPropose => {
                WcParams::SessionPropose(serde_json::from_value::<
                    SessionProposeParams,
                >(
                    msg.params.unwrap().clone()
                )?)
            }
            WcMethod::SessionAuthenticate => {
                WcParams::SessionAuthenticate(serde_json::from_value::<
                    SessionAuthenticateParams,
                >(
                    msg.params.unwrap().clone()
                )?)
            }
            WcMethod::SessionSettle => {
                WcParams::SessionSettle(serde_json::from_value::<
                    SessionSettleParams,
                >(
                    msg.params.unwrap().clone()
                )?)
            }
            WcMethod::SessionRequest => {
                WcParams::SessionRequest(serde_json::from_value::<
                    SessionRequestParams,
                >(
                    msg.params.unwrap().clone()
                )?)
            }
            WcMethod::None => WcParams::Result(msg.result.unwrap_or_default()),
        };

        Ok(Message {
            jsonrpc: msg.jsonrpc.clone(),
            method: Some(method.clone()),
            params: Some(wc_params),
            result: None,
            id: msg.id.clone(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionProposeParams {
    #[serde(rename = "requiredNamespaces")]
    pub required_namespaces: HashMap<String, Namespace>,
    #[serde(rename = "optionalNamespaces")]
    pub optional_namespaces: HashMap<String, Namespace>,
    pub relays: Vec<Relay>,
    #[serde(rename = "pairingTopic")]
    pub pairing_topic: String,
    pub proposer: Participant,
    #[serde(rename = "expiryTimestamp")]
    pub expiry_timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionProposeResponse {
    pub relay: Relay,
    #[serde(rename = "responderPublicKey")]
    pub responder_public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Namespace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<String>>,
    pub chains: Vec<String>,
    pub events: Vec<String>,
    pub methods: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relay {
    pub protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionAuthenticateParams {
    #[serde(rename = "authPayload")]
    pub auth_payload: AuthPayload,
    pub requester: Participant,
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
pub struct Participant {
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

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionAuthenticateResponse {
    pub cacaos: Vec<Cacao>,
    pub responder: Participant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionSettleParams {
    pub controller: Participant,
    pub expiry: u64,
    pub namespaces: HashMap<String, Namespace>,
    pub relay: Relay,
    #[serde(rename = "sessionProperties")]
    pub session_properties: Option<SessionSettleProperties>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionSettleProperties {
    pub capabilities: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRequestParams {
    #[serde(rename = "sessionId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub request: SessionRequestObject,
    #[serde(rename = "chainId")]
    pub chain_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionRequestObject {
    pub method: SessionRequestMethod,
    pub params: SessionRequestData,
    #[serde(rename = "expiryTimestamp")]
    pub expiry_timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SessionRequestMethod {
    #[serde(rename = "personal_sign")]
    PersonalSign,
    #[serde(rename = "eth_sendTransaction")]
    EthSendTransaction,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SessionRequestData {
    EthSendTransaction([Box<TransactionRequest>; 1]),
    PersonalSign([String; 2]),
}

impl Serialize for SessionRequestData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SessionRequestData::EthSendTransaction([tx]) => {
                let mut seq = serializer.serialize_seq(Some(1))?;
                seq.serialize_element(tx)?;
                seq.end()
            }
            SessionRequestData::PersonalSign(arr) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&arr[0])?;
                seq.serialize_element(&arr[1])?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for SessionRequestObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            Method,
            Params,
            ExpiryTimestamp,
        }

        struct SessionRequestVisitor;

        impl<'de> Visitor<'de> for SessionRequestVisitor {
            type Value = SessionRequestObject;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("SessionRequestObject with method, params, and expiryTimestamp")
            }

            fn visit_map<V>(
                self,
                mut map: V,
            ) -> Result<SessionRequestObject, V::Error>
            where
                V: MapAccess<'de>,
            {
                use serde_json::Value;

                let mut method: Option<SessionRequestMethod> = None;
                let mut raw_params: Option<Value> = None;
                let mut expiry: Option<u64> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Method => method = Some(map.next_value()?),
                        Field::Params => raw_params = Some(map.next_value()?),
                        Field::ExpiryTimestamp => {
                            expiry = Some(map.next_value()?)
                        }
                    }
                }

                let method = method
                    .ok_or_else(|| serde::de::Error::missing_field("method"))?;
                let raw_params = raw_params
                    .ok_or_else(|| serde::de::Error::missing_field("params"))?;
                let expiry = expiry.ok_or_else(|| {
                    serde::de::Error::missing_field("expiryTimestamp")
                })?;

                // Deserialize the params based on the method
                let params = match method {
                    SessionRequestMethod::EthSendTransaction => {
                        let arr: [Box<TransactionRequest>; 1] =
                            serde_json::from_value(raw_params)
                                .map_err(serde::de::Error::custom)?;
                        SessionRequestData::EthSendTransaction(arr)
                    }
                    SessionRequestMethod::PersonalSign => {
                        let arr: [String; 2] =
                            serde_json::from_value(raw_params)
                                .map_err(serde::de::Error::custom)?;
                        SessionRequestData::PersonalSign(arr)
                    }
                };

                Ok(SessionRequestObject {
                    method,
                    params,
                    expiry_timestamp: expiry,
                })
            }
        }

        deserializer.deserialize_map(SessionRequestVisitor)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::rpc::types::{TransactionInput, TransactionRequest};
    use alloy::signers::k256::sha2::{Digest, Sha256};
    use alloy::{
        hex,
        primitives::{TxKind, U256},
    };
    use serde_json::json;

    use super::*;
    use crate::{
        message::Message,
        relay_auth::Keypair,
        utils::{derive_sym_key, parse_uri, sha256},
    };

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

        let decoded = WcMessage::from_str(req).unwrap();

        println!("Decoded: {decoded:?}");

        assert_eq!(decoded.id.to_u128().unwrap(), 1743510684985756);
        assert_eq!(decoded.method, Some(WcMethod::SessionPropose));
        assert_eq!(decoded.jsonrpc, "2.0");
        assert!(decoded.params.is_some());
        let params = decoded.params.unwrap();
        let params = params.as_session_propose().unwrap();
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

        let decoded = WcMessage::from_str(req).unwrap();

        println!("Decoded: {decoded:?}");

        assert_eq!(decoded.id.to_u128().unwrap(), 1743510684985985);
        assert_eq!(decoded.method, Some(WcMethod::SessionAuthenticate));
        assert_eq!(decoded.jsonrpc, "2.0");
        assert!(decoded.params.is_some());
        let params = decoded.params.unwrap();
        let params = params.as_session_authenticate().unwrap();
        assert_eq!(
            params.requester.public_key,
            "04f1c07b7205c273b6af5b85ac267cbe28c22d036873ffe4621abc4d9213430e"
        )
    }

    #[test]
    fn test_decode_fetch_messages() {
        let resp = "{\"id\":1744205603590064025,\"jsonrpc\":\"2.0\",\"result\":{\"hasMore\":false,\"messages\":[{\"attestation\":\"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDQyMDkxOTAsImlkIjoiZWRhYjVmMjQyNTNmZGUyYTVkYzI4NTcyZmRkNGE4NTViYTJhZjRkOGM2ZmQxMjQxN2NlMWUwNDMzODY5MjcwMCIsIm9yaWdpbiI6Imh0dHBzOi8vYXBwa2l0LWxhYi5yZW93bi5jb20iLCJpc1NjYW0iOmZhbHNlLCJpc1ZlcmlmaWVkIjp0cnVlfQ.zeNQehxpiQ0JqVBHTlkxgDwValU2NhGEsUMT5irJgiM92d1M361ifoxRIJfh1_EF2dVBqyr6zLV4cbp3g4jLSQ\",\"message\":\"ALW+zRyGiw5kj8hlp/Xv1jQ3vGFNcFNsfp4PyyVPbkcbMohD0sGhUejguhlNRA0fXnCfzQ9/hdI5xcmy1SubXts/Db6Kt1cStgOgIXSGReS3jP2AgldAv5WR77dfXDytJzYmg6af9lbKMYCuI+4qWyuaswKvsO4cyeRaT1jVsITT6uy+z2A50H0uBuNcnE4YGKia8yxlZYfLj0dbJ1Q/zX8d9DF/YLBQzUhLOD6P9ajCDUTNs7S24lDtB1xglkKHyxG4/cSktAGmvu7QWcYzkzeLmGcqxK7TxO3+N8baOMf4bq0n2tJjFCQPrs31d/mrQc1e7d7GwmndZjvbWRL+ab+B2INkfs6cEkLTtwu10TXGAScQCrrVtBR/apIiGFpg27YD+KbbM7hCmFoOIxJc1DXH8psf+MjDhwLqQRVxMe26DYbL50jwqQmDu71qvi4DHZgRyAq/wWSIHe+BGqfZKzK45zK7cz72WsZhuEjOqmDK0gZePbHzWaVvI9uApzpVXGVPOwp4eeZOBYbED+Oucq6CovHRjVIw0CZitjQH14yv0XNIFZ1U1/byB/jWgvQwW42O3v9M3cmljeXTeuEaao+bngEv6zN7CDpGMbiQ4gDTxihtpTv7Mgl+9LpyhrtY79QJ6XMx9wkWuxkbsIrQalFgJuhcJEMfULjLSe49gzIC91gSJ5rVKd1ej82yIsDHUn6roKFb0McQXJNa5vb+Wh1cfn46LeX+m6XBRFXGKqr6xXs4dujZg2TeDA9XyNT4B99hXGQl4BkNmAv6BYjH6pB63Fr7f+10iyf9SrfXlYVR9mLTqsVVd53sVuKWW6esKhgPHc2+Fd30+LRMTmhG/IebxRaRBpBvjjh8lkVFowQn37TruR4sVX0NB/UsqX2U9Ns9A1LLMVI3+QycUmU/aDPR3fxmn1OF2abskgjvWLr3lqVVZGPf3nFgxMfU4u/+xsztwuw2Pc5lFos06z+dY0sZaRpB4b59Qb79KT/1CFodRjfGDcM6eRbaj2XcMfn46HkczxKl494aiu6KwLIzx5ChpCt9EMyO6SV/dhEhvL/cwcWAZsUmft5yPSa24J5bCtTetcL7fGMrjyyJYsQBFMgdQJC7YtlUcrPm5NIhJu8DYjef86sr8m38t2vixFGifC55RQhlKdG12cUrtY9TVQMJrEBdLsmuBbSFVa9oSzbh4yNvPRciLkaUAo5A5QfBlfZmbLZutE9v9IsjmIqZ78xys6Q93Hx5keDk3xdM1/1and9v5kjVMvmpQX1vqtlebIJY5sqM3BZVt9Tyxg6eSl+fKI+Jug+K19T9b1dGsfqByIf/js9pEAATxbV+e8I2CAtxNlipfHJleamZY1mVe74sokGMbM/Tz7MYYXp8MePKPXH+Te6yFMtvHfHdPi1Qmte+w9VLEin2PuLWt/DNX277YrOvhBYuRx30L9DWAXSIcN3qnxI6GpL45dX2rf8pyMdO1vdsPQG/Sr1EnU8jTi+ul182Zyen04kOhtqtuoYV2Sh73k2/6AVRWPtFqhGUI0cUBrdVnE1PAFgRaYMDmTTMYFnmz/PXptuP/T14x5F0wdoFNOUw88opmRrIsqQgtRYIwMa5303aHhB7H+aY7Hg3/y2RNOxklXUMikwI/8bHw0l2jVS69egUe1JMVk51sG8IxG45lf/q7zUEm5BcJ6QJ21OTqZqMJHPDEO0r0okc1C17/rylIh9c0+2zUdqJa7N0sV9Qd9oGNciKswoHLeNhHdQQrEyEFjmQr5TV9MM8HaWVIrRf5SGgsAmSd+GHUyz1sNt8DzlOQja2qKEZIgNZYBE6f667dX5WTmNcQ9zZje45uVKRkO8YGkBT0m1b4iD+hgHuYQdkLQMHvfsDiZo=\",\"publishedAt\":1744205591202,\"tag\":1100,\"topic\":\"74818ca920a949b9adad9ed0c5bdfa1f5e6ea5e5b1a18e71a7ba1ac9923295e5\"},{\"attestation\":\"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDQyMDkxOTAsImlkIjoiZGU0MjhhYjU0NzhiZWJkOGU5M2M3OGFhNTVjYTNkYTEwZWViYzE0MTY4MTgwYWJkNTYxYmRhZmVmYjMxMmZkOSIsIm9yaWdpbiI6Imh0dHBzOi8vYXBwa2l0LWxhYi5yZW93bi5jb20iLCJpc1NjYW0iOmZhbHNlLCJpc1ZlcmlmaWVkIjp0cnVlfQ.EJMNd8iO0Uvr1owRbomGuC3One2K6pfKZa3nvIl4MpI00EkHL86Tdo63MJXKtGK65ixFZqhx-L__M8kXbhFoJA\",\"message\":\"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\",\"publishedAt\":1744205591323,\"tag\":1116,\"topic\":\"74818ca920a949b9adad9ed0c5bdfa1f5e6ea5e5b1a18e71a7ba1ac9923295e5\"}]}}";
        let result =
            serde_json::from_str::<JsonRpcResponse<FetchMessageResult>>(resp)
                .unwrap();
        println!("result {result:?}");
    }

    // this is with https://appkit-lab.reown.com/library/wagmi-all/
    #[test]
    fn test_cacao_flow() {
        let uri_params = parse_uri(
        "wc:b61b370a99504fa0bd4c8aef4eecdd77c2be9e94e72fb74aedca828e5f33cb79@2?relay-protocol=irn&symKey=4ef8aa7fff3e8354b5032525520255ab526cc661f16b5eff95fe7cd3f0b32f0b&expiryTimestamp=1743768178&methods=wc_sessionAuthenticate".to_string(),
        ).unwrap();

        // First message: SessionPropose
        let message1 = decrypt(
            "AEJKPBI19Jv57WrKe5BHyZDoaW8pTQi1Fdl97klacGd8HAl0AwQpstTerQkoMPRzr2mVhlzwox30pf1S3fzIo0VcWeIi3exFlSg+vrrdkUaiS0U3U+1FwWAjpk06wlhaOKplgdVvoBNIBIVG0h6QZSqT/V3tz6jYtm276i6RJpPGjh6H2lTWRU7WQZXzy/g/cIO7J/lnai4ZV20oPCeymPGDsI2gWGb2Rf4rB2CYC2NxkVbhRvP0jMGreIegF2IOIUl3IIl8XCgnwvn7AaP6FrYnHk8klFh2r1+649csqtfc3i3pWKdsRN9H2HUeoH+UL3zy5jj2LCDMbtghpqPoul5rERC0ccEzXUaKS5APDkWLB5WqepXsbXRedxQ0JQkAAagqeLa2CZP9STFDnNOUiVx1x53lxB5coQROnt2Byc3W3xnEkufFp+ygnfrMSBCmM/mTr5FJ+gQJIognqJ32f1C2o1UqI+8MQ/WiKL9fZXKzATxMGVNKHwoLKhTotYRET6ocCaBVttFUXP7Bzvp/lL1xrweFI9xb83SXEQojildGKhhW5/YWeHJsY9Om+wo9o+0mpgRaydkXz8ad24aFEJnmZ50Q1hv7DzhwTQZ1aQZn9RSvKiaEFimz5M7GusXP/92wKLOFldo18HzoLczQ3rgNno549sfosR7z6QgXjIR2+L2CdA4Cxy10zDpUIhHg0t7Ey+kPtiRxP8lQVa/e0m6bQusaM1SsyEifPVNjtk4JUj4dTvdD5BDvFeMOFiuzsNtoZom2vsdLz71j1eLSpIAGwbMmsgjtbc8wboqceQnTR5fAIS9D4On7Og9Nr4E1Mz9Jo7LtUK9Hg1Crq08g1cSEPZdIMX6dZqc1viEdwzaR2Hks9e7DwUBN5j5T4Jmb0Elm9Ke7SMuC1bD7Ijp0PQbWkgondo0iBQyXT7Q8A+HWX/kfar80gFsSt5KvUG2A9wGxwnJw8WnDhxcnyleXh+0COIInzQ1uFNA+RQeymsjFqMpw1QFlfySe6S0brgs2ty14ZXM11hWOvjNf2kynBAux8JeOnUpSPOnl2VwNuFo04CQLUtlabyb5T9Cwtk7ftph+mZDOj2feCGkFJXF/9IRMsN7kBCyxoc5hdnFNHFbN7rcHvYeS8B3n3mN1Rf6jiyOwuSbu0RgBBeRMgTFoMhx6KylaMA/8jsv/NlV7XMO8Z8+2I0ZBZW1xhGI+1LeR7EtEMQOBwpeqnEmcD+cwfsFWzO+w8cOeTLSNfyTyrAVzK5xvCfBtmwq2Zcv9B7fHVwGVU46io4zZVf0VA4OcD/OPuGRpLQLM/YH29+NCLMYdMgFP/aK3T6tSXaDgmfTW7MfzaxaePo/QDeZiDiMewCgj5OAZWHE9JCICVywZ2AaGBry6MbVVr7pz/1zKtoH7bZ10k9xxlqFLrcVq3j0Es2yQ3E2lr2Hhbiu7D1gKfky9AjotKJ2Lc19vby4ZYs4c4AjxIClO0L+OXbDkavmxd3kAKw0Dpnfw/Riw3WDyfRMWDuPSZInPCcWhrtU+u9yfN58fpccl+17bTWzW1tacJrH3NHI35ln99nrpMklN6akdDaYG9qnQB/leY/JiUC5I6Bx37hA/ErtFAf9wPE1lQ7+vwallJQnm1bSXkCQWV+huJwNDaTdzMgmjkglaK67vOkBUBr4YmOWvzoxIt5ZYJPuipZlzE8koyhj7jTIb0HO0vvvCDI+M4ubrvSkqkcQ86MFZA+zw2Vgej/WcccrqaM1MnbV9MT6f5GDxmktLtV89aSOb3ZUY0fkgDj65evl9qXFOdroB57+SyxgOSv62pGRq9sstrlplQqnsgPrNeIZ+sowMKE7o89Iy9QtcuYHpUmA8tcHtD0WX8GevvnghIr0=",
            uri_params.sym_key,
        );
        message1
            .clone()
            .decode()
            .expect("SessionPropose decode failed");
        assert_eq!(
            message1,
            Message {
                jsonrpc: "2.0".to_string(),
                method: Some(WcMethod::SessionPropose.to_string()),
                params: Some(json!({
                    "expiryTimestamp": 1743768178,
                    "id": 1743767878967710_u64,
                    "optionalNamespaces": {
                        "eip155": {
                            "chains": [
                                "eip155:137", "eip155:1", "eip155:10", "eip155:324",
                                "eip155:42161", "eip155:8453", "eip155:84532",
                                "eip155:1301", "eip155:80094", "eip155:11155111",
                                "eip155:100", "eip155:295", "eip155:1313161554",
                                "eip155:5000", "eip155:2741"
                            ],
                            "events": ["chainChanged", "accountsChanged"],
                            "methods": [
                                "personal_sign", "eth_accounts", "eth_requestAccounts",
                                "eth_sendRawTransaction", "eth_sendTransaction",
                                "eth_sign", "eth_signTransaction",
                                "eth_signTypedData", "eth_signTypedData_v3",
                                "eth_signTypedData_v4", "wallet_addEthereumChain",
                                "wallet_getAssets", "wallet_getCallsStatus",
                                "wallet_getCapabilities", "wallet_getPermissions",
                                "wallet_grantPermissions", "wallet_registerOnboarding",
                                "wallet_requestPermissions", "wallet_revokePermissions",
                                "wallet_scanQRCode", "wallet_sendCalls",
                                "wallet_switchEthereumChain", "wallet_watchAsset"
                            ]
                        }
                    },
                    "pairingTopic": "b61b370a99504fa0bd4c8aef4eecdd77c2be9e94e72fb74aedca828e5f33cb79",
                    "proposer": {
                        "metadata": {
                            "description": "AppKit Lab is the test environment for Reown's AppKit",
                            "icons": ["https://appkit-lab.reown.com/favicon.svg"],
                            "name": "AppKit Lab",
                            "url": "https://appkit-lab.reown.com"
                        },
                        "publicKey": "62dbe3bc5bf8395e6f247a2b7aaedcf11e33fccd68d77da1b2752d4f0cc3755f"
                    },
                    "relays": [{"protocol": "irn"}],
                    "requiredNamespaces": {}
                })),
                result: None,
                id: Id::U128(1743767878967710),
            }
        );

        // Second message: SessionAuthenticate
        let message2 = decrypt(
            "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",
            uri_params.sym_key,
        );
        message2
            .clone()
            .decode()
            .expect("SessionAuthenticate decode failed");
        assert_eq!(
            message2,
            Message {
                jsonrpc: "2.0".to_string(),
                method: Some(WcMethod::SessionAuthenticate.to_string()),
                params: Some(json!({
                    "authPayload": {
                        "aud": "https://appkit-lab.reown.com",
                        "chains": [
                            "eip155:137", "eip155:1", "eip155:10", "eip155:324", "eip155:42161",
                            "eip155:8453", "eip155:84532", "eip155:1301", "eip155:80094",
                            "eip155:11155111", "eip155:100", "eip155:295", "eip155:1313161554",
                            "eip155:5000", "eip155:2741"
                        ],
                        "domain": "appkit-lab.reown.com",
                        "iat": "2025-04-04T11:57:58.967Z",
                        "nonce": "2dc2e52ebcfc7d0306403e3053b9e3fac8ebed330381c8dc94fda94ffb21fad2",
                        "resources": [
                            "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvZXRoX2FjY291bnRzIjpbe31dLCJyZXF1ZXN0L2V0aF9yZXF1ZXN0QWNjb3VudHMiOlt7fV0sInJlcXVlc3QvZXRoX3NlbmRSYXdUcmFuc2FjdGlvbiI6W3t9XSwicmVxdWVzdC9ldGhfc2VuZFRyYW5zYWN0aW9uIjpbe31dLCJyZXF1ZXN0L2V0aF9zaWduIjpbe31dLCJyZXF1ZXN0L2V0aF9zaWduVHJhbnNhY3Rpb24iOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGEiOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjMiOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjQiOlt7fV0sInJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XSwicmVxdWVzdC93YWxsZXRfYWRkRXRoZXJldW1DaGFpbiI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ2V0QXNzZXRzIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9nZXRDYWxsc1N0YXR1cyI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ2V0Q2FwYWJpbGl0aWVzIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9nZXRQZXJtaXNzaW9ucyI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ3JhbnRQZXJtaXNzaW9ucyI6W3t9XSwicmVxdWVzdC93YWxsZXRfcmVnaXN0ZXJPbmJvYXJkaW5nIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9yZXF1ZXN0UGVybWlzc2lvbnMiOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3Jldm9rZVBlcm1pc3Npb25zIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9zY2FuUVJDb2RlIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9zZW5kQ2FsbHMiOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3N3aXRjaEV0aGVyZXVtQ2hhaW4iOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3dhdGNoQXNzZXQiOlt7fV19fX0"
                        ],
                        "statement": "Please sign with your account",
                        "type": "caip122",
                        "version": "1"
                    },
                    "expiryTimestamp": 1743771478,
                    "requester": {
                        "metadata": {
                            "description": "AppKit Lab is the test environment for Reown's AppKit",
                            "icons": ["https://appkit-lab.reown.com/favicon.svg"],
                            "name": "AppKit Lab",
                            "url": "https://appkit-lab.reown.com"
                        },
                        "publicKey": "62dbe3bc5bf8395e6f247a2b7aaedcf11e33fccd68d77da1b2752d4f0cc3755f"
                    }
                })),
                result: None,
                id: Id::U128(1743767878967691),
            }
        );

        let (
            _self_private_key,
            _self_public_key,
            _other_public_key,
            _response_topic,
            diffie_sym_key,
            _diffie_topic,
        ) = calculate(
            "000bd03964f8577117caa2f8ee5ef02e46b71c672d93605f447ef96d365c4002",
            "62dbe3bc5bf8395e6f247a2b7aaedcf11e33fccd68d77da1b2752d4f0cc3755f",
        );

        // Third message: SessionAuthenticateResponse
        let message3 = decrypt(
            "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",
            diffie_sym_key,
        );
        let message3_decoded = message3
            .decode_result::<SessionAuthenticateResponse>()
            .expect("SessionAuthenticateResponse decode failed");
        assert_eq!(
            message3,
            Message {
                jsonrpc: "2.0".to_string(),
                method: None,
                params: None,
                result: Some(json!({
                  "cacaos": [
                    {
                      "h": {
                        "t": "caip122"
                      },
                      "p": {
                        "aud": "https://appkit-lab.reown.com",
                        "domain": "appkit-lab.reown.com",
                        "iat": "2025-04-04T11:57:58.967Z",
                        "iss": "did:pkh:eip155:137:0x93a00dcebe229461F0d2D3462f834DfFD0fBbBd3",
                        "nonce": "2dc2e52ebcfc7d0306403e3053b9e3fac8ebed330381c8dc94fda94ffb21fad2",
                        "resources": [
                          "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvZXRoX3NlbmRSYXdUcmFuc2FjdGlvbiI6W3siY2hhaW5zIjpbImVpcDE1NToxMzciLCJlaXAxNTU6MSIsImVpcDE1NToxMCIsImVpcDE1NTozMjQiLCJlaXAxNTU6NDIxNjEiLCJlaXAxNTU6ODQ1MyIsImVpcDE1NTo4NDUzMiIsImVpcDE1NToxMTE1NTExMSJdfV0sInJlcXVlc3QvZXRoX3NlbmRUcmFuc2FjdGlvbiI6W3siY2hhaW5zIjpbImVpcDE1NToxMzciLCJlaXAxNTU6MSIsImVpcDE1NToxMCIsImVpcDE1NTozMjQiLCJlaXAxNTU6NDIxNjEiLCJlaXAxNTU6ODQ1MyIsImVpcDE1NTo4NDUzMiIsImVpcDE1NToxMTE1NTExMSJdfV0sInJlcXVlc3QvZXRoX3NpZ24iOlt7ImNoYWlucyI6WyJlaXAxNTU6MTM3IiwiZWlwMTU1OjEiLCJlaXAxNTU6MTAiLCJlaXAxNTU6MzI0IiwiZWlwMTU1OjQyMTYxIiwiZWlwMTU1Ojg0NTMiLCJlaXAxNTU6ODQ1MzIiLCJlaXAxNTU6MTExNTUxMTEiXX1dLCJyZXF1ZXN0L2V0aF9zaWduVHJhbnNhY3Rpb24iOlt7ImNoYWlucyI6WyJlaXAxNTU6MTM3IiwiZWlwMTU1OjEiLCJlaXAxNTU6MTAiLCJlaXAxNTU6MzI0IiwiZWlwMTU1OjQyMTYxIiwiZWlwMTU1Ojg0NTMiLCJlaXAxNTU6ODQ1MzIiLCJlaXAxNTU6MTExNTUxMTEiXX1dLCJyZXF1ZXN0L2V0aF9zaWduVHlwZWREYXRhIjpbeyJjaGFpbnMiOlsiZWlwMTU1OjEzNyIsImVpcDE1NToxIiwiZWlwMTU1OjEwIiwiZWlwMTU1OjMyNCIsImVpcDE1NTo0MjE2MSIsImVpcDE1NTo4NDUzIiwiZWlwMTU1Ojg0NTMyIiwiZWlwMTU1OjExMTU1MTExIl19XSwicmVxdWVzdC9ldGhfc2lnblR5cGVkRGF0YV92MyI6W3siY2hhaW5zIjpbImVpcDE1NToxMzciLCJlaXAxNTU6MSIsImVpcDE1NToxMCIsImVpcDE1NTozMjQiLCJlaXAxNTU6NDIxNjEiLCJlaXAxNTU6ODQ1MyIsImVpcDE1NTo4NDUzMiIsImVpcDE1NToxMTE1NTExMSJdfV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjQiOlt7ImNoYWlucyI6WyJlaXAxNTU6MTM3IiwiZWlwMTU1OjEiLCJlaXAxNTU6MTAiLCJlaXAxNTU6MzI0IiwiZWlwMTU1OjQyMTYxIiwiZWlwMTU1Ojg0NTMiLCJlaXAxNTU6ODQ1MzIiLCJlaXAxNTU6MTExNTUxMTEiXX1dLCJyZXF1ZXN0L3BlcnNvbmFsX3NpZ24iOlt7ImNoYWlucyI6WyJlaXAxNTU6MTM3IiwiZWlwMTU1OjEiLCJlaXAxNTU6MTAiLCJlaXAxNTU6MzI0IiwiZWlwMTU1OjQyMTYxIiwiZWlwMTU1Ojg0NTMiLCJlaXAxNTU6ODQ1MzIiLCJlaXAxNTU6MTExNTUxMTEiXX1dfX19"
                        ],
                        "statement": "Please sign with your account I further authorize the stated URI to perform the following actions on my behalf: (1) 'request': 'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'eth_signTransaction', 'eth_signTypedData', 'eth_signTypedData_v3', 'eth_signTypedData_v4', 'personal_sign' for 'eip155'.",
                        "version": "1"
                      },
                      "s": {
                        "s": "0xd99e4fc4558539f2deb36041d85173e066a6a021c276cb320b983b94a989a73124f7409e3a28da775c790172998753a7579390907890c0106ca74c93ba4f50801c",
                        "t": "eip191"
                      }
                    }
                  ],
                  "responder": {
                    "metadata": {
                      "description": "React Wallet for WalletConnect",
                      "icons": ["https://avatars.githubusercontent.com/u/37784886"],
                      "name": "React Wallet Example",
                      "url": "https://walletconnect.com/"
                    },
                    "publicKey": "b888ea88e58ad03b935da236b662c037f3b391210ef4aabaf83025f046797645"
                  }
                })),
                id: Id::U128(1743767878967691)
            }
        );

        let cacao = message3_decoded
            .result
            .as_ref()
            .unwrap()
            .cacaos
            .first()
            .unwrap();
        cacao.verify().unwrap();

        println!("cacao verification success");

        // assert!(false);
    }

    // with localhost:3002
    #[test]
    fn test_settle_flow() {
        let uri_params = parse_uri(
            "wc:6c0a8da4a0c672f063bc9972ea1a40b88c5a20c5b8984237987121d6f6024025@2?relay-protocol=irn&symKey=1b53c9465436bef7fd23211a0c233c60b6799b47c20db904df0bbe2ff6227a13&expiryTimestamp=1744290863".to_string(),
        ).unwrap();

        // first message from dapp to wallet
        // irn tag 1100
        let message1 = decrypt(
            "APJp0bXg8XcsUBeyyf/yAxikhfBBmguNF2VZiUAprqsNdWulICHbgvfzpbhvhnV3Q6nSt513k58Tp87MDp5s0G/iir1/IIV8qC7mShut4dOMTzCj9yderIErYmkgaR+XYqDBLn/uXQT8xIHrnyy9egWu3CE0bk2exTYC30abagrMcB8lclXkwTSz3H+39bbUv5G+8rWyYMFpYJaUF2KQUtIkeL4jV4kpT4S0+3cYMfwbS5+9yKR4iOzxfYkb93qOiZH1dIYZzHV5ng5VzjwI7Cd4CZqoJtFxQWHMH/+0hxWCiONbaGMGXLpJUysd7iOfjpuRWOzDvpLb3MYIBSf1sePiSiE/mm63qSkbZURbIScY9HJGJ5tXVacfA1w6XCtsDzhgeuVROsKS62salM1u0umwaaDBFyD6rDoNf94YItcdAYqb4Zp/nMiHzWo6vHebc+xpBJw14gqETVP4XiYmGbbGrSxyG4+tN2u8I/e9zyT5aGqdr6OyZ04PF5biFzyz9IyC/2mdsWOGU10uV6246A2r9yXyS2kyEK2Ed+mumvBETPnD4Tx8Jop2+x96WrBggunJrH1M6eOA2zeu1XdA1qpYnHKQ7JmePifbZR+VkGmyXxJ4omUXFcG+VaMjghWrOp6tlwDXbcQDVpTDuN2mEi28SwAhbJf8m4ag+90UGXtjTFbXv6AM7pGTdJD9x9Bs9mLUHlRYzCSS6uObpMDVgVi+ZiVXOPirmrW9QX8xEzzGIgXzCTg7JiT0RbfMmhdwd/dAwNO4kXl7s9XaSlMQycA6rgmKhR0Z3c9hLKflD6JPsehq50Fs08l/qIzgI1/Kw/8O/HKVhhpsdAqKZj89qDdauNXBb3SHbbOg",
            uri_params.sym_key,
        );
        message1
            .clone()
            .decode()
            .expect("SessionPropose decode failed");
        assert_eq!(
            message1,
            Message {
                jsonrpc: "2.0".to_string(),
                method: Some(WcMethod::SessionPropose.to_string()),
                params: Some(json!({
                  "expiryTimestamp": 1744290864,
                  "optionalNamespaces": {
                    "eip155": {
                      "chains": ["eip155:1", "eip155:137"],
                      "events": ["chainChanged", "accountsChanged"],
                      "methods": ["eth_sendTransaction", "personal_sign"]
                    }
                  },
                  "pairingTopic": "6c0a8da4a0c672f063bc9972ea1a40b88c5a20c5b8984237987121d6f6024025",
                  "proposer": {
                    "metadata": {
                      "description": "App to test WalletConnect network",
                      "icons": [],
                      "name": "React App",
                      "url": "http://localhost:3002"
                    },
                    "publicKey": "690a17937795cf5af845bd7c0701156f647d9bcb211eb7bd85d362fa371cb02d"
                  },
                  "relays": [
                    {
                      "protocol": "irn"
                    }
                  ],
                  "requiredNamespaces": {}
                }
                )),
                result: None,
                id: Id::U128(1744290564004257),
            }
        );

        let (
            _self_private_key,
            _self_public_key,
            _other_public_key,
            _response_topic,
            diffie_sym_key,
            _diffie_topic,
        ) = calculate(
            "93f31989e2f2582d7c7eb1b074ca7bcac003dea3b0b960a9538da56aee3654c3",
            "690a17937795cf5af845bd7c0701156f647d9bcb211eb7bd85d362fa371cb02d",
        );

        // first publish from wallet to dapp
        // irn tag 1102
        let message2 = decrypt(
            "APjVUGlm0Tmem9SpiHcoYZ0qfWRqv7Hsu57c4/d47+nIzRQrQJ8ftmHzGOI/168HZccREP/Qvu6FOvXZM8MK2/buJAZIdXW6qF4h2wTVAKvpkftgBxfdj32S2eX5Azzaw3X62tu5xeKljTZVkE4SG5uK1iYvruEOcFNAwibAyavk65Gi4RXSlK0ZkQrTlbBy5oN35OnGukIzuz6m+lHXCJe122Go3PCkIJRmLreorxiwlhqPiapXzLrSKNAcvwN7PB/DpnFGTe3D5CCaCEDYeUziIsvGJTsOU52ceYc0LvWGC16mPKJY4ZS3IkdCu3pjjhmC2GdrTwkNm3vTvmhxzU9SiZ+cecN44US+FfKehzbnm6OrglBaty656IL0S+BDn3BhzPenZwFLsc7mUrRaTnMLbXfqIlujKeAuW1U86byIX5mo3UKlGMJYA+GKCm6ZoKdsLeRZWMI4rYsGkU58mj8SLzIVt9VZNP6MSNVjb5BginuVSVhT1QtAfKrNW1LG0dGhSc/10irLB7O8gvJvMS5r4weABdm1DPKEoyC9iNxmmrKpPmkwmqfrB5I6Bwyj/3ZK8camMxRgUlp2q16Sb/zK68Y7Lrw/2hhq7XpyKIm91j5aamL1VacwbqgLLdIqi2KpKLOWI6J1AUSDvppItW3gZ9Lf/kE1NsI3FVY7/xTmYzRYipsAwHMzLryMPl/7prt0XtjCTm2fG2coEhWt85e8BJSUBTBwaefZhgzSCZKz65FJXEWNNXZsO900bnN0LQjT8f4Iy5KA5M7gArihlhlVlYdaQ0uhk2mdXkWUvE0Lv2UlvKp0P5y/sXGGIkNIxHKY18MxBlrX/zebjAKk3VUR6ljoss69sNOW5AiX/OfUGxyxNNj09RWvP/RCpZ5dzl0DsG+CVHPNAxpok8Fo3sN4rlcXyCqJC8a2HN3XFud6v4p++fvZIy/h2JjlDpACZ/H2a+y8SquOOgHCoyoD0R2v5WojiHntkaN14nOKYqbeNGRpqZ19jb9xj+O+SG2zj4OEJyX07yRdV6efG23sirGkKOuyxAds9YM3+1fSAfqhN8sZeV5qXXbbQrUROG8Koin0avGXGs3zgH0zu6WkCe9dKZ0+rmhVOMSb3QQHRksrtDXSgvHbH4QRPAisLqGO",
            diffie_sym_key,
        );
        message2
            .clone()
            .decode()
            .expect("SessionSettle decode failed");
        // message2
        //     .try_decode::<SessionSettleParams>()
        //     .expect("SessionSettle decode failed");
        assert_eq!(
            message2,
            Message {
                jsonrpc: "2.0".to_string(),
                method: Some(WcMethod::SessionSettle.to_string()),
                params: Some(json!({
                  "controller": {
                    "metadata": {
                      "description": "React Wallet for WalletConnect",
                      "icons": [
                        "https://avatars.githubusercontent.com/u/37784886"
                      ],
                      "name": "React Wallet Example",
                      "url": "https://walletconnect.com/"
                    },
                    "publicKey": "886cea3da4d8ffa0ea6a10350ae9c2c882c52da1f00666adbb94af802e7d2414"
                  },
                  "expiry": 1744895416,
                  "namespaces": {
                    "eip155": {
                      "accounts": [
                        "eip155:1:0x93a00dcebe229461F0d2D3462f834DfFD0fBbBd3",
                        "eip155:1:0xCEF2AA53EDB74479013e169Df978831920dA04f4",
                        "eip155:137:0x93a00dcebe229461F0d2D3462f834DfFD0fBbBd3",
                        "eip155:137:0xCEF2AA53EDB74479013e169Df978831920dA04f4"
                      ],
                      "chains": [
                        "eip155:1",
                        "eip155:137"
                      ],
                      "events": [
                        "accountsChanged",
                        "chainChanged"
                      ],
                      "methods": [
                        "personal_sign",
                        "eth_sendTransaction"
                      ]
                    }
                  },
                  "relay": {
                    "protocol": "irn"
                  },
                  "sessionProperties": {
                    "capabilities": "{}"
                  }
                })),
                result: None,
                id: Id::U128(1744290616431615),
            }
        );

        // irn tag 1101
        let message3 = decrypt(
            "AL2vbPOzZHGYzB1rtjfHiTv5SBD/B35wB+Qp+//MIuVxKQqSLfFH9natGX+qZoyDSzcHmO5WIqFEv/C8Kdm3rpAFsRSbl5jf/midSnUeChAYUTVn79YW67VMsWqmdCOjZ49eil20DqqsPITb6Aej9cfpOQJbxGYNawMhRaHKgy7uhyxJdsvJFJopO8QUjQmma87hG3cbws4q9AZ5sMpwHDEdfKXSc+8Q6akA1ZuueUoycwciLv16JU4Bf/bq2vB+Et4=",
            uri_params.sym_key,
        );
        // message3
        //     .try_decode::<SessionProposeResponse>()
        //     .expect("SessionProposeResponse decode failed");
        assert_eq!(
            message3,
            Message {
                jsonrpc: "2.0".to_string(),
                method: None,
                params: None,
                result: Some(json!({
                    "relay": {
                        "protocol": "irn"
                    },
                    "responderPublicKey": "886cea3da4d8ffa0ea6a10350ae9c2c882c52da1f00666adbb94af802e7d2414",
                })),
                id: Id::U128(1744290564004257),
            }
        );

        // assert!(false);
    }

    fn decrypt(encoded: &str, sym_key: [u8; 32]) -> Message {
        let result = Message::decrypt(encoded, sym_key, None).unwrap();

        println!("\n{result:?}");

        result
    }

    #[allow(clippy::type_complexity)]
    fn calculate(
        self_private_key: &str,
        other_public_key: &str,
    ) -> (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        std::string::String,
    ) {
        let self_private_key =
            hex::decode_to_array::<_, 32>(self_private_key).unwrap();
        let kp = Keypair::from_seed(self_private_key);
        let self_public_key = kp.public_key;

        println!(
            "\nself private key: {self_private_key:?}",
            self_private_key = hex::encode(self_private_key)
        );
        println!(
            "self public key : {self_public_key:?}",
            self_public_key = hex::encode(self_public_key)
        );

        let other_public_key =
            hex::decode_to_array::<_, 32>(other_public_key).unwrap();

        println!(
            "other public key: {other_public_key}",
            other_public_key = hex::encode(other_public_key)
        );
        let response_topic = sha256(other_public_key);
        println!("announcing topic: {}", hex::encode(response_topic));

        let sym_key = derive_sym_key(self_private_key, other_public_key);
        println!("sym_key: {}", hex::encode(sym_key));

        let new_topic = hex::encode(Sha256::digest(sym_key));
        println!("new topic: {new_topic}");

        #[allow(clippy::needless_return)]
        return (
            self_private_key,
            self_public_key,
            other_public_key,
            response_topic,
            sym_key,
            new_topic,
        );
    }

    #[test]
    fn decode_session_request_eth_transaction() {
        let request_original = json!({"id":"1745231798527575","jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"eth_sendTransaction","params":[{"chainId":"0x1","gas":"0x3635b","maxFeePerGas":"0x9389ef24","maxPriorityFeePerGas":"0x77359400","value":"0xde0b6b3a7640000","from":"0x0000000000000000000000000000000000000123","to":"0x66a9893cc07d91d95644aedd05d03f95e1dba8af","data":"0x3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000680626bd00000000000000000000000000000000000000000000000000000000000000040b000604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc20001f4dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c00000000000000000000000000000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000000000012300000000000000000000000000000000000000000000000000000000607363570c"}],"expiryTimestamp":1745232098},"chainId":"eip155:1"}});

        let request = WcMessage::from_value(request_original.clone()).unwrap();

        assert_eq!(
            serde_json::to_value(request.clone()).unwrap(),
            request_original,
            "serialization inconsistency",
        );

        assert_eq!(request.method, Some(WcMethod::SessionRequest));
        assert_eq!(request.jsonrpc, "2.0");

        let params = request.params.unwrap();
        let params = params.as_session_request().unwrap();
        assert_eq!(
            params.request.method,
            SessionRequestMethod::EthSendTransaction
        );

        let data = "0x3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000680626bd00000000000000000000000000000000000000000000000000000000000000040b000604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc20001f4dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c00000000000000000000000000000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000000000012300000000000000000000000000000000000000000000000000000000607363570c".parse().unwrap();
        assert_eq!(
            params.request.params,
            SessionRequestData::EthSendTransaction([Box::new(
                TransactionRequest {
                    chain_id: Some(1),
                    gas: Some(0x3635b),
                    max_fee_per_gas: Some(0x9389ef24),
                    max_priority_fee_per_gas: Some(0x77359400),
                    value: Some(
                        U256::from_str_radix("de0b6b3a7640000", 16).unwrap()
                    ),
                    from: Some(
                        "0x0000000000000000000000000000000000000123"
                            .parse()
                            .unwrap()
                    ),
                    to: Some(TxKind::Call(
                        "0x66a9893cc07d91d95644aedd05d03f95e1dba8af"
                            .parse()
                            .unwrap()
                    )),
                    input: TransactionInput {
                        input: None,
                        data: Some(data)
                    },
                    ..Default::default()
                }
            )])
        );
    }

    #[test]
    fn decode_session_request_personal_sign() {
        let request_original = json!({"id":"1749782874445682","jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"personal_sign","params":["0x6170706b69742d6c61622e72656f776e2e636f6d2077616e747320796f7520746f207369676e20696e207769746820796f757220457468657265756d206163636f756e743a0a3078303030303030303030303030303030303030303030303030303030303030303030303030303132330a0a506c65617365207369676e207769746820796f7572206163636f756e740a0a5552493a2068747470733a2f2f6170706b69742d6c61622e72656f776e2e636f6d0a56657273696f6e3a20310a436861696e2049443a203133370a4e6f6e63653a20323535643664363463323861373366313639666536616466383836656133306561306463633838656363396630356232393938356332343061393866666630610a4973737565642041743a20323032352d30362d31335430323a34373a35342e3135365a", "0x0000000000000000000000000000000000000123"],"expiryTimestamp":1749783174},"chainId":"eip155:1"}});

        let request = WcMessage::from_value(request_original.clone()).unwrap();

        assert_eq!(
            serde_json::to_value(request.clone()).unwrap(),
            request_original,
            "serialization inconsistency",
        );

        assert_eq!(request.method, Some(WcMethod::SessionRequest));
        assert_eq!(request.jsonrpc, "2.0");
        let params = request.params.unwrap();
        let params = params.as_session_request().unwrap();
        assert_eq!(params.request.method, SessionRequestMethod::PersonalSign);
        assert_eq!(
            params.request.params,
            SessionRequestData::PersonalSign([
                "0x6170706b69742d6c61622e72656f776e2e636f6d2077616e747320796f7520746f207369676e20696e207769746820796f757220457468657265756d206163636f756e743a0a3078303030303030303030303030303030303030303030303030303030303030303030303030303132330a0a506c65617365207369676e207769746820796f7572206163636f756e740a0a5552493a2068747470733a2f2f6170706b69742d6c61622e72656f776e2e636f6d0a56657273696f6e3a20310a436861696e2049443a203133370a4e6f6e63653a20323535643664363463323861373366313639666536616466383836656133306561306463633838656363396630356232393938356332343061393866666630610a4973737565642041743a20323032352d30362d31335430323a34373a35342e3135365a".to_string(),
                "0x0000000000000000000000000000000000000123".to_string()
            ])
        );
    }
}
