/// Types
///
/// All the RPC types and logic to encode and decode. There are some tests with
/// actual payloads to ensure that the logic works.
///
use std::collections::HashMap;
use std::fmt::{self, Display};

use alloy::primitives::Address;
use alloy::rpc::types::TransactionRequest;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Number;
use serde_json::Value;

use crate::cacao::Cacao;
use crate::error::Result;

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
    pub fn to_u128(&self) -> Result<u128> {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
#[serde(try_from = "u16", into = "u16")]
pub enum IrnTag {
    // https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#methods
    UnsupportedMethod = 0,

    PairingDelete = 1000,
    PairingDeleteResponse = 1001,

    PairingPing = 1002,
    PairingPingResponse = 1003,

    PairingExtend = 1004,
    PairingExtendResponse = 1005,

    // https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#methods
    SessionPropose = 1100,
    SessionProposeApproveResponse = 1101,
    SessionProposeRejectResponse = 1120,
    SessionProposeAutoRejectResponse = 1121,

    SessionSettle = 1102,
    SessionSettleResponse = 1103,

    SessionUpdate = 1104,
    SessionUpdateResponse = 1105,

    SessionExtend = 1106,
    SessionExtendResponse = 1107,

    SessionRequest = 1108,
    SessionRequestResponse = 1109,

    SessionEvent = 1110,
    SessionEventResponse = 1111,

    SessionDelete = 1112,
    SessionDeleteResponse = 1113,

    SessionPing = 1114,
    SessionPingResponse = 1115,

    SessionAuthenticate = 1116,
    SessionAuthenticateApproveResponse = 1117,
    SessionAuthenticateRejectResponse = 1118,
    SessionAuthenticateAutoRejectResponse = 1119,
}

impl From<IrnTag> for u16 {
    fn from(tag: IrnTag) -> Self {
        tag as u16
    }
}

impl TryFrom<u16> for IrnTag {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IrnTag::UnsupportedMethod),

            1000 => Ok(IrnTag::PairingDelete),
            1001 => Ok(IrnTag::PairingDeleteResponse),

            1002 => Ok(IrnTag::PairingPing),
            1003 => Ok(IrnTag::PairingPingResponse),

            1004 => Ok(IrnTag::PairingExtend),
            1005 => Ok(IrnTag::PairingExtendResponse),

            1100 => Ok(IrnTag::SessionPropose),
            1101 => Ok(IrnTag::SessionProposeApproveResponse),
            1120 => Ok(IrnTag::SessionProposeRejectResponse),
            1121 => Ok(IrnTag::SessionProposeAutoRejectResponse),

            1102 => Ok(IrnTag::SessionSettle),
            1103 => Ok(IrnTag::SessionSettleResponse),

            1104 => Ok(IrnTag::SessionUpdate),
            1105 => Ok(IrnTag::SessionUpdateResponse),

            1106 => Ok(IrnTag::SessionExtend),
            1107 => Ok(IrnTag::SessionExtendResponse),

            1108 => Ok(IrnTag::SessionRequest),
            1109 => Ok(IrnTag::SessionRequestResponse),

            1110 => Ok(IrnTag::SessionEvent),
            1111 => Ok(IrnTag::SessionEventResponse),

            1112 => Ok(IrnTag::SessionDelete),
            1113 => Ok(IrnTag::SessionDeleteResponse),

            1114 => Ok(IrnTag::SessionPing),
            1115 => Ok(IrnTag::SessionPingResponse),

            1116 => Ok(IrnTag::SessionAuthenticate),
            1117 => Ok(IrnTag::SessionAuthenticateApproveResponse),

            1118 => Ok(IrnTag::SessionAuthenticateRejectResponse),
            1119 => Ok(IrnTag::SessionAuthenticateAutoRejectResponse),

            _ => Err(format!("{:?}", crate::Error::InvalidIrnTag(value))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum JsonRpcMethod {
    #[serde(rename = "irn_publish")]
    IrnPublish,

    #[serde(rename = "irn_subscribe")]
    IrnSubscribe,

    #[serde(rename = "irn_subscription")]
    IrnSubscription,

    #[serde(rename = "irn_fetchMessages")]
    IrnFetchMessages,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct IrnPublishParams {
    pub topic: String,
    pub message: String,
    pub ttl: u64,
    pub prompt: bool,
    pub tag: IrnTag,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct IrnSubscriptionParams {
    pub id: Id,
    pub data: IrnSubscriptionData,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct IrnSubscriptionData {
    pub topic: String,
    pub message: String,
    #[serde(rename = "publishedAt")]
    pub published_at: Id,
    pub tag: IrnTag,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IrnFetchMessageResult {
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionProposeResponse {
    pub relay: Relay,
    #[serde(rename = "responderPublicKey")]
    pub responder_public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Namespace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<String>>,
    pub chains: Vec<String>,
    pub events: Vec<String>,
    pub methods: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Relay {
    pub protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionAuthenticateParams {
    #[serde(rename = "authPayload")]
    pub auth_payload: AuthPayload,
    pub requester: Participant,
    #[serde(rename = "expiryTimestamp")]
    pub expiry_timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Participant {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub metadata: Metadata,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Metadata {
    pub name: String,
    pub description: String,
    pub url: String,
    pub icons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionAuthenticateResponse {
    pub cacaos: Vec<Cacao>,
    pub responder: Participant,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionSettleParams {
    pub controller: Participant,
    pub expiry: u64,
    pub namespaces: HashMap<String, Namespace>,
    pub relay: Relay,
    #[serde(rename = "sessionProperties")]
    pub session_properties: Option<SessionSettleProperties>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionSettleProperties {
    pub capabilities: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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

#[derive(Clone, Debug, Serialize, PartialEq)]
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
    EthSendTransaction(Box<TransactionRequest>),
    PersonalSign { message: String, account: Address },
}

impl Serialize for SessionRequestData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SessionRequestData::EthSendTransaction(tx) => {
                let mut seq = serializer.serialize_seq(Some(1))?;
                seq.serialize_element(tx)?;
                seq.end()
            }
            SessionRequestData::PersonalSign { message, account } => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&message)?;
                seq.serialize_element(&account)?;
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
                        let tx: [Box<TransactionRequest>; 1] =
                            serde_json::from_value(raw_params)
                                .map_err(serde::de::Error::custom)?;
                        SessionRequestData::EthSendTransaction(tx[0].clone())
                    }
                    SessionRequestMethod::PersonalSign => {
                        let (message, account) =
                            serde_json::from_value(raw_params)
                                .map_err(serde::de::Error::custom)?;
                        SessionRequestData::PersonalSign { message, account }
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
    use super::*;

    #[test]
    fn test_decode_id() {
        let result = serde_json::from_str::<Id>("\"1234\"").unwrap();
        println!("result {result:?}");

        let result = serde_json::from_str::<Id>("1234").unwrap();
        println!("result {result:?}");
    }

    #[test]
    fn test_decode_fetch_messages() {
        let resp = "{\"id\":1744205603590064025,\"jsonrpc\":\"2.0\",\"result\":{\"hasMore\":false,\"messages\":[{\"attestation\":\"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDQyMDkxOTAsImlkIjoiZWRhYjVmMjQyNTNmZGUyYTVkYzI4NTcyZmRkNGE4NTViYTJhZjRkOGM2ZmQxMjQxN2NlMWUwNDMzODY5MjcwMCIsIm9yaWdpbiI6Imh0dHBzOi8vYXBwa2l0LWxhYi5yZW93bi5jb20iLCJpc1NjYW0iOmZhbHNlLCJpc1ZlcmlmaWVkIjp0cnVlfQ.zeNQehxpiQ0JqVBHTlkxgDwValU2NhGEsUMT5irJgiM92d1M361ifoxRIJfh1_EF2dVBqyr6zLV4cbp3g4jLSQ\",\"message\":\"ALW+zRyGiw5kj8hlp/Xv1jQ3vGFNcFNsfp4PyyVPbkcbMohD0sGhUejguhlNRA0fXnCfzQ9/hdI5xcmy1SubXts/Db6Kt1cStgOgIXSGReS3jP2AgldAv5WR77dfXDytJzYmg6af9lbKMYCuI+4qWyuaswKvsO4cyeRaT1jVsITT6uy+z2A50H0uBuNcnE4YGKia8yxlZYfLj0dbJ1Q/zX8d9DF/YLBQzUhLOD6P9ajCDUTNs7S24lDtB1xglkKHyxG4/cSktAGmvu7QWcYzkzeLmGcqxK7TxO3+N8baOMf4bq0n2tJjFCQPrs31d/mrQc1e7d7GwmndZjvbWRL+ab+B2INkfs6cEkLTtwu10TXGAScQCrrVtBR/apIiGFpg27YD+KbbM7hCmFoOIxJc1DXH8psf+MjDhwLqQRVxMe26DYbL50jwqQmDu71qvi4DHZgRyAq/wWSIHe+BGqfZKzK45zK7cz72WsZhuEjOqmDK0gZePbHzWaVvI9uApzpVXGVPOwp4eeZOBYbED+Oucq6CovHRjVIw0CZitjQH14yv0XNIFZ1U1/byB/jWgvQwW42O3v9M3cmljeXTeuEaao+bngEv6zN7CDpGMbiQ4gDTxihtpTv7Mgl+9LpyhrtY79QJ6XMx9wkWuxkbsIrQalFgJuhcJEMfULjLSe49gzIC91gSJ5rVKd1ej82yIsDHUn6roKFb0McQXJNa5vb+Wh1cfn46LeX+m6XBRFXGKqr6xXs4dujZg2TeDA9XyNT4B99hXGQl4BkNmAv6BYjH6pB63Fr7f+10iyf9SrfXlYVR9mLTqsVVd53sVuKWW6esKhgPHc2+Fd30+LRMTmhG/IebxRaRBpBvjjh8lkVFowQn37TruR4sVX0NB/UsqX2U9Ns9A1LLMVI3+QycUmU/aDPR3fxmn1OF2abskgjvWLr3lqVVZGPf3nFgxMfU4u/+xsztwuw2Pc5lFos06z+dY0sZaRpB4b59Qb79KT/1CFodRjfGDcM6eRbaj2XcMfn46HkczxKl494aiu6KwLIzx5ChpCt9EMyO6SV/dhEhvL/cwcWAZsUmft5yPSa24J5bCtTetcL7fGMrjyyJYsQBFMgdQJC7YtlUcrPm5NIhJu8DYjef86sr8m38t2vixFGifC55RQhlKdG12cUrtY9TVQMJrEBdLsmuBbSFVa9oSzbh4yNvPRciLkaUAo5A5QfBlfZmbLZutE9v9IsjmIqZ78xys6Q93Hx5keDk3xdM1/1and9v5kjVMvmpQX1vqtlebIJY5sqM3BZVt9Tyxg6eSl+fKI+Jug+K19T9b1dGsfqByIf/js9pEAATxbV+e8I2CAtxNlipfHJleamZY1mVe74sokGMbM/Tz7MYYXp8MePKPXH+Te6yFMtvHfHdPi1Qmte+w9VLEin2PuLWt/DNX277YrOvhBYuRx30L9DWAXSIcN3qnxI6GpL45dX2rf8pyMdO1vdsPQG/Sr1EnU8jTi+ul182Zyen04kOhtqtuoYV2Sh73k2/6AVRWPtFqhGUI0cUBrdVnE1PAFgRaYMDmTTMYFnmz/PXptuP/T14x5F0wdoFNOUw88opmRrIsqQgtRYIwMa5303aHhB7H+aY7Hg3/y2RNOxklXUMikwI/8bHw0l2jVS69egUe1JMVk51sG8IxG45lf/q7zUEm5BcJ6QJ21OTqZqMJHPDEO0r0okc1C17/rylIh9c0+2zUdqJa7N0sV9Qd9oGNciKswoHLeNhHdQQrEyEFjmQr5TV9MM8HaWVIrRf5SGgsAmSd+GHUyz1sNt8DzlOQja2qKEZIgNZYBE6f667dX5WTmNcQ9zZje45uVKRkO8YGkBT0m1b4iD+hgHuYQdkLQMHvfsDiZo=\",\"publishedAt\":1744205591202,\"tag\":1100,\"topic\":\"74818ca920a949b9adad9ed0c5bdfa1f5e6ea5e5b1a18e71a7ba1ac9923295e5\"},{\"attestation\":\"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDQyMDkxOTAsImlkIjoiZGU0MjhhYjU0NzhiZWJkOGU5M2M3OGFhNTVjYTNkYTEwZWViYzE0MTY4MTgwYWJkNTYxYmRhZmVmYjMxMmZkOSIsIm9yaWdpbiI6Imh0dHBzOi8vYXBwa2l0LWxhYi5yZW93bi5jb20iLCJpc1NjYW0iOmZhbHNlLCJpc1ZlcmlmaWVkIjp0cnVlfQ.EJMNd8iO0Uvr1owRbomGuC3One2K6pfKZa3nvIl4MpI00EkHL86Tdo63MJXKtGK65ixFZqhx-L__M8kXbhFoJA\",\"message\":\"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\",\"publishedAt\":1744205591323,\"tag\":1116,\"topic\":\"74818ca920a949b9adad9ed0c5bdfa1f5e6ea5e5b1a18e71a7ba1ac9923295e5\"}]}}";
        let result = serde_json::from_str::<
            JsonRpcResponse<IrnFetchMessageResult>,
        >(resp)
        .unwrap();
        println!("result {result:?}");
    }
}
