use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A basic JSON-RPC 2.0 request.
#[derive(Serialize)]
pub struct JsonRpcRequest<ParamType = Value> {
    pub jsonrpc: &'static str,
    pub method: JsonRpcMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ParamType>, // Could be array or object
    pub id: String,
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

#[derive(Debug, Serialize, Deserialize)]
pub enum JsonRpcMethod {
    #[serde(rename = "irn_publish")]
    IrnPublish,

    #[serde(rename = "irn_subscribe")]
    IrnSubscribe,

    #[serde(rename = "irn_fetchMessages")]
    IrnFetchMessages,

    #[serde(rename = "wc_sessionAuthenticate")]
    SessionAuthenticate,
}

type SessionAuthenticateRequest = JsonRpcRequest<SessionAuthenticateParams>;

#[derive(Debug, Deserialize)]
pub struct SessionAuthenticateParams {
    pub authPayload: AuthPayload,
    pub requester: Requester,
    pub expiryTimestamp: u64,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct Requester {
    pub publicKey: String,
    pub metadata: Metadata,
}

#[derive(Debug, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub description: String,
    pub url: String,
    pub icons: Vec<String>,
}
