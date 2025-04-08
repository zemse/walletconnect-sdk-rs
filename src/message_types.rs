use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::cacao::Cacao;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionProposeParams {
    #[serde(rename = "requiredNamespaces")]
    pub required_namespaces: HashMap<String, Namespace>,
    #[serde(rename = "optionalNamespaces")]
    pub optional_namespaces: HashMap<String, Namespace>,
    pub relays: Vec<Relay>,
    #[serde(rename = "pairingTopic")]
    pub pairing_topic: String,
    pub proposer: Entity,
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
pub struct SessionAuthenticateParams {
    #[serde(rename = "authPayload")]
    pub auth_payload: AuthPayload,
    pub requester: Entity,
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
pub struct Entity {
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
    pub responder: Entity,
}
