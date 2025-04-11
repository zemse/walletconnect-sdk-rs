use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::error::Result;

use crate::{cacao::Cacao, rpc_types::Id};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Key, Nonce};
use alloy::hex;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use serde::de::DeserializeOwned;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message<T = Value> {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<MessageMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    pub id: Id,
}

pub enum MessageEm {
    SessionPropose { jsonrpc: String, method: String },
}

pub const IV_LENGTH: usize = 12;
pub const KEY_LENGTH: usize = 32;
pub const TYPE_LENGTH: usize = 1;
pub const TYPE_0: u8 = 0;
pub const TYPE_1: u8 = 1;
pub const TYPE_2: u8 = 2;

impl<T: Serialize + DeserializeOwned> Message<T> {
    pub fn encrypt(
        &self,
        sym_key: [u8; 32],
        type_byte: Option<u8>,
        sender_public_key: Option<String>,
        encoding: Option<EncodingType>,
    ) -> Result<String> {
        let type_byte = type_byte.unwrap_or(TYPE_0);
        if type_byte == TYPE_1 && sender_public_key.is_none() {
            return Err("Missing sender public key for type 1 envelope".into());
        }

        let mut iv = vec![0u8; IV_LENGTH];
        OsRng.fill_bytes(&mut iv);

        let key = Key::<ChaCha20Poly1305>::from_slice(&sym_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&iv);

        let message = serde_json::to_string(self)?;
        println!("encrypting: {message:?}");
        let sealed = cipher
            .encrypt(nonce, message.as_bytes())
            .expect("encryption failed");

        Ok(EncryptedEnvelope {
            type_byte,
            sealed,
            iv,
            sender_public_key: sender_public_key.as_ref().map(|hex| {
                hex::decode(hex).expect("invalid sender_public_key")
            }),
        }
        .serialize(encoding.clone().unwrap_or(EncodingType::Base64)))
    }

    pub fn create_success_response<R>(&self, result_data: R) -> Message<R> {
        Message {
            jsonrpc: self.jsonrpc.clone(),
            method: None,
            params: None,
            result: Some(result_data),
            id: self.id.clone(),
        }
    }

    pub fn create_error_response(
        &self,
        _code: i64,
        _message: String,
        _data: Option<Value>,
    ) -> Message {
        todo!()
    }

    pub fn is(&self, method: MessageMethod) -> bool {
        self.method == Some(method)
    }
}

impl Message {
    pub fn decrypt(
        cipher_text: &str,
        sym_key: [u8; 32],
        encoding: Option<EncodingType>,
    ) -> Result<Self> {
        let key = Key::<ChaCha20Poly1305>::from_slice(&sym_key);

        let encoding_params = EncryptedEnvelope::deserialize(
            cipher_text,
            encoding.clone().unwrap_or(EncodingType::Base64),
        );
        println!("decoding envelope: {encoding_params:?}");

        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&encoding_params.iv);
        let decrypted =
            cipher.decrypt(nonce, encoding_params.sealed.as_ref())?;
        let str = String::from_utf8(decrypted)?;
        Ok(serde_json::from_str::<Self>(&str).inspect_err(|e| {
            println!("Failed to deserialize JSON-RPC request: {e}\n{str}");
        })?)
    }

    pub fn try_decode<ParamsType>(&self) -> Result<Message<ParamsType>>
    where
        ParamsType: DeserializeOwned,
    {
        let params = self
            .params
            .as_ref()
            .map(|p| serde_json::from_value::<ParamsType>(p.clone()))
            .transpose()?;
        Ok(Message {
            jsonrpc: self.jsonrpc.clone(),
            method: self.method.clone(),
            params,
            result: None,
            id: self.id.clone(),
        })
    }

    // pub fn into_json_param(self) -> Result<MessageParam> {
    //     match self.method {
    //         Some(MessageMethod::SessionPropose) => {
    //             Ok(MessageParam::SessionPropose(serde_json::from_value::<
    //                 Message<SessionProposeParams>,
    //             >(
    //                 self.into_value()?
    //             )?))
    //         }
    //         Some(MessageMethod::SessionAuthenticate) => {
    //             Ok(MessageParam::SessionAuthenticate(serde_json::from_value::<
    //                 Message<SessionAuthenticateParams>,
    //             >(
    //                 self.into_value()?
    //             )?))
    //         }
    //         Some(MessageMethod::SessionSettle) => {
    //             Ok(MessageParam::SessionSettle(serde_json::from_value::<
    //                 Message<SessionSettleParams>,
    //             >(
    //                 self.into_value()?
    //             )?))
    //         }

    //         None => {
    //             // Method is None, it means message is a result
    //             todo!()
    //         }
    //     }
    // }

    pub fn into_value(self) -> Result<Value> {
        Ok(serde_json::to_value(self)?)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MessageMethod {
    #[serde(rename = "wc_sessionPropose")]
    SessionPropose,

    #[serde(rename = "wc_sessionAuthenticate")]
    SessionAuthenticate,

    #[serde(rename = "wc_sessionSettle")]
    SessionSettle,
}

#[derive(Clone, Debug)]
pub enum MessageParam {
    SessionPropose(SessionProposeParams),
    SessionAuthenticate(SessionAuthenticateParams),
    SessionSettle(SessionSettleParams),
}

impl MessageParam {
    pub fn method(&self) -> Option<MessageMethod> {
        match self {
            MessageParam::SessionPropose(_) => {
                Some(MessageMethod::SessionPropose)
            }
            MessageParam::SessionSettle(_) => {
                Some(MessageMethod::SessionSettle)
            }
            MessageParam::SessionAuthenticate(_) => {
                Some(MessageMethod::SessionAuthenticate)
            }
        }
    }

    pub fn params(&self) -> Option<Value> {
        match self {
            MessageParam::SessionPropose(params) => {
                Some(serde_json::to_value(params).unwrap())
            }
            MessageParam::SessionSettle(params) => {
                Some(serde_json::to_value(params).unwrap())
            }
            MessageParam::SessionAuthenticate(params) => {
                Some(serde_json::to_value(params).unwrap())
            }
        }
    }
}

#[derive(Debug)]
pub struct EncryptedEnvelope {
    pub type_byte: u8,
    pub sealed: Vec<u8>,
    pub iv: Vec<u8>,
    // only for type 1 message - helps dapp to calculate diffie_sym_key
    pub sender_public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum EncodingType {
    Base64,
    Base64Url,
}

impl EncryptedEnvelope {
    pub fn serialize(&self, encoding: EncodingType) -> String {
        let mut bytes = vec![self.type_byte];

        match self.type_byte {
            TYPE_2 => {
                bytes.extend_from_slice(&self.sealed);
            }
            TYPE_1 => {
                let sender = self
                    .sender_public_key
                    .as_ref()
                    .expect("Missing sender public key for type 1 envelope");
                bytes.extend_from_slice(sender);
                bytes.extend_from_slice(&self.iv);
                bytes.extend_from_slice(&self.sealed);
            }
            _ => {
                // TYPE_0
                bytes.extend_from_slice(&self.iv);
                bytes.extend_from_slice(&self.sealed);
            }
        }

        match encoding {
            EncodingType::Base64 => Base64::encode_string(&bytes),
            EncodingType::Base64Url => Base64UrlUnpadded::encode_string(&bytes),
        }
    }

    pub fn deserialize(encoded: &str, encoding: EncodingType) -> Self {
        let bytes = match encoding {
            EncodingType::Base64 => {
                Base64::decode_vec(encoded).expect("invalid base64")
            }
            EncodingType::Base64Url => Base64UrlUnpadded::decode_vec(encoded)
                .expect("invalid base64url"),
        };

        let type_byte = bytes[0];
        let slice1 = TYPE_LENGTH;

        match type_byte {
            TYPE_1 => {
                let slice2 = slice1 + KEY_LENGTH;
                let slice3 = slice2 + IV_LENGTH;
                let sender_public_key = bytes[slice1..slice2].to_vec();
                let iv = bytes[slice2..slice3].to_vec();
                let sealed = bytes[slice3..].to_vec();
                EncryptedEnvelope {
                    type_byte,
                    sealed,
                    iv,
                    sender_public_key: Some(sender_public_key),
                }
            }
            TYPE_2 => {
                let sealed = bytes[slice1..].to_vec();
                let mut iv = vec![0u8; IV_LENGTH];
                OsRng.fill_bytes(&mut iv);
                EncryptedEnvelope {
                    type_byte,
                    sealed,
                    iv,
                    sender_public_key: None,
                }
            }
            _ => {
                // TYPE_0 default
                let slice2 = slice1 + IV_LENGTH;
                let iv = bytes[slice1..slice2].to_vec();
                let sealed = bytes[slice2..].to_vec();
                EncryptedEnvelope {
                    type_byte,
                    sealed,
                    iv,
                    sender_public_key: None,
                }
            }
        }
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
