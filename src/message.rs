/// Message
///
/// Logic to encrypt and decrypt raw payload, which can be sent over the IRN.
///
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Key, Nonce};
use alloy::hex;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use chacha20poly1305::ChaCha20Poly1305;
use log::debug;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;
use crate::types::Id;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageError {
    pub message: Option<String>,
    pub code: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Message<M = String, T = Value> {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<M>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<MessageError>,
    pub id: Id,
}

pub const IV_LENGTH: usize = 12;
pub const KEY_LENGTH: usize = 32;
pub const TYPE_LENGTH: usize = 1;
pub const TYPE_0: u8 = 0;
pub const TYPE_1: u8 = 1;
pub const TYPE_2: u8 = 2;

impl<T: Serialize + DeserializeOwned> Message<String, T> {
    pub fn result(result: T, id: Id) -> Message<String, T> {
        Message {
            jsonrpc: "2.0".to_string(),
            method: None,
            params: None,
            result: Some(result),
            error: None,
            id,
        }
    }
}

impl<
    M: PartialEq + Serialize + DeserializeOwned,
    T: Serialize + DeserializeOwned,
> Message<M, T>
{
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/7bcb116d17a76a9b61cd5b90ebd2087411f48f53/packages/utils/src/crypto.ts#L86
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
        debug!("encrypting message -> {message}");
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
}

impl<M, P> Message<M, P>
where
    M: PartialEq,
{
    pub fn is(&self, method: M) -> bool {
        self.method == Some(method)
    }

    pub fn create_success_response<R>(
        &self,
        result_data: R,
    ) -> Message<String, R> {
        Message {
            jsonrpc: self.jsonrpc.clone(),
            method: None,
            params: None,
            result: Some(result_data),
            error: None,
            id: self.id.clone(),
        }
    }

    pub fn create_error_response(
        &self,
        message: String,
        code: i64,
    ) -> Message<M, Value> {
        Message {
            jsonrpc: self.jsonrpc.clone(),
            method: None,
            params: None,
            result: None,
            error: Some(MessageError {
                message: Some(message),
                code: Some(code as usize),
            }),
            id: self.id.clone(),
        }
    }
}

impl Message<String, Value> {
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/7bcb116d17a76a9b61cd5b90ebd2087411f48f53/packages/utils/src/crypto.ts#L105
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

        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&encoding_params.iv);
        let decrypted =
            cipher.decrypt(nonce, encoding_params.sealed.as_ref())?;
        let str = String::from_utf8(decrypted)?;
        debug!("decrypted message -> {str}");
        Ok(serde_json::from_str::<Self>(&str).map_err(|e| {
            format!("Failed to deserialize JSON-RPC request: {e}\n{str}")
        })?)
    }

    pub fn try_decode<M, P>(&self) -> Result<Message<M, P>>
    where
        M: DeserializeOwned + Clone,
        P: DeserializeOwned,
    {
        let method = self
            .method
            .as_ref()
            .map(|m| serde_plain::from_str::<M>(m.as_str()))
            .transpose()?;
        let params = self
            .params
            .as_ref()
            .map(|p| serde_json::from_value::<P>(p.clone()))
            .transpose()?;
        let result = self
            .result
            .as_ref()
            .map(|r| serde_json::from_value::<P>(r.clone()))
            .transpose()?;

        Ok(Message {
            jsonrpc: self.jsonrpc.clone(),
            method,
            params,
            result,
            error: self.error.clone(),
            id: self.id.clone(),
        })
    }

    pub fn decode_result<R>(&self) -> Result<Message<String, R>>
    where
        R: DeserializeOwned,
    {
        let result = self
            .result
            .as_ref()
            .map(|r| serde_json::from_value::<R>(r.clone()))
            .transpose()?;
        Ok(Message {
            jsonrpc: self.jsonrpc.clone(),
            method: None,
            params: None,
            result,
            error: None,
            id: self.id.clone(),
        })
    }

    pub fn into_value(self) -> Result<Value> {
        Ok(serde_json::to_value(self)?)
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
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/b39a5d4e62f5517ef47a70b5b93f27585b7132e8/packages/core/src/controllers/crypto.ts#L111
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

    // https://github.com/WalletConnect/walletconnect-monorepo/blob/b39a5d4e62f5517ef47a70b5b93f27585b7132e8/packages/core/src/controllers/crypto.ts#L131
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

#[cfg(test)]
mod tests {
    use serde_json::{Number, json};

    use super::*;
    use crate::message::TYPE_1;
    use crate::{relay_auth::Keypair, types::Id, utils::derive_sym_key};

    #[test]
    fn test_encrypt_decrypt() {
        let key = Keypair::generate();
        let sym_key = derive_sym_key(key.seed, key.public_key);

        let message = Message::result(
            json!({
                "cacao": {
                    "header": {
                        "h": "caip122"
                    },
                    "payload": {
                        "iss": {
                            "account_address": hex::encode(key.public_key),
                            "chain_id": "eip155"
                        },
                        "domain": "https://example.com",
                        "uri": "wc:1234@2?relay-protocol=irn",
                        "version": "1.0.0",
                        "statement": "Please sign this message to authenticate",
                        "nonce": hex::encode(key.seed),
                    },
                    "signature": {
                        "t": "eip191",
                    }
                }
            }),
            Id::Number(Number::from(12345)),
        );

        let encrypted_message = message
            .encrypt(
                sym_key,
                Some(TYPE_1),
                Some(hex::encode(key.public_key)),
                None,
            )
            .unwrap();

        let decrypted_message =
            Message::decrypt(&encrypted_message, sym_key, None).unwrap();

        assert_eq!(message.jsonrpc, decrypted_message.jsonrpc);
    }
}
