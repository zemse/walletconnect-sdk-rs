use crate::connection::Connection;
use crate::error::Result;
use crate::message_types::{SessionAuthenticateParams, SessionProposeParams};
use crate::rpc_types::{FetchMessageResult, Id, JsonRpcMethod, JsonRpcParam};
use crate::utils::UriParameters;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Key, Nonce};
use alloy::hex;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::str;

pub struct Pairing<'a> {
    params: UriParameters,
    connection: &'a Connection,
    proposal_request: Option<SessionProposeParams>,
    authenticate_request: Option<SessionAuthenticateParams>,
    // approve_done: bool,
}

impl<'a> Pairing<'a> {
    pub fn new(uri: &str, connection: &'a Connection) -> Self {
        let params = UriParameters::from(uri.to_string());
        Self {
            params,
            connection,
            proposal_request: None,
            authenticate_request: None,
            // approve_done: false,
        }
    }

    fn sym_key(&self) -> [u8; 32] {
        self.params.sym_key
    }

    pub fn proposal_request(&self) -> Option<&SessionProposeParams> {
        self.proposal_request.as_ref()
    }

    pub fn authenticate_request(&self) -> Option<&SessionAuthenticateParams> {
        self.authenticate_request.as_ref()
    }

    pub(crate) fn set_proposal_and_authenticate_request(
        &mut self,
        proposal_request: SessionProposeParams,
        authenticate_request: SessionAuthenticateParams,
    ) {
        self.proposal_request = Some(proposal_request);
        self.authenticate_request = Some(authenticate_request);
    }

    pub fn approve(&self) {}

    pub fn irn_subscribe(&self) -> Result<String> {
        self.connection.request::<String>(
            JsonRpcMethod::IrnSubscribe,
            Some(json!({
                "topic": self.params.topic
            })),
        )
    }

    pub fn irn_fetch_messages(&self) -> Result<FetchMessageResult> {
        self.connection.request::<FetchMessageResult>(
            JsonRpcMethod::IrnFetchMessages,
            Some(json!({
                "topic": self.params.topic
            })),
        )
    }

    pub fn irn_fetch_messages_and_decrypt(&self) -> Result<Vec<JsonRpcParam>> {
        self.irn_fetch_messages()?
            .messages
            .into_iter()
            .map(|m| -> Result<JsonRpcParam> {
                let decrypted_message = Message::decrypt(
                    &m.message,
                    self.sym_key(),
                    Some(EncodingType::Base64),
                )?;

                match decrypted_message.method {
                    Some(JsonRpcMethod::SessionPropose) => {
                        Ok(JsonRpcParam::SessionPropose(
                            serde_json::from_value::<SessionProposeParams>(
                                decrypted_message
                                    .params
                                    .ok_or("params not present")?,
                            )?,
                        ))
                    }
                    Some(JsonRpcMethod::SessionAuthenticate) => {
                        Ok(JsonRpcParam::SessionAuthenticate(
                            serde_json::from_value::<SessionAuthenticateParams>(
                                decrypted_message
                                    .params
                                    .ok_or("params not present")?,
                            )?,
                        ))
                    }
                    Some(
                        JsonRpcMethod::IrnPublish
                        | JsonRpcMethod::IrnSubscribe
                        | JsonRpcMethod::IrnFetchMessages,
                    ) => Err("unexpected".into()),
                    None => {
                        // Method is None, it means message is a result
                        todo!()
                    }
                }
            })
            .collect::<Result<Vec<JsonRpcParam>>>()
    }
}

const IV_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;
const TYPE_LENGTH: usize = 1;
const TYPE_0: u8 = 0;
const TYPE_1: u8 = 1;
const TYPE_2: u8 = 2;

#[derive(Debug)]
pub struct EncryptedEnvelope {
    pub type_byte: u8,
    pub sealed: Vec<u8>,
    pub iv: Vec<u8>,
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
pub struct Message<T = Value> {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<JsonRpcMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    pub id: Id,
}

pub enum MessageEm {
    SessionPropose { jsonrpc: String, method: String },
}

impl Message {
    pub fn encrypt(
        &self,
        sym_key: String,
        type_byte: Option<u8>,
        iv: Option<String>,
        sender_public_key: Option<String>,
        encoding: Option<EncodingType>,
    ) -> Result<String> {
        let type_byte = type_byte.unwrap_or(TYPE_0);
        if type_byte == TYPE_1 && sender_public_key.is_none() {
            return Err("Missing sender public key for type 1 envelope".into());
        }

        let iv = match iv {
            Some(iv_hex) => hex::decode(iv_hex)?,
            None => {
                let mut iv = vec![0u8; IV_LENGTH];
                OsRng.fill_bytes(&mut iv);
                iv
            }
        };

        let key = hex::decode(&sym_key).expect("invalid sym_key hex");
        let key = Key::<ChaCha20Poly1305>::from_slice(&key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&iv);

        let message = serde_json::to_string(self)?;
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
        Ok(serde_json::from_str::<Self>(&str).inspect_err(|e| {
            println!("Failed to deserialize JSON-RPC request: {e}\n{str}");
        })?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        message_types::SessionAuthenticateResponse,
        relay_auth::Keypair,
        utils::{derive_sym_key, parse_uri, sha256},
    };
    use alloy::signers::k256::sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn test_decoding_actual_messages() {
        let uri_params = parse_uri(
            "wc:b61b370a99504fa0bd4c8aef4eecdd77c2be9e94e72fb74aedca828e5f33cb79@2?relay-protocol=irn&symKey=4ef8aa7fff3e8354b5032525520255ab526cc661f16b5eff95fe7cd3f0b32f0b&expiryTimestamp=1743768178&methods=wc_sessionAuthenticate".to_string(),
        ).unwrap();

        // first message at wallet side
        decrypt_print(
            "AEJKPBI19Jv57WrKe5BHyZDoaW8pTQi1Fdl97klacGd8HAl0AwQpstTerQkoMPRzr2mVhlzwox30pf1S3fzIo0VcWeIi3exFlSg+vrrdkUaiS0U3U+1FwWAjpk06wlhaOKplgdVvoBNIBIVG0h6QZSqT/V3tz6jYtm276i6RJpPGjh6H2lTWRU7WQZXzy/g/cIO7J/lnai4ZV20oPCeymPGDsI2gWGb2Rf4rB2CYC2NxkVbhRvP0jMGreIegF2IOIUl3IIl8XCgnwvn7AaP6FrYnHk8klFh2r1+649csqtfc3i3pWKdsRN9H2HUeoH+UL3zy5jj2LCDMbtghpqPoul5rERC0ccEzXUaKS5APDkWLB5WqepXsbXRedxQ0JQkAAagqeLa2CZP9STFDnNOUiVx1x53lxB5coQROnt2Byc3W3xnEkufFp+ygnfrMSBCmM/mTr5FJ+gQJIognqJ32f1C2o1UqI+8MQ/WiKL9fZXKzATxMGVNKHwoLKhTotYRET6ocCaBVttFUXP7Bzvp/lL1xrweFI9xb83SXEQojildGKhhW5/YWeHJsY9Om+wo9o+0mpgRaydkXz8ad24aFEJnmZ50Q1hv7DzhwTQZ1aQZn9RSvKiaEFimz5M7GusXP/92wKLOFldo18HzoLczQ3rgNno549sfosR7z6QgXjIR2+L2CdA4Cxy10zDpUIhHg0t7Ey+kPtiRxP8lQVa/e0m6bQusaM1SsyEifPVNjtk4JUj4dTvdD5BDvFeMOFiuzsNtoZom2vsdLz71j1eLSpIAGwbMmsgjtbc8wboqceQnTR5fAIS9D4On7Og9Nr4E1Mz9Jo7LtUK9Hg1Crq08g1cSEPZdIMX6dZqc1viEdwzaR2Hks9e7DwUBN5j5T4Jmb0Elm9Ke7SMuC1bD7Ijp0PQbWkgondo0iBQyXT7Q8A+HWX/kfar80gFsSt5KvUG2A9wGxwnJw8WnDhxcnyleXh+0COIInzQ1uFNA+RQeymsjFqMpw1QFlfySe6S0brgs2ty14ZXM11hWOvjNf2kynBAux8JeOnUpSPOnl2VwNuFo04CQLUtlabyb5T9Cwtk7ftph+mZDOj2feCGkFJXF/9IRMsN7kBCyxoc5hdnFNHFbN7rcHvYeS8B3n3mN1Rf6jiyOwuSbu0RgBBeRMgTFoMhx6KylaMA/8jsv/NlV7XMO8Z8+2I0ZBZW1xhGI+1LeR7EtEMQOBwpeqnEmcD+cwfsFWzO+w8cOeTLSNfyTyrAVzK5xvCfBtmwq2Zcv9B7fHVwGVU46io4zZVf0VA4OcD/OPuGRpLQLM/YH29+NCLMYdMgFP/aK3T6tSXaDgmfTW7MfzaxaePo/QDeZiDiMewCgj5OAZWHE9JCICVywZ2AaGBry6MbVVr7pz/1zKtoH7bZ10k9xxlqFLrcVq3j0Es2yQ3E2lr2Hhbiu7D1gKfky9AjotKJ2Lc19vby4ZYs4c4AjxIClO0L+OXbDkavmxd3kAKw0Dpnfw/Riw3WDyfRMWDuPSZInPCcWhrtU+u9yfN58fpccl+17bTWzW1tacJrH3NHI35ln99nrpMklN6akdDaYG9qnQB/leY/JiUC5I6Bx37hA/ErtFAf9wPE1lQ7+vwallJQnm1bSXkCQWV+huJwNDaTdzMgmjkglaK67vOkBUBr4YmOWvzoxIt5ZYJPuipZlzE8koyhj7jTIb0HO0vvvCDI+M4ubrvSkqkcQ86MFZA+zw2Vgej/WcccrqaM1MnbV9MT6f5GDxmktLtV89aSOb3ZUY0fkgDj65evl9qXFOdroB57+SyxgOSv62pGRq9sstrlplQqnsgPrNeIZ+sowMKE7o89Iy9QtcuYHpUmA8tcHtD0WX8GevvnghIr0=",
            uri_params.sym_key,
        );

        // second message at wallet side
        decrypt_print(
            "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",
            uri_params.sym_key,
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

        let message = decrypt_print(
            "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",
            diffie_sym_key,
        );

        let result = serde_json::from_value::<SessionAuthenticateResponse>(
            message.result.expect("result is None"),
        )
        .expect("serde failed");

        let cacao = result.cacaos.first().unwrap();

        // verifies the signature
        cacao.verify().unwrap();

        println!("cacao verification success");
    }

    fn decrypt_print(encoded: &str, sym_key: [u8; 32]) -> Message {
        let result =
            Message::decrypt(encoded, sym_key, Some(EncodingType::Base64))
                .unwrap();

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
}
