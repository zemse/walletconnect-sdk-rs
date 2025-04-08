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
        utils::{derive_sym_key, sha256},
        wallet_kit::WalletKit,
    };
    use alloy::signers::k256::sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn test_decode_paring() {
        // wc:9417e2513ad0339105069eaa644023ffc9a5b6a6b66626623d117cf21be01a46@2?relay-protocol=irn&symKey=3d0a9b08ac5e6d83bbc32ea4fbe799d2bf8d1a148beff2f93072b96156bea503&expiryTimestamp=1743677660&methods=wc_sessionAuthenticate

        // first msg receive from server SessionAuthenticate tag 1116
        let encoded = "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";
        let result = Message::decrypt(
            encoded,
          hex!("3d0a9b08ac5e6d83bbc32ea4fbe799d2bf8d1a148beff2f93072b96156bea503"),
          Some(EncodingType::Base64),
        )
        .unwrap();

        println!("{result:?}");

        // second msg receive from server SessionPropose tag 1110
        let encoded = "ABTeLGsAxuT8R87O89OT7yaFDKQbzg2oy1ARbfl//ntxz0eo1FE9n8CjXFSV0aLuwkMMyTintn+SOmaFU9qSSeG5rg/yk2WBWnd311YJSKkUwPehJlfgYQnP8JdUMKpDCdZXUWX1TqZ+KTnhDhS86n3beOl+nlvhIV0kt5TnVnm7wC8xmcLWBtjr/KzWAyNcEW6gVpnsW3yoPQ++sowd8GQnuJeq4cDXL9FQYePyrIgrCbay9mYyMjvJemOjOipbQu47PXlMjKZkFhbVyrYsr6b0CHLk9Qyj/qkcMwP+A0XaNXlnybEEIgH5wq3r7o5yyqmmku1uFyEwOLecEE5ByupTE7MTrIqiCWcf0+uS7/Zxo/eB4A+jdbZxZxhGdGaMAKa6wHRd6w25wz4kfFbobdW4U49/fbqABNN5uB+EkyZxPCY+V2QqVDcM5meqBlToqNkTc/R8F9etGiCj6jrQd2c6N/D/tNd8xn+eOmzPuLVFgsVveXgm0ZCeMy43tnQNxnLBHLWXgk4knrBWVpgFqR55yNxnEYyBYbUTBemlGg0QHqxNG9AUH2KrbXQuNAe2PEg5EVUzPZoHPFVD1C/cd5k5NVUmTpUxwj3hVPgLKACab3RuHIhsJSRyMEwJZbnOpy8uG/i/a8pUZXC1SOZGRUUraXE/od/C/DD8gj1XeU4VkUlPGxho5a+/LRQaLnZs1sgnOwjuJcrFTA6QlticoBfOOVBnd6WXu7gwi1WT3Vxeq9JWLTPdTYmt1DHBZaie8OQKFoE9L+l3GrsBdd0PIHpHKzIUXfbhYYiv71yQDTMoDcspRMcDLVkw50yk/6wI01WCFiP7o6B3WgHyh6LSSRx9AQHHWq5HzPZVw6NEdbZpdcr0lQJ8oB8dBsqVCo1eiN5gDbMABf9jpzP1eg0r5cfcjlK1pfdKwJsHKDqz/wbrdYod7uxFN64j8DuFajYx/w+CUtxU7qUckdjomcofX3Iqw1nSO3GAhcMMs7l6lhR7lrRdr2M/t4+yYxz237GMr272yECpf1ArBBWTX5l3et9hjMc16Cr6yc4/nVPUP7Qqk9278NlTYfeBYNDtV/hCTz19jZwfUOtvro58ioR+M8O7UrMfjbiLTBh1/ItqjhkinpZs8YdE8OP5OHr2LFKtdRUHLqIXXOxWgCxWvG7HcUGcuiUpZojKl96oAlbL2uy4I8/c+iC9PjTcCLGItKEyWLou1sE+Fg2B8rQJDCq7A3BPtI0ST7gxH2GUKU1FsxHdx2lzIE6vEOAV0TCaT+QACZHqfZy4TJw5H/gfDEFgiMJC3uLIFHWvAuxyv34LAXshgPMxPm3DhJzhJqtGTK3vTH8hHnrYIQPsKFpiIm6vdxYVIdjWBDeJmgqviCmIq6OJOQfff11v7oUbvZ8vu5/YO9fL+zlt5/k1J5XOkCQo3LfeEMtS1bCdcvPPrLAD1hPtkxVgIX67LrfAi2/rNZ8hBrZxVXckGOp83mHxLTeQKqTJyRb8KiEr9P5Nuywtvcno5Pg0jyrPw5XSXOr+3t2AVQ4Tzkhx/gnB0pNRJk4wEIrMw8yfbValbxlEwipM6R50UC8TZXErqMtYkIM7D2iblqEtxpCulTeGM9oOsCSttExiFJ1eC8tB2bHJel85EVn8gXMOM0uv+3/ktwQ+xlNZ7OmTUOzUY0o+J9TzAI/OVF4KHlv2E+4VeZfYEZU8GuF9xlBgqP+nQ/BTaRdnLDX0MndaQH11/AIQB4roBD4brnD8dw5o6xS4iW00j1dnHICPX7qqiwPCOlLHk024z/Q/2Y10z3duKM+zOzjtlAUTlZQ8IVJkLL8TF05wEdC2gSyG8KGB3uKKbmVTZgJak9FYspxZ";
        let result = Message::decrypt(
            encoded,
          hex!("3d0a9b08ac5e6d83bbc32ea4fbe799d2bf8d1a148beff2f93072b96156bea503"),
          Some(EncodingType::Base64),
        )
        .unwrap();

        println!("\n{result:?}");

        // second msg receive from server SessionPropose tag 1110
        let encoded = "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";
        let result = Message::decrypt(
            encoded,
            hex!("7559648a11635b285312460b6f034e009a2197b7371189f614d214835dde7f07"),
            Some(EncodingType::Base64),
        )
        .unwrap();
        println!("\n{result:?}");
        // hex!(  "390249ddc6b7a44a6d8590689f2b5a533c97861656b6b4747d239220b9cb4953"),
    }

    #[test]
    fn test_decrypt() {
        let self_private_key = hex::decode_to_array::<_, 32>(
            "390249ddc6b7a44a6d8590689f2b5a533c97861656b6b4747d239220b9cb4953",
        )
        .unwrap();
        let kp = Keypair::from_seed(self_private_key);
        let self_public_key = kp.public_key;

        println!(
            "private key : {self_private_key:?}",
            self_private_key = hex::encode(self_private_key)
        );
        println!(
            "public key : {self_public_key:?}",
            self_public_key = hex::encode(self_public_key)
        );

        let cid = WalletKit::new(self_private_key).get_client_id();
        println!("cid: {cid}");

        let other_public_key = hex::decode_to_array::<_, 32>(
            "4f97bcf745f3902f4963283ac1505fd7806bedb4aea38815161229f4509e805c",
        )
        .unwrap();

        println!(
            "other public key: {other_public_key}",
            other_public_key = hex::encode(other_public_key)
        );
        let response_topic = Sha256::digest(other_public_key);
        println!("announcing topic: {}", hex::encode(response_topic));

        let sym_key = derive_sym_key(self_private_key, other_public_key);
        println!("sym_key: {}", hex::encode(sym_key));

        let new_topic = hex::encode(Sha256::digest(sym_key));
        println!("new topic: {new_topic}");

        // TODO understand how can construct sym_key on their end, afaik we are sending our public key inside this message
        let msg = "ASWsYbCwxdWJGOyJ/2rDZ+uz8ZIcFWOlh8RoYblJTZJIuuDjsvZfzNByMy03cCdksjTeKkgr06z9HT3NHJs6pt78WxMGDKjWQZtwmW7Vd7yjOFs8U2YnnRnqn3hauKIcpLeeSGLh1hHTGJRqumqoXPFG90V4+skjejaH0F8KJctQx96TiiVvY2V5fMBMU7rip62aAlzgot4rtUSyO1w0LHsfyRa5fb3yqfZzJ8LTmJgrRIrPVLY7rnxzQYM8K+FdHSrlbNq6U66kS4z8Td5hVE3LulFdu+BdqBehbpAAfvnsNiH8q+CLDGGh2f7XBkTFV1A+mm7GEyfhTJHaZpxcjKqRwIMEA1KNoJUJ65HrjSYXtanrE2fTuIySnYL3aGJ/8RBP6vJZwEj87iwZR1Jl9MhcTfLXhoHiGMZJfhIpCG0oScNB2GNuY1mqwLHTQ4Q1R21HAepDO/xGI4XL5R/FAXF2lnL4ZJwOoHBrhSvCYuinV00/bx9EC3dHnnZcbOlXxn29z/hDuRAa8TuEBFlxj/sKWfnvMx+GV80txUKIO9NqfLg6jYONsrtQ7xO/p/Jyif8SqR15GVvrVTaXgPcbyEs55bFSURKIJN0Mbf0tDq/idu9NIRdWWDh3JdTxYZw3seHTYJky0zfNQ/0VLUSaUO4KV73SaWYIw/VJ2A3WblVH2DcvpuQc+OvH2mnC8xuceESkjWyYtLBPsvF8zXcJ63DrpyvEq1TbFsGhqOKmWBaUvIpoZacyrDsu2/umA6lwwdzI0QneMv2P6afLeLBYygdKOzWWv/p7UGEaYQ5CEEvaeFNKVgD9I+DccPjAyjcxXHuQ0cF0Tz513YZxj8/VwyYV2/vicf30Uh2Ru6GvAguRiSWhhDmWbxMNoI2HEIZRLOf2Imk+0j6Z0O5C8UQJXjFrpZSnRKnr01fR1ixirQIzThvxt8iqOnyBHCXitQ49Na+wVsBc7aM8KJ0+j4RPMP5Z+wIGp19TuBmX4t8EUgYghBBowzwxHTDiKIcN/X9U/KNsmNNtelrXYD1g0bbDzQoy6TnRxyXZcgH4aMYqzWVlckF7u9QPQjpkpjOEGR9tb7uIogNaZWBZCvwj+4t81yMY44OnhZpCY5cCpK5D8QgmWsWgJj9eoBjxPJwox8KjuT3jyGN4KDndbUfLbfemhsMfFwS2MBITChtVw1EHSKDFlQtobzonRN1CY89Q4iUjVJ0RzJbfpvSJs+8XYsHF31kNU5dKt2/5sph7PDBM4ulbvU/TTa86uMIoFIBjYc6i+BvSrqLyM2mH6KBDpf+lq1StfNlPZtki42L9Y3I7nfCGFaz+PO+DCixVYiGywk/y5y9ufsrEIL4PYMc11af5UVv/visnqzmq3u/hjrHC5Bn4ULHSGUp8ows5R25IXfsV8GNlHrkrTd5Un2ZUu5TQ3hgkd01QxcUUbZdXsM/0EyxWMTe4+pZGTcw37PoXfr9JYm4+ftSwHrJI2V8FOmKB3LhoLwLsBYQaBqSQyJuJmCOLy7zoSNT9CZ8+G4yO5acG/WNExntvq7qLQ25Y42KKBVjfZ45Q65ZwV7kO8ry2VDuaf3ZvnXFJ3kzaQulhW+M+ba9wjHItnZpraroAtgD18DbCR1aiNVehrL4Ju3LJq7OKT6K68DOm26/1w/+0KaSu968wPQnDAVMXOXSMlXK32zWTN2KVzuzqj45UKiJCXV1z8pLv0cny8eR1HwZLl+5+bCYVON9D3qmaubiuK3uxoiAgwWZC92E6b2jiKL5F1Q6/M5h+o3CsLp/JaZturd1lBHoXijfB20Ya0jibJx+c9toywZIK/8huJ+106SCW2OpoKBMS0WDg0DnWpYhVOH60H05t5T+uwlUsY5WCAE+9ajPqJX7bxU3TAoAusT2dyRtbXctAbTBRpSmMN4qsz/s890HjyEtS/RwNMGTgw9IoUXyhZ6aksS6NGQLaxytvOS+A8YfJqNno03ddvFPB6B38yPH4tx2Aes3VDep+67AyjUY0qu8Ltlrx+qTtWtyxNMA9/FFoRbi6lrIXh1FW8dUCwk4NDpZ+o4gS7P6MudpySsjbvoHgY21cRSMpUOsEiDXSgdwfK4L7T5vt/BRx5cAKs3eLFcA6E491rt8CufxdFf2vN9VLgh0EHD2JjUQwzOxUiyLiXglVI9Cq6nVlMO23LSgN1IYOJ8gyNWVIr6DFg76yMWqHGajhkStUBKC1Ay1SLgbj4diFTlVuidbHxtLMt1CxKoEMRk3l6/xOSFzVjPFu0Fox/WJlrvswg8mhjvbdN3Iw7+j/1QRF7k0dpbzqu7UMXu5otDzVjioznv3RI/8lbbDPu3RV3i1mg5K9xh3+tRYBgjG3oXCNaqr19MIAJ5uXBV14OcIS3zDj9L+T0qMDY+492Z2NY2XYKGw+nUGM4FiZDM/Syeuj3A0lLg0mE05GArSRriUmdYnjIh1VUSorikJdB35ZzfD6ef7n3RHDD1bEeZMMETEmJFEaKHTMZ0re2qnk5ajcudhXkwwZjJt78M04sDVe+yiWRAdJtyescRsdCrynow1L9EMWtSiGsg3M8eI4XrG+4XDa0NFfkEasryRnw2uniKFQAizbKuI2uBfQ+PXS2u/Yf94j7IRs+Ua+dtjGk91flltRiratKeGGfQ9F/22G8Fc0P+eoD6j3DPCq6DwjWNax9b/ebFNF+B2SKeVL4ziNVcJSRFJjaNpO4dAyHm1vCLD4aUgNXPQWbsL9b5IIfJdo+b7Kpm80eN5puUblhUikce1GJZwXC6EPV5PHDxepz5ssMbOuWUR3wJVo/NHnbHt7xMPwELvip7vzKlvPX9WCFeHUUs68360/kuSTeDy29hNTXtgfmKdnUKbrMC57D3mH/2GvVgd32SplyOcmbWIlNsmsFtXddxSkRVDRJYF5jvXlqvf+yhLkP8hggIXA/C3/QRihyHNRBrUFZ1OUwO1pn9xOkbat3y98qFQ6m3W4zhOy1Q/E30imtlAIABASpzDJv3xAF71XgNlQd82l/FaPvYAmO0morgfcXBUD7W+XvJJZNghSOJZLSJO/ZvXsvcz57Py0igoCpqOXPWCw7xhoUh+O0Vda6YsPgCBmmQ1I2h2j+9Tq1cDLGk7+e3ggz7tNu/DFSEXT1mAfSl9q/ZhY3w5yw85nuT6ygmnVGC6fRCV8IwX235nyZKNSXJ0hDbU4fJ4mqTnTiieS+TvAx03gOw3vwkl/Wb94dwfWSMu6CpVnOz3Z9odfatZMFsw9eusvlKTJV6Fp+VbuhCxOzhvvHDJ/UL2MkFR4CdCrHFKvRItsuPeFMER37zsd3hOnwq4W8atMNwGglSSQGupvAYtsMfU1/QI99wa3LqePKdr3KLyOdkivxLQxXGr8SX4ceWbiBb9QX6Gj9kngqKafX9+0lrlrlIzmtwsHFQ7yqIgpJmK3D7c0GQhW1jc4oafCZw4rDwRw0ipLk7cNcPvgn702aczXIVBXXZys+tgDmDbUEkXUGvd7aJh+D2vxWOakh3a0VcxWzDYLQE3XhP11vUFwz93u5FP33+dTirb9vpdNl4iiywR2YRTIttaS64aHc7n4M8aEAWIOeAN+L+Q/WU2EFXmmArCkIwQfCgSOzuNgRA8V0zv3doiWiuxN7QPQjCwpSxNc/NWLG7pVOgMgCrRwhEZaEsf1U5CnuxrlGPFJ+8GuwD2Bj9cx0ZvsHmp+RQ6msoY7XMPLIJrOvIW/A78nsiwcgKxrQc/dbOOuIR3Y5IGfDinx67oUD/MDkNjXWf4bvIXyQgpWCjzFKBEtGjS7dbTbJXVeX420GzvsgeB2klIwzPOiDS4hlt3SA8zE";
        let result =
            Message::decrypt(msg, sym_key, Some(EncodingType::Base64)).unwrap();

        println!("{result:?}");
    }

    #[test]
    fn test_fresh() {
        // wc:b61b370a99504fa0bd4c8aef4eecdd77c2be9e94e72fb74aedca828e5f33cb79@2?relay-protocol=irn&symKey=4ef8aa7fff3e8354b5032525520255ab526cc661f16b5eff95fe7cd3f0b32f0b&expiryTimestamp=1743768178&methods=wc_sessionAuthenticate

        let sym_key = hex!(
            "4ef8aa7fff3e8354b5032525520255ab526cc661f16b5eff95fe7cd3f0b32f0b"
        );
        let topic = hex!(
            "b61b370a99504fa0bd4c8aef4eecdd77c2be9e94e72fb74aedca828e5f33cb79"
        );

        // first message at wallet side
        decrypt_print(
            "AEJKPBI19Jv57WrKe5BHyZDoaW8pTQi1Fdl97klacGd8HAl0AwQpstTerQkoMPRzr2mVhlzwox30pf1S3fzIo0VcWeIi3exFlSg+vrrdkUaiS0U3U+1FwWAjpk06wlhaOKplgdVvoBNIBIVG0h6QZSqT/V3tz6jYtm276i6RJpPGjh6H2lTWRU7WQZXzy/g/cIO7J/lnai4ZV20oPCeymPGDsI2gWGb2Rf4rB2CYC2NxkVbhRvP0jMGreIegF2IOIUl3IIl8XCgnwvn7AaP6FrYnHk8klFh2r1+649csqtfc3i3pWKdsRN9H2HUeoH+UL3zy5jj2LCDMbtghpqPoul5rERC0ccEzXUaKS5APDkWLB5WqepXsbXRedxQ0JQkAAagqeLa2CZP9STFDnNOUiVx1x53lxB5coQROnt2Byc3W3xnEkufFp+ygnfrMSBCmM/mTr5FJ+gQJIognqJ32f1C2o1UqI+8MQ/WiKL9fZXKzATxMGVNKHwoLKhTotYRET6ocCaBVttFUXP7Bzvp/lL1xrweFI9xb83SXEQojildGKhhW5/YWeHJsY9Om+wo9o+0mpgRaydkXz8ad24aFEJnmZ50Q1hv7DzhwTQZ1aQZn9RSvKiaEFimz5M7GusXP/92wKLOFldo18HzoLczQ3rgNno549sfosR7z6QgXjIR2+L2CdA4Cxy10zDpUIhHg0t7Ey+kPtiRxP8lQVa/e0m6bQusaM1SsyEifPVNjtk4JUj4dTvdD5BDvFeMOFiuzsNtoZom2vsdLz71j1eLSpIAGwbMmsgjtbc8wboqceQnTR5fAIS9D4On7Og9Nr4E1Mz9Jo7LtUK9Hg1Crq08g1cSEPZdIMX6dZqc1viEdwzaR2Hks9e7DwUBN5j5T4Jmb0Elm9Ke7SMuC1bD7Ijp0PQbWkgondo0iBQyXT7Q8A+HWX/kfar80gFsSt5KvUG2A9wGxwnJw8WnDhxcnyleXh+0COIInzQ1uFNA+RQeymsjFqMpw1QFlfySe6S0brgs2ty14ZXM11hWOvjNf2kynBAux8JeOnUpSPOnl2VwNuFo04CQLUtlabyb5T9Cwtk7ftph+mZDOj2feCGkFJXF/9IRMsN7kBCyxoc5hdnFNHFbN7rcHvYeS8B3n3mN1Rf6jiyOwuSbu0RgBBeRMgTFoMhx6KylaMA/8jsv/NlV7XMO8Z8+2I0ZBZW1xhGI+1LeR7EtEMQOBwpeqnEmcD+cwfsFWzO+w8cOeTLSNfyTyrAVzK5xvCfBtmwq2Zcv9B7fHVwGVU46io4zZVf0VA4OcD/OPuGRpLQLM/YH29+NCLMYdMgFP/aK3T6tSXaDgmfTW7MfzaxaePo/QDeZiDiMewCgj5OAZWHE9JCICVywZ2AaGBry6MbVVr7pz/1zKtoH7bZ10k9xxlqFLrcVq3j0Es2yQ3E2lr2Hhbiu7D1gKfky9AjotKJ2Lc19vby4ZYs4c4AjxIClO0L+OXbDkavmxd3kAKw0Dpnfw/Riw3WDyfRMWDuPSZInPCcWhrtU+u9yfN58fpccl+17bTWzW1tacJrH3NHI35ln99nrpMklN6akdDaYG9qnQB/leY/JiUC5I6Bx37hA/ErtFAf9wPE1lQ7+vwallJQnm1bSXkCQWV+huJwNDaTdzMgmjkglaK67vOkBUBr4YmOWvzoxIt5ZYJPuipZlzE8koyhj7jTIb0HO0vvvCDI+M4ubrvSkqkcQ86MFZA+zw2Vgej/WcccrqaM1MnbV9MT6f5GDxmktLtV89aSOb3ZUY0fkgDj65evl9qXFOdroB57+SyxgOSv62pGRq9sstrlplQqnsgPrNeIZ+sowMKE7o89Iy9QtcuYHpUmA8tcHtD0WX8GevvnghIr0=",
            sym_key,
        );

        // second message at wallet side
        decrypt_print(
            "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",
            sym_key,
        );

        let (
            self_private_key,
            self_public_key,
            other_public_key,
            response_topic,
            diffie_sym_key,
            diffie_topic,
        ) = parse_context(
            "000bd03964f8577117caa2f8ee5ef02e46b71c672d93605f447ef96d365c4002",
            "62dbe3bc5bf8395e6f247a2b7aaedcf11e33fccd68d77da1b2752d4f0cc3755f",
        );

        let message = decrypt_print(
            "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",
            diffie_sym_key,
        );

        let result = serde_json::from_value::<SessionAuthenticateResponse>(
            message.result.expect("123"),
        )
        .expect("serde faield");

        let cacao = result.cacaos.first().unwrap();
        // let runtime = Runtime::new().unwrap();

        // struct Hello;
        // impl GetRpcUrl for Hello {
        //     async fn get_rpc_url(&self, _: String) -> Option<url::Url> {
        //     }
        // }

        // runtime
        //     .block_on(cacao.verify::<Hello>(None).into_future())
        //     .unwrap();

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
    fn parse_context(
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
