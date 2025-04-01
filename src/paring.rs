use crate::connection::Connection;
use crate::error::Result;
use crate::rpc_types::{FetchMessageResult, JsonRpcMethod};
use crate::utils::UriParameters;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Key, Nonce};
use alloy::hex;
use alloy::signers::k256::sha2::Sha256;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use rand::RngCore;
use serde_json::json;
use std::str;

pub struct Pairing<'a> {
    params: UriParameters,
    connection: &'a Connection,
}

impl<'a> Pairing<'a> {
    pub fn new(uri: &str, connection: &'a Connection) -> Self {
        let params = UriParameters::from(uri.to_string());
        Self { params, connection }
    }

    fn sym_key(&self) -> &String {
        &self.params.sym_key
    }

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

    pub fn irn_fetch_messages_and_decrypt(&self) -> Result<Vec<String>> {
        let result = self.irn_fetch_messages()?;

        Ok(result
            .messages
            .iter()
            .map(|m| {
                decrypt(
                    self.sym_key().to_string(),
                    &m.message,
                    Some(EncodingType::Base64),
                )
            })
            .collect())
    }

    fn generate_payload() {}
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

pub fn encrypt(
    message: String,
    sym_key: String,
    type_byte: Option<u8>,
    iv: Option<String>,
    sender_public_key: Option<String>,
    encoding: Option<EncodingType>,
) -> String {
    let type_byte = type_byte.unwrap_or(TYPE_0);
    if type_byte == TYPE_1 && sender_public_key.is_none() {
        panic!("Missing sender public key for type 1 envelope");
    }

    let iv = match iv {
        Some(iv_hex) => hex::decode(iv_hex).expect("invalid iv hex"),
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

    let sealed = cipher
        .encrypt(nonce, message.as_bytes())
        .expect("encryption failed");

    EncryptedEnvelope {
        type_byte,
        sealed,
        iv,
        sender_public_key: sender_public_key
            .as_ref()
            .map(|hex| hex::decode(hex).expect("invalid sender_public_key")),
    }
    .serialize(encoding.clone().unwrap_or(EncodingType::Base64))
}

pub fn decrypt(
    sym_key: String,
    encoded: &str,
    encoding: Option<EncodingType>,
) -> String {
    let key = hex::decode(&sym_key).expect("invalid sym_key hex");
    let key = Key::<ChaCha20Poly1305>::from_slice(&key);

    let encoding_params = EncryptedEnvelope::deserialize(
        encoded,
        encoding.clone().unwrap_or(EncodingType::Base64),
    );

    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&encoding_params.iv);
    let decrypted = cipher
        .decrypt(nonce, encoding_params.sealed.as_ref())
        .expect("decryption failed");
    String::from_utf8(decrypted).expect("invalid utf-8")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode() {
        let encoded = "ABaMRDxn3+QlJi60Vt3YliWkcxnrO9AzyTqEU456iIeB40XGAiD0i5PcqbzA/3lSomtWiefq6JJAtZsC+QZUcGHTZnhFRJrOA9Rri0etgOqE5pwMI8GltJdqUTGJn9Ic3ExqIhduU8tPXl4ZrfB2EEapvXJkluT0Ep/vtr5NHT+7PT8iajMcY80zi2X42DxyvJE0hjDvkZG13pKjUzgTwOcnGdbr/UnvG2Qfm7J0dImtMRIXZPosFwVkUCbPWEv+f8vrSSD2HUFcGVAwnGnVWa+KlTdb+ZJhQm/Ym7VQCDta2g3bd90BSaQLvNrXVlBhSoUAsCyw1WZmsYj3MgaE8hunXJ4nAFnd0/vOoQuGp9aT57KTA+HlqyUMP12PydmRPw3FzTFvYMMMGsCys8gkiHNlqvT2MxVEbyqiKTPB6+TzUDmkfy+fdyMiBZ1EqBNJVfbvxEiIoeEm5CErNHdy5sw21g6TUDapRVwNM+aVr1qaytDtgdm+drx6g3+5orLpp/ETpRE1hA6STrZTK3fkyEc8WSuAKy4P3jFza9mRY3GXGA4E46YyLYMSLsTuECwwT3uaU7FG9yutV0RySILeOMftoZWq/02DujGcHOKcmLQgCoE/a35GkvTbnDgybU6Xl4O5G23vCpwNx+wIgn+sLpsVxbW5XbBsmhcEfeSE35Rr7UJecEVdy5Tz3Bb4Nxt9AKDjhl2EOxYGKkCUlCrAy62CMCKgfEJ8uTaeLpX+dORukfwAe+mG4olV65bqzNBZcOgCiVLPyPCbiJPj37rHuzowLbhCD6wgN3x5cVyJ3il0rPhR+GbGnBwRMH1QJMKRy5592CWU2bHdH3kEOdV1q6sz2Z+RYCyRozFHB+nRHnQ3OvFELh04bFBn9jJSVAU3O2JmDu1DG5UOlNnr+ZE10LkcGgmQR41TO73CYlhV1KAoxqtFYX9yFhf1iVbwr06AIHYZVUilcEx2PZJLZy5xJ440gDFvfdj52A22tRFYE0IErBGVvlxEeIruH7JzeAW8Gp9CtIgAsJrmR/30ossNOcIZsC9o0jDuAM1PxguBh8lNYt2D4ROgs+N070y2AIsiR++JLleIT8MG8u8zHyo6vhVYEkkuq2x7fd0EP9qXRFvhBCGBb/kqvUoFtpZPcbEaoikhxu3/p2JfiC15Svq1gbx6td6Fap7FzePYGGDyvflLXt7AW+nF6jouJSXvsZQEe2GWD7bwp7zwUcbrqLWkcvCk2+LNbVjI1BlrA5DMIYl8AwhtyFalHQqe3aOkz3V49bj18TnqS41kJGXuFuqWNSBGWZrmjj+kgNMa0uHUNcMWs0i31FETsdCW5eps8ytSHrEzdc2f8QQhxulZkV5VF0SNPsdH8hmK4B3nn6QrvWV/ZB667fjHjHXtldwhwtkey7rnrF1xgZYFx5D9CqwNlvQ4cZaAQPLX7WSrar30GjBD2GgzUJV6V1RR6pD/zkrBYEhqbBvfoSIbn2ysl85aVasdFvc4n9JcIIHmRckBtjCT7dI+sNhfu/ay6CaP1cuWjGodwLFdFQfBN/Qt2B5Hi8nUJAmqvau4nloRVahIlQ0lQ2CLZy3KnuPPiKz7u8Y452sEFyBiQfgTILTR0DsH5T9pjWX65F/wzzV3wIba0zjg6ahGjhDHzgSl8HrOBh/cNVRjGD+zX9T+ZYuQn16/jSoTpjutbfjjbqU/VT26DRl7SbEeCjTd1VzsIL9+EbobHC/WDgFI7aZqS6jCsXsi9oJAvTJG/3uzPU2DaO/1SWxlttytEJMiLw5X1Do9gNfX7ervdNc4/xbckn6Z0SPqm6s/nNK8Ys9MFnsa1t99O67LB+6h2HVgTc1NePVbQLUhRw35";
        let result = decrypt(
            "80418419ce3b773aa1b755ad7d24cfb47b970cdc635ba3955a436198add2e91e"
                .to_string(),
            encoded,
            Some(EncodingType::Base64),
        );
        println!("{result:?}");

        let encoded = "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";
        let result = decrypt(
            "80418419ce3b773aa1b755ad7d24cfb47b970cdc635ba3955a436198add2e91e"
                .to_string(),
            encoded,
            Some(EncodingType::Base64),
        );
        println!("{result:?}");
    }
}
