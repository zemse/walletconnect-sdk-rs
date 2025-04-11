use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SigningKey, ed25519::signature::SignerMut};
use serde::{Deserialize, Serialize};

use crate::utils::{encode_iss, random_bytes32};

#[derive(Debug, Clone)]
pub struct Keypair {
    pub seed: [u8; 32],
    pub secret_key: [u8; 64],
    pub public_key: [u8; 32],
}

impl Keypair {
    pub fn generate() -> Self {
        Keypair::from_seed(random_bytes32())
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let mut signing_key = SigningKey::from(self.seed);
        signing_key.sign(data).to_bytes()
    }

    pub fn from_bytes64_secret(secret_key: [u8; 64]) -> Self {
        let mut seed = [0u8; 32];
        let mut public_key = [0u8; 32];

        seed.copy_from_slice(&secret_key[..32]);
        public_key.copy_from_slice(&secret_key[32..]);

        let signing_key = SigningKey::from_bytes(&seed);
        let calculated_public_key = signing_key.verifying_key().to_bytes();

        assert_eq!(
            public_key, calculated_public_key,
            "Public key does not match the signing key"
        );

        Keypair {
            seed,
            secret_key,
            public_key,
        }
    }

    // https://github.com/WalletConnect/walletconnect-utils/blob/4d8eb66bcea89857c630017774845e872a66922a/relay/relay-auth/src/api.ts#L14
    pub fn from_seed(seed: [u8; 32]) -> Keypair {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();

        let mut secret_key = [0u8; 64];

        secret_key[..32].copy_from_slice(&seed);
        secret_key[32..].copy_from_slice(&public_key);

        Keypair {
            seed,
            secret_key,
            public_key,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct IridiumJWTHeader {
    pub alg: &'static str,
    pub typ: &'static str,
}

#[derive(Serialize, Deserialize)]
pub struct IridiumJWTPayload {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Serialize)]
pub struct IridiumJWTSigned<'a> {
    pub header: &'a IridiumJWTHeader,
    pub payload: &'a IridiumJWTPayload,
    pub signature: String,
}

/// Converts a struct to base64url-encoded JSON
fn encode_json<T: ?Sized + Serialize>(val: &T) -> String {
    Base64UrlUnpadded::encode_string(
        serde_json::to_string(val).unwrap().as_bytes(),
    )
}

/// Concatenates base64url(header) + "." + base64url(payload) and returns data + string
fn encode_data(
    header: &IridiumJWTHeader,
    payload: &IridiumJWTPayload,
) -> (Vec<u8>, String) {
    let h = encode_json(header);
    let p = encode_json(payload);
    let joined = format!("{h}.{p}");
    (joined.as_bytes().to_vec(), joined)
}

pub fn sign_jwt(
    sub: &str,
    aud: &str,
    ttl: u64,
    keypair: &Keypair,
    iat_opt: Option<u64>,
) -> String {
    // Get current timestamp if not provided
    let iat = iat_opt.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let exp = iat + ttl;

    let header = IridiumJWTHeader {
        alg: "EdDSA",
        typ: "JWT",
    };
    let iss = encode_iss(&keypair.public_key);
    let payload = IridiumJWTPayload {
        iss,
        sub: sub.to_string(),
        aud: aud.to_string(),
        iat,
        exp,
    };

    let (data, jwt_head_payload) = encode_data(&header, &payload);

    let signature = keypair.sign(&data);
    let sig_encoded = Base64UrlUnpadded::encode_string(&signature);

    format!("{jwt_head_payload}.{sig_encoded}")
}
