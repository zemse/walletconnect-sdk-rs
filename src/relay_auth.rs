/// Relay Auth
///
/// Utils to sign JWT for authorizing with Relay RPC
///
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::hex;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SigningKey, ed25519::signature::SignerMut};
use serde::{Deserialize, Serialize};

use crate::{
    constants::CRYPTO_JWT_TTL,
    utils::{encode_iss, random_bytes32},
};

pub struct RelayAuth {
    client_seed: [u8; 32],
}

impl RelayAuth {
    pub fn new(client_seed: [u8; 32]) -> Self {
        Self { client_seed }
    }

    // https://github.com/WalletConnect/walletconnect-monorepo/blob/1e618504de2c1802359ffec486120784c04bd240/packages/core/src/controllers/crypto.ts#L59
    pub fn get_client_id(&self) -> String {
        let seed = self.client_seed;
        let key_pair = Keypair::from_seed(seed);
        encode_iss(&key_pair.public_key)
    }

    // https://github.com/WalletConnect/walletconnect-monorepo/blob/b39a5d4e62f5517ef47a70b5b93f27585b7132e8/packages/core/src/controllers/crypto.ts#L73
    pub fn sign_jwt(&self, aud: &str) -> String {
        let keypair = Keypair::from_seed(self.client_seed);

        let sub = random_bytes32(); // randomSessionIdentifier;
        let ttl = CRYPTO_JWT_TTL;
        sign_jwt(&hex::encode(sub), aud, ttl, &keypair, None)
    }
}

// Only used for JWT signing, not used for encryption
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

fn encode_json<T: ?Sized + Serialize>(val: &T) -> String {
    Base64UrlUnpadded::encode_string(
        serde_json::to_string(val).unwrap().as_bytes(),
    )
}

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

#[cfg(test)]
mod test {
    use super::RelayAuth;

    #[test]
    fn test_1() {
        let wk = RelayAuth::new([0; 32]);
        let client_id = wk.get_client_id();
        assert_eq!(
            client_id,
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        );
    }

    #[test]
    fn test_2() {
        let wk = RelayAuth::new([
            23, 113, 199, 94, 246, 41, 119, 10, 250, 248, 253, 136, 173, 241,
            191, 149, 165, 249, 17, 42, 46, 189, 120, 175, 78, 88, 53, 83, 254,
            16, 32, 150,
        ]);
        let client_id = wk.get_client_id();
        assert_eq!(
            client_id,
            "did:key:z6MkriJMhx6cLMiwwfuJ3NCGw8C8UjB9KoVHB7QSBaBxMx3y"
        );
    }
}
