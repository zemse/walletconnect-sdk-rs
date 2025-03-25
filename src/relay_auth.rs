use ed25519_dalek::SigningKey;

use crate::utils::random_bytes32;

#[derive(Debug, Clone)]
pub struct Keypair {
    pub secret_key: [u8; 64],
    pub public_key: [u8; 32],
}

// https://github.com/WalletConnect/walletconnect-utils/blob/4d8eb66bcea89857c630017774845e872a66922a/relay/relay-auth/src/api.ts#L14
pub fn generate_keypair(seed: Option<[u8; 32]>) -> Keypair {
    let seed = seed.unwrap_or_else(random_bytes32);

    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();

    let mut secret_key = [0u8; 64];

    secret_key[..32].copy_from_slice(&seed);
    secret_key[32..].copy_from_slice(&public_key);

    Keypair {
        secret_key,
        public_key,
    }
}
