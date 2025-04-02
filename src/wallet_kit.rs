use alloy::hex;

use crate::{
    constants::CRYPTO_JWT_TTL,
    relay_auth::{Keypair, sign_jwt},
    utils::{encode_iss, random_bytes32},
};

pub struct WalletKit {
    pub client_seed: [u8; 32],
}

impl WalletKit {
    pub fn new(client_seed: [u8; 32]) -> Self {
        Self { client_seed }
    }

    // https://github.com/WalletConnect/walletconnect-monorepo/blob/1e618504de2c1802359ffec486120784c04bd240/packages/core/src/controllers/crypto.ts#L59
    pub fn get_client_id(&self) -> String {
        let seed = self.client_seed;
        let key_pair = Keypair::from_seed(seed);
        encode_iss(&key_pair.public_key)
    }

    pub fn sign_jwt(&self, aud: &str) -> String {
        let keypair = Keypair::from_seed(self.client_seed);

        let sub = random_bytes32(); // randomSessionIdentifier;
        let ttl = CRYPTO_JWT_TTL;
        sign_jwt(&hex::encode(sub), aud, ttl, &keypair, None)
    }
}

#[cfg(test)]
mod test {
    use super::WalletKit;

    #[test]
    fn test_1() {
        let wk = WalletKit::new([0; 32]);
        let client_id = wk.get_client_id();
        assert_eq!(
            client_id,
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        );
    }

    #[test]
    fn test_2() {
        let wk = WalletKit::new([
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
