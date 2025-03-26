use alloy::hex;

use crate::{
    constants::CRYPTO_JWT_TTL,
    relay_auth::{self, sign_jwt},
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
        let key_pair = relay_auth::generate_keypair(Some(seed));
        encode_iss(&key_pair.public_key)
    }

    pub fn sign_jwt(&self, aud: &str) -> String {
        let keypair = relay_auth::generate_keypair(Some(self.client_seed));

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
            "did:key:zTBBBWhJtNWGWbVmA3mVAZW3MRme4rjvh2MQatqaELRGpReHcyTCzXPrg7rdoSnxX"
        );
    }
}
