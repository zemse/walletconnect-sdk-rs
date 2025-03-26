use crate::{
    relay_auth,
    utils::{encode_iss, random_bytes32},
};

pub struct WalletKit {
    pub client_seed: [u8; 32],
}

impl Default for WalletKit {
    fn default() -> Self {
        // TODO store the random value in the system and retrieve it
        let client_seed = random_bytes32();
        Self::from_client_seed(client_seed)
    }
}

impl WalletKit {
    pub fn from_client_seed(client_seed: [u8; 32]) -> Self {
        Self { client_seed }
    }

    // https://github.com/WalletConnect/walletconnect-monorepo/blob/1e618504de2c1802359ffec486120784c04bd240/packages/core/src/controllers/crypto.ts#L59
    pub fn get_client_id(&self) -> String {
        let seed = self.client_seed;
        let key_pair = relay_auth::generate_keypair(Some(seed));
        encode_iss(&key_pair.public_key)
    }
}

#[cfg(test)]
mod test {
    use super::WalletKit;

    #[test]
    fn test_1() {
        let wk = WalletKit::from_client_seed([0; 32]);
        let client_id = wk.get_client_id();
        assert_eq!(
            client_id,
            "did:key:zTBBBWhJtNWGWbVmA3mVAZW3MRme4rjvh2MQatqaELRGpReHcyTCzXPrg7rdoSnxX"
        );
    }
}
