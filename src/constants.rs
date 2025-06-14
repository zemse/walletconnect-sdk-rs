pub const JWT_IRIDIUM_ALG: &str = "EdDSA";
pub const JWT_IRIDIUM_TYP: &str = "JWT";

pub const JWT_DELIMITER: &str = ".";
pub const JWT_ENCODING: &str = "base64url";
pub const JSON_ENCODING: &str = "utf8";
pub const DATA_ENCODING: &str = "utf8";

pub const DID_DELIMITER: &str = ":";
pub const DID_PREFIX: &str = "did";
pub const DID_METHOD: &str = "key";

pub const MULTICODEC_ED25519_ENCODING: &str = "base58btc";
pub const MULTICODEC_ED25519_BASE: &str = "z";
pub const MULTICODEC_ED25519_HEADER: &str = "K36";
pub const MULTICODEC_ED25519_LENGTH: usize = 32;

pub const KEY_PAIR_SEED_LENGTH: usize = 32;

// https://github.com/WalletConnect/walletconnect-monorepo/blob/b39a5d4e62f5517ef47a70b5b93f27585b7132e8/packages/core/src/controllers/crypto.ts
pub const CRYPTO_CONTEXT: &str = "crypto";
pub const CRYPTO_CLIENT_SEED: &str = "client_ed25519_seed";
pub const CRYPTO_JWT_TTL: u64 = 86400; // ONE_DAY
