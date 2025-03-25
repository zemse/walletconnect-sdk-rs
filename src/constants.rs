// Use a module or crate structure as you prefer. Here is a simple file-level example:

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
