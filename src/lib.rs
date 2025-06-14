pub mod cacao;
pub mod connection;
pub mod constants;
pub mod error;
pub mod message;
pub mod paring;
pub mod relay_auth;
pub mod types;
pub mod utils;
///
/// API for interacting with WalletConnect relay
///
/// let conn = Connection::new(
///     "https://relay.walletconnect.org/rpc",
///     "https://relay.walletconnect.org",
///     project_id,
///     client_seed,  Metadata {
///         name: "WalletConnect Rust SDK".to_string(),
///         description: "WalletConnect Rust SDK enables to connect to relay and interact with dapp".to_string(),
///         url: "https://github.com/zemse/walletconnect-sdk".to_string(),
///         icons: vec![],
///     },
/// );
pub use connection::Connection;
///
/// Exposed for easy access
pub use error::Error;
pub(crate) use error::Result;
