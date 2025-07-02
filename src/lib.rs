//! # walletconnect-sdk
//!
//! A Rust implementation of [WalletConnect specs](https://specs.walletconnect.com/2.0/).
//!
//! ## Features
//! - Pairing using session settle
//! - Types
//!
//! ## Example
//! API for interacting with WalletConnect relay
//!
//! ```rust
//! // Get project_id from https://cloud.reown.com
//! let project_id = "xxxx";
//!
//! // Generate random once, store it in client and reuse it for all connections
//! let client_seed = [123u8; 32];
//!
//! let conn = Connection::new(
//!     "https://relay.walletconnect.org/rpc",
//!     "https://relay.walletconnect.org",
//!     project_id,
//!     client_seed,  Metadata {
//!         name: "My Wallet Name".to_string(),
//!         description: "My wallet interacts with dapp".to_string(),
//!         url: "https://my-wallet-site.com".to_string(),
//!         icons: vec![],
//!     },
//! );
//!
//! let uri_from_dapp = "wc:e4b9eb7a1372bf88abc46c37acac3687301afdfd0d2a4c2355945d66a1164464@2?relay-protocol=irn&symKey=d7430284e1b70853829a010518a088cde0e163bcad5f24425e3b17578b2b402d&expiryTimestamp=1749783095&methods=wc_sessionAuthenticate";
//!
//! let (mut pairing, _) = conn
//!     .init_pairing(uri_from_dapp)
//!     .await
//!     .expect("pairing failed");
//!
//! pairing
//!     .approve_with_session_settle(
//!         // Address of the wallet that is connecting to dApp
//!         "0x0000000000000000000000000000000000000123"
//!             .parse()
//!             .unwrap(),
//!     )
//!     .await
//!     .expect("approve failed");
//!
//! loop {
//!     let result =
//!         pairing.watch_messages(Topic::Derived, None).await.unwrap();
//!
//!     println!("result: {result:?}");
//! }
//! ```
//!
//! ## License
//! MIT OR Apache-2.0

pub mod cacao;
pub mod connection;
pub mod constants;
pub mod error;
pub mod message;
pub mod pairing;
pub mod relay_auth;
pub mod types;
pub mod utils;
pub mod wc_message;

/// Exposed for easy access
pub use connection::Connection;
pub use error::Error;
pub(crate) use error::Result;
pub use pairing::Pairing;
