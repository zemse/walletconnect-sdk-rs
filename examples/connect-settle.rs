use walletconnect_sdk::{connection::Connection, message::Metadata};

/// This example shows how to use connect to a dApp using our wallet and use the
/// wc_sessionSettle method. Does not require private key.
fn main() {
    // ProjectId is required to prevent DOS on the relay. In case following
    // cause rate limits, you can create your own from https://cloud.reown.com
    let project_id = "35d44d49c2dee217a3eb24bb4410acc7";

    // Used to sign JWTs. Must be generated and stored by client. Same seed
    // should be reused for all connections.
    let client_seed = [123u8; 32];

    let conn = Connection::new(
        "https://relay.walletconnect.org/rpc",
        "https://relay.walletconnect.org",
        project_id,
        client_seed,  Metadata {
            name: "WalletConnect Rust SDK".to_string(),
            description: "WalletConnect Rust SDK enables to connect to relay and interact with dapp".to_string(),
            url: "https://github.com/zemse/walletconnect-sdk".to_string(),
            icons: vec![],
        },
    );

    // WalletConnect URI - you can get it by visiting any dApp and clicking on
    // "Connect Wallet" and select WalletConnect
    let uri_from_dapp = "wc:ef2c61c8b0afae3f4d1b03afde31d5067f4483eb0c99267e5405576722bef16d@2?relay-protocol=irn&symKey=b27591b7d74c383292a5132dc056eb417125b4324f8b9bf1d077773c3aaf6917&expiryTimestamp=1744374176&methods=wc_sessionAuthenticate";

    let mut pairing = conn.init_pairing(uri_from_dapp).expect("pairing failed");

    pairing
        .approve_with_session_settle(
            "0x0000000000000000000000000000000000000123"
                .parse()
                .unwrap(),
        )
        .unwrap();
}
