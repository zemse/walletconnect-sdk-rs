use walletconnect_sdk::{
    connection::Connection, pairing::Topic, types::Metadata,
};

/// This example shows how to use connect to a dApp using our wallet and use the
/// wc_sessionSettle method. Does not require private key.
#[tokio::main]
async fn main() {
    env_logger::init();

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
    let uri_from_dapp = "wc:e4b9eb7a1372bf88abc46c37acac3687301afdfd0d2a4c2355945d66a1164464@2?relay-protocol=irn&symKey=d7430284e1b70853829a010518a088cde0e163bcad5f24425e3b17578b2b402d&expiryTimestamp=1749783095&methods=wc_sessionAuthenticate";

    let mut pairing = conn
        .init_pairing(uri_from_dapp)
        .await
        .expect("pairing failed");

    pairing
        .approve_with_session_settle(
            "0x0000000000000000000000000000000000000123"
                .parse()
                .unwrap(),
        )
        .await
        .expect("approve failed");

    loop {
        let result =
            pairing.watch_messages(Topic::Derived, None).await.unwrap();

        println!("result: {result:?}");
    }
}
