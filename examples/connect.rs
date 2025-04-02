use walletconnect_sdk::connection::Connection;

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
        client_seed,
    );

    // WalletConnect URI - you can get it by visiting any dApp and clicking on
    // "Connect Wallet" and select WalletConnect
    let uri_from_dapp = "wc:d0bb3bf179a70fd10245144ac7355c52a767806c9b2d852b99fc7be935934882@2?relay-protocol=irn&symKey=2cbcbf78e71e27387de926f93569f89f73fa9093e431bebf110f959133168fc8&expiryTimestamp=1743510984&methods=wc_sessionAuthenticate";

    let pairing = conn.pair(uri_from_dapp).expect("pairing failed");

    // inspect pairing requests if it looks good
    println!(
        "Pairing request: {:?} {:?}",
        pairing.proposal_request(),
        pairing.authenticate_request()
    );
}
