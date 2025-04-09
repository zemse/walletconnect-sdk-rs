use alloy::signers::{
    SignerSync, k256::ecdsa::SigningKey, local::PrivateKeySigner,
};
use rand::rngs::OsRng;
use walletconnect_sdk::{connection::Connection, message_types::Metadata};

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
    let uri_from_dapp = "wc:d10e1168921368fd38b0ef81728779e2d8b8e311983ec4e42e5b1d20830c36c9@2?relay-protocol=irn&symKey=99398d0e827746535bf55791b3c76d2ba09f89e6bf9c863a2149b033e2085024&expiryTimestamp=1744207726&methods=wc_sessionAuthenticate";

    let pairing = conn.pair(uri_from_dapp).expect("pairing failed");

    let private_key = SigningKey::random(&mut OsRng);
    let signer = PrivateKeySigner::from(private_key);

    // inspect pairing requests if it looks good
    let (mut cacao, proposal, auth) =
        pairing.get_proposal(signer.address()).unwrap();
    println!("cacao: {cacao:?}");
    println!("proposal: {proposal:?}");
    println!("auth: {auth:?}");

    let message = cacao.caip122_message().unwrap();
    let signature = signer.sign_message_sync(message.as_bytes()).unwrap();
    cacao.insert_signature(signature).unwrap();

    pairing.approve(cacao).unwrap();
}
