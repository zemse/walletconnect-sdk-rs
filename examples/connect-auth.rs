use alloy::signers::{
    SignerSync, k256::ecdsa::SigningKey, local::PrivateKeySigner,
};
use rand::rngs::OsRng;
use walletconnect_sdk::{connection::Connection, types::Metadata};

/// This example shows how to use connect to a dApp using our wallet and use the
/// wc_sessionAuthenticate method. This requires private key to sign the CACAO.
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
    let uri_from_dapp = "wc:60b429580a4c390b05661a1921a806abe0fa9891c6f38b303a519367d3aafba0@2?relay-protocol=irn&symKey=d08415aff3fb5b387b4a607ad20d5431e81e54dad759f9a658d99353a6815775&expiryTimestamp=1744387698&methods=wc_sessionAuthenticate";

    let (pairing, _) = conn
        .init_pairing(uri_from_dapp)
        .await
        .expect("pairing failed");

    let private_key = SigningKey::random(&mut OsRng);
    let signer = PrivateKeySigner::from(private_key);

    // inspect pairing requests if it looks good
    let (mut cacao, proposal, auth) =
        pairing.get_proposal_old(signer.address(), 1).unwrap();
    println!("cacao: {cacao:?}");
    println!("proposal: {proposal:?}");
    println!("auth: {auth:?}");

    let message = cacao.caip122_message().unwrap();
    let signature = signer.sign_message_sync(message.as_bytes()).unwrap();
    cacao.insert_signature(signature).unwrap();

    pairing.approve_with_cacao(cacao).await.unwrap();
    // TODO there's error from dApp side "Signature verification failed"
}
