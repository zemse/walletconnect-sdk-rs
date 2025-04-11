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
    let uri_from_dapp = "wc:ef2c61c8b0afae3f4d1b03afde31d5067f4483eb0c99267e5405576722bef16d@2?relay-protocol=irn&symKey=b27591b7d74c383292a5132dc056eb417125b4324f8b9bf1d077773c3aaf6917&expiryTimestamp=1744374176&methods=wc_sessionAuthenticate";

    let pairing = conn.init_pairing(uri_from_dapp).expect("pairing failed");

    let private_key = SigningKey::random(&mut OsRng);
    let signer = PrivateKeySigner::from(private_key);

    // Using route 1
    // {

    //     // inspect pairing requests if it looks good
    //     let (mut cacao, proposal, auth) =
    //         pairing.get_proposal_old(signer.address()).unwrap();
    //     println!("cacao: {cacao:?}");
    //     println!("proposal: {proposal:?}");
    //     println!("auth: {auth:?}");

    //     let message = cacao.caip122_message().unwrap();
    //     let signature = signer.sign_message_sync(message.as_bytes()).unwrap();
    //     cacao.insert_signature(signature).unwrap();

    //     pairing.approve_with_cacao(cacao).unwrap();
    // }

    // Using route 2
    {
        pairing
            .approve_with_session_settle(signer.address())
            .unwrap();
    }
}
