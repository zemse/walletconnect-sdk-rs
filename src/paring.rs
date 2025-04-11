use crate::cacao::Cacao;
use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::message::{
    Message, MessageMethod, MessageParam, Namespace, Participant, Relay,
    SessionAuthenticateParams, SessionAuthenticateResponse,
    SessionProposeParams, SessionProposeResponse, SessionSettleParams,
};
use crate::rpc_types::{EncryptedMessage, IrnTag};
use crate::utils::{
    DAYS, UriParameters, derive_sym_key, random_bytes32, sha256, unix_timestamp,
};
use alloy::hex;
use alloy::primitives::Address;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::str;

#[derive(Debug, Clone, Copy)]
pub enum Topic {
    // We get this topic from the URI scanned from QR code
    Initial,
    // This is hash of the dapp's public key, used during handshake
    Response,
    // This is using derived symmetric key from both public keys
    Derived,
}

pub struct Pairing<'a> {
    private_key: [u8; 32],
    params: UriParameters,
    connection: &'a Connection,
    proposal_request: Option<Message<SessionProposeParams>>,
    authenticate_request: Option<Message<SessionAuthenticateParams>>,
    approve_done: bool,
}

impl<'a> Pairing<'a> {
    pub fn new(uri: &str, connection: &'a Connection) -> Self {
        let params = UriParameters::from(uri.to_string());
        Self {
            private_key: random_bytes32(),
            params,
            connection,
            proposal_request: None,
            authenticate_request: None,
            approve_done: false,
        }
    }

    fn public_key(&self) -> String {
        let secret = x25519_dalek::StaticSecret::from(self.private_key);
        let public_key = x25519_dalek::PublicKey::from(&secret);
        hex::encode(public_key.to_bytes())
    }

    fn other_public_key(&self) -> Result<[u8; 32]> {
        let proposer_public_key = self
            .proposal_request
            .as_ref()
            .and_then(|p| p.params.as_ref())
            .map(|p| &p.proposer.public_key);
        let auth_public_key = self
            .authenticate_request
            .as_ref()
            .and_then(|p| p.params.as_ref())
            .map(|p| &p.requester.public_key);
        proposer_public_key
            .or(auth_public_key)
            .map(|k| {
                hex::decode_to_array::<String, 32>(k.clone())
                    .map_err(Error::from)
            })
            .ok_or::<Error>(
                "other_public_key not found because pairing is not init".into(),
            )?
    }

    pub fn participant(&self) -> Participant {
        Participant {
            public_key: self.public_key(),
            metadata: self.connection.metadata.clone(),
        }
    }

    fn sym_key(&self, topic: Topic) -> Result<[u8; 32]> {
        Ok(match topic {
            Topic::Initial => self.params.sym_key,
            Topic::Response | Topic::Derived => {
                derive_sym_key(self.private_key, self.other_public_key()?)
            }
        })
    }

    fn topic(&self, topic: Topic) -> Result<String> {
        Ok(match topic {
            // Usually topic is hash of sym key
            Topic::Initial | Topic::Derived => {
                hex::encode(sha256(self.sym_key(topic)?))
            }
            // In this specific case, the topic is not hash of sym key
            Topic::Response => hex::encode(sha256(self.other_public_key()?)),
        })
    }

    /// Initialise the pairing process
    ///
    /// 1. Subscribe to the relay with the topic in the URI
    /// 2. Fetch messages from the relay sent by the dapp
    /// 3. Decrypt the messages
    /// 4. Check if the first message is a session_propose and the second is a session_authenticate
    ///
    /// To continue the process further, use the `approve` method
    pub fn init_pairing(&mut self) -> Result<()> {
        let topic = &self.params.topic;

        let subscription_id = self.connection.irn_subscribe(topic)?;
        println!("Pairing subscription_id: {:?}", subscription_id);

        let messages = self.fetch_messages(Topic::Initial)?;

        if messages.is_empty() {
            return Err(
                "Please generate a fresh WalletConnect URI from the dApp"
                    .into(),
            );
        }

        if messages.len() == 1 {
            // Sometimes dApps send us just the SessionPropose message
            self.proposal_request =
                Some(messages[0].try_decode::<SessionProposeParams>()?);
        } else if messages.len() == 2 {
            // Sometimes dApps send us both SessionPropose and SessionAuthenticate messages
            let (proposal_request, authenticate_request) =
                if messages[0].is(MessageMethod::SessionPropose) {
                    (&messages[0], &messages[1])
                } else {
                    (&messages[1], &messages[0])
                };

            let proposal_request =
                proposal_request.try_decode::<SessionProposeParams>()?;
            let authenticate_request = authenticate_request
                .try_decode::<SessionAuthenticateParams>(
            )?;
            assert_eq!(
                proposal_request
                    .params
                    .as_ref()
                    .unwrap()
                    .proposer
                    .public_key,
                authenticate_request
                    .params
                    .as_ref()
                    .unwrap()
                    .requester
                    .public_key,
                "proposer and requester public keys are not equal - {messages:?}"
            );

            self.proposal_request = Some(proposal_request.clone());
            self.authenticate_request = Some(authenticate_request.clone());
        }
        Ok(())
    }

    pub fn get_proposal(&self) -> Result<&Message<SessionProposeParams>> {
        self.proposal_request
            .as_ref()
            .ok_or("error: proposal_request is None".into())
    }

    pub fn get_proposal_old(
        &self,
        account_address: Address,
    ) -> Result<(
        Cacao,
        Message<SessionProposeParams>,
        Message<SessionAuthenticateParams>,
    )> {
        if self.proposal_request.is_none()
            || self.authenticate_request.is_none()
        {
            return Err("Pairing not initialised".into());
        }

        let cacao = Cacao::from_auth_request(
            &self
                .authenticate_request
                .as_ref()
                .unwrap()
                .params
                .as_ref()
                .unwrap()
                .auth_payload,
            account_address,
        )?;

        Ok((
            cacao,
            self.proposal_request.clone().unwrap(),
            self.authenticate_request.clone().unwrap(),
        ))
    }

    pub fn approve_with_session_settle(
        &mut self,
        account_address: Address,
    ) -> Result<()> {
        let response = self.get_proposal()?.create_success_response(
            SessionProposeResponse {
                relay: Relay {
                    protocol: "irn".to_string(),
                },
                responder_public_key: self.public_key(),
            },
        );

        let result = self.send_message(
            Topic::Initial,
            response,
            Some(0),
            IrnTag::SessionProposeResponse,
            3600,
        )?;
        println!(
            "Pairing publish SessionProposeResponse result: {:?}",
            result
        );

        let topic_initial = self.topic(Topic::Initial)?;
        let topic_response = self.topic(Topic::Response)?;
        let topic_derived = self.topic(Topic::Derived)?;
        println!(
            "\ntopic_initial: {:?}\n topic_response: {:?}\n topic_derived: {:?}\n",
            topic_initial, topic_response, topic_derived
        );

        self.connection.irn_subscribe(&topic_derived)?;

        let session_settle = self.new_message(MessageParam::SessionSettle(
            SessionSettleParams {
                controller: self.participant(),
                expiry: unix_timestamp()? + 10 * DAYS,
                namespaces: [(
                    "eip155".to_string(),
                    Namespace {
                        accounts: Some(vec![
                            format!("eip155:1:{account_address}"),
                            format!("eip155:137:{account_address}"),
                        ]),
                        chains: vec![
                            "eip155:1".to_string(),
                            "eip155:137".to_string(),
                        ],
                        events: vec![
                            "accountsChanged".to_string(),
                            "chainChanged".to_string(),
                        ],
                        methods: vec![
                            "personal_sign".to_string(),
                            "eth_sendTransaction".to_string(),
                        ],
                    },
                )]
                .into(),
                relay: Relay {
                    protocol: "irn".to_string(),
                },
                session_properties: None,
            },
        ));

        let session_settle_resp = self.send_message(
            Topic::Derived,
            session_settle,
            Some(0),
            IrnTag::SessionSettle,
            3600,
        )?;

        println!(
            "Pairing publish session_settle_resp result: {:?}",
            session_settle_resp
        );

        let messages = self.fetch_messages(Topic::Derived)?;
        println!("Pairing fetch messages: {:?}", messages);

        self.approve_done = true;
        Ok(())
    }

    fn fetch_messages(&self, topic: Topic) -> Result<Vec<Message>> {
        self.connection
            .irn_fetch_messages(&self.topic(topic)?)?
            .iter()
            .map(|m| Message::decrypt(&m.message, self.sym_key(topic)?, None))
            .collect()
        // ::<Result<Vec<_>>>
    }

    fn new_message(&self, content: MessageParam) -> Message {
        Message {
            jsonrpc: "2.0".to_string(),
            method: content.method(),
            params: content.params(),
            result: None,
            id: self.connection.get_id(),
        }
    }

    pub fn send_message<T>(
        &self,
        topic: Topic,
        message: Message<T>,
        type_byte: Option<u8>,
        tag: IrnTag,
        ttl: u64,
    ) -> Result<Value>
    where
        T: Serialize + DeserializeOwned,
    {
        let cipher_text = message.encrypt(
            self.sym_key(topic)?,
            type_byte,
            Some(self.public_key()),
            None,
        )?;

        let result = self.connection.irn_publish(EncryptedMessage::new(
            self.topic(topic)?,
            cipher_text,
            tag,
            ttl,
        ))?;

        Ok(result)
    }

    pub fn approve_with_cacao(&self, cacao: Cacao) -> Result<()> {
        if cacao.signature.is_none() {
            return Err("Cacao signature is None".into());
        }

        let response = SessionAuthenticateResponse {
            cacaos: vec![cacao],
            responder: self.participant(),
        };

        let message = self
            .authenticate_request
            .as_ref()
            .unwrap()
            .create_success_response(response);

        let cipher_text = message.encrypt(
            self.sym_key(Topic::Derived)?,
            Some(1),
            Some(self.public_key()),
            None,
        )?;

        let result = self.connection.irn_publish(EncryptedMessage::new(
            hex::encode(sha256(self.other_public_key()?)),
            cipher_text,
            IrnTag::SessionAuthenticateResponse,
            3600,
        ))?;

        println!("Pairing publish result: {:?}", result);
        Ok(())
    }
}
