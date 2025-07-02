/// Pairing
///
/// Implementation of walletconnect specs to pair with a dApp and fetch messages.
///
use std::time::Duration;
use std::{str, thread};

use alloy::hex;
use alloy::primitives::Address;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::cacao::Cacao;
use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::message::Message;
use crate::types::{
    EncryptedMessage, IrnTag, Namespace, Participant, Relay,
    SessionAuthenticateResponse, SessionProposeResponse, SessionSettleParams,
};
use crate::utils::{
    DAYS, UriParameters, derive_sym_key, random_bytes32, sha256, unix_timestamp,
};
use crate::wc_message::{WcData, WcMessage, WcMethod};

#[derive(Debug, Clone, Copy)]
pub enum Topic {
    // We get this topic from the URI scanned from QR code
    Initial,
    // This is hash of the dapp's public key, used during handshake
    Response,
    // This is using derived symmetric key from both public keys
    Derived,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pairing {
    private_key: [u8; 32],
    params: UriParameters,
    connection: Connection,
    proposal_request: Option<WcMessage>,
    authenticate_request: Option<WcMessage>,
    approve_done: bool,
}

impl Pairing {
    pub fn new(uri: &str, connection: Connection) -> crate::Result<Self> {
        let params = UriParameters::try_from(uri.to_string())?;
        Ok(Self {
            // Generate a fresh private key for the pairing
            private_key: random_bytes32(),
            params,
            connection,
            proposal_request: None,
            authenticate_request: None,
            approve_done: false,
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
    pub async fn init_pairing(&mut self) -> Result<WcMessage> {
        self.subscribe(Topic::Initial).await?;

        let messages = self.fetch_messages(Topic::Initial).await?;

        if messages.is_empty() {
            return Err(
                "Please generate a fresh WalletConnect URI from the dApp"
                    .into(),
            );
        }

        if messages.len() == 1 {
            // Sometimes dApps send us just the SessionPropose message
            if messages[0].method() != Some(WcMethod::SessionPropose) {
                return Err("Message is not SessionPropose".into());
            }

            self.proposal_request = Some(messages[0].clone());
            Ok(messages[0].clone())
        } else if messages.len() == 2 {
            // Sometimes dApps send us both SessionPropose and SessionAuthenticate messages
            let proposal_request = messages
                .iter()
                .find(|m| m.method() == Some(WcMethod::SessionPropose))
                .ok_or("SessionPropose message not found")?;

            let authenticate_request = messages
                .iter()
                .find(|m| m.method() == Some(WcMethod::SessionAuthenticate))
                .ok_or("SessionAuthenticate message not found")?;

            self.proposal_request = Some(proposal_request.clone());
            self.authenticate_request = Some(authenticate_request.clone());

            {
                let proposal_request =
                    proposal_request.data.as_session_propose().ok_or(
                        crate::Error::InternalError2("not session propose"),
                    )?;
                let authenticate_request = authenticate_request
                    .data
                    .as_session_authenticate()
                    .ok_or(crate::Error::InternalError2(
                        "not session authenticate",
                    ))?;
                assert_eq!(
                    proposal_request.proposer.public_key,
                    authenticate_request.requester.public_key,
                    "proposer and requester public keys are not equal - {messages:?}"
                );
            }
            Ok(proposal_request.clone())
        } else {
            Err(format!(
                "Expected 1 or 2 messages, got {}: {messages:?}",
                messages.len()
            )
            .into())
        }
    }

    /// Approve the pairing by using wc_sessionSettle
    ///
    /// 1. Create a SessionProposeResponse message on the SessionProposal message id, mention our public key in it.
    /// 2. Create a SessionSettle message with the session properties encrypted using the derived symmetric key
    /// 3. Also subscribe to the topic derived from the symmetric key to receive messages from the dappcxd
    pub async fn approve_with_session_settle(
        &mut self,
        account_address: Address,
    ) -> Result<Vec<WcMessage>> {
        let proposal = self.get_proposal()?;
        let response = proposal.create_response(
            WcData::SessionProposeResponse(SessionProposeResponse {
                relay: Relay {
                    protocol: "irn".to_string(),
                },
                responder_public_key: self.public_key(),
            }),
            None,
        );

        self.send_message(
            Topic::Initial,
            &response.into_raw()?,
            Some(0),
            IrnTag::SessionProposeApproveResponse,
            3600,
        )
        .await?;

        self.subscribe(Topic::Derived).await?;

        let proposal =
            proposal.data.as_session_propose().ok_or("not proposal")?;

        let session_settle =
            self.new_message(WcData::SessionSettle(SessionSettleParams {
                controller: self.participant(),
                expiry: unix_timestamp()? + 10 * DAYS,
                namespaces: proposal
                    .required_namespaces
                    .clone()
                    .into_iter()
                    .chain(proposal.optional_namespaces.clone())
                    .map(|(name, n)| {
                        (
                            name,
                            Namespace {
                                accounts: Some(
                                    n.chains
                                        .iter()
                                        .map(|c| {
                                            format!("{c}:{account_address}")
                                        })
                                        .collect(),
                                ),
                                ..n
                            },
                        )
                    })
                    .collect(),
                relay: Relay {
                    protocol: "irn".to_string(),
                },
                session_properties: None,
            }))?;

        self.send_message(
            Topic::Derived,
            &session_settle,
            Some(0),
            IrnTag::SessionSettle,
            3600,
        )
        .await?;

        let mut excess_messages = vec![];
        let mut success = false;

        loop {
            let mut messages = self.fetch_messages(Topic::Derived).await?;
            let mut rm_idx = None;
            for (i, msg) in messages.iter().enumerate() {
                if msg.id == session_settle.id {
                    let result = msg.data.as_result::<bool>();

                    if let Some(result) = result {
                        success = result;
                    }

                    rm_idx = Some(i);
                }
            }
            if let Some(i) = rm_idx {
                messages.remove(i);
            }
            excess_messages.extend(messages);
            if rm_idx.is_some() {
                break;
            }
        }

        if success {
            self.approve_done = true;
            Ok(excess_messages)
        } else {
            Err(crate::Error::PairingNotApproved)
        }
    }

    /// Approve the pairing by responding to wc_sessionAuthenticate
    ///
    /// 1. Create a SessionAuthenticateResponse message on the
    ///    SessionAuthenticate message id. Encrypt the message using derived
    ///    symetric key and mention our public key by using the type 1 envelope.
    pub async fn approve_with_cacao(&self, cacao: Cacao) -> Result<()> {
        if cacao.signature.is_none() {
            return Err("Cacao signature is None".into());
        }

        cacao.verify()?;

        let message =
            self.authenticate_request.as_ref().unwrap().create_response(
                WcData::SessionAuthenticateResponse(
                    SessionAuthenticateResponse {
                        cacaos: vec![cacao],
                        responder: self.participant(),
                    },
                ),
                None,
            );

        self.send_message(
            Topic::Derived,
            &message.into_raw()?,
            Some(1),
            IrnTag::SessionAuthenticateApproveResponse,
            3600,
        )
        .await?;

        Ok(())
    }

    pub async fn watch_messages(
        &self,
        topic: Topic,
        dur: Option<Duration>,
    ) -> Result<Vec<WcMessage>> {
        loop {
            let result = self.fetch_messages(topic).await?;
            if !result.is_empty() {
                return Ok(result);
            }
            thread::sleep(dur.unwrap_or(Duration::from_secs(1)));
        }
    }

    fn new_message(&self, data: WcData) -> crate::Result<Message> {
        if data.result()?.is_some() {
            return Err("Cannot create new message with result".into());
        }
        Ok(Message {
            jsonrpc: "2.0".to_string(),
            method: data.method().map(|s| s.to_string()),
            params: data.params()?,
            result: None,
            error: None,
            id: self.connection.get_id(),
        })
    }

    /// Subscribe to the topic so we can fetch messages
    ///
    /// This returns subscription id - not sure how it is useful
    async fn subscribe(&self, topic: Topic) -> Result<String> {
        self.connection.irn_subscribe(&self.topic(topic)?).await
    }

    async fn fetch_messages(&self, topic: Topic) -> Result<Vec<WcMessage>> {
        self.connection
            .irn_fetch_messages(&self.topic(topic)?)
            .await?
            .iter()
            .map(|m| {
                Message::decrypt(&m.message, self.sym_key(topic)?, None)
                    .and_then(|m| m.decode())
            })
            .collect()
    }

    pub async fn send_message<T>(
        &self,
        topic: Topic,
        message: &Message<String, T>,
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

        let result = self
            .connection
            .irn_publish(EncryptedMessage::new(
                self.topic(topic)?,
                cipher_text,
                tag,
                ttl,
            ))
            .await?;

        Ok(result)
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
            .and_then(|p| p.data.as_session_propose())
            .map(|p| &p.proposer.public_key);
        let auth_public_key = self
            .authenticate_request
            .as_ref()
            .and_then(|p| p.data.as_session_authenticate())
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

    pub(crate) fn participant(&self) -> Participant {
        Participant {
            public_key: self.public_key(),
            metadata: self.connection.metadata().clone(),
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

    pub fn get_proposal(&self) -> Result<&WcMessage> {
        self.proposal_request
            .as_ref()
            .ok_or("error: proposal_request is None".into())
    }

    #[allow(dead_code)]
    pub fn get_proposal_old(
        &self,
        account_address: Address,
        chain_id: u64,
    ) -> Result<(Cacao, WcMessage, WcMessage)> {
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
                .data
                .as_session_authenticate()
                .unwrap()
                .auth_payload,
            account_address,
            chain_id,
        )?;

        Ok((
            cacao,
            // TODO is this necessary?
            self.proposal_request.clone().unwrap(),
            self.authenticate_request.clone().unwrap(),
        ))
    }
}
