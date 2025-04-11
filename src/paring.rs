use crate::cacao::Cacao;
use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::message_types::{
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
    // other_public_key: Option<[u8; 32]>,
    // approve_done: bool,
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
            // other_public_key: None,
            // approve_done: false,
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
        // let result = self.irn_fetch_messages_and_decrypt()?;

        // let messages = self
        //     .connection
        //     .irn_fetch_messages(topic)?
        //     .iter()
        //     .map(|m| {
        //         self.decrypt(m, Topic::Initial)
        //             .and_then(|m| m.into_json_param())
        //     })
        //     .collect::<Result<Vec<_>>>()?;
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
            // TODO There is some decoding issue at the dapp side when we send our cacao
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
        &self,
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

    // pub fn decrypt(
    //     &self,
    //     irn_message: &EncryptedMessage,
    //     topic: Topic,
    // ) -> Result<Message> {
    //     Message::decrypt(&irn_message.message, self.sym_key(topic)?, None)
    // }
}

#[cfg(test)]
mod tests {
    use crate::message_types::TYPE_1;
    use crate::rpc_types::Id;
    use crate::{
        message_types::SessionAuthenticateResponse,
        relay_auth::Keypair,
        utils::{derive_sym_key, parse_uri, sha256},
    };
    use alloy::signers::k256::sha2::{Digest, Sha256};
    use serde_json::{Number, json};

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = Keypair::generate();
        let sym_key = derive_sym_key(key.seed, key.public_key);

        let message = Message {
            jsonrpc: "2.0".to_string(),
            method: None,
            params: None,
            result: Some(json!({
                "cacao": {
                    "header": {
                        "h": "caip122"
                    },
                    "payload": {
                        "iss": {
                            "account_address": hex::encode(key.public_key),
                            "chain_id": "eip155"
                        },
                        "domain": "https://example.com",
                        "uri": "wc:1234@2?relay-protocol=irn",
                        "version": "1.0.0",
                        "statement": "Please sign this message to authenticate",
                        "nonce": hex::encode(key.seed),
                    },
                    "signature": {
                        "t": "eip191",
                    }
                }
            })),
            id: Id::Number(Number::from(12345)),
        };

        let encrypted_message = message
            .encrypt(
                sym_key,
                Some(TYPE_1),
                Some(hex::encode(key.public_key)),
                None,
            )
            .unwrap();

        let decrypted_message =
            Message::decrypt(&encrypted_message, sym_key, None).unwrap();

        assert_eq!(message.jsonrpc, decrypted_message.jsonrpc);
    }

    // this is with https://appkit-lab.reown.com/library/wagmi-all/
    #[test]
    fn test_decoding_actual_messages() {
        let uri_params = parse_uri(
            "wc:b61b370a99504fa0bd4c8aef4eecdd77c2be9e94e72fb74aedca828e5f33cb79@2?relay-protocol=irn&symKey=4ef8aa7fff3e8354b5032525520255ab526cc661f16b5eff95fe7cd3f0b32f0b&expiryTimestamp=1743768178&methods=wc_sessionAuthenticate".to_string(),
        ).unwrap();

        // first message at wallet side
        decrypt_print(
            "AEJKPBI19Jv57WrKe5BHyZDoaW8pTQi1Fdl97klacGd8HAl0AwQpstTerQkoMPRzr2mVhlzwox30pf1S3fzIo0VcWeIi3exFlSg+vrrdkUaiS0U3U+1FwWAjpk06wlhaOKplgdVvoBNIBIVG0h6QZSqT/V3tz6jYtm276i6RJpPGjh6H2lTWRU7WQZXzy/g/cIO7J/lnai4ZV20oPCeymPGDsI2gWGb2Rf4rB2CYC2NxkVbhRvP0jMGreIegF2IOIUl3IIl8XCgnwvn7AaP6FrYnHk8klFh2r1+649csqtfc3i3pWKdsRN9H2HUeoH+UL3zy5jj2LCDMbtghpqPoul5rERC0ccEzXUaKS5APDkWLB5WqepXsbXRedxQ0JQkAAagqeLa2CZP9STFDnNOUiVx1x53lxB5coQROnt2Byc3W3xnEkufFp+ygnfrMSBCmM/mTr5FJ+gQJIognqJ32f1C2o1UqI+8MQ/WiKL9fZXKzATxMGVNKHwoLKhTotYRET6ocCaBVttFUXP7Bzvp/lL1xrweFI9xb83SXEQojildGKhhW5/YWeHJsY9Om+wo9o+0mpgRaydkXz8ad24aFEJnmZ50Q1hv7DzhwTQZ1aQZn9RSvKiaEFimz5M7GusXP/92wKLOFldo18HzoLczQ3rgNno549sfosR7z6QgXjIR2+L2CdA4Cxy10zDpUIhHg0t7Ey+kPtiRxP8lQVa/e0m6bQusaM1SsyEifPVNjtk4JUj4dTvdD5BDvFeMOFiuzsNtoZom2vsdLz71j1eLSpIAGwbMmsgjtbc8wboqceQnTR5fAIS9D4On7Og9Nr4E1Mz9Jo7LtUK9Hg1Crq08g1cSEPZdIMX6dZqc1viEdwzaR2Hks9e7DwUBN5j5T4Jmb0Elm9Ke7SMuC1bD7Ijp0PQbWkgondo0iBQyXT7Q8A+HWX/kfar80gFsSt5KvUG2A9wGxwnJw8WnDhxcnyleXh+0COIInzQ1uFNA+RQeymsjFqMpw1QFlfySe6S0brgs2ty14ZXM11hWOvjNf2kynBAux8JeOnUpSPOnl2VwNuFo04CQLUtlabyb5T9Cwtk7ftph+mZDOj2feCGkFJXF/9IRMsN7kBCyxoc5hdnFNHFbN7rcHvYeS8B3n3mN1Rf6jiyOwuSbu0RgBBeRMgTFoMhx6KylaMA/8jsv/NlV7XMO8Z8+2I0ZBZW1xhGI+1LeR7EtEMQOBwpeqnEmcD+cwfsFWzO+w8cOeTLSNfyTyrAVzK5xvCfBtmwq2Zcv9B7fHVwGVU46io4zZVf0VA4OcD/OPuGRpLQLM/YH29+NCLMYdMgFP/aK3T6tSXaDgmfTW7MfzaxaePo/QDeZiDiMewCgj5OAZWHE9JCICVywZ2AaGBry6MbVVr7pz/1zKtoH7bZ10k9xxlqFLrcVq3j0Es2yQ3E2lr2Hhbiu7D1gKfky9AjotKJ2Lc19vby4ZYs4c4AjxIClO0L+OXbDkavmxd3kAKw0Dpnfw/Riw3WDyfRMWDuPSZInPCcWhrtU+u9yfN58fpccl+17bTWzW1tacJrH3NHI35ln99nrpMklN6akdDaYG9qnQB/leY/JiUC5I6Bx37hA/ErtFAf9wPE1lQ7+vwallJQnm1bSXkCQWV+huJwNDaTdzMgmjkglaK67vOkBUBr4YmOWvzoxIt5ZYJPuipZlzE8koyhj7jTIb0HO0vvvCDI+M4ubrvSkqkcQ86MFZA+zw2Vgej/WcccrqaM1MnbV9MT6f5GDxmktLtV89aSOb3ZUY0fkgDj65evl9qXFOdroB57+SyxgOSv62pGRq9sstrlplQqnsgPrNeIZ+sowMKE7o89Iy9QtcuYHpUmA8tcHtD0WX8GevvnghIr0=",
            uri_params.sym_key,
        );

        // second message at wallet side
        decrypt_print(
            "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",
            uri_params.sym_key,
        );

        let (
            _self_private_key,
            _self_public_key,
            _other_public_key,
            _response_topic,
            diffie_sym_key,
            _diffie_topic,
        ) = calculate(
            "000bd03964f8577117caa2f8ee5ef02e46b71c672d93605f447ef96d365c4002",
            "62dbe3bc5bf8395e6f247a2b7aaedcf11e33fccd68d77da1b2752d4f0cc3755f",
        );

        let message = decrypt_print(
            "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",
            diffie_sym_key,
        );

        let result = serde_json::from_value::<SessionAuthenticateResponse>(
            message.result.expect("result is None"),
        )
        .expect("serde failed");

        let cacao = result.cacaos.first().unwrap();

        // verifies the signature
        cacao.verify().unwrap();

        println!("cacao verification success");
    }

    // with localhost:3002
    #[test]
    fn test_decoding_actual_2() {
        let uri_params = parse_uri(
            "wc:6c0a8da4a0c672f063bc9972ea1a40b88c5a20c5b8984237987121d6f6024025@2?relay-protocol=irn&symKey=1b53c9465436bef7fd23211a0c233c60b6799b47c20db904df0bbe2ff6227a13&expiryTimestamp=1744290863".to_string(),
        ).unwrap();

        // first message from dapp to wallet
        // tag 1100
        decrypt_print(
            "APJp0bXg8XcsUBeyyf/yAxikhfBBmguNF2VZiUAprqsNdWulICHbgvfzpbhvhnV3Q6nSt513k58Tp87MDp5s0G/iir1/IIV8qC7mShut4dOMTzCj9yderIErYmkgaR+XYqDBLn/uXQT8xIHrnyy9egWu3CE0bk2exTYC30abagrMcB8lclXkwTSz3H+39bbUv5G+8rWyYMFpYJaUF2KQUtIkeL4jV4kpT4S0+3cYMfwbS5+9yKR4iOzxfYkb93qOiZH1dIYZzHV5ng5VzjwI7Cd4CZqoJtFxQWHMH/+0hxWCiONbaGMGXLpJUysd7iOfjpuRWOzDvpLb3MYIBSf1sePiSiE/mm63qSkbZURbIScY9HJGJ5tXVacfA1w6XCtsDzhgeuVROsKS62salM1u0umwaaDBFyD6rDoNf94YItcdAYqb4Zp/nMiHzWo6vHebc+xpBJw14gqETVP4XiYmGbbGrSxyG4+tN2u8I/e9zyT5aGqdr6OyZ04PF5biFzyz9IyC/2mdsWOGU10uV6246A2r9yXyS2kyEK2Ed+mumvBETPnD4Tx8Jop2+x96WrBggunJrH1M6eOA2zeu1XdA1qpYnHKQ7JmePifbZR+VkGmyXxJ4omUXFcG+VaMjghWrOp6tlwDXbcQDVpTDuN2mEi28SwAhbJf8m4ag+90UGXtjTFbXv6AM7pGTdJD9x9Bs9mLUHlRYzCSS6uObpMDVgVi+ZiVXOPirmrW9QX8xEzzGIgXzCTg7JiT0RbfMmhdwd/dAwNO4kXl7s9XaSlMQycA6rgmKhR0Z3c9hLKflD6JPsehq50Fs08l/qIzgI1/Kw/8O/HKVhhpsdAqKZj89qDdauNXBb3SHbbOg",
            uri_params.sym_key,
        );

        let (
            _self_private_key,
            _self_public_key,
            _other_public_key,
            _response_topic,
            diffie_sym_key,
            _diffie_topic,
        ) = calculate(
            "93f31989e2f2582d7c7eb1b074ca7bcac003dea3b0b960a9538da56aee3654c3",
            "690a17937795cf5af845bd7c0701156f647d9bcb211eb7bd85d362fa371cb02d",
        );

        // first publish from wallet to dapp
        // tag 1102
        decrypt_print(
            "APjVUGlm0Tmem9SpiHcoYZ0qfWRqv7Hsu57c4/d47+nIzRQrQJ8ftmHzGOI/168HZccREP/Qvu6FOvXZM8MK2/buJAZIdXW6qF4h2wTVAKvpkftgBxfdj32S2eX5Azzaw3X62tu5xeKljTZVkE4SG5uK1iYvruEOcFNAwibAyavk65Gi4RXSlK0ZkQrTlbBy5oN35OnGukIzuz6m+lHXCJe122Go3PCkIJRmLreorxiwlhqPiapXzLrSKNAcvwN7PB/DpnFGTe3D5CCaCEDYeUziIsvGJTsOU52ceYc0LvWGC16mPKJY4ZS3IkdCu3pjjhmC2GdrTwkNm3vTvmhxzU9SiZ+cecN44US+FfKehzbnm6OrglBaty656IL0S+BDn3BhzPenZwFLsc7mUrRaTnMLbXfqIlujKeAuW1U86byIX5mo3UKlGMJYA+GKCm6ZoKdsLeRZWMI4rYsGkU58mj8SLzIVt9VZNP6MSNVjb5BginuVSVhT1QtAfKrNW1LG0dGhSc/10irLB7O8gvJvMS5r4weABdm1DPKEoyC9iNxmmrKpPmkwmqfrB5I6Bwyj/3ZK8camMxRgUlp2q16Sb/zK68Y7Lrw/2hhq7XpyKIm91j5aamL1VacwbqgLLdIqi2KpKLOWI6J1AUSDvppItW3gZ9Lf/kE1NsI3FVY7/xTmYzRYipsAwHMzLryMPl/7prt0XtjCTm2fG2coEhWt85e8BJSUBTBwaefZhgzSCZKz65FJXEWNNXZsO900bnN0LQjT8f4Iy5KA5M7gArihlhlVlYdaQ0uhk2mdXkWUvE0Lv2UlvKp0P5y/sXGGIkNIxHKY18MxBlrX/zebjAKk3VUR6ljoss69sNOW5AiX/OfUGxyxNNj09RWvP/RCpZ5dzl0DsG+CVHPNAxpok8Fo3sN4rlcXyCqJC8a2HN3XFud6v4p++fvZIy/h2JjlDpACZ/H2a+y8SquOOgHCoyoD0R2v5WojiHntkaN14nOKYqbeNGRpqZ19jb9xj+O+SG2zj4OEJyX07yRdV6efG23sirGkKOuyxAds9YM3+1fSAfqhN8sZeV5qXXbbQrUROG8Koin0avGXGs3zgH0zu6WkCe9dKZ0+rmhVOMSb3QQHRksrtDXSgvHbH4QRPAisLqGO",
            diffie_sym_key,
        );
        // tag 1101
        decrypt_print(
            "AL2vbPOzZHGYzB1rtjfHiTv5SBD/B35wB+Qp+//MIuVxKQqSLfFH9natGX+qZoyDSzcHmO5WIqFEv/C8Kdm3rpAFsRSbl5jf/midSnUeChAYUTVn79YW67VMsWqmdCOjZ49eil20DqqsPITb6Aej9cfpOQJbxGYNawMhRaHKgy7uhyxJdsvJFJopO8QUjQmma87hG3cbws4q9AZ5sMpwHDEdfKXSc+8Q6akA1ZuueUoycwciLv16JU4Bf/bq2vB+Et4=",
            uri_params.sym_key,
        );
    }

    fn decrypt_print(encoded: &str, sym_key: [u8; 32]) -> Message {
        let result = Message::decrypt(encoded, sym_key, None).unwrap();

        println!("\n{result:?}");

        result
    }

    #[allow(clippy::type_complexity)]
    fn calculate(
        self_private_key: &str,
        other_public_key: &str,
    ) -> (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        std::string::String,
    ) {
        let self_private_key =
            hex::decode_to_array::<_, 32>(self_private_key).unwrap();
        let kp = Keypair::from_seed(self_private_key);
        let self_public_key = kp.public_key;

        println!(
            "\nself private key: {self_private_key:?}",
            self_private_key = hex::encode(self_private_key)
        );
        println!(
            "self public key : {self_public_key:?}",
            self_public_key = hex::encode(self_public_key)
        );

        let other_public_key =
            hex::decode_to_array::<_, 32>(other_public_key).unwrap();

        println!(
            "other public key: {other_public_key}",
            other_public_key = hex::encode(other_public_key)
        );
        let response_topic = sha256(other_public_key);
        println!("announcing topic: {}", hex::encode(response_topic));

        let sym_key = derive_sym_key(self_private_key, other_public_key);
        println!("sym_key: {}", hex::encode(sym_key));

        let new_topic = hex::encode(Sha256::digest(sym_key));
        println!("new topic: {new_topic}");

        #[allow(clippy::needless_return)]
        return (
            self_private_key,
            self_public_key,
            other_public_key,
            response_topic,
            sym_key,
            new_topic,
        );
    }
}
