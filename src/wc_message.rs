use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    message::{Message, MessageError},
    types::{
        Id, IrnTag, SessionAuthenticateParams, SessionAuthenticateResponse,
        SessionProposeParams, SessionProposeResponse, SessionRequestParams,
        SessionSettleParams,
    },
};

#[derive(Clone, Debug, PartialEq)]
pub struct WcMessage {
    pub data: WcData,
    pub id: Id,
    pub irn_tag_override: Option<IrnTag>,
}

impl WcMessage {
    pub fn from_value(value: Value) -> crate::Result<WcMessage> {
        serde_json::from_value::<Message>(value)?.decode()
    }

    pub fn into_raw(&self) -> crate::Result<Message> {
        Ok(Message {
            jsonrpc: "2.0".to_string(),
            method: self.data.method().map(|m| m.to_string()),
            params: self.data.params()?,
            result: self.data.result()?,
            error: self.data.error(),
            id: self.id.clone(),
        })
    }

    pub fn method(&self) -> Option<WcMethod> {
        self.data.method()
    }

    pub fn params(&self) -> crate::Result<Option<Value>> {
        self.data.params()
    }

    pub fn create_response(
        &self,
        response_data: WcData,
        irn_tag_override: Option<IrnTag>,
    ) -> WcMessage {
        WcMessage {
            data: response_data,
            id: self.id.clone(),
            irn_tag_override,
        }
    }

    pub fn irn_tag(&self) -> IrnTag {
        match &self.data {
            WcData::SessionPing => IrnTag::SessionPing,
            WcData::SessionPropose(_) => IrnTag::SessionPropose,
            WcData::SessionAuthenticate(_) => IrnTag::SessionAuthenticate,
            WcData::SessionSettle(_) => IrnTag::SessionSettle,
            WcData::SessionRequest(_) => IrnTag::SessionRequest,
            WcData::SessionDelete(_) => IrnTag::SessionDelete,

            WcData::SessionPingResponseSuccess => IrnTag::SessionPingResponse,
            WcData::SessionProposeResponse(_) => {
                IrnTag::SessionProposeApproveResponse
            }
            WcData::SessionAuthenticateResponse(_) => {
                IrnTag::SessionAuthenticateApproveResponse
            }
            WcData::SessionSettleResult(_) => IrnTag::SessionSettleResponse,
            WcData::SessionRequestResponse(_) => IrnTag::SessionRequestResponse,
            WcData::UnknownResult(_) => IrnTag::UnsupportedMethod,
            WcData::Error { .. } => IrnTag::UnsupportedMethod, // TODO it should use request IRN
        }
    }

    // https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#methods
    pub fn ttl(&self) -> u64 {
        match &self.data {
            WcData::SessionPing => 30,
            WcData::SessionPropose(_) => 300,
            WcData::SessionAuthenticate(_) => 3600,
            WcData::SessionSettle(_) => 300,
            WcData::SessionRequest(_) => 300,
            WcData::SessionDelete(_) => 86400,

            WcData::SessionPingResponseSuccess => 30,
            WcData::SessionProposeResponse(_) => 300,
            WcData::SessionAuthenticateResponse(_) => 3600,
            WcData::SessionSettleResult(_) => 300,
            WcData::SessionRequestResponse(_) => 300,
            WcData::UnknownResult(_) => 300,

            WcData::Error { .. } => 300,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum WcMethod {
    #[serde(rename = "wc_sessionPing")]
    SessionPing,

    #[serde(rename = "wc_sessionPropose")]
    SessionPropose,

    #[serde(rename = "wc_sessionAuthenticate")]
    SessionAuthenticate,

    #[serde(rename = "wc_sessionSettle")]
    SessionSettle,

    #[serde(rename = "wc_sessionRequest")]
    SessionRequest,

    #[serde(rename = "wc_sessionDelete")]
    SessionDelete,
}

impl Display for WcMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_plain::to_string(self).unwrap())
    }
}

impl FromStr for WcMethod {
    type Err = crate::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        serde_plain::from_str(s).map_err(|e| e.into())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum WcData {
    SessionPing,
    SessionPropose(SessionProposeParams),
    SessionAuthenticate(SessionAuthenticateParams),
    SessionSettle(SessionSettleParams),
    SessionRequest(SessionRequestParams),
    SessionDelete(Value),

    SessionPingResponseSuccess,
    SessionProposeResponse(SessionProposeResponse),
    SessionAuthenticateResponse(SessionAuthenticateResponse),
    SessionSettleResult(bool),
    SessionRequestResponse(Value),
    UnknownResult(Value),

    Error { message: String, code: usize },
}

impl Serialize for WcData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::SessionPing => Value::Null.serialize(serializer),
            Self::SessionPropose(p) => p.serialize(serializer),
            Self::SessionAuthenticate(p) => p.serialize(serializer),
            Self::SessionSettle(p) => p.serialize(serializer),
            Self::SessionRequest(p) => p.serialize(serializer),
            Self::SessionDelete(v) => v.serialize(serializer),

            Self::SessionPingResponseSuccess => {
                Value::Null.serialize(serializer)
            }
            Self::SessionProposeResponse(p) => p.serialize(serializer),
            Self::SessionAuthenticateResponse(p) => p.serialize(serializer),
            Self::SessionSettleResult(p) => p.serialize(serializer),
            Self::SessionRequestResponse(p) => p.serialize(serializer),
            Self::UnknownResult(v) => v.serialize(serializer),

            Self::Error { message, code } => {
                let mut map = serde_json::Map::new();
                map.insert(
                    "message".to_string(),
                    Value::String(message.clone()),
                );
                map.insert("code".to_string(), Value::Number((*code).into()));
                Value::Object(map).serialize(serializer)
            }
        }
    }
}

impl WcData {
    pub fn method(&self) -> Option<WcMethod> {
        match self {
            Self::SessionPing => Some(WcMethod::SessionPing),
            Self::SessionPropose(_) => Some(WcMethod::SessionPropose),
            Self::SessionAuthenticate(_) => Some(WcMethod::SessionAuthenticate),
            Self::SessionSettle(_) => Some(WcMethod::SessionSettle),
            Self::SessionRequest(_) => Some(WcMethod::SessionRequest),
            Self::SessionDelete(_) => Some(WcMethod::SessionDelete),

            Self::SessionPingResponseSuccess => None,
            Self::SessionProposeResponse(_) => None,
            Self::SessionAuthenticateResponse(_) => None,
            Self::SessionSettleResult(_) => None,
            Self::SessionRequestResponse(_) => None,
            Self::UnknownResult(_) => None,

            Self::Error { .. } => None,
        }
    }

    pub fn params(&self) -> crate::Result<Option<Value>> {
        Ok(match self {
            Self::SessionPing => None,
            Self::SessionPropose(p) => Some(serde_json::to_value(p)?),
            Self::SessionAuthenticate(p) => Some(serde_json::to_value(p)?),
            Self::SessionSettle(p) => Some(serde_json::to_value(p)?),
            Self::SessionRequest(p) => Some(serde_json::to_value(p)?),
            Self::SessionDelete(v) => Some(v.clone()),

            Self::SessionPingResponseSuccess => None,
            Self::SessionProposeResponse(_) => None,
            Self::SessionAuthenticateResponse(_) => None,
            Self::SessionSettleResult(_) => None,
            Self::SessionRequestResponse(_) => None,
            Self::UnknownResult(_) => None,

            Self::Error { .. } => None,
        })
    }

    pub fn result(&self) -> crate::Result<Option<Value>> {
        match self {
            Self::SessionPing
            | Self::SessionPropose(_)
            | Self::SessionAuthenticate(_)
            | Self::SessionSettle(_)
            | Self::SessionRequest(_)
            | Self::SessionDelete(_) => Ok(None),

            Self::SessionPingResponseSuccess => Ok(Some(Value::Null)),
            Self::SessionProposeResponse(v) => {
                Ok(Some(serde_json::to_value(v)?))
            }
            Self::SessionAuthenticateResponse(v) => {
                Ok(Some(serde_json::to_value(v)?))
            }
            Self::SessionSettleResult(v) => Ok(Some(serde_json::to_value(v)?)),
            Self::SessionRequestResponse(v) => Ok(Some(v.clone())),
            Self::UnknownResult(v) => Ok(Some(v.clone())),

            Self::Error { .. } => Ok(None),
        }
    }

    pub fn error(&self) -> Option<MessageError> {
        match self {
            Self::Error { message, code } => Some(MessageError {
                message: Some(message.clone()),
                code: Some(*code),
            }),
            _ => None,
        }
    }

    pub fn as_session_propose(&self) -> Option<&SessionProposeParams> {
        match self {
            Self::SessionPropose(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_session_authenticate(
        &self,
    ) -> Option<&SessionAuthenticateParams> {
        match self {
            Self::SessionAuthenticate(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_session_settle(&self) -> Option<&SessionSettleParams> {
        match self {
            Self::SessionSettle(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_session_request(&self) -> Option<&SessionRequestParams> {
        match self {
            Self::SessionRequest(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_result<R>(&self) -> Option<R>
    where
        R: DeserializeOwned,
    {
        match self {
            Self::UnknownResult(v) => {
                serde_json::from_value::<R>(v.clone()).ok()
            }
            _ => None,
        }
    }
}

impl Message {
    pub fn decode(self) -> crate::Result<WcMessage> {
        WcMessage::try_from(self)
    }
}

impl FromStr for WcMessage {
    type Err = crate::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let message = serde_json::from_str::<Message>(s)?;
        message.decode()
    }
}

impl TryFrom<Message> for WcMessage {
    type Error = crate::Error;

    fn try_from(msg: Message) -> std::result::Result<Self, Self::Error> {
        let method = msg
            .method
            .as_ref()
            .map(|method| {
                WcMethod::from_str(method).map_err(|e| {
                    crate::Error::InternalError3(
                        "Invalid method",
                        format!("{method} {e:?}"),
                    )
                })
            })
            .transpose()?;
        if method.is_some() && msg.params.is_none() {
            return Err(crate::Error::InternalError3(
                "Params is none",
                serde_json::to_string(&msg).unwrap(),
            ));
        }
        let wc_params = match method {
            Some(WcMethod::SessionPing) => WcData::SessionPing,
            Some(WcMethod::SessionPropose) => {
                WcData::SessionPropose(serde_json::from_value::<
                    SessionProposeParams,
                >(
                    msg.params.unwrap().clone()
                )?)
            }
            Some(WcMethod::SessionAuthenticate) => {
                WcData::SessionAuthenticate(serde_json::from_value::<
                    SessionAuthenticateParams,
                >(
                    msg.params.unwrap().clone()
                )?)
            }
            Some(WcMethod::SessionSettle) => {
                WcData::SessionSettle(serde_json::from_value::<
                    SessionSettleParams,
                >(
                    msg.params.unwrap().clone()
                )?)
            }
            Some(WcMethod::SessionRequest) => {
                WcData::SessionRequest(serde_json::from_value::<
                    SessionRequestParams,
                >(
                    msg.params.unwrap().clone()
                )?)
            }
            Some(WcMethod::SessionDelete) => {
                WcData::SessionDelete(msg.params.unwrap().clone())
            }

            // TODO implement typeful decoding or results here
            None => {
                if let Some(error) = &msg.error {
                    WcData::Error {
                        message: error.message.clone().unwrap_or_default(),
                        code: error.code.unwrap_or(0),
                    }
                } else {
                    WcData::UnknownResult(msg.result.unwrap_or_default())
                }
            }
        };

        Ok(WcMessage {
            data: wc_params,
            id: msg.id.clone(),
            irn_tag_override: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::primitives::FixedBytes;
    use alloy::rpc::types::{TransactionInput, TransactionRequest};
    use alloy::signers::k256::sha2::{Digest, Sha256};
    use alloy::{
        hex,
        primitives::{TxKind, U256},
    };
    use serde_json::json;

    use super::*;
    use crate::types::{
        IrnPublishParams, IrnSubscriptionParams, JsonRpcRequest,
        SessionAuthenticateResponse, SessionRequestData, SessionRequestMethod,
    };
    use crate::{
        message::Message,
        relay_auth::Keypair,
        utils::{derive_sym_key, parse_uri, sha256},
    };

    #[test]
    fn test_decode_wc_session_propose() {
        let req = "{\"id\":1743510684985756,\"jsonrpc\":\"2.0\",\"method\":\"wc_sessionPropose\",\"params\":{\"requiredNamespaces\":{},\"optionalNamespaces\":{\"eip155\":{\"chains\":[\"eip155:137\",\"eip155:1\",\"eip155:10\",\"eip155:324\",\"eip155:42161\",\"eip155:8453\",\"eip155:84532\",\"eip155:1301\",\"eip155:80094\",\"eip155:11155111\",\"eip155:100\",\"eip155:295\",\"eip155:1313161554\",\"eip155:5000\"],\"methods\":[\"personal_sign\",\"eth_accounts\",\"eth_requestAccounts\",\"eth_sendRawTransaction\",\"eth_sendTransaction\",\"eth_sign\",\"eth_signTransaction\",\"eth_signTypedData\",\"eth_signTypedData_v3\",\"eth_signTypedData_v4\",\"wallet_addEthereumChain\",\"wallet_getAssets\",\"wallet_getCallsStatus\",\"wallet_getCapabilities\",\"wallet_getPermissions\",\"wallet_grantPermissions\",\"wallet_registerOnboarding\",\"wallet_requestPermissions\",\"wallet_revokePermissions\",\"wallet_scanQRCode\",\"wallet_sendCalls\",\"wallet_switchEthereumChain\",\"wallet_watchAsset\"],\"events\":[\"chainChanged\",\"accountsChanged\"]}},\"relays\":[{\"protocol\":\"irn\"}],\"pairingTopic\":\"d0bb3bf179a70fd10245144ac7355c52a767806c9b2d852b99fc7be935934882\",\"proposer\":{\"publicKey\":\"04f1c07b7205c273b6af5b85ac267cbe28c22d036873ffe4621abc4d9213430e\",\"metadata\":{\"name\":\"AppKit Lab\",\"description\":\"AppKit Lab is the test environment for Reown's AppKit\",\"url\":\"https://appkit-lab.reown.com\",\"icons\":[\"https://appkit-lab.reown.com/favicon.svg\"]}},\"expiryTimestamp\":1743510984,\"id\":1743510684985756}}";

        let decoded = WcMessage::from_str(req).unwrap();

        println!("Decoded: {decoded:?}");

        assert_eq!(decoded.id.to_u128().unwrap(), 1743510684985756);
        assert_eq!(decoded.data.method(), Some(WcMethod::SessionPropose));
        let params = decoded.data.as_session_propose().unwrap();
        assert_eq!(
            params.pairing_topic,
            "d0bb3bf179a70fd10245144ac7355c52a767806c9b2d852b99fc7be935934882"
        );
        assert_eq!(
            params.proposer.public_key,
            "04f1c07b7205c273b6af5b85ac267cbe28c22d036873ffe4621abc4d9213430e"
        )
    }

    #[test]
    fn test_decode_wc_session_authenticate() {
        let req = "{\"id\":1743510684985985,\"jsonrpc\":\"2.0\",\"method\":\"wc_sessionAuthenticate\",\"params\":{\"authPayload\":{\"type\":\"caip122\",\"chains\":[\"eip155:137\",\"eip155:1\",\"eip155:10\",\"eip155:324\",\"eip155:42161\",\"eip155:8453\",\"eip155:84532\",\"eip155:1301\",\"eip155:80094\",\"eip155:11155111\",\"eip155:100\",\"eip155:295\",\"eip155:1313161554\",\"eip155:5000\"],\"statement\":\"Please sign with your account\",\"aud\":\"https://appkit-lab.reown.com\",\"domain\":\"appkit-lab.reown.com\",\"version\":\"1\",\"nonce\":\"cfab4ebf5b80e510b9812b06fb62af56ca7e2c0115d4b88bdeec024313451e6f\",\"iat\":\"2025-04-01T12:31:24.985Z\",\"resources\":[\"urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvZXRoX2FjY291bnRzIjpbe31dLCJyZXF1ZXN0L2V0aF9yZXF1ZXN0QWNjb3VudHMiOlt7fV0sInJlcXVlc3QvZXRoX3NlbmRSYXdUcmFuc2FjdGlvbiI6W3t9XSwicmVxdWVzdC9ldGhfc2VuZFRyYW5zYWN0aW9uIjpbe31dLCJyZXF1ZXN0L2V0aF9zaWduIjpbe31dLCJyZXF1ZXN0L2V0aF9zaWduVHJhbnNhY3Rpb24iOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGEiOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjMiOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjQiOlt7fV0sInJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XSwicmVxdWVzdC93YWxsZXRfYWRkRXRoZXJldW1DaGFpbiI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ2V0QXNzZXRzIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9nZXRDYWxsc1N0YXR1cyI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ2V0Q2FwYWJpbGl0aWVzIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9nZXRQZXJtaXNzaW9ucyI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ3JhbnRQZXJtaXNzaW9ucyI6W3t9XSwicmVxdWVzdC93YWxsZXRfcmVnaXN0ZXJPbmJvYXJkaW5nIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9yZXF1ZXN0UGVybWlzc2lvbnMiOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3Jldm9rZVBlcm1pc3Npb25zIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9zY2FuUVJDb2RlIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9zZW5kQ2FsbHMiOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3N3aXRjaEV0aGVyZXVtQ2hhaW4iOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3dhdGNoQXNzZXQiOlt7fV19fX0\"]},\"requester\":{\"publicKey\":\"04f1c07b7205c273b6af5b85ac267cbe28c22d036873ffe4621abc4d9213430e\",\"metadata\":{\"name\":\"AppKit Lab\",\"description\":\"AppKit Lab is the test environment for Reown's AppKit\",\"url\":\"https://appkit-lab.reown.com\",\"icons\":[\"https://appkit-lab.reown.com/favicon.svg\"]}},\"expiryTimestamp\":1743514284}}";

        let decoded = WcMessage::from_str(req).unwrap();

        println!("Decoded: {decoded:?}");

        assert_eq!(decoded.id.to_u128().unwrap(), 1743510684985985);
        assert_eq!(decoded.data.method(), Some(WcMethod::SessionAuthenticate));
        let params = decoded.data.as_session_authenticate().unwrap();
        assert_eq!(
            params.requester.public_key,
            "04f1c07b7205c273b6af5b85ac267cbe28c22d036873ffe4621abc4d9213430e"
        )
    }

    // this is with https://appkit-lab.reown.com/library/wagmi-all/
    #[test]
    fn test_cacao_flow() {
        let uri_params = parse_uri(
        "wc:b61b370a99504fa0bd4c8aef4eecdd77c2be9e94e72fb74aedca828e5f33cb79@2?relay-protocol=irn&symKey=4ef8aa7fff3e8354b5032525520255ab526cc661f16b5eff95fe7cd3f0b32f0b&expiryTimestamp=1743768178&methods=wc_sessionAuthenticate".to_string(),
        ).unwrap();

        // First message: SessionPropose
        let message1 = decrypt(
            "AEJKPBI19Jv57WrKe5BHyZDoaW8pTQi1Fdl97klacGd8HAl0AwQpstTerQkoMPRzr2mVhlzwox30pf1S3fzIo0VcWeIi3exFlSg+vrrdkUaiS0U3U+1FwWAjpk06wlhaOKplgdVvoBNIBIVG0h6QZSqT/V3tz6jYtm276i6RJpPGjh6H2lTWRU7WQZXzy/g/cIO7J/lnai4ZV20oPCeymPGDsI2gWGb2Rf4rB2CYC2NxkVbhRvP0jMGreIegF2IOIUl3IIl8XCgnwvn7AaP6FrYnHk8klFh2r1+649csqtfc3i3pWKdsRN9H2HUeoH+UL3zy5jj2LCDMbtghpqPoul5rERC0ccEzXUaKS5APDkWLB5WqepXsbXRedxQ0JQkAAagqeLa2CZP9STFDnNOUiVx1x53lxB5coQROnt2Byc3W3xnEkufFp+ygnfrMSBCmM/mTr5FJ+gQJIognqJ32f1C2o1UqI+8MQ/WiKL9fZXKzATxMGVNKHwoLKhTotYRET6ocCaBVttFUXP7Bzvp/lL1xrweFI9xb83SXEQojildGKhhW5/YWeHJsY9Om+wo9o+0mpgRaydkXz8ad24aFEJnmZ50Q1hv7DzhwTQZ1aQZn9RSvKiaEFimz5M7GusXP/92wKLOFldo18HzoLczQ3rgNno549sfosR7z6QgXjIR2+L2CdA4Cxy10zDpUIhHg0t7Ey+kPtiRxP8lQVa/e0m6bQusaM1SsyEifPVNjtk4JUj4dTvdD5BDvFeMOFiuzsNtoZom2vsdLz71j1eLSpIAGwbMmsgjtbc8wboqceQnTR5fAIS9D4On7Og9Nr4E1Mz9Jo7LtUK9Hg1Crq08g1cSEPZdIMX6dZqc1viEdwzaR2Hks9e7DwUBN5j5T4Jmb0Elm9Ke7SMuC1bD7Ijp0PQbWkgondo0iBQyXT7Q8A+HWX/kfar80gFsSt5KvUG2A9wGxwnJw8WnDhxcnyleXh+0COIInzQ1uFNA+RQeymsjFqMpw1QFlfySe6S0brgs2ty14ZXM11hWOvjNf2kynBAux8JeOnUpSPOnl2VwNuFo04CQLUtlabyb5T9Cwtk7ftph+mZDOj2feCGkFJXF/9IRMsN7kBCyxoc5hdnFNHFbN7rcHvYeS8B3n3mN1Rf6jiyOwuSbu0RgBBeRMgTFoMhx6KylaMA/8jsv/NlV7XMO8Z8+2I0ZBZW1xhGI+1LeR7EtEMQOBwpeqnEmcD+cwfsFWzO+w8cOeTLSNfyTyrAVzK5xvCfBtmwq2Zcv9B7fHVwGVU46io4zZVf0VA4OcD/OPuGRpLQLM/YH29+NCLMYdMgFP/aK3T6tSXaDgmfTW7MfzaxaePo/QDeZiDiMewCgj5OAZWHE9JCICVywZ2AaGBry6MbVVr7pz/1zKtoH7bZ10k9xxlqFLrcVq3j0Es2yQ3E2lr2Hhbiu7D1gKfky9AjotKJ2Lc19vby4ZYs4c4AjxIClO0L+OXbDkavmxd3kAKw0Dpnfw/Riw3WDyfRMWDuPSZInPCcWhrtU+u9yfN58fpccl+17bTWzW1tacJrH3NHI35ln99nrpMklN6akdDaYG9qnQB/leY/JiUC5I6Bx37hA/ErtFAf9wPE1lQ7+vwallJQnm1bSXkCQWV+huJwNDaTdzMgmjkglaK67vOkBUBr4YmOWvzoxIt5ZYJPuipZlzE8koyhj7jTIb0HO0vvvCDI+M4ubrvSkqkcQ86MFZA+zw2Vgej/WcccrqaM1MnbV9MT6f5GDxmktLtV89aSOb3ZUY0fkgDj65evl9qXFOdroB57+SyxgOSv62pGRq9sstrlplQqnsgPrNeIZ+sowMKE7o89Iy9QtcuYHpUmA8tcHtD0WX8GevvnghIr0=",
            uri_params.sym_key,
        );
        message1
            .clone()
            .decode()
            .expect("SessionPropose decode failed");
        assert_eq!(
            message1,
            Message {
                jsonrpc: "2.0".to_string(),
                method: Some(WcMethod::SessionPropose.to_string()),
                params: Some(json!({
                    "expiryTimestamp": 1743768178,
                    "id": 1743767878967710_u64,
                    "optionalNamespaces": {
                        "eip155": {
                            "chains": [
                                "eip155:137", "eip155:1", "eip155:10", "eip155:324",
                                "eip155:42161", "eip155:8453", "eip155:84532",
                                "eip155:1301", "eip155:80094", "eip155:11155111",
                                "eip155:100", "eip155:295", "eip155:1313161554",
                                "eip155:5000", "eip155:2741"
                            ],
                            "events": ["chainChanged", "accountsChanged"],
                            "methods": [
                                "personal_sign", "eth_accounts", "eth_requestAccounts",
                                "eth_sendRawTransaction", "eth_sendTransaction",
                                "eth_sign", "eth_signTransaction",
                                "eth_signTypedData", "eth_signTypedData_v3",
                                "eth_signTypedData_v4", "wallet_addEthereumChain",
                                "wallet_getAssets", "wallet_getCallsStatus",
                                "wallet_getCapabilities", "wallet_getPermissions",
                                "wallet_grantPermissions", "wallet_registerOnboarding",
                                "wallet_requestPermissions", "wallet_revokePermissions",
                                "wallet_scanQRCode", "wallet_sendCalls",
                                "wallet_switchEthereumChain", "wallet_watchAsset"
                            ]
                        }
                    },
                    "pairingTopic": "b61b370a99504fa0bd4c8aef4eecdd77c2be9e94e72fb74aedca828e5f33cb79",
                    "proposer": {
                        "metadata": {
                            "description": "AppKit Lab is the test environment for Reown's AppKit",
                            "icons": ["https://appkit-lab.reown.com/favicon.svg"],
                            "name": "AppKit Lab",
                            "url": "https://appkit-lab.reown.com"
                        },
                        "publicKey": "62dbe3bc5bf8395e6f247a2b7aaedcf11e33fccd68d77da1b2752d4f0cc3755f"
                    },
                    "relays": [{"protocol": "irn"}],
                    "requiredNamespaces": {}
                })),
                result: None,
                error: None,
                id: Id::U128(1743767878967710),
            }
        );

        // Second message: SessionAuthenticate
        let message2 = decrypt(
            "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",
            uri_params.sym_key,
        );
        message2
            .clone()
            .decode()
            .expect("SessionAuthenticate decode failed");
        assert_eq!(
            message2,
            Message {
                jsonrpc: "2.0".to_string(),
                method: Some(WcMethod::SessionAuthenticate.to_string()),
                params: Some(json!({
                    "authPayload": {
                        "aud": "https://appkit-lab.reown.com",
                        "chains": [
                            "eip155:137", "eip155:1", "eip155:10", "eip155:324", "eip155:42161",
                            "eip155:8453", "eip155:84532", "eip155:1301", "eip155:80094",
                            "eip155:11155111", "eip155:100", "eip155:295", "eip155:1313161554",
                            "eip155:5000", "eip155:2741"
                        ],
                        "domain": "appkit-lab.reown.com",
                        "iat": "2025-04-04T11:57:58.967Z",
                        "nonce": "2dc2e52ebcfc7d0306403e3053b9e3fac8ebed330381c8dc94fda94ffb21fad2",
                        "resources": [
                            "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvZXRoX2FjY291bnRzIjpbe31dLCJyZXF1ZXN0L2V0aF9yZXF1ZXN0QWNjb3VudHMiOlt7fV0sInJlcXVlc3QvZXRoX3NlbmRSYXdUcmFuc2FjdGlvbiI6W3t9XSwicmVxdWVzdC9ldGhfc2VuZFRyYW5zYWN0aW9uIjpbe31dLCJyZXF1ZXN0L2V0aF9zaWduIjpbe31dLCJyZXF1ZXN0L2V0aF9zaWduVHJhbnNhY3Rpb24iOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGEiOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjMiOlt7fV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjQiOlt7fV0sInJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XSwicmVxdWVzdC93YWxsZXRfYWRkRXRoZXJldW1DaGFpbiI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ2V0QXNzZXRzIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9nZXRDYWxsc1N0YXR1cyI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ2V0Q2FwYWJpbGl0aWVzIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9nZXRQZXJtaXNzaW9ucyI6W3t9XSwicmVxdWVzdC93YWxsZXRfZ3JhbnRQZXJtaXNzaW9ucyI6W3t9XSwicmVxdWVzdC93YWxsZXRfcmVnaXN0ZXJPbmJvYXJkaW5nIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9yZXF1ZXN0UGVybWlzc2lvbnMiOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3Jldm9rZVBlcm1pc3Npb25zIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9zY2FuUVJDb2RlIjpbe31dLCJyZXF1ZXN0L3dhbGxldF9zZW5kQ2FsbHMiOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3N3aXRjaEV0aGVyZXVtQ2hhaW4iOlt7fV0sInJlcXVlc3Qvd2FsbGV0X3dhdGNoQXNzZXQiOlt7fV19fX0"
                        ],
                        "statement": "Please sign with your account",
                        "type": "caip122",
                        "version": "1"
                    },
                    "expiryTimestamp": 1743771478,
                    "requester": {
                        "metadata": {
                            "description": "AppKit Lab is the test environment for Reown's AppKit",
                            "icons": ["https://appkit-lab.reown.com/favicon.svg"],
                            "name": "AppKit Lab",
                            "url": "https://appkit-lab.reown.com"
                        },
                        "publicKey": "62dbe3bc5bf8395e6f247a2b7aaedcf11e33fccd68d77da1b2752d4f0cc3755f"
                    }
                })),
                result: None,
                error: None,
                id: Id::U128(1743767878967691),
            }
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

        // Third message: SessionAuthenticateResponse
        let message3 = decrypt(
            "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",
            diffie_sym_key,
        );
        let message3_decoded = message3
            .decode_result::<SessionAuthenticateResponse>()
            .expect("SessionAuthenticateResponse decode failed");
        assert_eq!(
            message3,
            Message {
                jsonrpc: "2.0".to_string(),
                method: None,
                params: None,
                result: Some(json!({
                  "cacaos": [
                    {
                      "h": {
                        "t": "caip122"
                      },
                      "p": {
                        "aud": "https://appkit-lab.reown.com",
                        "domain": "appkit-lab.reown.com",
                        "iat": "2025-04-04T11:57:58.967Z",
                        "iss": "did:pkh:eip155:137:0x93a00dcebe229461F0d2D3462f834DfFD0fBbBd3",
                        "nonce": "2dc2e52ebcfc7d0306403e3053b9e3fac8ebed330381c8dc94fda94ffb21fad2",
                        "resources": [
                          "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvZXRoX3NlbmRSYXdUcmFuc2FjdGlvbiI6W3siY2hhaW5zIjpbImVpcDE1NToxMzciLCJlaXAxNTU6MSIsImVpcDE1NToxMCIsImVpcDE1NTozMjQiLCJlaXAxNTU6NDIxNjEiLCJlaXAxNTU6ODQ1MyIsImVpcDE1NTo4NDUzMiIsImVpcDE1NToxMTE1NTExMSJdfV0sInJlcXVlc3QvZXRoX3NlbmRUcmFuc2FjdGlvbiI6W3siY2hhaW5zIjpbImVpcDE1NToxMzciLCJlaXAxNTU6MSIsImVpcDE1NToxMCIsImVpcDE1NTozMjQiLCJlaXAxNTU6NDIxNjEiLCJlaXAxNTU6ODQ1MyIsImVpcDE1NTo4NDUzMiIsImVpcDE1NToxMTE1NTExMSJdfV0sInJlcXVlc3QvZXRoX3NpZ24iOlt7ImNoYWlucyI6WyJlaXAxNTU6MTM3IiwiZWlwMTU1OjEiLCJlaXAxNTU6MTAiLCJlaXAxNTU6MzI0IiwiZWlwMTU1OjQyMTYxIiwiZWlwMTU1Ojg0NTMiLCJlaXAxNTU6ODQ1MzIiLCJlaXAxNTU6MTExNTUxMTEiXX1dLCJyZXF1ZXN0L2V0aF9zaWduVHJhbnNhY3Rpb24iOlt7ImNoYWlucyI6WyJlaXAxNTU6MTM3IiwiZWlwMTU1OjEiLCJlaXAxNTU6MTAiLCJlaXAxNTU6MzI0IiwiZWlwMTU1OjQyMTYxIiwiZWlwMTU1Ojg0NTMiLCJlaXAxNTU6ODQ1MzIiLCJlaXAxNTU6MTExNTUxMTEiXX1dLCJyZXF1ZXN0L2V0aF9zaWduVHlwZWREYXRhIjpbeyJjaGFpbnMiOlsiZWlwMTU1OjEzNyIsImVpcDE1NToxIiwiZWlwMTU1OjEwIiwiZWlwMTU1OjMyNCIsImVpcDE1NTo0MjE2MSIsImVpcDE1NTo4NDUzIiwiZWlwMTU1Ojg0NTMyIiwiZWlwMTU1OjExMTU1MTExIl19XSwicmVxdWVzdC9ldGhfc2lnblR5cGVkRGF0YV92MyI6W3siY2hhaW5zIjpbImVpcDE1NToxMzciLCJlaXAxNTU6MSIsImVpcDE1NToxMCIsImVpcDE1NTozMjQiLCJlaXAxNTU6NDIxNjEiLCJlaXAxNTU6ODQ1MyIsImVpcDE1NTo4NDUzMiIsImVpcDE1NToxMTE1NTExMSJdfV0sInJlcXVlc3QvZXRoX3NpZ25UeXBlZERhdGFfdjQiOlt7ImNoYWlucyI6WyJlaXAxNTU6MTM3IiwiZWlwMTU1OjEiLCJlaXAxNTU6MTAiLCJlaXAxNTU6MzI0IiwiZWlwMTU1OjQyMTYxIiwiZWlwMTU1Ojg0NTMiLCJlaXAxNTU6ODQ1MzIiLCJlaXAxNTU6MTExNTUxMTEiXX1dLCJyZXF1ZXN0L3BlcnNvbmFsX3NpZ24iOlt7ImNoYWlucyI6WyJlaXAxNTU6MTM3IiwiZWlwMTU1OjEiLCJlaXAxNTU6MTAiLCJlaXAxNTU6MzI0IiwiZWlwMTU1OjQyMTYxIiwiZWlwMTU1Ojg0NTMiLCJlaXAxNTU6ODQ1MzIiLCJlaXAxNTU6MTExNTUxMTEiXX1dfX19"
                        ],
                        "statement": "Please sign with your account I further authorize the stated URI to perform the following actions on my behalf: (1) 'request': 'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'eth_signTransaction', 'eth_signTypedData', 'eth_signTypedData_v3', 'eth_signTypedData_v4', 'personal_sign' for 'eip155'.",
                        "version": "1"
                      },
                      "s": {
                        "s": "0xd99e4fc4558539f2deb36041d85173e066a6a021c276cb320b983b94a989a73124f7409e3a28da775c790172998753a7579390907890c0106ca74c93ba4f50801c",
                        "t": "eip191"
                      }
                    }
                  ],
                  "responder": {
                    "metadata": {
                      "description": "React Wallet for WalletConnect",
                      "icons": ["https://avatars.githubusercontent.com/u/37784886"],
                      "name": "React Wallet Example",
                      "url": "https://walletconnect.com/"
                    },
                    "publicKey": "b888ea88e58ad03b935da236b662c037f3b391210ef4aabaf83025f046797645"
                  }
                })),
                error: None,
                id: Id::U128(1743767878967691)
            }
        );

        let cacao = message3_decoded
            .result
            .as_ref()
            .unwrap()
            .cacaos
            .first()
            .unwrap();
        cacao.verify().unwrap();

        println!("cacao verification success");

        // assert!(false);
    }

    // with localhost:3002
    #[test]
    fn test_settle_flow() {
        let uri_params = parse_uri(
            "wc:6c0a8da4a0c672f063bc9972ea1a40b88c5a20c5b8984237987121d6f6024025@2?relay-protocol=irn&symKey=1b53c9465436bef7fd23211a0c233c60b6799b47c20db904df0bbe2ff6227a13&expiryTimestamp=1744290863".to_string(),
        ).unwrap();

        // first message from dapp to wallet
        // irn tag 1100
        let message1 = decrypt(
            "APJp0bXg8XcsUBeyyf/yAxikhfBBmguNF2VZiUAprqsNdWulICHbgvfzpbhvhnV3Q6nSt513k58Tp87MDp5s0G/iir1/IIV8qC7mShut4dOMTzCj9yderIErYmkgaR+XYqDBLn/uXQT8xIHrnyy9egWu3CE0bk2exTYC30abagrMcB8lclXkwTSz3H+39bbUv5G+8rWyYMFpYJaUF2KQUtIkeL4jV4kpT4S0+3cYMfwbS5+9yKR4iOzxfYkb93qOiZH1dIYZzHV5ng5VzjwI7Cd4CZqoJtFxQWHMH/+0hxWCiONbaGMGXLpJUysd7iOfjpuRWOzDvpLb3MYIBSf1sePiSiE/mm63qSkbZURbIScY9HJGJ5tXVacfA1w6XCtsDzhgeuVROsKS62salM1u0umwaaDBFyD6rDoNf94YItcdAYqb4Zp/nMiHzWo6vHebc+xpBJw14gqETVP4XiYmGbbGrSxyG4+tN2u8I/e9zyT5aGqdr6OyZ04PF5biFzyz9IyC/2mdsWOGU10uV6246A2r9yXyS2kyEK2Ed+mumvBETPnD4Tx8Jop2+x96WrBggunJrH1M6eOA2zeu1XdA1qpYnHKQ7JmePifbZR+VkGmyXxJ4omUXFcG+VaMjghWrOp6tlwDXbcQDVpTDuN2mEi28SwAhbJf8m4ag+90UGXtjTFbXv6AM7pGTdJD9x9Bs9mLUHlRYzCSS6uObpMDVgVi+ZiVXOPirmrW9QX8xEzzGIgXzCTg7JiT0RbfMmhdwd/dAwNO4kXl7s9XaSlMQycA6rgmKhR0Z3c9hLKflD6JPsehq50Fs08l/qIzgI1/Kw/8O/HKVhhpsdAqKZj89qDdauNXBb3SHbbOg",
            uri_params.sym_key,
        );
        message1
            .clone()
            .decode()
            .expect("SessionPropose decode failed");
        assert_eq!(
            message1,
            Message {
                jsonrpc: "2.0".to_string(),
                method: Some(WcMethod::SessionPropose.to_string()),
                params: Some(json!({
                  "expiryTimestamp": 1744290864,
                  "optionalNamespaces": {
                    "eip155": {
                      "chains": ["eip155:1", "eip155:137"],
                      "events": ["chainChanged", "accountsChanged"],
                      "methods": ["eth_sendTransaction", "personal_sign"]
                    }
                  },
                  "pairingTopic": "6c0a8da4a0c672f063bc9972ea1a40b88c5a20c5b8984237987121d6f6024025",
                  "proposer": {
                    "metadata": {
                      "description": "App to test WalletConnect network",
                      "icons": [],
                      "name": "React App",
                      "url": "http://localhost:3002"
                    },
                    "publicKey": "690a17937795cf5af845bd7c0701156f647d9bcb211eb7bd85d362fa371cb02d"
                  },
                  "relays": [
                    {
                      "protocol": "irn"
                    }
                  ],
                  "requiredNamespaces": {}
                }
                )),
                result: None,
                error: None,
                id: Id::U128(1744290564004257),
            }
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
        // irn tag 1102
        let message2 = decrypt(
            "APjVUGlm0Tmem9SpiHcoYZ0qfWRqv7Hsu57c4/d47+nIzRQrQJ8ftmHzGOI/168HZccREP/Qvu6FOvXZM8MK2/buJAZIdXW6qF4h2wTVAKvpkftgBxfdj32S2eX5Azzaw3X62tu5xeKljTZVkE4SG5uK1iYvruEOcFNAwibAyavk65Gi4RXSlK0ZkQrTlbBy5oN35OnGukIzuz6m+lHXCJe122Go3PCkIJRmLreorxiwlhqPiapXzLrSKNAcvwN7PB/DpnFGTe3D5CCaCEDYeUziIsvGJTsOU52ceYc0LvWGC16mPKJY4ZS3IkdCu3pjjhmC2GdrTwkNm3vTvmhxzU9SiZ+cecN44US+FfKehzbnm6OrglBaty656IL0S+BDn3BhzPenZwFLsc7mUrRaTnMLbXfqIlujKeAuW1U86byIX5mo3UKlGMJYA+GKCm6ZoKdsLeRZWMI4rYsGkU58mj8SLzIVt9VZNP6MSNVjb5BginuVSVhT1QtAfKrNW1LG0dGhSc/10irLB7O8gvJvMS5r4weABdm1DPKEoyC9iNxmmrKpPmkwmqfrB5I6Bwyj/3ZK8camMxRgUlp2q16Sb/zK68Y7Lrw/2hhq7XpyKIm91j5aamL1VacwbqgLLdIqi2KpKLOWI6J1AUSDvppItW3gZ9Lf/kE1NsI3FVY7/xTmYzRYipsAwHMzLryMPl/7prt0XtjCTm2fG2coEhWt85e8BJSUBTBwaefZhgzSCZKz65FJXEWNNXZsO900bnN0LQjT8f4Iy5KA5M7gArihlhlVlYdaQ0uhk2mdXkWUvE0Lv2UlvKp0P5y/sXGGIkNIxHKY18MxBlrX/zebjAKk3VUR6ljoss69sNOW5AiX/OfUGxyxNNj09RWvP/RCpZ5dzl0DsG+CVHPNAxpok8Fo3sN4rlcXyCqJC8a2HN3XFud6v4p++fvZIy/h2JjlDpACZ/H2a+y8SquOOgHCoyoD0R2v5WojiHntkaN14nOKYqbeNGRpqZ19jb9xj+O+SG2zj4OEJyX07yRdV6efG23sirGkKOuyxAds9YM3+1fSAfqhN8sZeV5qXXbbQrUROG8Koin0avGXGs3zgH0zu6WkCe9dKZ0+rmhVOMSb3QQHRksrtDXSgvHbH4QRPAisLqGO",
            diffie_sym_key,
        );
        message2
            .clone()
            .decode()
            .expect("SessionSettle decode failed");
        // message2
        //     .try_decode::<SessionSettleParams>()
        //     .expect("SessionSettle decode failed");
        assert_eq!(
            message2,
            Message {
                jsonrpc: "2.0".to_string(),
                method: Some(WcMethod::SessionSettle.to_string()),
                params: Some(json!({
                  "controller": {
                    "metadata": {
                      "description": "React Wallet for WalletConnect",
                      "icons": [
                        "https://avatars.githubusercontent.com/u/37784886"
                      ],
                      "name": "React Wallet Example",
                      "url": "https://walletconnect.com/"
                    },
                    "publicKey": "886cea3da4d8ffa0ea6a10350ae9c2c882c52da1f00666adbb94af802e7d2414"
                  },
                  "expiry": 1744895416,
                  "namespaces": {
                    "eip155": {
                      "accounts": [
                        "eip155:1:0x93a00dcebe229461F0d2D3462f834DfFD0fBbBd3",
                        "eip155:1:0xCEF2AA53EDB74479013e169Df978831920dA04f4",
                        "eip155:137:0x93a00dcebe229461F0d2D3462f834DfFD0fBbBd3",
                        "eip155:137:0xCEF2AA53EDB74479013e169Df978831920dA04f4"
                      ],
                      "chains": [
                        "eip155:1",
                        "eip155:137"
                      ],
                      "events": [
                        "accountsChanged",
                        "chainChanged"
                      ],
                      "methods": [
                        "personal_sign",
                        "eth_sendTransaction"
                      ]
                    }
                  },
                  "relay": {
                    "protocol": "irn"
                  },
                  "sessionProperties": {
                    "capabilities": "{}"
                  }
                })),
                result: None,
                error: None,
                id: Id::U128(1744290616431615),
            }
        );

        // irn tag 1101
        let message3 = decrypt(
            "AL2vbPOzZHGYzB1rtjfHiTv5SBD/B35wB+Qp+//MIuVxKQqSLfFH9natGX+qZoyDSzcHmO5WIqFEv/C8Kdm3rpAFsRSbl5jf/midSnUeChAYUTVn79YW67VMsWqmdCOjZ49eil20DqqsPITb6Aej9cfpOQJbxGYNawMhRaHKgy7uhyxJdsvJFJopO8QUjQmma87hG3cbws4q9AZ5sMpwHDEdfKXSc+8Q6akA1ZuueUoycwciLv16JU4Bf/bq2vB+Et4=",
            uri_params.sym_key,
        );
        // message3
        //     .try_decode::<SessionProposeResponse>()
        //     .expect("SessionProposeResponse decode failed");
        assert_eq!(
            message3,
            Message {
                jsonrpc: "2.0".to_string(),
                method: None,
                params: None,
                result: Some(json!({
                    "relay": {
                        "protocol": "irn"
                    },
                    "responderPublicKey": "886cea3da4d8ffa0ea6a10350ae9c2c882c52da1f00666adbb94af802e7d2414",
                })),
                error: None,
                id: Id::U128(1744290564004257),
            }
        );

        // assert!(false);
    }

    fn decrypt(encoded: &str, sym_key: [u8; 32]) -> Message {
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

    #[test]
    fn decode_session_request_eth_transaction() {
        let request_original = json!({"id":"1745231798527575","jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"eth_sendTransaction","params":[{"chainId":"0x1","gas":"0x3635b","maxFeePerGas":"0x9389ef24","maxPriorityFeePerGas":"0x77359400","value":"0xde0b6b3a7640000","from":"0x0000000000000000000000000000000000000123","to":"0x66a9893cc07d91d95644aedd05d03f95e1dba8af","data":"0x3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000680626bd00000000000000000000000000000000000000000000000000000000000000040b000604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc20001f4dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c00000000000000000000000000000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000000000012300000000000000000000000000000000000000000000000000000000607363570c"}],"expiryTimestamp":1745232098},"chainId":"eip155:1"}});

        let request = WcMessage::from_value(request_original.clone()).unwrap();

        assert_eq!(
            serde_json::to_value(request.into_raw().unwrap()).unwrap(),
            request_original,
            "serialization inconsistency",
        );

        assert_eq!(request.data.method(), Some(WcMethod::SessionRequest));

        let params = request.data.as_session_request().unwrap();
        assert_eq!(
            params.request.method,
            SessionRequestMethod::EthSendTransaction
        );

        let data = "0x3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000680626bd00000000000000000000000000000000000000000000000000000000000000040b000604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc20001f4dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c00000000000000000000000000000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000000000012300000000000000000000000000000000000000000000000000000000607363570c".parse().unwrap();
        assert_eq!(
            params.request.params,
            SessionRequestData::EthSendTransaction(Box::new(
                TransactionRequest {
                    chain_id: Some(1),
                    gas: Some(0x3635b),
                    max_fee_per_gas: Some(0x9389ef24),
                    max_priority_fee_per_gas: Some(0x77359400),
                    value: Some(
                        U256::from_str_radix("de0b6b3a7640000", 16).unwrap()
                    ),
                    from: Some(
                        "0x0000000000000000000000000000000000000123"
                            .parse()
                            .unwrap()
                    ),
                    to: Some(TxKind::Call(
                        "0x66a9893cc07d91d95644aedd05d03f95e1dba8af"
                            .parse()
                            .unwrap()
                    )),
                    input: TransactionInput {
                        input: None,
                        data: Some(data)
                    },
                    ..Default::default()
                }
            ))
        );
    }

    #[test]
    fn decode_session_request_personal_sign() {
        let request_original = json!({"id":"1749782874445682","jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"personal_sign","params":["0x6170706b69742d6c61622e72656f776e2e636f6d2077616e747320796f7520746f207369676e20696e207769746820796f757220457468657265756d206163636f756e743a0a3078303030303030303030303030303030303030303030303030303030303030303030303030303132330a0a506c65617365207369676e207769746820796f7572206163636f756e740a0a5552493a2068747470733a2f2f6170706b69742d6c61622e72656f776e2e636f6d0a56657273696f6e3a20310a436861696e2049443a203133370a4e6f6e63653a20323535643664363463323861373366313639666536616466383836656133306561306463633838656363396630356232393938356332343061393866666630610a4973737565642041743a20323032352d30362d31335430323a34373a35342e3135365a", "0x0000000000000000000000000000000000000123"],"expiryTimestamp":1749783174},"chainId":"eip155:1"}});

        let request = WcMessage::from_value(request_original.clone()).unwrap();

        assert_eq!(
            serde_json::to_value(request.into_raw().unwrap()).unwrap(),
            request_original,
            "serialization inconsistency",
        );

        assert_eq!(request.data.method(), Some(WcMethod::SessionRequest));
        let params = request.data.as_session_request().unwrap();
        assert_eq!(params.request.method, SessionRequestMethod::PersonalSign);
        assert_eq!(
            params.request.params,
            SessionRequestData::PersonalSign {
                message: "0x6170706b69742d6c61622e72656f776e2e636f6d2077616e747320796f7520746f207369676e20696e207769746820796f757220457468657265756d206163636f756e743a0a3078303030303030303030303030303030303030303030303030303030303030303030303030303132330a0a506c65617365207369676e207769746820796f7572206163636f756e740a0a5552493a2068747470733a2f2f6170706b69742d6c61622e72656f776e2e636f6d0a56657273696f6e3a20310a436861696e2049443a203133370a4e6f6e63653a20323535643664363463323861373366313639666536616466383836656133306561306463633838656363396630356232393938356332343061393866666630610a4973737565642041743a20323032352d30362d31335430323a34373a35342e3135365a".to_string(),
                account: "0x0000000000000000000000000000000000000123".parse().unwrap()
            }

        );
    }

    #[test]
    fn full_scenario_personal_sign() {
        // wc:e70cc46faf27cc551138570ed7ea3d186715b1878e78e7b3a4e840897e63797e@2?relay-protocol=irn&symKey=bdc0c9a238da979b85d42ca30ba2b92049ceaa9e16c59400a49898812ee6f747&expiryTimestamp=1750246699
        let pairing_sym_key = FixedBytes::<32>::from_str(
            "bdc0c9a238da979b85d42ca30ba2b92049ceaa9e16c59400a49898812ee6f747",
        )
        .unwrap()
        .into();

        let (
            _self_private_key,
            _self_public_key,
            _other_public_key,
            _response_topic,
            diffie_sym_key,
            _diffie_topic,
        ) = calculate(
            "e4a79a1a00a823f0a6a5b791aeb72c928d16032eff54ac50d1ad927890c08bf7",
            "0ead7d6eebb88f3b2eece0d1879b7ca76ce83b32c46b8a0d7131503c747a3022",
        );

        // SessionProposal sent by dapp
        decode_irn_subscription(
            json!({"id":"448063081849090","jsonrpc":"2.0","method":"irn_subscription","params":{"id":"6ef6156084c9fca668105f05cb484ef7f13dccada5992cad516998c996a9719c","data":{"topic":"e70cc46faf27cc551138570ed7ea3d186715b1878e78e7b3a4e840897e63797e","message":"AKlsUT6PHpKfKxSf9XUkTTL0DLxpf/AxqR2joQjOH0B8qMBcKfQq5ntR124+WNDXzfOamufgbr1NeWt7r5MuqwcPdyvYzY6dutqI/eAFxpAq4UiRLfH2iuAMbN4UNGzk1Ohw2+J+BeVAybEiEIAmMyF4ECtWMOcsP20tN3+7+zSwrKzgpt507yccqqpgo9ofNMJDk3hxZRoL9SNJB8BI2/gouLxRlY0fjVaRtPlobf4TYKhElieuoE/HMybTrNBDOedPSAgGIrCIdaabVlCp2cX75cfUvc2Cv9aImlFjTFgGfsu0XKbPDqNKKx5tQA7xBAk1R1fB/lNSvds6LAvu6iq2E2LLnIq5uQgrh1p80KRhoRpmFrEbs/e8ql2coSm6fHgFO7oCSUJOPlfCWnb/IwJ5x92ZUNdX3TBbp6f1YcnToKR4eWFeC5AcyuB8YuSQztPJfINTXRE85sh4gg/tBBW3y2QAZLw4j5ijnVl7o1PmLJA4Ub3Rrig4S8ke51/iUh0zbnaEiXHDisUq0wQLRjVWrmN71TIwBrHLpjQBMZ3a4IzDeG9lPfHW6Bqq0vlxHCuiB7eoUmNC6s9jy2Vl9LbesV3jxzY4aWdsvk+Vj1lZliqTS2Ey8Kgc4AIFOr+x9oHxWiK1eP/5n+ybSa8v2LIIinxLDnT+Xz9KxYG8e3vHzWsk+9+C8XObdNdVgJ0e0s8+aEjwKS8e+qTh8PKE2Z/HHsHvWaT4Tbr8Mu5bQGPtV6n4Yhdr2bJPujsVqFqzeNmPw9p6zGBZIcanLoUuQLPrSEOjz3e2+qUhkv+lJ4P6TlsVCl/P2t9vHBdxWXJ+kn6El3GHkX9c+fGDi+wcd/iaMwd6pcmaGvf0w/eGV9fXDH6h+Y4A1eBOzFtL8uIF8QqFz6NZYSFLmuXC6JWzNH72ZbTrWYeQviGhtHUcRfxA+cU1POeRU2sIsdI1dweiQD9GLdFQKB6j4QFF5iLORYEfQI/yGnS6qxl1T4kyDRZs5ymQYcXfpV3cwhJlwESHA3ygq9tUSoFPG6pZK8j0C88C78feIw9rC7ZI9gyNnX16h53arbT4Akes6lZO28JYNfVK6sg9T1FUhB2eaP8qnB6k98O0wyV1VtKhRwCYjyGy7LIMdyK+E2wlGPVJXWfW2530DS8mcmfTgAgzDRQp/Cdl0mBJ0E63PIMutWdyi0NRGrPv3U79vv9UB8nvy1E9Rcyxy2qbUqJoPlX1AyHljGMXGRzh0enln4sdZYhM8M5PppMUTHkIjuBQVo4h/6UPZgfSe9NEh9H0VyZG5nuOCPVQ7jXqBi682gFo0sbn2eYAaT/Z5lwbfH3AJUbGnMQ8gnSCd60oFSBVF/L/BpjsHHIAUFEziSjSQy/fDZs4TjyM079A625JQXrl0tqLiUn2d66Y6JgTG105pA5D0viJXjkrzFUxas8c2v0oun2fK8BOLZ66I9q+xO5k0Q3U25ZA/pofwSfQahJxFPvkvP8TDCFO/HXwdrnw4LSC/aJ22axMITIqt6sGY7kw7v0JoiCrCx9cUGLYWBPqg7caVE+V399wV1StVRAJEM0O+gUyZB7Ya/WyFs2C95yAIREK/GJOi7TekcXP5VfBikUPFqhLY69dId5f0xaUMOR0LTjo2OByYzQCJ2j3UL0k2XHy4ZkNseTjLsCQqfSsnGF8hS5MGFvPoGDoq2de6swFYdpJ/1aTWpjl","attestation":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTAyNDk5OTksImlkIjoiODhkODA2MmJkODA3YjQzMTU3YTk5N2ZhZTNiYWI1MTAxMzAwNWM4YTliMTZlMjI4ZjU3ZDI2ZjMxNmNjMGRhNyIsIm9yaWdpbiI6Imh0dHBzOi8vZXRoZXJzY2FuLmlvIiwiaXNTY2FtIjpmYWxzZSwiaXNWZXJpZmllZCI6dHJ1ZX0.VKm3mRYC5HL4QBZH6NkouaI3ZDQ4Rq6xy3kI9IW_24eca-c0oWpxcbh0uYfu0UP2shm83BnLCRSnqpmfZbEu5w","publishedAt":"1750246399610","tag":1100}}}),
            pairing_sym_key,
        );

        // SessionSettle sent by wallet
        decode_irn_publish(
            json!({"id":"1750246415207858176","jsonrpc":"2.0","method":"irn_publish","params":{"topic":"afb4ceaf17f6fd0bbb77e6e06f4a623602c264e52ca866e874ec5dfdfe52a1a6","message":"AHrziY1VHPDlcX5IcWc7HjxNB5Fo+0CgdUmKas3q3/+zqyX9+Ve3gis/ACdChVGVoyN7dUKhNTE6xRz5IJyIffX09y/4KigMhmVTQY+VLgjeUWXa0UyAD/IDgPwR8uz+TJDQU8gfAtOMqnMlWW2VwLsSeWgGRzAJDJL3QshoxaGgHbkTr4j9tFAt4/U9xjaFFQL+1kWuUqlTcFbhQQRVZrBPkKs5Rp9C8svx+pvkFp1biGuDIEOoxM10+pTqDzlaA0eUgqe4NyDY704piYLGR1E9NRK4Tn2seKpNghp+ZSVTPv8nOCz7rlp2m7makE1NWcG9nhHbaf1Fh4VSELKcwjmC7JsDEOXEU3+eoT7l8Cd1PpIB2Vxnwoj23VJGi6+gLUOvwoZUglp9VDrgv2eNyEvnHdF/m55Q++9w8TVS5V0/yNl9+3ujpqxWPFJyPAcf2WOzY0HaCOEBNd8SlHu+xQ3ilQbxJbH/4DVuq4o+a9o0cmdfe08XwfopJrZvHgwhhnd/h3kDzEF/lL4iLiVDEglzEbEqWZrhq1ThwzcvQdh88BVMQGbeHqSPDTz0Sulb9aRGqexroK9/y3ulrIdWT1BUPNcDc4xNiXKhhKI1ww3miwJqf0/3ZAMkOAlFh2MWpM3RvIWAt0oixs+E33U4c0zs3py1wDQqlSjZ5IzhddSTk5XO3MgcoGRKYp6T/DMmtCPArtHAg0P4lriBM4tssO1YFsb74XrbZzmHKaXZRqQHzQO6bjM00kJMIb3KFuv1kDT8QTLUDifHDkoDnTSbqzNa315lJ1GCRfKpoNwLYOAEfJrWMSvzIm0kM88Dl9AzfQsYvWl/PFunafqtTu7q3QdKYTSYNc6UNgCpa4kPJnG8elf7CbTuuxy0eXuJOOK4xQQX6Xt84SdO9cF4zQ3GraPHkRkD7f3Ka/cx4vwfFr3hstqvc/PPnVozhD1WkoUx8Zr3UkZVpFOesomAaTHsf0Ial4efmYFh8u+eECdbF4fJwH++MTuITE4A/UMkJ5WKMPbui6wN90qXDVuJ5cdRrtzyLmH2HqvV+V6m/GrY3Bstz5iArWtbnt7SdXG4Jl/5fPDH/v1M04jylvo1Rfi9u+yrdjsKPfR1AStU0LNJA6WBDP3jNperpIRsfNENf1Nb0eR0mRpdNKLDNP+blxIplroXaCfEHgxp0aGi+jVEXk9YeZW+39gyjb0Egn4gTwPDHIy+MMbDB2awXpz5ErOlkJho0CYyFXjfMtaD/k5+1hOJggsxIURQALhrvhcW/2tOFtTDORiIgQlR3vK2jt0k4gfTINm/KQ==","ttl":300,"prompt":false,"tag":1102}}),
            diffie_sym_key,
        );

        // SessionProposeApproveResponse sent by wallet
        decode_irn_publish(
            json!({"id":"1750246415811926016","jsonrpc":"2.0","method":"irn_publish","params":{"topic":"e70cc46faf27cc551138570ed7ea3d186715b1878e78e7b3a4e840897e63797e","message":"AHJshTKhYvdl64dwArd2vsvmO2ydtOxqIJXpfHFzy3+2WAxRuaTXx8rYhdVb8dh4oOQIwUH/Vd5U7S4E8ibeHOGKwFEqTHFfzDTcqibX51g+NWnRI9j/RPGNX3pnBkM/g/280hemT7clPZ6y7dZjrsUtNyGPRq0Rv0iVpd9eoSEYctmzsdJPeOZ6T2bioXq2A73j8ToRx+VHCORsHBRhUr675sgGIIHUkkDocJTYB2Je1wwuAchO8LWnA3xT3bTHPVg=","ttl":300,"prompt":false,"tag":1101}}),
            pairing_sym_key,
        );

        // SessionSettleResponse sent by dapp
        decode_irn_subscription(
            json!({"id":"448063082665219","jsonrpc":"2.0","method":"irn_subscription","params":{"id":"79811a422c6a3c86dc7d84f02f92be0716f2d6fdcf60d4f84648ad7b57c83417","data":{"topic":"afb4ceaf17f6fd0bbb77e6e06f4a623602c264e52ca866e874ec5dfdfe52a1a6","message":"APTQlEFUWFg7kjBhgh3r+MSG+uxa55RbLCqyq5hKxUYQ8u7xIDWF9rZ41io6/W4cf0Pix6F2GsRP0pkfXxeLqkPwUskNvCOxckh1jKXOPndQGg==","publishedAt":"1750246416471","tag":1103}}}),
            diffie_sym_key,
        );

        // SessionRequest sent by dapp - message data for personal_sign
        decode_irn_subscription(
            json!({"id":"448063087047684","jsonrpc":"2.0","method":"irn_subscription","params":{"id":"79811a422c6a3c86dc7d84f02f92be0716f2d6fdcf60d4f84648ad7b57c83417","data":{"topic":"afb4ceaf17f6fd0bbb77e6e06f4a623602c264e52ca866e874ec5dfdfe52a1a6","message":"AGOyYTpn4DXj7g4RiGKrsrZK7t8f25GKgX1R978FIMTIObWzf7UCioUavnhHl+cmWpwKQG02/ezEg+SjwGnHnbPv+5Yc3OEBJQUFL3pQKQ8RGZUycQZoDJMu0tEtnMMNjT+9d4khymh1R2NG128kFE1ra0xb7uq6afj/KUg0TpcyFeHVDuGCMH7B1vqAj8fzhRmlLIT33s0VNmTKYNP4SGXlrv3w/qibUtEwmzJdb1z/YKrYKeFw6YYAU2RbPLr1Uuh53WOyMYKOxQL3BSpyrAvZSqc3yxGQeIr0hfc8X+VmOHTAq3w7Y+KzGnma+oq9upJFFJriZyyJrg0IBXVTpheoFkkOFSwKHHim41J0RNJ94AxGGnPADi9U0nQ=","attestation":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTAyNTAwMzMsImlkIjoiY2MzNmU2ODI2NmE4M2MzMDcyMWExNmQzNjEwZTdlYWFlNTZiODQ2ZmRjMWZjODA4ODk5ZWQ3N2E0NGJmMDFhMiIsIm9yaWdpbiI6Imh0dHBzOi8vZXRoZXJzY2FuLmlvIiwiaXNTY2FtIjpmYWxzZSwiaXNWZXJpZmllZCI6dHJ1ZX0.UfQoDgHxxXEQPyIU5F3ArTIG8qUGYnoa9g0M5B7R4oevLmlHsf2Hj7DbnqH32yZSGaV2i44vWEMQ0eg1e-t-8A","publishedAt":"1750246433590","tag":1108}}}),
            diffie_sym_key,
        );

        // SessionRequestResponse sent by wallet - signature
        decode_irn_publish(
            json!({"id":"1750246437184891136","jsonrpc":"2.0","method":"irn_publish","params":{"topic":"afb4ceaf17f6fd0bbb77e6e06f4a623602c264e52ca866e874ec5dfdfe52a1a6","message":"AFuBrVKYS2ukxISpfnX9t6Jspf+9lNTO2xvVi6aOlJu/mYdMc/bxfb0hmJwO1U3QVL1739ZpdMMMoqw+Ftq93TPBvpfwcmifCND+ALuJ4fxF0/0asczvERCX/WbmeMvnBnaEiQglFlu8fQcEPRUmk5K8Lhh0SEs3REwznBg3bbiihq3+3xxc6BqvjYrG8b+gj9qQArIEwKdZ4hX0CiOzYQ6YiGy7ipcs4yt1IQ91tP2pjTKg7PHWQJOKoRrnavGvlwi3N+CNI9qAOyPqy+70/sOUWPs=","ttl":300,"prompt":false,"tag":1109}}),
            diffie_sym_key,
        );

        // assert!(false);
    }

    #[test]
    fn full_scenario_eth_send_tx() {
        // wc:a86aa0340ed162f569b5119c541b083e46c03f957a27d5a09da7cd768345f838@2?relay-protocol=irn&symKey=e21ac7b17b90035430ca4bb14337e6b3366b4aa152d947a23381236d7817286e&expiryTimestamp=1750257533
        let pairing_sym_key = FixedBytes::<32>::from_str(
            "e21ac7b17b90035430ca4bb14337e6b3366b4aa152d947a23381236d7817286e",
        )
        .unwrap()
        .into();

        let (
            _self_private_key,
            _self_public_key,
            _other_public_key,
            _response_topic,
            diffie_sym_key,
            _diffie_topic,
        ) = calculate(
            "74d832d4136fa8f6309e226a0ca1cfb995f41b145456a529ae57bfd9e1e6340e",
            "567a56436b6c7fef4b661f49e48708e3a943f1b7b73f188f7432ebbb26d06069",
        );

        decode_irn_subscription(
            json!({"id":"448065858770944","jsonrpc":"2.0","method":"irn_subscription","params":{"id":"1171b8fc82d59077fa844c81396cdd546c15f8987cbe50916b94a7889e05f2a7","data":{"topic":"a86aa0340ed162f569b5119c541b083e46c03f957a27d5a09da7cd768345f838","message":"AKP8vXSeDeqJYnF6Q2OGB73Xs1o3qX547ZmG6N+ZNVOn2pBKCNpwpZJUSqn4jjV0UsCBXWL15Ym3JSo93YxN584Ou6XGi0yFriDwWbCd5S7SZ3pEIPsATcPvI4jtHDdTWS6R/XCowMOHk/vP5mDEIuP+de1t23vFp0BQpiY8KDvkKCALAxHhgtCrJijDpxAwxNBzqPPa0LsJTHWfW1wdftu1Gk6ISvHkKISe/NNCqhBUi4SaSE8P7JEiAwdSSc/FJVavzVWqtBsy0yBK4vjxy2IczQfGTjX60ZU7RoMYAtxB7xSozWLnn+KuiZBAAQB/cMW6+S7Bz/d+GLub89EGUpFVy+H3wFOzgffgP3wZCbJElDisNqyOSW3Z2C8UM+puY/H+imyv2vM4iw6XQbyAcu67Wt+VUS9vHJu7XQCF91YYaqLHxJtyGiUiZ7UcVZhFJ2oflbKQTqwarup/7EV1OGp9txfHxrcJsExPGhpZutpqrw85Q1u7RPYeX01WbXXaEUVTiUxJgG2EIkCG8FRwDTL/NctRsMcp9ZipDVY1lTAIodk+b0+a4PpdjR2+UKGdzGQVm7brBYWuSUl+gppKwPOTaUTDE5ySD14+ie6g5tB0I/Y1Ht3/fGDHbaT520nwHbzHTX5p0xk3CBvDJS3d9amd2dnWBaP6T94JRfLv4IcqavIPl8G5HXxPP9fJqyiSrjYRWQ2+547EBNX8f4+TsRCwVK97SwacoRlpiW31z/LEXP/hUUDBL6zlEzeFrwGgxVe1CU5sz+cytX6m54AkLLlJjLfYdA0/dl/oSWqnqP03bkm/VZ+XxfaqzDYypyaG8PJgPZvQ6SKcwl4vSiErxKc873X0","attestation":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTAyNjA4MzMsImlkIjoiZmVlMmU5YWNjYjM1ZTE0MjE5ZTBmYmYzMWYxZDQ1OTEwNjY5YWY4NzUyODFmMjFiZTk0ODJlZDgyZjQ5OTZjZCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMiIsImlzU2NhbSI6bnVsbCwiaXNWZXJpZmllZCI6dHJ1ZX0.esdhIALvXwDA5rmtzXRwzLXdYdbD5YzDHfWRHOFtzq5Nw2rObVMCV0wosEmjTMwlFD3yk5ogyG6T_8Hwh2LSeg","publishedAt":"1750257233816","tag":1100}}}),
            pairing_sym_key,
        );

        decode_irn_publish(
            json!({"id":"1750257262510215424","jsonrpc":"2.0","method":"irn_publish","params":{"topic":"18c207e7f98488b7ffc460f2d27e1eee73820178d5959ace1fd1beff61446b54","message":"AGJsPBJdWmvZvi5a5uahFWCqOOs8matbbbQjA9bIeIdeS/BNRtOooMY2wsRGr3d39Vh5buHEn9VHsNfwkbd88/2A1K1kG2jIwl0qhsgMUI5EblEyXMFsM8Zf4rrPS8ir5ANR5Ie5wPAGBzh6KjRFOMwQmi2M+tad+uWxt1MhpV5n7nNusSIbavksH0iEMI7I8JPEjfNpOJwSMnkS6ZgodRTauLX16yPoodCPU4WP3UJG2nLl+O39aV/PUZkTyZjOr+SvVSF2Pyi39tJmZLxjCOiG8yUPoOi7OnisNaMRBoqMSmrBIkKbQNI9u1gs9koDrMNPU2gCkTl0xWtS4hD63H47/jk6H4V7h81AidK17cYmg4k2RuOsqEkEFbi5gK3MG+ecCbmXbcIq2ur6oRmhWR0m5JyLYPuZbitMH8AXRzZfns5ojSxZNNguAukcc2tHVIF2OwYXQZeoZgmeYKWAIZRsDJ2ZqlLCee0b4bIKplQIaS3wg1qkeT7QpwpBpOWd2PI/Yf96ZvUT4niIlRrBzVnEzy+ICrw23vUwyOJpHJ0ThcDKXcfGYgpRe4QaLRoR6m7hvWGE9p0NyR/tMH3cMuxs3zuPaznLlWxOElzBeVPiXQgOnijSWrx+nGvmGqUtzlLlbfPwP9Sh7r7ceyhfv0J4pznl/ypSe1Oq549wZXbS8nX01hDZGEM9EFc51lDOiimsuhTxjkWL9YOGHWDXZVeJpHe8/uJzvKQikca7XuF5qiFj8+qGgiAT4g5ySrXzDCO3E75gVTDPUv/OFSK1f2tQapIbTorWsstIAtGPbIB70+k6T7gd3YyWddHAyFM8sHmnewF8t9gsZFqVrBNmKY5FmTU6/49HfFNp0whAvddZdjHRgnGIybn5p8tyUzS7lRiQtEuOTf8c7McC9IfBiEXTP8roXNELU6KfWHbOmECnBrHCqTDxNpflTnW7O9QaIK8QdKNWIZkvxMAmhLiKIwre5mGdE8ZjqkaXwScW4WR0D1shbNXEpw==","ttl":300,"prompt":false,"tag":1102}}),
            diffie_sym_key,
        );

        decode_irn_publish(
            json!({"id":"1750257263070232064","jsonrpc":"2.0","method":"irn_publish","params":{"topic":"a86aa0340ed162f569b5119c541b083e46c03f957a27d5a09da7cd768345f838","message":"AFyRRg2d2xef5T5lPSOCxzmJjpUb2NT2FVTLpwU6riLMgfAIZaJie18N2LW97GUQJC0DUFeRvQGu0pWV0Tiq25YqGbifEhfOfwDP+xwNi1KUH3uD94X+QBhJuAJhhm7S8h5KGPeGiedbObuauJes9R3/sMvpl0roPeHnSP4BahXq/mX6tUHnhAVHSV7VM76POTV8wYG1kZbxBtgoZURDXot8N3tQ4qXivbe/xSWKJ0semoqKvgAGKQm3l1Tjiy5IJi8=","ttl":300,"prompt":false,"tag":1101}}	),
            pairing_sym_key,
        );

        decode_irn_subscription(
            json!({"id":"448065859558146","jsonrpc":"2.0","method":"irn_subscription","params":{"id":"5825a343b3a8bc864a174ba1a8e4de42490cd886c85a7c622bccb68148b900c1","data":{"topic":"18c207e7f98488b7ffc460f2d27e1eee73820178d5959ace1fd1beff61446b54","message":"ANDjfTbCIF5xuWC3SI35S2df52cgqhlxDod66R3DB1OreS2fxWxEB/F745QOWoaZT73Vh4Q9HVlDejk/W6WAXdN8RjYL5fEUAP9ly4JW9wwYwA==","publishedAt":"1750257263742","tag":1103}}}),
            diffie_sym_key,
        );

        decode_irn_subscription(
            json!({"id":"448065859558403","jsonrpc":"2.0","method":"irn_subscription","params":{"id":"1171b8fc82d59077fa844c81396cdd546c15f8987cbe50916b94a7889e05f2a7","data":{"topic":"a86aa0340ed162f569b5119c541b083e46c03f957a27d5a09da7cd768345f838","message":"ANFy+qiYgSDxaHgpx5NUrBUUNR7aTktaeGoRt7jYWENIBfpqPSPOFBP/OG6tZeMUrvMRMBya1r78C61ynVEpHCHttZEQv5YcGAO+taYNcX5/hARqWU3p9bgf4KZxvHi3PWExaapKHC3swK5Djbqu7fX2Uub0wRJaSdNJasWTGd7/FXCP+BAZQl/bvCNH9SgTMuPtRv9K","publishedAt":"1750257263742","tag":1000}}}),
            pairing_sym_key,
        );

        // SessionRequest sent by dapp - tx data for eth_sendTransaction
        decode_irn_subscription(
            json!({"id":"448065860891397","jsonrpc":"2.0","method":"irn_subscription","params":{"id":"5825a343b3a8bc864a174ba1a8e4de42490cd886c85a7c622bccb68148b900c1","data":{"topic":"18c207e7f98488b7ffc460f2d27e1eee73820178d5959ace1fd1beff61446b54","message":"AMfq9/oq8O4gBj64W8icN8wY3lHwXHJv5HcPFB//44hYBkErnJOF7Vz2OYLfNvarP33xFjNRE7xbgICc6XzTMT8191FPDmzLJKjaikQiZjdRdXNn5Q/xDH0WwUGXlE6gjcRLz/kXTNE6J1DTTre36vu1ttn33vQszRgi3fKm5cxts9QBBrAz/L+iqgH4+cxzi+SHBLYzbIbCx9xF/lu6eNX8OHqO438ivbTGeBDUslSLeke7CWg2UeSI31iPQb+VfLiBtt49kWJC4/4BJxr9SQYKpyoXSiHnN661lOb6KvRRwEA9eJfwNPc6j+aq7ErWxlzP8uP81S0NM/FWB6J3Ws3o9M/6iQlVVI9qrSl9zAeXCs/b/Kh4E2R3BcW/pIuyEkQGoTn2fF28No+AniZwcFcpFjqGB80LZoQKTQgSPxB2IDnuM//UsHjrKfM+oHOPGzn7m1Ps1jCNBis2f/9a14Dx6Ddl00HmmXF9vi6xR16hUYCV+fSagAXSd1P9JXrMJ8twDGzSfjdNp9+dWSRRpdwTyY6udX8=","attestation":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTAyNjA4NjgsImlkIjoiNGFjMWU2NjY3YzFjYzgyZWUyMzlmZmZiNGJmZTE0M2UyYTQzZjdjODM0NDAzZjU3MTY5Mjg4MjBiMzNjMmU0YiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMiIsImlzU2NhbSI6bnVsbCwiaXNWZXJpZmllZCI6dHJ1ZX0.hnBHBG-OhJWumKZ171r_8U5GfzR1w8-GmKy23t7mZzY8LstuUeVuI1eUyZDd93rxwryR98MmVzlPc9_CgXSc4A","publishedAt":"1750257268949","tag":1108}}}),
            diffie_sym_key,
        );

        // SessionRequestResponse sent by wallet - tx hash that has been submitted
        decode_irn_publish(
            json!({"id":"1750257289741548032","jsonrpc":"2.0","method":"irn_publish","params":{"topic":"18c207e7f98488b7ffc460f2d27e1eee73820178d5959ace1fd1beff61446b54","message":"AAJvwnNZRNLuhMsu0wUurXPTLULwrQLuu1jKIS1FR96kqZkBeVHjugmZTArl9IArWLSTcaAB5itYdsSx1s+eoNnI5DhT+EQjbHiDenfs4E1kyoggj2kXHfM6E79TebpPoEmLJa7WMW/SNUcAg1LMMNg6HZNdqlW30+Zs66pf4DBkoRbCnVMwh2ToWY3c5FiAuv4=","ttl":300,"prompt":false,"tag":1109}}),
            diffie_sym_key,
        );

        // assert!(false);
    }

    fn decode_irn_subscription(value: Value, sym_key: [u8; 32]) {
        let req =
            serde_json::from_value::<JsonRpcRequest<IrnSubscriptionParams>>(
                value,
            )
            .unwrap();
        println!("============================================\nreq: {req:#?}");

        let msg =
            Message::decrypt(&req.params.unwrap().data.message, sym_key, None)
                .unwrap()
                .decode();
        println!("msg: {msg:#?}");
    }

    fn decode_irn_publish(value: Value, sym_key: [u8; 32]) {
        let req =
            serde_json::from_value::<JsonRpcRequest<IrnPublishParams>>(value)
                .unwrap();
        println!("============================================\nreq: {req:#?}");

        let msg = Message::decrypt(&req.params.unwrap().message, sym_key, None)
            .unwrap()
            .decode();
        println!("msg: {msg:#?}");
    }
}
