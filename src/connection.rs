/// Connection
///
/// Authenticate with the WalletConnect RPC using JWT and fetch or publish
/// encrypted payloads.
///
use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;
use rand::Rng;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::error::Result;
use crate::pairing::Pairing;
use crate::relay_auth::RelayAuth;
use crate::types::{
    EncryptedMessage, Id, IrnFetchMessageResult, JsonRpcMethod, JsonRpcRequest,
    JsonRpcResponse, Metadata,
};
use crate::wc_message::WcMessage;

#[derive(Debug, Clone)]
pub struct Connection {
    rpc: String,
    id: usize,
    jwt: String,
    project_id: String,
    metadata: Metadata,
}

impl Connection {
    pub fn new(
        rpc: &str,
        jwt_rpc: &str,
        project_id: &str,
        client_seed: [u8; 32],
        metadata: Metadata,
    ) -> Self {
        let relay_auth = RelayAuth::new(client_seed);
        let initial: u16 = rand::thread_rng().r#gen();
        let jwt = relay_auth.sign_jwt(jwt_rpc);
        Self {
            rpc: rpc.to_string(),
            id: initial as usize,
            jwt,
            project_id: project_id.to_string(),
            metadata,
        }
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub(crate) fn get_id(&self) -> Id {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards");

        let date_ns = now.as_millis() * 1_000_000;
        let extra = self.id as u128;

        (date_ns + extra).into()
    }

    pub async fn init_pairing(self, uri: &str) -> Result<(Pairing, WcMessage)> {
        let mut pairing = Pairing::new(uri, self);
        let m = pairing.init_pairing().await?;
        Ok((pairing, m))
    }

    pub async fn irn_subscribe(&self, topic: &str) -> Result<String> {
        self.request::<String>(
            JsonRpcMethod::IrnSubscribe,
            Some(json!({
                "topic": topic
            })),
        )
        .await
    }

    pub async fn irn_fetch_messages(
        &self,
        topic: &str,
    ) -> Result<Vec<EncryptedMessage>> {
        let mut arr = vec![];
        loop {
            let result = self
                .request::<IrnFetchMessageResult>(
                    JsonRpcMethod::IrnFetchMessages,
                    Some(json!({
                        "topic": topic
                    })),
                )
                .await?;
            arr.extend(result.messages);
            if !result.has_more {
                break;
            }
        }
        Ok(arr)
    }

    pub async fn irn_publish(
        &self,
        encrypted_message: EncryptedMessage,
    ) -> Result<Value> {
        self.request(
            JsonRpcMethod::IrnPublish,
            Some(serde_json::to_value(encrypted_message)?),
        )
        .await
    }

    async fn request<ResultType>(
        &self,
        method: JsonRpcMethod,
        params: Option<Value>,
    ) -> Result<ResultType>
    where
        ResultType: DeserializeOwned,
    {
        let request = JsonRpcRequest {
            id: self.get_id(),
            jsonrpc: "2.0".to_string(),
            method,
            params,
        };
        debug!("request -> {request}");
        let client = Client::new();
        let response = client
            .post(&self.rpc)
            .query(&[("projectId", &self.project_id)])
            .bearer_auth(&self.jwt)
            .json(&request)
            .send()
            .into_future()
            .await?
            .text()
            .await?;
        debug!("response -> {response}");
        let response =
            serde_json::from_str::<JsonRpcResponse>(response.as_str())?;

        if let Some(result) = response.result {
            Ok(serde_json::from_value::<ResultType>(result).inspect_err(
                |e| println!("Failed to decode JSON RPC Response Error: {e}"),
            )?)
        } else if let Some(error) = response.error {
            Err(error.into())
        } else {
            Err(format!("Unexpected response: {response:?}").into())
        }
    }
}
