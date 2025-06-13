use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;
use rand::Rng;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::error::Result;
use crate::paring::Pairing;
use crate::relay_auth::RelayAuth;
use crate::types::{
    EncryptedMessage, FetchMessageResult, Id, JsonRpcMethod, JsonRpcRequest,
    JsonRpcResponse, Metadata,
};

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

    pub async fn init_pairing(&self, uri: &str) -> Result<Pairing> {
        let mut pairing = Pairing::new(uri, self);
        pairing.init_pairing().await?;
        Ok(pairing)
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
                .request::<FetchMessageResult>(
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

    pub async fn ping(&self) {
        self.request::<Value>(
            JsonRpcMethod::IrnPublish,
        Some(json!({
                    "topic":"399de3bd2499b8fe10647e3c3ce4bb96d6fa1db18ee6f3fec4042167509e0a49",
                    "message":"ACwGLx2vdQZg6dVj9eswLqBJL4jvNsy5NR9lavO2tb6+h7ll+HRgWYrx/XaJgov4KYeq0I31duzgcDWmBz9JtP0snPo5ZVYr5NZf4/Ylyo8wkrnRGq6i8d8/fRx0pHW4nTF6mTXBBDVEa4mJVrkMukx71gfKGluxhGdRL9AsMoFLffvGcyDCLvs/bKePFd7mUNp9rNzEa47vJzj79HhTqs/BH/IOKnHngzBHkfQjg6OI8Dx1E1gQLEqZyBPDY5CzihKYbJIkiLpabZ/klTZikfssfA8bGzYyNdpnQqf3itq5f3Y5dC17QZDVntNxNjJ+ymRAgGdAZZKV6kaiZZoc87G+GoRmq17Zdx1nzOpi+q+05jvFyN6pbJYOdmqdqXyHCz96bAENlfZV3oVlqdCi1FT/YuOayfWfMza6jm5qb4naQ+YHPyYRWXHhB9lAHX96XdyhJ8BgPZrLNS8/yBjkBSqL9wAKfrh9KLOlUYk4XcVjqdXE9MA=",
                    "ttl":300,
                    "prompt":false,
                    "tag":1109
                }))
        ).await.unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_ping() {
        let conn = Connection::new(
            "https://relay.walletconnect.org/rpc",
            "https://relay.walletconnect.org",
            "35d44d49c2dee217a3eb24bb4410acc7",
            [0; 32],
            Metadata {
                name: "WalletConnect Rust SDK".to_string(),
                description: "WalletConnect Rust SDK enables to connect to relay and interact with dapp".to_string(),
                url: "https://github.com/zemse/walletconnect-sdk".to_string(),
                icons: vec![],
            },
        );
        conn.ping().await;
    }
}
