use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

use crate::error::Result;
use crate::paring::Pairing;
use crate::wallet_kit::WalletKit;

pub struct Connection {
    rpc: String,
    id: usize,
    jwt: String,
    project_id: String,
}

impl Connection {
    pub fn new(
        rpc: &str,
        jwt_rpc: &str,
        project_id: &str,
        client_seed: [u8; 32],
    ) -> Self {
        let wallet_kit = WalletKit::new(client_seed);
        let initial: u16 = rand::thread_rng().r#gen();
        let jwt = wallet_kit.sign_jwt(jwt_rpc);
        Self {
            rpc: rpc.to_string(),
            id: initial as usize,
            jwt,
            project_id: project_id.to_string(),
        }
    }

    fn get_id(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards");

        let date_ns = now.as_millis() * 1_000_000;
        let extra = self.id as u128;

        (date_ns + extra).to_string()
    }

    pub fn pair(&self, uri: &str) -> Result<Value> {
        let pairing = Pairing::new(uri, self);
        let subscription_id = pairing.irn_subscribe()?;
        println!("Pairing subscription_id: {:?}", subscription_id);
        let result = pairing.irn_fetch_messages_and_decrypt()?;
        println!("irn fetch messages: {:?}", result);

        Err("Pairing not implemented".into())
    }

    pub fn irn_publish(
        &self,
        topic: &str,
        message: &str,
        ttl: u64,
        prompt: bool,
        tag: u64,
    ) -> Result<Value> {
        self.request(
            "irn_publish".to_string(),
            Some(json!({
                "topic": topic,
                "message": message,
                "ttl": ttl,
                "prompt": prompt,
                "tag": tag,
            })),
        )
    }

    pub fn ping(&self) {
        self.request::<Value>(
    "irn_publish".to_string(),
        Some(json!({
                    "topic":"399de3bd2499b8fe10647e3c3ce4bb96d6fa1db18ee6f3fec4042167509e0a49",
                    "message":"ACwGLx2vdQZg6dVj9eswLqBJL4jvNsy5NR9lavO2tb6+h7ll+HRgWYrx/XaJgov4KYeq0I31duzgcDWmBz9JtP0snPo5ZVYr5NZf4/Ylyo8wkrnRGq6i8d8/fRx0pHW4nTF6mTXBBDVEa4mJVrkMukx71gfKGluxhGdRL9AsMoFLffvGcyDCLvs/bKePFd7mUNp9rNzEa47vJzj79HhTqs/BH/IOKnHngzBHkfQjg6OI8Dx1E1gQLEqZyBPDY5CzihKYbJIkiLpabZ/klTZikfssfA8bGzYyNdpnQqf3itq5f3Y5dC17QZDVntNxNjJ+ymRAgGdAZZKV6kaiZZoc87G+GoRmq17Zdx1nzOpi+q+05jvFyN6pbJYOdmqdqXyHCz96bAENlfZV3oVlqdCi1FT/YuOayfWfMza6jm5qb4naQ+YHPyYRWXHhB9lAHX96XdyhJ8BgPZrLNS8/yBjkBSqL9wAKfrh9KLOlUYk4XcVjqdXE9MA=",
                    "ttl":300,
                    "prompt":false,
                    "tag":1109
                }))
        ).unwrap();
    }

    pub fn request<ResponseType>(
        &self,
        method: String,
        params: Option<Value>,
    ) -> Result<ResponseType>
    where
        ResponseType: DeserializeOwned,
    {
        let client = Client::new();
        let rt = Runtime::new().expect("runtime failed");
        let response = rt.block_on(
            rt.block_on(
                client
                    .post(&self.rpc)
                    .query(&[("projectId", &self.project_id)])
                    .bearer_auth(&self.jwt)
                    .json(&JsonRpcRequest {
                        id: self.get_id(),
                        jsonrpc: "2.0",
                        method,
                        params,
                    })
                    .send()
                    .into_future(),
            )?
            .json::<JsonRpcResponse>()
            .into_future(),
        )?;

        if let Some(result) = response.result {
            Ok(serde_json::from_value::<ResponseType>(result)?)
        } else if let Some(error) = response.error {
            Err(error.into())
        } else {
            Err(format!("Unexpected response: {:?}", response).into())
        }
    }
}

/// A basic JSON-RPC 2.0 request.
#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>, // Could be array or object
    id: String,
}

/// A basic JSON-RPC 2.0 response with either a result or an error.
#[derive(Deserialize, Debug)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<u64>,
}

/// A JSON-RPC error object (code, message, and optional data).
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping() {
        let conn = Connection::new(
            "https://relay.walletconnect.org/rpc",
            "https://relay.walletconnect.org",
            "35d44d49c2dee217a3eb24bb4410acc7",
            [0; 32],
        );
        conn.ping();
    }
}
